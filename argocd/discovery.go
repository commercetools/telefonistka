package argocd

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: Blocklisted import crypto/sha1: weak cryptographic primitive (gosec), this is not a cryptographic use case
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/argoproj/argo-cd/v3/pkg/apiclient/application"
	applicationsetpkg "github.com/argoproj/argo-cd/v3/pkg/apiclient/applicationset"
	argoappv1 "github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
)

// This function will search for an ApplicationSet by the componentPath and repo name by comparing the componentPath with the ApplicationSet's spec.generators.[]git.directories
func findRelevantAppSetByPath(ctx context.Context, componentPath string, repo string, appSetClient applicationsetpkg.ApplicationSetServiceClient, logger *slog.Logger) (appSet *argoappv1.ApplicationSet, err error) {
	logger.Debug("Searching for matching ApplicationSet", "component_path", componentPath, "repo", repo)
	appSetQuery := applicationsetpkg.ApplicationSetListQuery{}

	foundAppSets, err := appSetClient.List(ctx, &appSetQuery)
	if err != nil {
		return nil, fmt.Errorf("Error listing ArgoCD ApplicationSets: %w", err)
	}
	for _, appSet := range foundAppSets.Items {
		for _, generator := range appSet.Spec.Generators {
			if generator.Git != nil && generator.Git.RepoURL == repo {
				for _, dir := range generator.Git.Directories {
					match, matchErr := path.Match(dir.Path, componentPath)
					if matchErr != nil {
						logger.Warn("Malformed glob in ApplicationSet directory pattern", "appset", appSet.Name, "pattern", dir.Path, "err", matchErr)
						continue
					}
					if match {
						logger.Debug("Found matching ApplicationSet", "appset", appSet.Name, "component_path", componentPath, "repo", repo)
						return &appSet, nil
					}
				}
			}

			if generator.Plugin != nil &&
				generator.Plugin.Input.Parameters != nil {
				for key, value := range generator.Plugin.Input.Parameters {
					if key == "path" {
						var parsedPath string

						if err := json.Unmarshal(value.Raw, &parsedPath); err != nil {
							return nil, fmt.Errorf("unable to unmarshal plugin generator path: %w", err)
						}

						match, matchErr := path.Match(parsedPath, componentPath)
						if matchErr != nil {
							logger.Warn("Malformed glob in ApplicationSet plugin path", "appset", appSet.Name, "pattern", parsedPath, "err", matchErr)
							continue
						}
						if match {
							logger.Debug("Found matching ApplicationSet", "appset", appSet.Name, "component_path", componentPath, "repo", repo)
							return &appSet, nil
						}
					}
				}
			}
		}
	}
	logger.Debug("No matching ApplicationSet found", "component_path", componentPath, "repo", repo, "appsets_checked", len(foundAppSets.Items))
	return nil, fmt.Errorf("%w: component %s (repo %s)", ErrAppSetNotFound, componentPath, repo)
}

// findArgocdAppBySHA1Label finds an ArgoCD application by the SHA1 label of the component path it's supposed to avoid performance issues with the "manifest-generate-paths" annotation method which requires pulling all ArgoCD applications(!) on every PR event.
// The SHA1 label is assumed to be populated by the ApplicationSet controller(or apps of apps  or similar).
func findArgocdAppBySHA1Label(ctx context.Context, componentPath string, repo string, appClient application.ApplicationServiceClient, logger *slog.Logger) (app *argoappv1.Application, err error) {
	// Calculate sha1 of component path to use in a label selector
	cPathBa := []byte(componentPath)
	hasher := sha1.New() //nolint:gosec // G505: Blocklisted import crypto/sha1: weak cryptographic primitive (gosec), this is not a cryptographic use case
	hasher.Write(cPathBa)
	componentPathSha1 := hex.EncodeToString(hasher.Sum(nil))
	labelSelector := fmt.Sprintf("telefonistka.io/component-path-sha1=%s", componentPathSha1)
	logger.Debug("Using label selector", "selector", labelSelector)
	appLabelQuery := application.ApplicationQuery{
		Selector: &labelSelector,
		Repo:     &repo,
	}
	foundApps, err := appClient.List(ctx, &appLabelQuery)
	if err != nil {
		return nil, fmt.Errorf("Error listing ArgoCD applications: %w", err)
	}
	if len(foundApps.Items) == 0 {
		logger.Info("No ArgoCD application found for component path sha1 for selector", "component_path", componentPath, "sha", componentPathSha1, "repo", repo, "selector", labelSelector)
		return nil, nil
	}

	// we expect only one app with this label and repo selectors
	return &foundApps.Items[0], nil
}

// findArgocdAppByManifestPathAnnotation is the default method to find an ArgoCD application by the manifest-generate-paths annotation.
// It assumes the ArgoCD (optional) manifest-generate-paths annotation is set on all relevant apps.
// Notice that this method includes a full list of all ArgoCD applications in the repo, this could be a performance issue if there are many apps in the repo.
func findArgocdAppByManifestPathAnnotation(ctx context.Context, componentPath string, repo string, appClient application.ApplicationServiceClient, logger *slog.Logger) (app *argoappv1.Application, err error) {
	// argocd.argoproj.io/manifest-generate-paths
	appQuery := application.ApplicationQuery{
		Repo: &repo,
	}
	// AFAIKT I can't use standard grpc instrumentation here, since the argocd client abstracts too much (including the choice between Grpc and Grpc-web)
	// I'll just manually log the time it takes to get the apps for now
	getAppsStart := time.Now()
	allRepoApps, err := appClient.List(ctx, &appQuery)
	getAppsDuration := time.Since(getAppsStart).Milliseconds()
	logger.Debug("Got ArgoCD applications for repo", "count", len(allRepoApps.Items), "repo", repo, "ms", getAppsDuration)
	if err != nil {
		return nil, err
	}
	for _, app := range allRepoApps.Items {
		// Check if the app has the annotation
		// https://argo-cd.readthedocs.io/en/stable/operator-manual/high_availability/#manifest-paths-annotation
		// Consider the annotation content can a semi-colon separated list of paths, an absolute path or a relative path(start with a ".")  and the manifest-paths-annotation could be a subpath of componentPath.
		// We need to check if the annotation is a subpath of componentPath

		appManifestPathsAnnotation := app.Annotations["argocd.argoproj.io/manifest-generate-paths"]

		for _, manifetsPathElement := range strings.Split(appManifestPathsAnnotation, ";") {
			// if `manifest-generate-paths` element starts with a "." it is a relative path(relative to repo root), we need to join it with the app source path
			if strings.HasPrefix(manifetsPathElement, ".") {
				manifetsPathElement = filepath.Join(app.Spec.Source.Path, manifetsPathElement)
			}

			// Checking is componentPath is a subpath of the manifetsPathElement
			// Using filepath.Rel solves all kinds of path issues, like double slashes, etc.
			rel, err := filepath.Rel(manifetsPathElement, componentPath)
			if !strings.HasPrefix(rel, "..") && err == nil {
				logger.Debug("Found app with manifest-generate-paths annotation that matches component path",
					"app", app.Name, "paths_annotation", appManifestPathsAnnotation, "component_path", componentPath)
				return &app, nil
			}
		}
	}
	logger.Info("No ArgoCD application found with manifest-generate-paths annotation that matches path",
		"component_path", componentPath, "repo", repo, "checked_count", len(allRepoApps.Items))
	return nil, nil
}

func findArgocdApp(ctx context.Context, componentPath string, repo string, appClient application.ApplicationServiceClient, useSHALabelForArgoDicovery bool, logger *slog.Logger) (app *argoappv1.Application, err error) {
	logger.Debug("Finding ArgoCD app", "component_path", componentPath, "repo", repo, "use_sha_label", useSHALabelForArgoDicovery)
	f := findArgocdAppByManifestPathAnnotation
	if useSHALabelForArgoDicovery {
		f = findArgocdAppBySHA1Label
	}
	return f(ctx, componentPath, repo, appClient, logger)
}
