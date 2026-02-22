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

// findRelevantAppSetByPath searches for an ApplicationSet whose Git or Plugin
// generator directory pattern matches componentPath in the given repo.
func findRelevantAppSetByPath(ctx context.Context, componentPath, repo string, appSetClient applicationsetpkg.ApplicationSetServiceClient, logger *slog.Logger) (*argoappv1.ApplicationSet, error) {
	logger.Debug("Searching for matching ApplicationSet", "component_path", componentPath, "repo", repo)

	found, err := appSetClient.List(ctx, &applicationsetpkg.ApplicationSetListQuery{})
	if err != nil {
		return nil, fmt.Errorf("listing ArgoCD ApplicationSets: %w", err)
	}
	for _, appSet := range found.Items {
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
	logger.Debug("No matching ApplicationSet found", "component_path", componentPath, "repo", repo, "appsets_checked", len(found.Items))
	return nil, fmt.Errorf("%w: component %s (repo %s)", ErrAppSetNotFound, componentPath, repo)
}

// findArgocdAppBySHA1Label finds an ArgoCD application by a SHA1 label
// derived from the component path. This avoids pulling all apps on
// every PR event (unlike the manifest-generate-paths annotation method).
// The label is assumed to be set by the ApplicationSet controller.
func findArgocdAppBySHA1Label(ctx context.Context, componentPath, repo string, appClient application.ApplicationServiceClient, logger *slog.Logger) (*argoappv1.Application, error) {
	hash := sha1.Sum([]byte(componentPath)) //nolint:gosec // not a cryptographic use case
	selector := fmt.Sprintf("telefonistka.io/component-path-sha1=%s", hex.EncodeToString(hash[:]))
	logger.Debug("Using label selector", "selector", selector)

	apps, err := appClient.List(ctx, &application.ApplicationQuery{
		Selector: &selector,
		Repo:     &repo,
	})
	if err != nil {
		return nil, fmt.Errorf("listing ArgoCD applications: %w", err)
	}
	if len(apps.Items) == 0 {
		logger.Info("No app found for SHA1 label", "component_path", componentPath, "selector", selector, "repo", repo)
		return nil, nil
	}
	return &apps.Items[0], nil
}

// findArgocdAppByManifestPathAnnotation is the default discovery method.
// It lists all apps for the repo and matches componentPath against each
// app's manifest-generate-paths annotation. This can be slow when there
// are many apps — see findArgocdAppBySHA1Label for an alternative.
func findArgocdAppByManifestPathAnnotation(ctx context.Context, componentPath, repo string, appClient application.ApplicationServiceClient, logger *slog.Logger) (*argoappv1.Application, error) {
	start := time.Now()
	apps, err := appClient.List(ctx, &application.ApplicationQuery{Repo: &repo})
	if err != nil {
		return nil, err
	}
	logger.Debug("Got ArgoCD applications for repo", "count", len(apps.Items), "repo", repo, "ms", time.Since(start).Milliseconds())

	for _, app := range apps.Items {
		annotation := app.Annotations["argocd.argoproj.io/manifest-generate-paths"]
		for _, manifestPath := range strings.Split(annotation, ";") {
			if strings.HasPrefix(manifestPath, ".") {
				manifestPath = filepath.Join(app.Spec.Source.Path, manifestPath)
			}
			rel, err := filepath.Rel(manifestPath, componentPath)
			if err == nil && !strings.HasPrefix(rel, "..") {
				logger.Debug("Found app matching manifest-generate-paths",
					"app", app.Name, "annotation", annotation, "component_path", componentPath)
				return &app, nil
			}
		}
	}
	logger.Info("No app found with matching manifest-generate-paths annotation",
		"component_path", componentPath, "repo", repo, "checked_count", len(apps.Items))
	return nil, nil
}

func findArgocdApp(ctx context.Context, componentPath, repo string, appClient application.ApplicationServiceClient, useSHALabelForArgoDiscovery bool, logger *slog.Logger) (*argoappv1.Application, error) {
	logger.Debug("Finding ArgoCD app", "component_path", componentPath, "repo", repo, "use_sha_label", useSHALabelForArgoDiscovery)
	f := findArgocdAppByManifestPathAnnotation
	if useSHALabelForArgoDiscovery {
		f = findArgocdAppBySHA1Label
	}
	return f(ctx, componentPath, repo, appClient, logger)
}
