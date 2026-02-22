package argocd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/argoproj/argo-cd/v3/pkg/apiclient/application"
)

func SetArgoCDAppRevision(ctx context.Context, ac ArgoCDClients, componentPath, revision, repo string, useSHALabelForArgoDiscovery bool, logger *slog.Logger) error {
	logger.Debug("Setting ArgoCD app revision", "component_path", componentPath, "revision", revision, "repo", repo)
	app, err := findArgocdApp(ctx, componentPath, repo, ac.App, useSHALabelForArgoDiscovery, logger)
	if err != nil {
		return fmt.Errorf("finding ArgoCD application for component %s: %w", componentPath, err)
	}
	if app == nil {
		return fmt.Errorf("%w: component %s", ErrAppNotFound, componentPath)
	}
	if app.Spec.Source.TargetRevision == revision {
		logger.Info("App already has revision", "app", app.Name, "revision", revision)
		return nil
	}

	patchObj := struct {
		Spec struct {
			Source struct {
				TargetRevision string `json:"targetRevision"`
			} `json:"source"`
		} `json:"spec"`
	}{}
	patchObj.Spec.Source.TargetRevision = revision
	patchJSON, _ := json.Marshal(patchObj)
	patch := string(patchJSON)
	logger.Debug("Patching app", "namespace", app.Namespace, "app", app.Name, "patch", patch)

	patchType := "merge"
	_, err = ac.App.Patch(ctx, &application.ApplicationPatchRequest{
		Name:         &app.Name,
		AppNamespace: &app.Namespace,
		PatchType:    &patchType,
		Patch:        &patch,
	})
	if err != nil {
		return fmt.Errorf("revision patching failed: %w", err)
	}
	logger.Info("ArgoCD App revision set", "app", app.Name, "revision", revision)
	return nil
}
