package argocd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/argoproj/argo-cd/v2/pkg/apiclient/application"
)

func SetArgoCDAppRevision(ctx context.Context, ac ArgoCDClients, componentPath string, revision string, repo string, useSHALabelForArgoDicovery bool) error {
	slog.Debug("Setting ArgoCD app revision", "component_path", componentPath, "revision", revision, "repo", repo)
	foundApp, err := findArgocdApp(ctx, componentPath, repo, ac.App, useSHALabelForArgoDicovery)
	if err != nil {
		return fmt.Errorf("error finding ArgoCD application for component path %s: %w", componentPath, err)
	}
	if foundApp == nil {
		return fmt.Errorf("%w: component %s", ErrAppNotFound, componentPath)
	}
	if foundApp.Spec.Source.TargetRevision == revision {
		slog.Info("App already has revision", "app", foundApp.Name, "revision", revision)
		return nil
	}

	patchObject := struct {
		Spec struct {
			Source struct {
				TargetRevision string `json:"targetRevision"`
			} `json:"source"`
		} `json:"spec"`
	}{}
	patchObject.Spec.Source.TargetRevision = revision
	patchJson, _ := json.Marshal(patchObject)
	patch := string(patchJson)
	slog.Debug("Patching app", "namespace", foundApp.Namespace, "app", foundApp.Name, "patch", patch)

	patchType := "merge"
	_, err = ac.App.Patch(ctx, &application.ApplicationPatchRequest{
		Name:         &foundApp.Name,
		AppNamespace: &foundApp.Namespace,
		PatchType:    &patchType,
		Patch:        &patch,
	})
	if err != nil {
		return fmt.Errorf("revision patching failed: %w", err)
	} else {
		slog.Info("ArgoCD App revision set", "app", foundApp.Name, "revision", revision)
	}

	return err
}
