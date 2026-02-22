package argocd

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"strings"

	"github.com/argoproj/argo-cd/v3/applicationset/utils"
	"github.com/argoproj/argo-cd/v3/pkg/apiclient/application"
	argoappv1 "github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
)

// copied from https://github.com/argoproj/argo-cd/blob/v2.11.4/applicationset/controllers/applicationset_controller.go#L493C1-L503C2
func getTempApplication(tmpl argoappv1.ApplicationSetTemplate) *argoappv1.Application {
	var app argoappv1.Application
	app.Name = tmpl.Name
	app.Namespace = tmpl.Namespace
	app.Annotations = tmpl.Annotations
	app.Labels = tmpl.Labels
	app.Finalizers = tmpl.Finalizers
	app.Spec = tmpl.Spec
	return &app
}

// generateAppSetGitGeneratorParams builds the params map for the
// ApplicationSet template, mimicking the Git generator in the
// ApplicationSet controller.
func generateAppSetGitGeneratorParams(p string) map[string]any {
	base := path.Base(p)
	return map[string]any{
		"path": map[string]any{
			"path":               p,
			"basename":           base,
			"filename":           base,
			"basenameNormalized": utils.SanitizeName(base),
			"filenameNormalized": utils.SanitizeName(base),
			"segments":           strings.Split(p, "/"),
		},
	}
}

func createTempAppObjectForNewApp(ctx context.Context, componentPath, repo, prBranch string, ac Clients, logger *slog.Logger) (*argoappv1.Application, error) {
	logger.Debug("ArgoCD app not found, searching for matching ApplicationSet", "component_path", componentPath, "repo", repo)
	appSet, err := findRelevantAppSetByPath(ctx, componentPath, repo, ac.AppSet, logger)
	if err != nil {
		return nil, err
	}

	params := generateAppSetGitGeneratorParams(componentPath)
	rendered, err := (&utils.Render{}).RenderTemplateParams(getTempApplication(appSet.Spec.Template), nil, params, true, nil)
	if err != nil {
		return nil, fmt.Errorf("rendering ApplicationSet template: %w", err)
	}

	rendered.Name = fmt.Sprintf("temp-%s", rendered.Name)
	// Remove auto-sync: the temp app only exists for diffing.
	if rendered.Spec.SyncPolicy != nil {
		rendered.Spec.SyncPolicy.Automated = nil
	}
	if rendered.Spec.Source != nil {
		rendered.Spec.Source.TargetRevision = prBranch
	}

	noValidate := false
	app, err := ac.App.Create(ctx, &application.ApplicationCreateRequest{
		Application: rendered,
		Validate:    &noValidate,
	})
	if err != nil {
		return nil, err
	}
	logger.Debug("Temporary app created from ApplicationSet", "app", rendered.Name, "appset", appSet.Name)
	return app, nil
}
