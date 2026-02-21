package argocd

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"strings"

	"github.com/argoproj/argo-cd/v2/applicationset/utils"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/application"
	argoappv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
)

// copied form https://github.com/argoproj/argo-cd/blob/v2.11.4/applicationset/controllers/applicationset_controller.go#L493C1-L503C2
func getTempApplication(applicationSetTemplate argoappv1.ApplicationSetTemplate) *argoappv1.Application {
	var tmplApplication argoappv1.Application
	tmplApplication.Annotations = applicationSetTemplate.Annotations
	tmplApplication.Labels = applicationSetTemplate.Labels
	tmplApplication.Namespace = applicationSetTemplate.Namespace
	tmplApplication.Name = applicationSetTemplate.Name
	tmplApplication.Spec = applicationSetTemplate.Spec
	tmplApplication.Finalizers = applicationSetTemplate.Finalizers

	return &tmplApplication
}

// This function generate the params map for the ApplicationSet template, mimicking the behavior of the ApplicationSet controller Git Generator
func generateAppSetGitGeneratorParams(p string) map[string]interface{} {
	params := make(map[string]interface{})
	paramPath := map[string]interface{}{}

	paramPath["path"] = p
	paramPath["basename"] = path.Base(paramPath["path"].(string))
	paramPath["filename"] = path.Base(p)
	paramPath["basenameNormalized"] = utils.SanitizeName(path.Base(paramPath["path"].(string)))
	paramPath["filenameNormalized"] = utils.SanitizeName(path.Base(paramPath["filename"].(string)))
	paramPath["segments"] = strings.Split(paramPath["path"].(string), "/")
	params["path"] = paramPath
	return params
}

func createTempAppObjectFroNewApp(ctx context.Context, componentPath string, repo string, prBranch string, ac ArgoCDClients, logger *slog.Logger) (app *argoappv1.Application, err error) {
	logger.Debug("ArgoCD app not found, searching for matching ApplicationSet", "component_path", componentPath, "repo", repo)
	appSetOfcomponent, err := findRelevantAppSetByPath(ctx, componentPath, repo, ac.AppSet, logger)
	if appSetOfcomponent != nil {
		useGoTemplate := true
		var goTemplateOptions []string
		params := generateAppSetGitGeneratorParams(componentPath)
		r := &utils.Render{}
		newAppObject, err := r.RenderTemplateParams(getTempApplication(appSetOfcomponent.Spec.Template), nil, params, useGoTemplate, goTemplateOptions)
		if err != nil {
			return nil, fmt.Errorf("rendering ApplicationSet template: %w", err)
		}

		// Mutating some of the app object fields to fit this specific use case
		tempAppName := fmt.Sprintf("temp-%s", newAppObject.Name)
		newAppObject.Name = tempAppName
		// We need to remove the automated sync policy, we just want to create a temporary app object, run a diff and remove it.
		newAppObject.Spec.SyncPolicy.Automated = nil
		newAppObject.Spec.Source.TargetRevision = prBranch

		validateTempApp := false
		appCreateRequest := application.ApplicationCreateRequest{
			Application: newAppObject,
			Validate:    &validateTempApp, // It makes more sense to handle template failures in the diff generation section
		}
		// Create the temporary app object
		app, err = ac.App.Create(ctx, &appCreateRequest)
		if err != nil {
			return nil, err
		}
		logger.Debug("Temporary app created from ApplicationSet", "app", tempAppName, "appset", appSetOfcomponent.Name)
		return app, nil
	} else {
		return nil, err
	}
}
