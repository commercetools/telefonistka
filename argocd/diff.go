package argocd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	cmdutil "github.com/argoproj/argo-cd/v2/cmd/util"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/application"
	projectpkg "github.com/argoproj/argo-cd/v2/pkg/apiclient/project"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/settings"
	argoappv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	argodiff "github.com/argoproj/argo-cd/v2/util/argo/diff"
	"github.com/argoproj/argo-cd/v2/util/argo/normalizers"
	"github.com/argoproj/gitops-engine/pkg/sync/hook"
	"github.com/gonvenience/ytbx"
	"github.com/homeport/dyff/pkg/dyff"
	yaml3 "gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// tempAppCleanupTimeout bounds how long we wait when deleting a
// temporary ArgoCD application during cleanup.
const tempAppCleanupTimeout = 30 * time.Second

// DiffConfig holds options that control how ArgoCD diffs are generated.
type DiffConfig struct {
	UseSHALabel    bool // use SHA1 label instead of manifest-generate-paths annotation
	CreateTempApps bool // create temporary ArgoCD app objects for new components
}

// DiffElement struct to store diff element details, this represents a single k8s object
type DiffElement struct {
	ObjectGroup     string
	ObjectName      string
	ObjectKind      string
	ObjectNamespace string
	Diff            string
}

// DiffResult struct to store diff result
type DiffResult struct {
	ComponentPath            string
	ArgoCdAppName            string
	ArgoCdAppURL             string
	DiffElements             []DiffElement
	HasDiff                  bool
	DiffError                error
	AppWasTemporarilyCreated bool
	AppSyncedFromPRBranch    bool
	ArgoCdAppHealthStatus    string
	ArgoCdAppSyncStatus      string
	ArgoCdAppAutoSyncEnabled bool
}

// Mostly copied from  https://github.com/argoproj/argo-cd/blob/4f6a8dce80f0accef7ed3b5510e178a6b398b331/cmd/argocd/commands/app.go#L1255C6-L1338
// But instead of printing the diff to stdout, we return it as a string in a struct so we can format it in a nice PR comment.
func generateArgocdAppDiff(ctx context.Context, keepDiffData bool, app *argoappv1.Application, proj *argoappv1.AppProject, resources *application.ManagedResourcesResponse, argoSettings *settings.Settings, diffOptions *DifferenceOption, logger *slog.Logger) (foundDiffs bool, diffElements []DiffElement, err error) {
	logger.Debug("Generating ArgoCD app diff", "app", app.Name, "keep_diff_data", keepDiffData, "managed_resources", len(resources.Items))
	liveObjs, err := cmdutil.LiveObjects(resources.Items)
	if err != nil {
		return false, nil, fmt.Errorf("Failed to get live objects: %w", err)
	}

	items := make([]objKeyLiveTarget, 0)
	var unstructureds []*unstructured.Unstructured
	for _, mfst := range diffOptions.res.Manifests {
		obj, err := argoappv1.UnmarshalToUnstructured(mfst)
		if err != nil {
			return false, nil, fmt.Errorf("Failed to unmarshal manifest: %w", err)
		}
		unstructureds = append(unstructureds, obj)
	}
	groupedObjs, err := groupObjsByKey(unstructureds, liveObjs, app.Spec.Destination.Namespace, logger)
	if err != nil {
		return false, nil, fmt.Errorf("Failed to group objects by key: %w", err)
	}
	items, err = groupObjsForDiff(resources, groupedObjs, items, argoSettings, app.InstanceName(argoSettings.ControllerNamespace), app.Spec.Destination.Namespace, logger)
	if err != nil {
		return false, nil, fmt.Errorf("Failed to group objects for diff: %w", err)
	}

	for _, item := range items {
		var diffElement DiffElement
		if item.target != nil && hook.IsHook(item.target) || item.live != nil && hook.IsHook(item.live) {
			continue
		}
		overrides := make(map[string]argoappv1.ResourceOverride)
		for k := range argoSettings.ResourceOverrides {
			val := argoSettings.ResourceOverrides[k]
			overrides[k] = *val
		}

		ignoreAggregatedRoles := false
		ignoreNormalizerOpts := normalizers.IgnoreNormalizerOpts{}
		diffConfig, err := argodiff.NewDiffConfigBuilder().
			WithDiffSettings(app.Spec.IgnoreDifferences, overrides, ignoreAggregatedRoles, ignoreNormalizerOpts).
			WithTracking(argoSettings.AppLabelKey, argoSettings.TrackingMethod).
			WithNoCache().
			WithStructuredMergeDiff(true).
			Build()
		if err != nil {
			return false, nil, fmt.Errorf("Failed to build diff config: %w", err)
		}
		diffRes, err := argodiff.StateDiff(item.live, item.target, diffConfig)
		if err != nil {
			return false, nil, fmt.Errorf("Failed to diff objects: %w", err)
		}

		if diffRes.Modified || item.target == nil || item.live == nil {
			diffElement.ObjectGroup = item.key.Group
			diffElement.ObjectKind = item.key.Kind
			diffElement.ObjectNamespace = item.key.Namespace
			diffElement.ObjectName = item.key.Name

			var live *unstructured.Unstructured
			var target *unstructured.Unstructured
			if item.target != nil && item.live != nil {
				target = &unstructured.Unstructured{}
				live = item.live
				err = json.Unmarshal(diffRes.PredictedLive, target)
				if err != nil {
					return false, nil, fmt.Errorf("Failed to unmarshal predicted live object: %w", err)
				}
			} else {
				live = item.live
				target = item.target
			}
			if !foundDiffs {
				foundDiffs = true
			}

			if keepDiffData {
				diffElement.Diff, err = diffLiveVsTargetObject(live, target)
			} else {
				diffElement.Diff = "✂️ ✂️  Redacted ✂️ ✂️ \nUnset component-level configuration key `disableArgoCDDiff` to see diff content."
			}
			if err != nil {
				return false, nil, fmt.Errorf("Failed to diff live objects: %w", err)
			}
		}
		diffElements = append(diffElements, diffElement)
	}
	return foundDiffs, diffElements, nil
}

// diffLiveVsTargetObject returns the diff of live and target in a format that
// is compatible with Github markdown diff highlighting.
func diffLiveVsTargetObject(live, target *unstructured.Unstructured) (string, error) {
	if live == nil {
		live = &unstructured.Unstructured{}
	}
	if target == nil {
		target = &unstructured.Unstructured{}
	}
	kind := target.GetKind()
	name := target.GetName()
	apiVersion := target.GetAPIVersion()

	var liveNode yaml3.Node
	var targetNode yaml3.Node

	//  unstructured.Unstructured > Byte
	marsheledLive, _ := live.MarshalJSON()
	marsheledTarget, _ := target.MarshalJSON()

	// Byte > YAML3
	_ = yaml3.Unmarshal(marsheledLive, &liveNode)
	_ = yaml3.Unmarshal(marsheledTarget, &targetNode)

	liveIf := ytbx.InputFile{
		Location: "live",
		Documents: []*yaml3.Node{
			&liveNode,
		},
	}

	targetIf := ytbx.InputFile{
		Location: "target",
		Documents: []*yaml3.Node{
			&targetNode,
		},
	}

	cOptions := []dyff.CompareOption{
		dyff.KubernetesEntityDetection(true),
	}

	dReport, err := dyff.CompareInputFiles(liveIf, targetIf, cOptions...)
	if err != nil {
		return "", fmt.Errorf("failed to generate Dyff report: %w", err)
	}

	reportWriter := &dyff.DiffSyntaxReport{
		PathPrefix:            "@@",
		RootDescriptionPrefix: "#",
		ChangeTypePrefix:      "!",
		HumanReport: dyff.HumanReport{
			Report:                dReport,
			Indent:                0,
			DoNotInspectCerts:     true,
			NoTableStyle:          true,
			OmitHeader:            false,
			UseGoPatchPaths:       false,
			MinorChangeThreshold:  0.1,
			MultilineContextLines: 4,
			PrefixMultiline:       true,
		},
	}

	out := new(bytes.Buffer)

	err = reportWriter.WriteReport(out)
	if err != nil {
		return "", fmt.Errorf("failed to format a Dyff report: %w", err)
	}
	header := "apiVersion: " + apiVersion + "\nkind: " + kind + "\nmetadata:\n  name: " + name + "\n"
	return header + out.String(), nil
}

// ensureApp locates (or creates) the ArgoCD application for a component.
//
// When the app already exists it is hard-refreshed so the live state is
// current. When no app is found and cfg.CreateTempApps is set, a
// temporary app object is created from the matching ApplicationSet
// template.
//
// The returned cleanup function MUST be deferred by the caller — it
// deletes the temporary app (or is a no-op for pre-existing apps).
func ensureApp(ctx context.Context, componentPath, repo, prBranch string, ac ArgoCDClients, cfg DiffConfig, logger *slog.Logger) (app *argoappv1.Application, tempCreated bool, cleanup func(), err error) {
	noop := func() {}

	app, err = findArgocdApp(ctx, componentPath, repo, ac.App, cfg.UseSHALabel, logger)
	if err != nil {
		return nil, false, noop, err
	}

	if app == nil {
		if !cfg.CreateTempApps {
			return nil, false, noop, fmt.Errorf("%w: component %s (repo %s)", ErrAppNotFound, componentPath, repo)
		}

		app, err = createTempAppObjectForNewApp(ctx, componentPath, repo, prBranch, ac, logger)
		if err != nil {
			return nil, false, noop, err
		}
		logger.Debug("Created temporary app object", "app", app.Name)

		// Capture values for the cleanup closure. Use a context
		// detached from the parent so the delete succeeds even if
		// the caller's context was cancelled, but bound it with a
		// timeout so we don't block forever if ArgoCD is
		// unresponsive.
		name := app.Name
		ns := app.Namespace
		cleanup = func() {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tempAppCleanupTimeout)
			defer cancel()
			if _, delErr := ac.App.Delete(cleanupCtx, &application.ApplicationDeleteRequest{
				Name:         &name,
				AppNamespace: &ns,
			}); delErr != nil {
				logger.Error("deleting temporary app", "app", name, "err", delErr)
			} else {
				logger.Debug("Deleted temporary app object", "app", name)
			}
		}
		return app, true, cleanup, nil
	}

	// App exists — hard-refresh so the live state is current.
	refreshType := string(argoappv1.RefreshTypeHard)
	appNameQuery := application.ApplicationQuery{
		Name:    &app.Name,
		Refresh: &refreshType,
	}
	app, err = ac.App.Get(ctx, &appNameQuery)
	if err != nil {
		return nil, false, noop, fmt.Errorf("refreshing application %s: %w", *appNameQuery.Name, err)
	}
	logger.Debug("Got ArgoCD app", "app", app.Name)
	return app, false, noop, nil
}

func generateDiffOfAComponent(ctx context.Context, commentDiff bool, componentPath string, prBranch string, repo string, ac ArgoCDClients, argoSettings *settings.Settings, cfg DiffConfig, logger *slog.Logger) (componentDiffResult DiffResult) {
	logger.Debug("Generating diff for component", "component_path", componentPath, "pr_branch", prBranch, "comment_diff", commentDiff)
	componentDiffResult.ComponentPath = componentPath

	app, tempCreated, cleanup, err := ensureApp(ctx, componentPath, repo, prBranch, ac, cfg, logger)
	if err != nil {
		componentDiffResult.DiffError = err
		return componentDiffResult
	}
	defer cleanup()
	componentDiffResult.AppWasTemporarilyCreated = tempCreated
	componentDiffResult.ArgoCdAppName = app.Name
	componentDiffResult.ArgoCdAppURL = fmt.Sprintf("%s/applications/%s", argoSettings.URL, app.Name)
	componentDiffResult.ArgoCdAppHealthStatus = string(app.Status.Health.Status)
	componentDiffResult.ArgoCdAppSyncStatus = string(app.Status.Sync.Status)
	componentDiffResult.ArgoCdAppAutoSyncEnabled = app.Spec.SyncPolicy.Automated != nil

	if app.Spec.Source.TargetRevision == prBranch && componentDiffResult.ArgoCdAppAutoSyncEnabled {
		componentDiffResult.DiffError = nil
		componentDiffResult.AppSyncedFromPRBranch = true

		return componentDiffResult
	}

	resources, err := ac.App.ManagedResources(ctx, &application.ResourcesQuery{ApplicationName: &app.Name, AppNamespace: &app.Namespace})
	if err != nil {
		componentDiffResult.DiffError = fmt.Errorf("fetching managed resources for %s: %w", app.Name, err)
		return componentDiffResult
	}

	// Get the application manifests, these are the target state of the application objects, taken from the git repo, specificly from the PR branch.
	diffOption := &DifferenceOption{}

	manifestQuery := application.ApplicationManifestQuery{
		Name:         &app.Name,
		Revision:     &prBranch,
		AppNamespace: &app.Namespace,
	}
	manifests, err := ac.App.GetManifests(ctx, &manifestQuery)
	if err != nil {
		componentDiffResult.DiffError = fmt.Errorf("fetching manifests for %s at %s: %w", app.Name, prBranch, err)
		return componentDiffResult
	}
	diffOption.res = manifests
	diffOption.revision = prBranch

	// Now we diff the live state(resources) and target state of the application objects(diffOption.res)
	detailedProject, err := ac.Project.GetDetailedProject(ctx, &projectpkg.ProjectQuery{Name: app.Spec.Project})
	if err != nil {
		componentDiffResult.DiffError = fmt.Errorf("fetching project %s: %w", app.Spec.Project, err)
		return componentDiffResult
	}

	componentDiffResult.HasDiff, componentDiffResult.DiffElements, componentDiffResult.DiffError = generateArgocdAppDiff(ctx, commentDiff, app, detailedProject.Project, resources, argoSettings, diffOption, logger)

	return componentDiffResult
}

// GenerateDiffOfChangedComponents generates diff of changed components
func GenerateDiffOfChangedComponents(ctx context.Context, componentsToDiff map[string]bool, prBranch string, repo string, cfg DiffConfig, argoClients ArgoCDClients, logger *slog.Logger) (hasComponentDiff bool, hasComponentDiffErrors bool, diffResults []DiffResult, err error) {
	logger.Debug("Generating diffs for changed components", "component_count", len(componentsToDiff), "pr_branch", prBranch)
	hasComponentDiff = false
	hasComponentDiffErrors = false

	argoSettings, err := argoClients.Setting.Get(ctx, &settings.SettingsQuery{})
	if err != nil {
		return false, true, nil, fmt.Errorf("fetching ArgoCD settings: %w", err)
	}

	diffResult := make(chan DiffResult, len(componentsToDiff))
	for componentPath, shouldIDiff := range componentsToDiff {
		go func(componentPath string, shouldDiff bool) {
			diffResult <- generateDiffOfAComponent(ctx, shouldIDiff, componentPath, prBranch, repo, argoClients, argoSettings, cfg, logger)
		}(componentPath, shouldIDiff)
	}

	var errs []error
	for range componentsToDiff {
		currentDiffResult := <-diffResult
		if currentDiffResult.DiffError != nil {
			logger.Error("generating diff", "component_path", currentDiffResult.ComponentPath, "err", currentDiffResult.DiffError)
			hasComponentDiffErrors = true
			errs = append(errs, currentDiffResult.DiffError)
		}
		if currentDiffResult.HasDiff {
			hasComponentDiff = true
		}
		diffResults = append(diffResults, currentDiffResult)
	}
	return hasComponentDiff, hasComponentDiffErrors, diffResults, errors.Join(errs...)
}
