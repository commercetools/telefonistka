package argocd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/argoproj/argo-cd/v3/pkg/apiclient/application"
	"github.com/argoproj/argo-cd/v3/pkg/apiclient/settings"
	argoappv1 "github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	argodiff "github.com/argoproj/argo-cd/v3/util/argo/diff"
	"github.com/argoproj/argo-cd/v3/util/argo/normalizers"
	"github.com/argoproj/gitops-engine/pkg/utils/kube"
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

// generateArgocdAppDiff pairs live cluster state (from ManagedResources)
// with target manifests (from GetManifests at the PR branch) and runs
// ArgoCD's StateDiff to produce per-object diffs.
func generateArgocdAppDiff(keepDiffData bool, app *argoappv1.Application, resources *application.ManagedResourcesResponse, argoSettings *settings.Settings, manifests []string, logger *slog.Logger) (foundDiffs bool, diffElements []DiffElement, err error) {
	logger.Debug("Generating ArgoCD app diff", "app", app.Name, "keep_diff_data", keepDiffData, "managed_resources", len(resources.Items))

	// 1. Index live state from ManagedResources using NormalizedLiveState.
	liveByKey := make(map[kube.ResourceKey]*unstructured.Unstructured, len(resources.Items))
	for _, res := range resources.Items {
		key := kube.ResourceKey{Group: res.Group, Kind: res.Kind, Namespace: res.Namespace, Name: res.Name}
		if key.Kind == kube.SecretKind && key.Group == "" {
			continue
		}
		if res.NormalizedLiveState == "" || res.NormalizedLiveState == "null" {
			continue
		}
		live := &unstructured.Unstructured{}
		if err := json.Unmarshal([]byte(res.NormalizedLiveState), live); err != nil {
			return false, nil, fmt.Errorf("unmarshaling live state for %s/%s: %w", key.Kind, key.Name, err)
		}
		liveByKey[key] = live
	}

	// 2. Dedup + index target manifests (last-write-wins).
	targetByKey := make(map[kube.ResourceKey]*unstructured.Unstructured, len(manifests))
	for _, mfst := range manifests {
		obj, err := argoappv1.UnmarshalToUnstructured(mfst)
		if err != nil {
			return false, nil, fmt.Errorf("unmarshaling manifest: %w", err)
		}
		if obj.GetNamespace() == "" {
			obj.SetNamespace(app.Spec.Destination.Namespace)
		}
		key := kube.GetResourceKey(obj)
		if key.Kind == kube.SecretKind && key.Group == "" {
			continue
		}
		if isHookOrIgnored(obj) {
			continue
		}
		targetByKey[key] = obj
	}

	// 3. Build DiffConfig once (reused for every item).
	overrides := make(map[string]argoappv1.ResourceOverride, len(argoSettings.ResourceOverrides))
	for k, v := range argoSettings.ResourceOverrides {
		overrides[k] = *v
	}
	diffConfig, err := argodiff.NewDiffConfigBuilder().
		WithDiffSettings(app.Spec.IgnoreDifferences, overrides, false, normalizers.IgnoreNormalizerOpts{}).
		WithTracking(argoSettings.AppLabelKey, argoSettings.TrackingMethod).
		WithNoCache().
		WithStructuredMergeDiff(true).
		Build()
	if err != nil {
		return false, nil, fmt.Errorf("building diff config: %w", err)
	}

	const redactedDiff = "✂️ ✂️  Redacted ✂️ ✂️ \nUnset component-level configuration key `disableArgoCDDiff` to see diff content."

	// 4. Pair targets with live and diff.
	for key, target := range targetByKey {
		live := liveByKey[key]
		delete(liveByKey, key)

		if live != nil && isHookOrIgnored(live) {
			continue
		}

		diffRes, err := argodiff.StateDiff(live, target, diffConfig)
		if err != nil {
			return false, nil, fmt.Errorf("diffing %s/%s: %w", key.Kind, key.Name, err)
		}

		if !diffRes.Modified && live != nil {
			continue
		}
		foundDiffs = true

		de := DiffElement{
			ObjectGroup:     key.Group,
			ObjectKind:      key.Kind,
			ObjectNamespace: key.Namespace,
			ObjectName:      key.Name,
		}
		if keepDiffData {
			if live != nil {
				predicted := &unstructured.Unstructured{}
				if err := json.Unmarshal(diffRes.PredictedLive, predicted); err != nil {
					return false, nil, fmt.Errorf("unmarshaling predicted live for %s/%s: %w", key.Kind, key.Name, err)
				}
				de.Diff, err = diffLiveVsTargetObject(live, predicted)
			} else {
				de.Diff, err = diffLiveVsTargetObject(nil, target)
			}
			if err != nil {
				return false, nil, fmt.Errorf("formatting diff for %s/%s: %w", key.Kind, key.Name, err)
			}
		} else {
			de.Diff = redactedDiff
		}
		diffElements = append(diffElements, de)
	}

	// 5. Remaining live-only entries are resources deleted by the PR.
	for key, live := range liveByKey {
		if live == nil || isHookOrIgnored(live) {
			continue
		}
		foundDiffs = true

		de := DiffElement{
			ObjectGroup:     key.Group,
			ObjectKind:      key.Kind,
			ObjectNamespace: key.Namespace,
			ObjectName:      key.Name,
		}
		if keepDiffData {
			de.Diff, err = diffLiveVsTargetObject(live, nil)
			if err != nil {
				return false, nil, fmt.Errorf("formatting diff for deleted %s/%s: %w", key.Kind, key.Name, err)
			}
		} else {
			de.Diff = redactedDiff
		}
		diffElements = append(diffElements, de)
	}

	return foundDiffs, diffElements, nil
}

// isHookOrIgnored returns true if the object carries an ArgoCD sync
// hook annotation or an explicit compare-options=ignore annotation.
func isHookOrIgnored(obj *unstructured.Unstructured) bool {
	annotations := obj.GetAnnotations()
	if _, ok := annotations["argocd.argoproj.io/hook"]; ok {
		return true
	}
	return annotations["argocd.argoproj.io/compare-options"] == "ignore"
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

	manifests, err := ac.App.GetManifests(ctx, &application.ApplicationManifestQuery{
		Name:         &app.Name,
		Revision:     &prBranch,
		AppNamespace: &app.Namespace,
	})
	if err != nil {
		componentDiffResult.DiffError = fmt.Errorf("fetching manifests for %s at %s: %w", app.Name, prBranch, err)
		return componentDiffResult
	}

	componentDiffResult.HasDiff, componentDiffResult.DiffElements, componentDiffResult.DiffError = generateArgocdAppDiff(commentDiff, app, resources, argoSettings, manifests.Manifests, logger)

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
