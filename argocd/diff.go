package argocd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/argoproj/argo-cd/v3/pkg/apiclient/application"
	"github.com/argoproj/argo-cd/v3/pkg/apiclient/settings"
	argoappv1 "github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	argodiff "github.com/argoproj/argo-cd/v3/util/argo/diff"
	"github.com/argoproj/argo-cd/v3/util/argo/normalizers"
	"github.com/argoproj/gitops-engine/pkg/utils/kube"
	telefonistka "github.com/commercetools/telefonistka"
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

// ServerInfo holds ArgoCD server metadata returned by [FetchServerInfo].
type ServerInfo struct {
	URL      string // ArgoCD dashboard base URL
	settings *settings.Settings
}

// AppURL returns the ArgoCD dashboard URL for the named application.
func (s ServerInfo) AppURL(appName string) string {
	return s.URL + "/applications/" + appName
}

// FetchServerInfo retrieves ArgoCD server settings.
func FetchServerInfo(ctx context.Context, ac Clients) (ServerInfo, error) {
	s, err := ac.Setting.Get(ctx, &settings.SettingsQuery{})
	if err != nil {
		return ServerInfo{}, fmt.Errorf("fetching ArgoCD settings: %w", err)
	}
	return ServerInfo{URL: s.URL, settings: s}, nil
}

// DiffComponent locates (or creates) the ArgoCD application for a
// component, fetches live and target state, runs ArgoCD's StateDiff,
// and returns a [telefonistka.ComponentDiff] containing only changed
// resources. Temporary apps are cleaned up before returning.
//
// When isRemoval is true the target manifest fetch is skipped,
// producing deletion pairs for every live resource.
func DiffComponent(ctx context.Context, componentPath, repo, revision string, ac Clients, cfg DiffConfig, server ServerInfo, isRemoval bool, logger *slog.Logger) (telefonistka.ComponentDiff, error) {
	app, tempCreated, cleanup, err := ensureApp(ctx, componentPath, repo, revision, ac, cfg, logger)
	if err != nil {
		return telefonistka.ComponentDiff{}, err
	}
	defer cleanup()

	cd := telefonistka.ComponentDiff{
		Name:            app.Name,
		Namespace:       app.Namespace,
		HealthStatus:    string(app.Status.Health.Status),
		SyncStatus:      string(app.Status.Sync.Status),
		AutoSyncEnabled: app.Spec.SyncPolicy.Automated != nil,
		TargetRevision:  app.Spec.Source.TargetRevision,
		TempCreated:     tempCreated,
	}

	if cd.TargetRevision == revision && cd.AutoSyncEnabled {
		return cd, nil
	}

	live, err := fetchLive(ctx, ac, app, logger)
	if err != nil {
		return cd, err
	}

	var target resourceSet
	if !isRemoval {
		target, err = fetchTarget(ctx, ac, app, revision, logger)
		if err != nil {
			return cd, err
		}
	}

	cd.Pairs, err = pairResources(live, target, app, server)
	return cd, err
}

// resourceSet is an opaque collection of Kubernetes resources
// indexed by resource key.
type resourceSet struct {
	byKey     map[kube.ResourceKey]*unstructured.Unstructured
	defaultNS string
}

// fetchLive returns the managed (live) resources for an application.
// Secrets and empty NormalizedLiveState entries are filtered out.
func fetchLive(ctx context.Context, ac Clients, app *argoappv1.Application, logger *slog.Logger) (resourceSet, error) {
	resources, err := ac.App.ManagedResources(ctx, &application.ResourcesQuery{
		ApplicationName: &app.Name,
		AppNamespace:    &app.Namespace,
	})
	if err != nil {
		return resourceSet{}, fmt.Errorf("fetching managed resources for %s: %w", app.Name, err)
	}

	rs := resourceSet{byKey: make(map[kube.ResourceKey]*unstructured.Unstructured, len(resources.Items))}
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
			return resourceSet{}, fmt.Errorf("unmarshaling live state for %s/%s: %w", key.Kind, key.Name, err)
		}
		rs.byKey[key] = live
	}
	return rs, nil
}

// fetchTarget returns target manifests at the given revision.
// Secrets and hook/ignored resources are filtered out. The default
// namespace from the app's destination is applied to resources that
// don't specify one.
func fetchTarget(ctx context.Context, ac Clients, app *argoappv1.Application, revision string, logger *slog.Logger) (resourceSet, error) {
	manifests, err := ac.App.GetManifests(ctx, &application.ApplicationManifestQuery{
		Name:         &app.Name,
		Revision:     &revision,
		AppNamespace: &app.Namespace,
	})
	if err != nil {
		return resourceSet{}, fmt.Errorf("fetching manifests for %s at %s: %w", app.Name, revision, err)
	}

	rs := resourceSet{
		byKey:     make(map[kube.ResourceKey]*unstructured.Unstructured, len(manifests.Manifests)),
		defaultNS: app.Spec.Destination.Namespace,
	}
	for _, mfst := range manifests.Manifests {
		obj, err := argoappv1.UnmarshalToUnstructured(mfst)
		if err != nil {
			return resourceSet{}, fmt.Errorf("unmarshaling manifest: %w", err)
		}
		if obj.GetNamespace() == "" {
			obj.SetNamespace(rs.defaultNS)
		}
		key := kube.GetResourceKey(obj)
		if key.Kind == kube.SecretKind && key.Group == "" {
			continue
		}
		if isHookOrIgnored(obj) {
			continue
		}
		rs.byKey[key] = obj
	}
	return rs, nil
}

// pairResources runs ArgoCD's StateDiff on each live/target pair
// and returns only changed resources as [telefonistka.ResourcePair] values.
// An empty target resourceSet produces deletion pairs for every
// live resource (component removal case).
func pairResources(live, target resourceSet, app *argoappv1.Application, server ServerInfo) ([]telefonistka.ResourcePair, error) {
	overrides := make(map[string]argoappv1.ResourceOverride, len(server.settings.ResourceOverrides))
	for k, v := range server.settings.ResourceOverrides {
		overrides[k] = *v
	}
	diffCfg, err := argodiff.NewDiffConfigBuilder().
		WithDiffSettings(app.Spec.IgnoreDifferences, overrides, false, normalizers.IgnoreNormalizerOpts{}).
		WithTracking(server.settings.AppLabelKey, server.settings.TrackingMethod).
		WithNoCache().
		WithStructuredMergeDiff(true).
		Build()
	if err != nil {
		return nil, fmt.Errorf("building diff config: %w", err)
	}

	// Working copy of live so we can delete consumed keys.
	remaining := make(map[kube.ResourceKey]*unstructured.Unstructured, len(live.byKey))
	for k, v := range live.byKey {
		remaining[k] = v
	}

	var pairs []telefonistka.ResourcePair

	for key, tgt := range target.byKey {
		liveObj := remaining[key]
		delete(remaining, key)

		if liveObj != nil && isHookOrIgnored(liveObj) {
			continue
		}

		diffRes, err := argodiff.StateDiff(liveObj, tgt, diffCfg)
		if err != nil {
			return nil, fmt.Errorf("diffing %s/%s: %w", key.Kind, key.Name, err)
		}

		if !diffRes.Modified && liveObj != nil {
			continue
		}

		pair := telefonistka.ResourcePair{
			Group:     key.Group,
			Kind:      key.Kind,
			Namespace: key.Namespace,
			Name:      key.Name,
		}
		if liveObj != nil {
			predicted := &unstructured.Unstructured{}
			if err := json.Unmarshal(diffRes.PredictedLive, predicted); err != nil {
				return nil, fmt.Errorf("unmarshaling predicted live for %s/%s: %w", key.Kind, key.Name, err)
			}
			pair.Live = liveObj
			pair.Target = predicted
		} else {
			pair.Target = tgt
		}
		pairs = append(pairs, pair)
	}

	// Remaining live-only entries are deletions.
	for key, liveObj := range remaining {
		if liveObj == nil || isHookOrIgnored(liveObj) {
			continue
		}
		pairs = append(pairs, telefonistka.ResourcePair{
			Group:     key.Group,
			Kind:      key.Kind,
			Namespace: key.Namespace,
			Name:      key.Name,
			Live:      liveObj,
		})
	}

	return pairs, nil
}

// isHookOrIgnored returns true if the object carries an ArgoCD
// sync hook annotation or an explicit compare-options=ignore
// annotation.
func isHookOrIgnored(obj *unstructured.Unstructured) bool {
	annotations := obj.GetAnnotations()
	if _, ok := annotations["argocd.argoproj.io/hook"]; ok {
		return true
	}
	return annotations["argocd.argoproj.io/compare-options"] == "ignore"
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
func ensureApp(ctx context.Context, componentPath, repo, prBranch string, ac Clients, cfg DiffConfig, logger *slog.Logger) (app *argoappv1.Application, tempCreated bool, cleanup func(), err error) {
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

