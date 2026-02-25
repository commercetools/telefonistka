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
	"github.com/commercetools/telefonistka/diff"
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

// AppInfo holds metadata about an ArgoCD application returned by
// [EnsureApp]. Callers MUST defer Cleanup.
type AppInfo struct {
	Name            string
	Namespace       string
	HealthStatus    string
	SyncStatus      string
	AutoSyncEnabled bool
	TargetRevision  string
	TempCreated     bool
	Cleanup         func() // MUST be deferred by caller
	app             *argoappv1.Application
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

// ResourceSet is an opaque collection of Kubernetes resources
// indexed by resource key. Produced by [FetchLive]/[FetchTarget],
// consumed by [PairResources].
type ResourceSet struct {
	byKey     map[kube.ResourceKey]*unstructured.Unstructured
	defaultNS string
}

// EnsureApp locates (or creates) the ArgoCD application for a
// component. The returned AppInfo.Cleanup MUST be deferred by the
// caller — it deletes temporary apps or is a no-op for pre-existing
// ones.
func EnsureApp(ctx context.Context, componentPath, repo, prBranch string, ac Clients, cfg DiffConfig, logger *slog.Logger) (AppInfo, error) {
	noop := func() {}
	app, tempCreated, cleanup, err := ensureApp(ctx, componentPath, repo, prBranch, ac, cfg, logger)
	if err != nil {
		return AppInfo{Cleanup: noop}, err
	}
	return AppInfo{
		Name:            app.Name,
		Namespace:       app.Namespace,
		HealthStatus:    string(app.Status.Health.Status),
		SyncStatus:      string(app.Status.Sync.Status),
		AutoSyncEnabled: app.Spec.SyncPolicy.Automated != nil,
		TargetRevision:  app.Spec.Source.TargetRevision,
		TempCreated:     tempCreated,
		Cleanup:         cleanup,
		app:             app,
	}, nil
}

// FetchServerInfo retrieves ArgoCD server settings.
func FetchServerInfo(ctx context.Context, ac Clients) (ServerInfo, error) {
	s, err := ac.Setting.Get(ctx, &settings.SettingsQuery{})
	if err != nil {
		return ServerInfo{}, fmt.Errorf("fetching ArgoCD settings: %w", err)
	}
	return ServerInfo{URL: s.URL, settings: s}, nil
}

// FetchLive returns the managed (live) resources for an application.
// Secrets and empty NormalizedLiveState entries are filtered out.
func FetchLive(ctx context.Context, ac Clients, info AppInfo, logger *slog.Logger) (ResourceSet, error) {
	resources, err := ac.App.ManagedResources(ctx, &application.ResourcesQuery{
		ApplicationName: &info.Name,
		AppNamespace:    &info.Namespace,
	})
	if err != nil {
		return ResourceSet{}, fmt.Errorf("fetching managed resources for %s: %w", info.Name, err)
	}

	rs := ResourceSet{byKey: make(map[kube.ResourceKey]*unstructured.Unstructured, len(resources.Items))}
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
			return ResourceSet{}, fmt.Errorf("unmarshaling live state for %s/%s: %w", key.Kind, key.Name, err)
		}
		rs.byKey[key] = live
	}
	return rs, nil
}

// FetchTarget returns target manifests at the given revision.
// Secrets and hook/ignored resources are filtered out. The default
// namespace from the app's destination is applied to resources that
// don't specify one.
func FetchTarget(ctx context.Context, ac Clients, info AppInfo, revision string, logger *slog.Logger) (ResourceSet, error) {
	manifests, err := ac.App.GetManifests(ctx, &application.ApplicationManifestQuery{
		Name:         &info.Name,
		Revision:     &revision,
		AppNamespace: &info.Namespace,
	})
	if err != nil {
		return ResourceSet{}, fmt.Errorf("fetching manifests for %s at %s: %w", info.Name, revision, err)
	}

	rs := ResourceSet{
		byKey:     make(map[kube.ResourceKey]*unstructured.Unstructured, len(manifests.Manifests)),
		defaultNS: info.app.Spec.Destination.Namespace,
	}
	for _, mfst := range manifests.Manifests {
		obj, err := argoappv1.UnmarshalToUnstructured(mfst)
		if err != nil {
			return ResourceSet{}, fmt.Errorf("unmarshaling manifest: %w", err)
		}
		if obj.GetNamespace() == "" {
			obj.SetNamespace(rs.defaultNS)
		}
		key := kube.GetResourceKey(obj)
		if key.Kind == kube.SecretKind && key.Group == "" {
			continue
		}
		if diff.IsHookOrIgnored(obj) {
			continue
		}
		rs.byKey[key] = obj
	}
	return rs, nil
}

// PairResources runs ArgoCD's StateDiff on each live/target pair
// and returns only changed resources as [diff.ResourcePair] values.
// An empty target ResourceSet produces deletion pairs for every
// live resource (component removal case).
func PairResources(live, target ResourceSet, info AppInfo, server ServerInfo) ([]diff.ResourcePair, error) {
	overrides := make(map[string]argoappv1.ResourceOverride, len(server.settings.ResourceOverrides))
	for k, v := range server.settings.ResourceOverrides {
		overrides[k] = *v
	}
	diffCfg, err := argodiff.NewDiffConfigBuilder().
		WithDiffSettings(info.app.Spec.IgnoreDifferences, overrides, false, normalizers.IgnoreNormalizerOpts{}).
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

	var pairs []diff.ResourcePair

	for key, tgt := range target.byKey {
		liveObj := remaining[key]
		delete(remaining, key)

		if liveObj != nil && diff.IsHookOrIgnored(liveObj) {
			continue
		}

		diffRes, err := argodiff.StateDiff(liveObj, tgt, diffCfg)
		if err != nil {
			return nil, fmt.Errorf("diffing %s/%s: %w", key.Kind, key.Name, err)
		}

		if !diffRes.Modified && liveObj != nil {
			continue
		}

		pair := diff.ResourcePair{
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
		if liveObj == nil || diff.IsHookOrIgnored(liveObj) {
			continue
		}
		pairs = append(pairs, diff.ResourcePair{
			Group:     key.Group,
			Kind:      key.Kind,
			Namespace: key.Namespace,
			Name:      key.Name,
			Live:      liveObj,
		})
	}

	return pairs, nil
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

