package argocd

import (
	"context"
	"encoding/json"
	"fmt"

	cmdutil "github.com/argoproj/argo-cd/v2/cmd/util"
	"github.com/argoproj/argo-cd/v2/controller"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/application"
	projectpkg "github.com/argoproj/argo-cd/v2/pkg/apiclient/project"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/settings"
	argoappv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	repoapiclient "github.com/argoproj/argo-cd/v2/reposerver/apiclient"
	"github.com/argoproj/argo-cd/v2/util/argo"
	argodiff "github.com/argoproj/argo-cd/v2/util/argo/diff"
	"github.com/argoproj/argo-cd/v2/util/cli"
	"github.com/argoproj/argo-cd/v2/util/errors"
	argoio "github.com/argoproj/argo-cd/v2/util/io"
	"github.com/argoproj/gitops-engine/pkg/sync/hook"
	"github.com/argoproj/gitops-engine/pkg/sync/ignore"
	"github.com/argoproj/gitops-engine/pkg/utils/kube"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type resourceInfoProvider struct {
	namespacedByGk map[schema.GroupKind]bool
}

// Infer if obj is namespaced or not from corresponding live objects list. If corresponding live object has namespace then target object is also namespaced.
// If live object is missing then it does not matter if target is namespaced or not.
func (p *resourceInfoProvider) IsNamespaced(gk schema.GroupKind) (bool, error) {
	return p.namespacedByGk[gk], nil
}

type objKeyLiveTarget struct {
	key    kube.ResourceKey
	live   *unstructured.Unstructured
	target *unstructured.Unstructured
}

func groupObjsByKey(localObs []*unstructured.Unstructured, liveObjs []*unstructured.Unstructured, appNamespace string) map[kube.ResourceKey]*unstructured.Unstructured {
	namespacedByGk := make(map[schema.GroupKind]bool)
	for i := range liveObjs {
		if liveObjs[i] != nil {
			key := kube.GetResourceKey(liveObjs[i])
			namespacedByGk[schema.GroupKind{Group: key.Group, Kind: key.Kind}] = key.Namespace != ""
		}
	}
	localObs, _, err := controller.DeduplicateTargetObjects(appNamespace, localObs, &resourceInfoProvider{namespacedByGk: namespacedByGk})
	errors.CheckError(err)
	objByKey := make(map[kube.ResourceKey]*unstructured.Unstructured)
	for i := range localObs {
		obj := localObs[i]
		if !(hook.IsHook(obj) || ignore.Ignore(obj)) {
			objByKey[kube.GetResourceKey(obj)] = obj
		}
	}
	return objByKey
}

func groupObjsForDiff(resources *application.ManagedResourcesResponse, objs map[kube.ResourceKey]*unstructured.Unstructured, items []objKeyLiveTarget, argoSettings *settings.Settings, appName, namespace string) []objKeyLiveTarget {
	resourceTracking := argo.NewResourceTracking()
	for _, res := range resources.Items {
		var live = &unstructured.Unstructured{}
		err := json.Unmarshal([]byte(res.NormalizedLiveState), &live)
		errors.CheckError(err)

		key := kube.ResourceKey{Name: res.Name, Namespace: res.Namespace, Group: res.Group, Kind: res.Kind}
		if key.Kind == kube.SecretKind && key.Group == "" {
			// Don't bother comparing secrets, argo-cd doesn't have access to k8s secret data
			delete(objs, key)
			continue
		}
		if local, ok := objs[key]; ok || live != nil {
			if local != nil && !kube.IsCRD(local) {
				err = resourceTracking.SetAppInstance(local, argoSettings.AppLabelKey, appName, namespace, argoappv1.TrackingMethod(argoSettings.GetTrackingMethod()))
				errors.CheckError(err)
			}

			items = append(items, objKeyLiveTarget{key, live, local})
			delete(objs, key)
		}
	}
	for key, local := range objs {
		if key.Kind == kube.SecretKind && key.Group == "" {
			// Don't bother comparing secrets, argo-cd doesn't have access to k8s secret data
			delete(objs, key)
			continue
		}
		items = append(items, objKeyLiveTarget{key, nil, local})
	}
	return items
}

func findandPrintDiff(ctx context.Context, app *argoappv1.Application, proj *argoappv1.AppProject, resources *application.ManagedResourcesResponse, argoSettings *settings.Settings, diffOptions *DifferenceOption) bool {
	var foundDiffs bool
	liveObjs, err := cmdutil.LiveObjects(resources.Items)
	errors.CheckError(err)
	items := make([]objKeyLiveTarget, 0)
	if diffOptions.revision != "" || (diffOptions.revisionSourceMappings != nil) {
		var unstructureds []*unstructured.Unstructured
		for _, mfst := range diffOptions.res.Manifests {
			obj, err := argoappv1.UnmarshalToUnstructured(mfst)
			errors.CheckError(err)
			unstructureds = append(unstructureds, obj)
		}
		groupedObjs := groupObjsByKey(unstructureds, liveObjs, app.Spec.Destination.Namespace)
		items = groupObjsForDiff(resources, groupedObjs, items, argoSettings, app.InstanceName(argoSettings.ControllerNamespace), app.Spec.Destination.Namespace)
	} else if diffOptions.serversideRes != nil {
		var unstructureds []*unstructured.Unstructured
		for _, mfst := range diffOptions.serversideRes.Manifests {
			obj, err := argoappv1.UnmarshalToUnstructured(mfst)
			errors.CheckError(err)
			unstructureds = append(unstructureds, obj)
		}
		groupedObjs := groupObjsByKey(unstructureds, liveObjs, app.Spec.Destination.Namespace)
		items = groupObjsForDiff(resources, groupedObjs, items, argoSettings, app.InstanceName(argoSettings.ControllerNamespace), app.Spec.Destination.Namespace)
	} else {
		for i := range resources.Items {
			res := resources.Items[i]
			var live = &unstructured.Unstructured{}
			err := json.Unmarshal([]byte(res.NormalizedLiveState), &live)
			errors.CheckError(err)

			var target = &unstructured.Unstructured{}
			err = json.Unmarshal([]byte(res.TargetState), &target)
			errors.CheckError(err)

			items = append(items, objKeyLiveTarget{kube.NewResourceKey(res.Group, res.Kind, res.Namespace, res.Name), live, target})
		}
	}

	for _, item := range items {
		if item.target != nil && hook.IsHook(item.target) || item.live != nil && hook.IsHook(item.live) {
			continue
		}
		overrides := make(map[string]argoappv1.ResourceOverride)
		for k := range argoSettings.ResourceOverrides {
			val := argoSettings.ResourceOverrides[k]
			overrides[k] = *val
		}

		ignoreAggregatedRoles := false
		diffConfig, err := argodiff.NewDiffConfigBuilder().
			WithDiffSettings(app.Spec.IgnoreDifferences, overrides, ignoreAggregatedRoles).
			WithTracking(argoSettings.AppLabelKey, argoSettings.TrackingMethod).
			WithNoCache().
			Build()
		errors.CheckError(err)
		diffRes, err := argodiff.StateDiff(item.live, item.target, diffConfig)
		errors.CheckError(err)

		if diffRes.Modified || item.target == nil || item.live == nil {
			fmt.Printf("\n===== %s/%s %s/%s ======\n", item.key.Group, item.key.Kind, item.key.Namespace, item.key.Name)
			var live *unstructured.Unstructured
			var target *unstructured.Unstructured
			if item.target != nil && item.live != nil {
				target = &unstructured.Unstructured{}
				live = item.live
				err = json.Unmarshal(diffRes.PredictedLive, target)
				errors.CheckError(err)
			} else {
				live = item.live
				target = item.target
			}
			if !foundDiffs {
				foundDiffs = true
			}
			_ = cli.PrintDiff(item.key.Name, live, target)
		}
	}
	return foundDiffs
}

// DifferenceOption struct to store diff options
type DifferenceOption struct {
	local                  string
	localRepoRoot          string
	revision               string
	cluster                *argoappv1.Cluster
	res                    *repoapiclient.ManifestResponse
	serversideRes          *repoapiclient.ManifestResponse
	revisionSourceMappings *map[int64]string
}

func createArgoCdClient(token string) (apiclient.Client, error) {
	opts := &apiclient.ClientOptions{
		ServerAddr: "localhost:8080",
		Insecure:   true,
		AuthToken:  token,
		PlainText:  true,
	}

	clientset, err := apiclient.NewClient(opts)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

// Play ArgoCD API
func Play(token string) {
	client, err := createArgoCdClient(token)
	if err != nil {
		panic(err)
	}
	ctx := context.Background()

	conn, appIf, err := client.NewApplicationClient()
	errors.CheckError(err)
	defer argoio.Close(conn)

	appName, appNs, revision := "foobar-staging-gcp-europe-west1-v1", "argocd-infra", "Oded-B-test-argocd-diff"
	refreshType := string(argoappv1.RefreshTypeHard)
	app, err := appIf.Get(ctx, &application.ApplicationQuery{
		Name:         &appName,
		Refresh:      &refreshType,
		AppNamespace: &appNs,
	})
	errors.CheckError(err)
	fmt.Printf("app: %v", app)
	resources, err := appIf.ManagedResources(ctx, &application.ResourcesQuery{ApplicationName: &appName, AppNamespace: &appNs})
	errors.CheckError(err)
	diffOption := &DifferenceOption{}

	q := application.ApplicationManifestQuery{
		Name:         &appName,
		Revision:     &revision,
		AppNamespace: &appNs,
	}
	res, err := appIf.GetManifests(ctx, &q)
	errors.CheckError(err)
	diffOption.res = res
	diffOption.revision = revision

	conn, projIf, err := client.NewProjectClient()
	errors.CheckError(err)
	defer argoio.Close(conn)
	detailedProject, err := projIf.GetDetailedProject(ctx, &projectpkg.ProjectQuery{Name: app.Spec.Project})

	conn, settingsIf := client.NewSettingsClientOrDie()
	defer argoio.Close(conn)
	argoSettings, err := settingsIf.Get(ctx, &settings.SettingsQuery{})
	errors.CheckError(err)

	errors.CheckError(err)
	b := findandPrintDiff(ctx, app, detailedProject.Project, resources, argoSettings, diffOption)
	fmt.Printf("b: %v", b)

}
