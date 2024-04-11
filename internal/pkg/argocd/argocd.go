package argocd

import (
	"context"
	"fmt"

	"github.com/argoproj/argo-cd/v2/pkg/apiclient"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/application"
	argoappv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	repoapiclient "github.com/argoproj/argo-cd/v2/reposerver/apiclient"
	"github.com/argoproj/argo-cd/v2/util/errors"
	argoio "github.com/argoproj/argo-cd/v2/util/io"
)

// type objKeyLiveTarget struct {
// key    kube.ResourceKey
// live   *unstructured.Unstructured
// target *unstructured.Unstructured
// }

// func groupObjsByKey(localObs []*unstructured.Unstructured, liveObjs []*unstructured.Unstructured, appNamespace string) map[kube.ResourceKey]*unstructured.Unstructured {
// namespacedByGk := make(map[schema.GroupKind]bool)
// for i := range liveObjs {
// if liveObjs[i] != nil {
// key := kube.GetResourceKey(liveObjs[i])
// namespacedByGk[schema.GroupKind{Group: key.Group, Kind: key.Kind}] = key.Namespace != ""
// }
// }
// localObs, _, err := controller.DeduplicateTargetObjects(appNamespace, localObs, &resourceInfoProvider{namespacedByGk: namespacedByGk})
// errors.CheckError(err)
// objByKey := make(map[kube.ResourceKey]*unstructured.Unstructured)
// for i := range localObs {
// obj := localObs[i]
// if !(hook.IsHook(obj) || ignore.Ignore(obj)) {
// objByKey[kube.GetResourceKey(obj)] = obj
// }
// }
// return objByKey
// }
//
// func findandPrintDiff(ctx context.Context, app *argoappv1.Application, proj *argoappv1.AppProject, resources *application.ManagedResourcesResponse, argoSettings *settings.Settings, diffOptions *DifferenceOption) bool {
// var foundDiffs bool
// liveObjs, err := cmdutil.LiveObjects(resources.Items)
// errors.CheckError(err)
// items := make([]objKeyLiveTarget, 0)
// if diffOptions.local != "" {
// localObjs := groupObjsByKey(getLocalObjects(ctx, app, proj, diffOptions.local, diffOptions.localRepoRoot, argoSettings.AppLabelKey, diffOptions.cluster.Info.ServerVersion, diffOptions.cluster.Info.APIVersions, argoSettings.KustomizeOptions, argoSettings.TrackingMethod), liveObjs, app.Spec.Destination.Namespace)
// items = groupObjsForDiff(resources, localObjs, items, argoSettings, app.InstanceName(argoSettings.ControllerNamespace), app.Spec.Destination.Namespace)
// } else if diffOptions.revision != "" || (diffOptions.revisionSourceMappings != nil) {
// var unstructureds []*unstructured.Unstructured
// for _, mfst := range diffOptions.res.Manifests {
// obj, err := argoappv1.UnmarshalToUnstructured(mfst)
// errors.CheckError(err)
// unstructureds = append(unstructureds, obj)
// }
// groupedObjs := groupObjsByKey(unstructureds, liveObjs, app.Spec.Destination.Namespace)
// items = groupObjsForDiff(resources, groupedObjs, items, argoSettings, app.InstanceName(argoSettings.ControllerNamespace), app.Spec.Destination.Namespace)
// } else if diffOptions.serversideRes != nil {
// var unstructureds []*unstructured.Unstructured
// for _, mfst := range diffOptions.serversideRes.Manifests {
// obj, err := argoappv1.UnmarshalToUnstructured(mfst)
// errors.CheckError(err)
// unstructureds = append(unstructureds, obj)
// }
// groupedObjs := groupObjsByKey(unstructureds, liveObjs, app.Spec.Destination.Namespace)
// items = groupObjsForDiff(resources, groupedObjs, items, argoSettings, app.InstanceName(argoSettings.ControllerNamespace), app.Spec.Destination.Namespace)
// } else {
// for i := range resources.Items {
// res := resources.Items[i]
// var live = &unstructured.Unstructured{}
// err := json.Unmarshal([]byte(res.NormalizedLiveState), &live)
// errors.CheckError(err)
//
// var target = &unstructured.Unstructured{}
// err = json.Unmarshal([]byte(res.TargetState), &target)
// errors.CheckError(err)
//
// items = append(items, objKeyLiveTarget{kube.NewResourceKey(res.Group, res.Kind, res.Namespace, res.Name), live, target})
// }
// }
//
// for _, item := range items {
// if item.target != nil && hook.IsHook(item.target) || item.live != nil && hook.IsHook(item.live) {
// continue
// }
// overrides := make(map[string]argoappv1.ResourceOverride)
// for k := range argoSettings.ResourceOverrides {
// val := argoSettings.ResourceOverrides[k]
// overrides[k] = *val
// }
//
// ignoreAggregatedRoles := false
// diffConfig, err := argodiff.NewDiffConfigBuilder().
// WithDiffSettings(app.Spec.IgnoreDifferences, overrides, ignoreAggregatedRoles).
// WithTracking(argoSettings.AppLabelKey, argoSettings.TrackingMethod).
// WithNoCache().
// Build()
// errors.CheckError(err)
// diffRes, err := argodiff.StateDiff(item.live, item.target, diffConfig)
// errors.CheckError(err)
//
// if diffRes.Modified || item.target == nil || item.live == nil {
// fmt.Printf("\n===== %s/%s %s/%s ======\n", item.key.Group, item.key.Kind, item.key.Namespace, item.key.Name)
// var live *unstructured.Unstructured
// var target *unstructured.Unstructured
// if item.target != nil && item.live != nil {
// target = &unstructured.Unstructured{}
// live = item.live
// err = json.Unmarshal(diffRes.PredictedLive, target)
// errors.CheckError(err)
// } else {
// live = item.live
// target = item.target
// }
// if !foundDiffs {
// foundDiffs = true
// }
// _ = cli.PrintDiff(item.key.Name, live, target)
// }
// }
// return foundDiffs
// }

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
	_, err = appIf.ManagedResources(ctx, &application.ResourcesQuery{ApplicationName: &appName, AppNamespace: &appNs})
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

	conn, _, err = client.NewProjectClient()
	errors.CheckError(err)
	defer argoio.Close(conn)

	// detailedProject, err := projIf.GetDetailedProject(ctx, &projectpkg.ProjectQuery{Name: app.Spec.Project})
	// errors.CheckError(err)
	// b := findandPrintDiff(ctx, app, detailedProject, resources, appIf, diffOption)

}
