package argocd

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: Blocklisted import crypto/sha1: weak cryptographic primitive (gosec), this is not a cryptographic use case
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

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
	"github.com/argoproj/argo-cd/v2/util/errors"
	argoio "github.com/argoproj/argo-cd/v2/util/io"
	"github.com/argoproj/gitops-engine/pkg/sync/hook"
	"github.com/argoproj/gitops-engine/pkg/sync/ignore"
	"github.com/argoproj/gitops-engine/pkg/utils/kube"
	"github.com/sergi/go-diff/diffmatchpatch"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// DiffResult struct to store diff result
type DiffResult struct {
	ComponentPath string
	ArgoCdAppName string
	ArgoCdAppURL  string
	DiffElements  []DiffElement
	HasDiff       bool
	DiffError     error
}

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
		live := &unstructured.Unstructured{}
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

func generateArgocdAppDiff(ctx context.Context, app *argoappv1.Application, proj *argoappv1.AppProject, resources *application.ManagedResourcesResponse, argoSettings *settings.Settings, diffOptions *DifferenceOption) (bool, []DiffElement, error) {
	// Mostly copied from  https://github.com/argoproj/argo-cd/blob/4f6a8dce80f0accef7ed3b5510e178a6b398b331/cmd/argocd/commands/app.go#L1255C6-L1338
	// But instead of printing the diff to stdout, we return it as a string in a struct so we can format it in a nice PR comment.
	var foundDiffs bool
	liveObjs, err := cmdutil.LiveObjects(resources.Items)
	if err != nil {
		return false, nil, err
	}

	items := make([]objKeyLiveTarget, 0)
	var unstructureds []*unstructured.Unstructured
	for _, mfst := range diffOptions.res.Manifests {
		obj, err := argoappv1.UnmarshalToUnstructured(mfst)
		if err != nil {
			return false, nil, err
		}
		unstructureds = append(unstructureds, obj)
	}
	groupedObjs := groupObjsByKey(unstructureds, liveObjs, app.Spec.Destination.Namespace)
	items = groupObjsForDiff(resources, groupedObjs, items, argoSettings, app.InstanceName(argoSettings.ControllerNamespace), app.Spec.Destination.Namespace)

	var diffElements []DiffElement
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
		diffConfig, err := argodiff.NewDiffConfigBuilder().
			WithDiffSettings(app.Spec.IgnoreDifferences, overrides, ignoreAggregatedRoles).
			WithTracking(argoSettings.AppLabelKey, argoSettings.TrackingMethod).
			WithNoCache().
			Build()
		if err != nil {
			return false, nil, err
		}
		diffRes, err := argodiff.StateDiff(item.live, item.target, diffConfig)
		if err != nil {
			return false, nil, err
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
					return false, nil, err
				}
			} else {
				live = item.live
				target = item.target
			}
			if !foundDiffs {
				foundDiffs = true
			}

			diffElement.Diff, err = diffLiveVsTargetObject(live, target)
			if err != nil {
				return false, nil, err
			}
		}
		diffElements = append(diffElements, diffElement)
	}
	return foundDiffs, diffElements, nil
}

// diffLiveVsTargetObject diffs the live and target objects, should return output that is compatible with github markdown diff highlighting format
func diffLiveVsTargetObject(live, target *unstructured.Unstructured) (string, error) {
	var err error
	// Diff the live and target objects
	liveData := []byte("")
	if live != nil {
		liveData, err = yaml.Marshal(live)
		if err != nil {
			return "", err
		}
	}
	targetData := []byte("")
	if target != nil {
		targetData, err = yaml.Marshal(target)
		if err != nil {
			return "", err
		}
	}

	dmp := diffmatchpatch.New()

	// some effort to get line by line outdput: https://github.com/sergi/go-diff/issues/69#issuecomment-688602689
	// TODO document this or make it more readable
	fileAdmp, fileBdmp, dmpStrings := dmp.DiffLinesToChars(string(liveData), string(targetData))
	diffs := dmp.DiffMain(fileAdmp, fileBdmp, false)
	diffs = dmp.DiffCharsToLines(diffs, dmpStrings)
	diffs = dmp.DiffCleanupSemantic(diffs)
	patch := dmp.PatchToText(dmp.PatchMake(diffs))
	return patch, nil
}

// DiffElement struct to store diff element details, this represents a single k8s object
type DiffElement struct {
	ObjectGroup     string
	ObjectName      string
	ObjectKind      string
	ObjectNamespace string
	Diff            string
}

// DifferenceOption struct to store diff options
type DifferenceOption struct {
	revision               string
	res                    *repoapiclient.ManifestResponse
	serversideRes          *repoapiclient.ManifestResponse
	revisionSourceMappings *map[int64]string
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func createArgoCdClient() (apiclient.Client, error) {
	plaintext, _ := strconv.ParseBool(getEnv("ARGOCD_PLAINTEXT", "false"))
	insecure, _ := strconv.ParseBool(getEnv("ARGOCD_INSECURE", "false"))

	opts := &apiclient.ClientOptions{
		ServerAddr: getEnv("ARGOCD_SERVER_ADDR", "localhost:8080"),
		AuthToken:  getEnv("ARGOCD_TOKEN", ""),
		PlainText:  plaintext,
		Insecure:   insecure,
	}

	clientset, err := apiclient.NewClient(opts)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

func generateDiffOfAComponent(ctx context.Context, componentPath string, prBranch string, repo string, appIf application.ApplicationServiceClient, projIf projectpkg.ProjectServiceClient, argoSettings *settings.Settings) DiffResult {
	currentDiffResult := DiffResult{
		ComponentPath: componentPath,
	}

	// Calculate sha1 of component path to use in a label selector
	cPathBa := []byte(componentPath)
	hasher := sha1.New() //nolint:gosec // G505: Blocklisted import crypto/sha1: weak cryptographic primitive (gosec), this is not a cryptographic use case
	hasher.Write(cPathBa)
	componentPathSha1 := hex.EncodeToString(hasher.Sum(nil))

	// Find ArgoCD application by the path SHA1 label selector and repo name
	// That label is assumed to be pupulated by the ApplicationSet controller(or apps of apps  or similar).
	labelSelector := fmt.Sprintf("telefonistka.io/component-path-sha1=%s", componentPathSha1)
	appLabelQuery := application.ApplicationQuery{
		Selector: &labelSelector,
		Repo:     &repo,
	}
	foundApps, err := appIf.List(ctx, &appLabelQuery)
	if err != nil {
		currentDiffResult.DiffError = err
		return currentDiffResult
	}
	if len(foundApps.Items) == 0 {
		currentDiffResult.DiffError = fmt.Errorf("No ArgoCD application found for component path %s(repo %s), used this label selector: %s", componentPath, repo, labelSelector)
		return currentDiffResult
	}

	// Get the application and its resources, resources are the live state of the application objects.
	refreshType := string(argoappv1.RefreshTypeHard)
	appNameQuery := application.ApplicationQuery{
		Name:    &foundApps.Items[0].Name, // we expect only one app with this label and repo selectors
		Refresh: &refreshType,
	}
	app, err := appIf.Get(ctx, &appNameQuery)
	if err != nil {
		currentDiffResult.DiffError = err
		return currentDiffResult
	}
	currentDiffResult.ArgoCdAppName = app.Name
	currentDiffResult.ArgoCdAppURL = fmt.Sprintf("%s/applications/%s", argoSettings.URL, app.Name)
	resources, err := appIf.ManagedResources(ctx, &application.ResourcesQuery{ApplicationName: &app.Name, AppNamespace: &app.Namespace})
	if err != nil {
		currentDiffResult.DiffError = err
		return currentDiffResult
	}

	// Get the application manifests, these are the target state of the application objects, taken from the git repo, specificly from the PR branch.
	diffOption := &DifferenceOption{}

	manifestQuery := application.ApplicationManifestQuery{
		Name:         &app.Name,
		Revision:     &prBranch,
		AppNamespace: &app.Namespace,
	}
	manifests, err := appIf.GetManifests(ctx, &manifestQuery)
	if err != nil {
		currentDiffResult.DiffError = err
		return currentDiffResult
	}
	diffOption.res = manifests
	diffOption.revision = prBranch

	// Now we diff the live state(resources) and target state of the application objects(diffOption.res)
	detailedProject, err := projIf.GetDetailedProject(ctx, &projectpkg.ProjectQuery{Name: app.Spec.Project})
	if err != nil {
		currentDiffResult.DiffError = err
		return currentDiffResult
	}

	currentDiffResult.HasDiff, currentDiffResult.DiffElements, err = generateArgocdAppDiff(ctx, app, detailedProject.Project, resources, argoSettings, diffOption)
	if err != nil {
		currentDiffResult.DiffError = err
	}

	return currentDiffResult
}

// GenerateDiffOfChangedComponents generates diff of changed components
func GenerateDiffOfChangedComponents(ctx context.Context, componentPathList []string, prBranch string, repo string) (bool, []DiffResult, error) {
	noDiffsAndErrors := true
	var diffResults []DiffResult
	// env var should be centralized
	client, err := createArgoCdClient()
	if err != nil {
		return false, nil, err
	}

	conn, appIf, err := client.NewApplicationClient()
	if err != nil {
		return false, nil, err
	}
	defer argoio.Close(conn)

	conn, projIf, err := client.NewProjectClient()
	if err != nil {
		return false, nil, err
	}
	defer argoio.Close(conn)

	conn, settingsIf, err := client.NewSettingsClient()
	if err != nil {
		return false, nil, err
	}
	defer argoio.Close(conn)
	argoSettings, err := settingsIf.Get(ctx, &settings.SettingsQuery{})
	if err != nil {
		return false, nil, err
	}

	for _, componentPath := range componentPathList {
		currentDiffResult := generateDiffOfAComponent(ctx, componentPath, prBranch, repo, appIf, projIf, argoSettings)
		if currentDiffResult.DiffError != nil || currentDiffResult.HasDiff {
			noDiffsAndErrors = false
		}
		diffResults = append(diffResults, currentDiffResult)
	}

	return noDiffsAndErrors, diffResults, err
}
