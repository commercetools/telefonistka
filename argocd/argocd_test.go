package argocd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/argoproj/argo-cd/v2/pkg/apiclient"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/application"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/settings"
	argoappv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	reposerverApiClient "github.com/argoproj/argo-cd/v2/reposerver/apiclient"
	"github.com/commercetools/telefonistka/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestFindRelevantAppSetByPathDoesNotExplode(t *testing.T) {
	t.Parallel()

	serverAddr := os.Getenv("ARGOCD_SERVER_ADDR")
	authToken := os.Getenv("ARGOCD_TOKEN")

	if serverAddr == "" || authToken == "" {
		t.Skipf("Set ARGOCD_SERVER_ADDR and ARGOCD_TOKEN to run test")
	}

	componentPath, repo := "clusters/playground/aws/eu-central-1/v1/cloud-tools/humio/logscale-daily-usage-reporter", "commercetools/k8s-gitops"

	opts := apiclient.ClientOptions{
		ServerAddr: serverAddr,
		AuthToken:  authToken,
		PlainText:  false,
		Insecure:   true,
	}
	c, err := apiclient.NewClient(&opts)
	if err != nil {
		t.Errorf("NewClient: %v", err)
	}
	_, ac, err := c.NewApplicationSetClient()
	if err != nil {
		t.Errorf("NewApplicationClient: %v", err)
	}

	if _, err := findRelevantAppSetByPath(
		context.Background(),
		componentPath,
		repo,
		ac,
		slog.Default(),
	); err != nil {
		t.Errorf("got unexpected error")
	}
}

func readLiveTarget(t *testing.T) (live, target *unstructured.Unstructured, expected string) {
	t.Helper()
	live = readManifest(t, "testdata/"+t.Name()+".live")
	target = readManifest(t, "testdata/"+t.Name()+".target")
	expected = readFileString(t, "testdata/"+t.Name()+".want")
	return live, target, expected
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func readManifest(t *testing.T, path string) *unstructured.Unstructured {
	t.Helper()

	s := readFileString(t, path)
	obj, err := argoappv1.UnmarshalToUnstructured(s)
	if err != nil {
		t.Fatalf("unmarshal %v: %v", path, err)
	}
	return obj
}

func TestDiffLiveVsTargetObject(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
	}{
		{"1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			live, target, want := readLiveTarget(t)
			got, err := diffLiveVsTargetObject(live, target)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if got != want {
				t.Errorf("got \n%q\n, want \n%q\n", got, want)
			}
		})
	}

	t.Run("no panic on nil inputs", func(t *testing.T) {
		defer func() {
			if err := recover(); err != nil {
				t.Errorf("got panic: %v", err)
			}
		}()
		diffLiveVsTargetObject(nil, nil) //nolint:errcheck // only interested in panic
	})
}

func TestRenderDiff(t *testing.T) {
	t.Parallel()
	live := readManifest(t, "testdata/TestRenderDiff.live")
	target := readManifest(t, "testdata/TestRenderDiff.target")
	want := readFileString(t, "testdata/TestRenderDiff.md")
	data, err := diffLiveVsTargetObject(live, target)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// backticks are tricky https://github.com/golang/go/issues/24475
	r := strings.NewReplacer("¬", "`")
	tmpl := r.Replace("¬¬¬diff\n{{.}}¬¬¬\n")

	rendered := renderTemplate(t, tmpl, data)

	if got, want := rendered.String(), want; got != want {
		t.Errorf("got \n%q\n, want \n%q\n", got, want)
	}
	t.Logf("got: \n%s\n", rendered.String())
}

func renderTemplate(t *testing.T, tpl string, data any) *bytes.Buffer {
	t.Helper()
	buf := bytes.NewBuffer(nil)
	tmpl := template.New("")
	tmpl = template.Must(tmpl.Parse(tpl))
	if err := tmpl.Execute(buf, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return buf
}

func TestFindArgocdAppBySHA1Label(t *testing.T) {
	// Here the filtering is done on the ArgoCD server side, so we are just testing the function returns a app
	t.Parallel()
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockApplicationClient := mocks.NewMockApplicationServiceClient(ctrl)
	expectedResponse := &argoappv1.ApplicationList{
		Items: []argoappv1.Application{
			{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"telefonistka.io/component-path-sha1": "111111",
					},
					Name: "right-app",
				},
			},
		},
	}

	mockApplicationClient.EXPECT().List(gomock.Any(), gomock.Any()).Return(expectedResponse, nil)

	app, err := findArgocdAppBySHA1Label(ctx, "random/path", "some-repo", mockApplicationClient, slog.Default())
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if app.Name != "right-app" {
		t.Errorf("App name is not right-app")
	}
}

func TestFindArgocdAppByPathAnnotation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockApplicationClient := mocks.NewMockApplicationServiceClient(ctrl)
	expectedResponse := &argoappv1.ApplicationList{
		Items: []argoappv1.Application{
			{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"argocd.argoproj.io/manifest-generate-paths": "wrong/path/",
					},
					Name: "wrong-app",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"argocd.argoproj.io/manifest-generate-paths": "right/path/",
					},
					Name: "right-app",
				},
			},
		},
	}

	mockApplicationClient.EXPECT().List(gomock.Any(), gomock.Any()).Return(expectedResponse, nil)

	apps, err := findArgocdAppByManifestPathAnnotation(ctx, "right/path", "some-repo", mockApplicationClient, slog.Default())
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	t.Logf("apps: %v", apps)
}

// Here I'm testing a ";" delimted path annotation
func TestFindArgocdAppByPathAnnotationSemiColon(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockApplicationClient := mocks.NewMockApplicationServiceClient(ctrl)
	expectedResponse := &argoappv1.ApplicationList{
		Items: []argoappv1.Application{
			{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"argocd.argoproj.io/manifest-generate-paths": "wrong/path/;wrong/path2/",
					},
					Name: "wrong-app",
				},
			},
			{ // This is the app we want to find - it has the right path as one of the elements in the annotation
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"argocd.argoproj.io/manifest-generate-paths": "wrong/path/;right/path/",
					},
					Name: "right-app",
				},
			},
		},
	}

	mockApplicationClient.EXPECT().List(gomock.Any(), gomock.Any()).Return(expectedResponse, nil)

	app, err := findArgocdAppByManifestPathAnnotation(ctx, "right/path", "some-repo", mockApplicationClient, slog.Default())
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if app.Name != "right-app" {
		t.Errorf("App name is not right-app")
	}
}

// Here I'm testing a "." path annotation - this is a special case where the path is relative to the repo root specified in the application .spec
func TestFindArgocdAppByPathAnnotationRelative(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockApplicationClient := mocks.NewMockApplicationServiceClient(ctrl)
	expectedResponse := &argoappv1.ApplicationList{
		Items: []argoappv1.Application{
			{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"argocd.argoproj.io/manifest-generate-paths": ".",
					},
					Name: "right-app",
				},
				Spec: argoappv1.ApplicationSpec{
					Source: &argoappv1.ApplicationSource{
						RepoURL: "",
						Path:    "right/path",
					},
				},
			},
		},
	}

	mockApplicationClient.EXPECT().List(gomock.Any(), gomock.Any()).Return(expectedResponse, nil)
	app, err := findArgocdAppByManifestPathAnnotation(ctx, "right/path", "some-repo", mockApplicationClient, slog.Default())
	if err != nil {
		t.Errorf("Error: %v", err)
	} else if app.Name != "right-app" {
		t.Errorf("App name is not right-app")
	}
}

// Here I'm testing a "." path annotation - this is a special case where the path is relative to the repo root specified in the application .spec
func TestFindArgocdAppByPathAnnotationRelative2(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockApplicationClient := mocks.NewMockApplicationServiceClient(ctrl)
	expectedResponse := &argoappv1.ApplicationList{
		Items: []argoappv1.Application{
			{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"argocd.argoproj.io/manifest-generate-paths": "./path",
					},
					Name: "right-app",
				},
				Spec: argoappv1.ApplicationSpec{
					Source: &argoappv1.ApplicationSource{
						RepoURL: "",
						Path:    "right/",
					},
				},
			},
		},
	}

	mockApplicationClient.EXPECT().List(gomock.Any(), gomock.Any()).Return(expectedResponse, nil)
	app, err := findArgocdAppByManifestPathAnnotation(ctx, "right/path", "some-repo", mockApplicationClient, slog.Default())
	if err != nil {
		t.Errorf("Error: %v", err)
	} else if app.Name != "right-app" {
		t.Errorf("App name is not right-app")
	}
}

func TestFindArgocdAppByPathAnnotationNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockApplicationClient := mocks.NewMockApplicationServiceClient(ctrl)
	expectedResponse := &argoappv1.ApplicationList{
		Items: []argoappv1.Application{
			{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"argocd.argoproj.io/manifest-generate-paths": "non-existing-path",
					},
					Name: "non-existing-app",
				},
				Spec: argoappv1.ApplicationSpec{
					Source: &argoappv1.ApplicationSource{
						RepoURL: "",
						Path:    "non-existing/",
					},
				},
			},
		},
	}

	mockApplicationClient.EXPECT().List(gomock.Any(), gomock.Any()).Return(expectedResponse, nil)
	app, err := findArgocdAppByManifestPathAnnotation(ctx, "non-existing/path", "some-repo", mockApplicationClient, slog.Default())
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if app != nil {
		log.Fatal("expected the application to be nil")
	}
}

func TestTempAppDeletedOnDiffError(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	mockAppClient := mocks.NewMockApplicationServiceClient(ctrl)
	mockAppSetClient := mocks.NewMockApplicationSetServiceClient(ctrl)

	ac := ArgoCDClients{
		App:    mockAppClient,
		AppSet: mockAppSetClient,
	}

	componentPath := "clusters/test/app"
	repo := "test-repo"
	prBranch := "feature-branch"

	// 1. No existing app — List returns empty.
	mockAppClient.EXPECT().
		List(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&argoappv1.ApplicationList{}, nil)

	// 2. AppSet matches component path via Git generator.
	mockAppSetClient.EXPECT().
		List(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&argoappv1.ApplicationSetList{
			Items: []argoappv1.ApplicationSet{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-appset"},
					Spec: argoappv1.ApplicationSetSpec{
						GoTemplate: true,
						Generators: []argoappv1.ApplicationSetGenerator{
							{
								Git: &argoappv1.GitGenerator{
									RepoURL: repo,
									Directories: []argoappv1.GitDirectoryGeneratorItem{
										{Path: "clusters/test/*"},
									},
								},
							},
						},
						Template: argoappv1.ApplicationSetTemplate{
							ApplicationSetTemplateMeta: argoappv1.ApplicationSetTemplateMeta{
								Name: "{{.path.basename}}",
							},
							Spec: argoappv1.ApplicationSpec{
								Source: &argoappv1.ApplicationSource{
									RepoURL:        repo,
									Path:           "{{.path.path}}",
									TargetRevision: "main",
								},
								SyncPolicy: &argoappv1.SyncPolicy{
									Automated: &argoappv1.SyncPolicyAutomated{},
								},
								Destination: argoappv1.ApplicationDestination{
									Server:    "https://kubernetes.default.svc",
									Namespace: "default",
								},
								Project: "default",
							},
						},
					},
				},
			},
		}, nil)

	tempApp := &argoappv1.Application{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "temp-app",
			Namespace: "argocd",
		},
		Spec: argoappv1.ApplicationSpec{
			Source: &argoappv1.ApplicationSource{
				TargetRevision: prBranch,
			},
			SyncPolicy: &argoappv1.SyncPolicy{},
			Project:     "default",
		},
		Status: argoappv1.ApplicationStatus{
			Health: argoappv1.HealthStatus{Status: "Unknown"},
			Sync:   argoappv1.SyncStatus{Status: "Unknown"},
		},
	}

	// 3. Create succeeds.
	mockAppClient.EXPECT().
		Create(gomock.Any(), gomock.Any()).
		Return(tempApp, nil)

	// 4. ManagedResources fails — simulating a mid-flight error.
	managedResourcesErr := fmt.Errorf("connection refused")
	mockAppClient.EXPECT().
		ManagedResources(gomock.Any(), gomock.Any()).
		Return(nil, managedResourcesErr)

	// 5. Delete MUST be called despite the error above.
	mockAppClient.EXPECT().
		Delete(gomock.Any(), gomock.Any()).
		Return(&application.ApplicationResponse{}, nil)

	result := generateDiffOfAComponent(
		context.Background(),
		false,
		componentPath,
		prBranch,
		repo,
		ac,
		&settings.Settings{URL: "https://argocd.test"},
		DiffConfig{UseSHALabel: true, CreateTempApps: true},
		slog.Default(),
	)

	assert.True(t, result.AppWasTemporarilyCreated, "expected temp app to be flagged as created")
	assert.ErrorContains(t, result.DiffError, "connection refused", "expected ManagedResources error to propagate")
	// gomock will fail the test if Delete was not called
}

func TestFetchArgoDiffConcurrently(t *testing.T) {
	t.Parallel()
	// MockApplicationServiceClient
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	// mock the argoClients
	mockAppServiceClient := mocks.NewMockApplicationServiceClient(mockCtrl)
	mockSettingsServiceClient := mocks.NewMockSettingsServiceClient(mockCtrl)
	// fake InitArgoClients

	argoClients := ArgoCDClients{
		App:     mockAppServiceClient,
		Setting: mockSettingsServiceClient,
	}
	// slowReply simulates a slow reply from the server
	slowReply := func(ctx context.Context, in any, opts ...any) {
		time.Sleep(time.Second)
	}

	// makeComponents for test
	makeComponents := func(num int) map[string]bool {
		components := make(map[string]bool, num)
		for i := 0; i < num; i++ {
			components[fmt.Sprintf("component/to/diff/%d", i)] = true
		}
		return components
	}

	mockSettingsServiceClient.EXPECT().
		Get(gomock.Any(), gomock.Any()).
		Return(&settings.Settings{
			URL: "https://test-argocd.test.test",
		}, nil)
	// mock the List method
	mockAppServiceClient.EXPECT().
		List(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&argoappv1.ApplicationList{
			Items: []argoappv1.Application{
				{
					TypeMeta:   metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{},
					Spec:       argoappv1.ApplicationSpec{},
					Status:     argoappv1.ApplicationStatus{},
					Operation:  &argoappv1.Operation{},
				},
			},
		}, nil).
		AnyTimes().
		Do(slowReply) // simulate slow reply

	// mock the Get method
	mockAppServiceClient.EXPECT().
		Get(gomock.Any(), gomock.Any()).
		Return(&argoappv1.Application{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-app",
			},
			Spec: argoappv1.ApplicationSpec{
				Source: &argoappv1.ApplicationSource{
					TargetRevision: "test-revision",
				},
				SyncPolicy: &argoappv1.SyncPolicy{
					Automated: &argoappv1.SyncPolicyAutomated{},
				},
			},
			Status:    argoappv1.ApplicationStatus{},
			Operation: &argoappv1.Operation{},
		}, nil).
		AnyTimes()

	// mock managedResource
	mockAppServiceClient.EXPECT().
		ManagedResources(gomock.Any(), gomock.Any()).
		Return(&application.ManagedResourcesResponse{}, nil).
		AnyTimes()

	// mock the GetManifests method
	mockAppServiceClient.EXPECT().
		GetManifests(gomock.Any(), gomock.Any()).
		Return(&reposerverApiClient.ManifestResponse{}, nil).
		AnyTimes()

	const numComponents = 5
	// start timer
	start := time.Now()

	// TODO: Test all the return values, for now we will just ignore the linter.
	_, _, diffResults, _ := GenerateDiffOfChangedComponents( //nolint:dogsled
		context.TODO(),
		makeComponents(numComponents),
		"test-pr-branch",
		"test-repo",
		DiffConfig{UseSHALabel: true},
		argoClients,
		slog.Default(),
	)

	// stop timer
	elapsed := time.Since(start)
	assert.Equal(t, numComponents, len(diffResults))
	// assert that the entire run takes less than numComponents * 1 second
	assert.Less(t, elapsed, time.Duration(numComponents)*time.Second)
}

func TestGenerateAppSetGitGeneratorParams(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		path              string
		wantPath          string
		wantBasename      string
		wantFilename      string
		wantBaseNorm      string
		wantFileNorm      string
		wantSegmentsCount int
	}{
		"simple path": {
			path:              "env/staging",
			wantPath:          "env/staging",
			wantBasename:      "staging",
			wantFilename:      "staging",
			wantBaseNorm:      "staging",
			wantFileNorm:      "staging",
			wantSegmentsCount: 2,
		},
		"nested path": {
			path:              "env/prod/us-east/c1",
			wantPath:          "env/prod/us-east/c1",
			wantBasename:      "c1",
			wantFilename:      "c1",
			wantBaseNorm:      "c1",
			wantFileNorm:      "c1",
			wantSegmentsCount: 4,
		},
		"root path": {
			path:              ".",
			wantPath:          ".",
			wantBasename:      ".",
			wantFilename:      ".",
			wantBaseNorm:      "",
			wantFileNorm:      "",
			wantSegmentsCount: 1,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			params := generateAppSetGitGeneratorParams(tc.path)
			pathMap, ok := params["path"].(map[string]interface{})
			if !ok {
				t.Fatalf("params[\"path\"] is not map[string]interface{}, got %T", params["path"])
			}
			if got := pathMap["path"].(string); got != tc.wantPath {
				t.Errorf("path = %q, want %q", got, tc.wantPath)
			}
			if got := pathMap["basename"].(string); got != tc.wantBasename {
				t.Errorf("basename = %q, want %q", got, tc.wantBasename)
			}
			if got := pathMap["filename"].(string); got != tc.wantFilename {
				t.Errorf("filename = %q, want %q", got, tc.wantFilename)
			}
			if got := pathMap["basenameNormalized"].(string); got != tc.wantBaseNorm {
				t.Errorf("basenameNormalized = %q, want %q", got, tc.wantBaseNorm)
			}
			if got := pathMap["filenameNormalized"].(string); got != tc.wantFileNorm {
				t.Errorf("filenameNormalized = %q, want %q", got, tc.wantFileNorm)
			}
			segments := pathMap["segments"].([]string)
			if got := len(segments); got != tc.wantSegmentsCount {
				t.Errorf("segments count = %d, want %d", got, tc.wantSegmentsCount)
			}
		})
	}
}

func TestGetTempApplication(t *testing.T) {
	t.Parallel()
	tmpl := argoappv1.ApplicationSetTemplate{
		ApplicationSetTemplateMeta: argoappv1.ApplicationSetTemplateMeta{
			Name:      "my-app",
			Namespace: "argocd",
			Labels: map[string]string{
				"env": "staging",
			},
			Annotations: map[string]string{
				"note": "test",
			},
		},
		Spec: argoappv1.ApplicationSpec{
			Source: &argoappv1.ApplicationSource{
				RepoURL: "https://github.com/example/repo",
			},
		},
	}
	tmpl.ApplicationSetTemplateMeta.Finalizers = []string{"resources-finalizer.argocd.argoproj.io"}

	app := getTempApplication(tmpl)

	if app.Name != "my-app" {
		t.Errorf("Name = %q, want %q", app.Name, "my-app")
	}
	if app.Namespace != "argocd" {
		t.Errorf("Namespace = %q, want %q", app.Namespace, "argocd")
	}
	if app.Labels["env"] != "staging" {
		t.Errorf("Labels[env] = %q, want %q", app.Labels["env"], "staging")
	}
	if app.Annotations["note"] != "test" {
		t.Errorf("Annotations[note] = %q, want %q", app.Annotations["note"], "test")
	}
	if len(app.Finalizers) != 1 || app.Finalizers[0] != "resources-finalizer.argocd.argoproj.io" {
		t.Errorf("Finalizers = %v, want [resources-finalizer.argocd.argoproj.io]", app.Finalizers)
	}
	if app.Spec.Source.RepoURL != "https://github.com/example/repo" {
		t.Errorf("Spec.Source.RepoURL = %q, want %q", app.Spec.Source.RepoURL, "https://github.com/example/repo")
	}
	if app.ResourceVersion != "" {
		t.Errorf("ResourceVersion should be zero-valued, got %q", app.ResourceVersion)
	}
}

func TestFindRelevantAppSetByPathPluginGenerator(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		pathPattern   string
		componentPath string
		wantName      string
		wantErr       bool
	}{
		"match": {
			pathPattern:   `"env/*"`,
			componentPath: "env/staging",
			wantName:      "plugin-appset",
		},
		"no match": {
			pathPattern:   `"other/*"`,
			componentPath: "env/staging",
			wantErr:       true,
		},
		"bad JSON": {
			pathPattern:   `not-valid-json`,
			componentPath: "env/staging",
			wantErr:       true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAppSetClient := mocks.NewMockApplicationSetServiceClient(ctrl)
			mockAppSetClient.EXPECT().
				List(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(&argoappv1.ApplicationSetList{
					Items: []argoappv1.ApplicationSet{
						{
							ObjectMeta: metav1.ObjectMeta{Name: "plugin-appset"},
							Spec: argoappv1.ApplicationSetSpec{
								Generators: []argoappv1.ApplicationSetGenerator{
									{
										Plugin: &argoappv1.PluginGenerator{
											Input: argoappv1.PluginInput{
												Parameters: argoappv1.PluginParameters{
													"path": apiextensionsv1.JSON{Raw: json.RawMessage(tc.pathPattern)},
												},
											},
										},
									},
								},
							},
						},
					},
				}, nil)

			appSet, err := findRelevantAppSetByPath(t.Context(), tc.componentPath, "repo", mockAppSetClient, slog.Default())
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if appSet.Name != tc.wantName {
				t.Errorf("appSet.Name = %q, want %q", appSet.Name, tc.wantName)
			}
		})
	}
}
