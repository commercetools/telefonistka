package main

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/argoproj/argo-cd/v2/pkg/apiclient/application"
	applicationsetpkg "github.com/argoproj/argo-cd/v2/pkg/apiclient/applicationset"
	projectpkg "github.com/argoproj/argo-cd/v2/pkg/apiclient/project"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/settings"
	argoappv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	repoapiclient "github.com/argoproj/argo-cd/v2/reposerver/apiclient"
	"github.com/commercetools/telefonistka/argocd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- Application service fake ---

type fakeAppServer struct {
	application.UnimplementedApplicationServiceServer
	mu      sync.Mutex
	apps    map[string]*argoappv1.Application
	patches []*application.ApplicationPatchRequest
}

func (s *fakeAppServer) addApp(app *argoappv1.Application) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apps[app.Name] = app
}

func (s *fakeAppServer) Patches() []*application.ApplicationPatchRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*application.ApplicationPatchRequest(nil), s.patches...)
}

func (s *fakeAppServer) List(_ context.Context, _ *application.ApplicationQuery) (*argoappv1.ApplicationList, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var items []argoappv1.Application
	for _, app := range s.apps {
		items = append(items, *app)
	}
	return &argoappv1.ApplicationList{Items: items}, nil
}

func (s *fakeAppServer) Get(_ context.Context, q *application.ApplicationQuery) (*argoappv1.Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	app, ok := s.apps[q.GetName()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "app %q not found", q.GetName())
	}
	return app, nil
}

func (s *fakeAppServer) Create(_ context.Context, req *application.ApplicationCreateRequest) (*argoappv1.Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	app := req.GetApplication()
	s.apps[app.Name] = app
	return app, nil
}

func (s *fakeAppServer) Delete(_ context.Context, req *application.ApplicationDeleteRequest) (*application.ApplicationResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.apps, req.GetName())
	return &application.ApplicationResponse{}, nil
}

func (s *fakeAppServer) Patch(_ context.Context, req *application.ApplicationPatchRequest) (*argoappv1.Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.patches = append(s.patches, req)
	app, ok := s.apps[req.GetName()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "app %q not found", req.GetName())
	}
	return app, nil
}

func (s *fakeAppServer) ManagedResources(context.Context, *application.ResourcesQuery) (*application.ManagedResourcesResponse, error) {
	return &application.ManagedResourcesResponse{}, nil
}

func (s *fakeAppServer) GetManifests(context.Context, *application.ApplicationManifestQuery) (*repoapiclient.ManifestResponse, error) {
	return &repoapiclient.ManifestResponse{}, nil
}

// --- Project service fake ---

type fakeProjectServer struct {
	projectpkg.UnimplementedProjectServiceServer
}

func (s *fakeProjectServer) GetDetailedProject(_ context.Context, req *projectpkg.ProjectQuery) (*projectpkg.DetailedProjectsResponse, error) {
	return &projectpkg.DetailedProjectsResponse{
		Project: &argoappv1.AppProject{
			ObjectMeta: metav1.ObjectMeta{Name: req.Name},
		},
	}, nil
}

// --- Settings service fake ---

type fakeSettingsServer struct {
	settings.UnimplementedSettingsServiceServer
}

func (s *fakeSettingsServer) Get(context.Context, *settings.SettingsQuery) (*settings.Settings, error) {
	return &settings.Settings{
		URL:         "https://argocd.fake",
		AppLabelKey: "app.kubernetes.io/instance",
	}, nil
}

// --- ApplicationSet service fake ---

type fakeAppSetServer struct {
	applicationsetpkg.UnimplementedApplicationSetServiceServer
}

func (s *fakeAppSetServer) List(context.Context, *applicationsetpkg.ApplicationSetListQuery) (*argoappv1.ApplicationSetList, error) {
	return &argoappv1.ApplicationSetList{}, nil
}

// --- Aggregate + helper ---

type FakeArgoCD struct {
	App     *fakeAppServer
	Project *fakeProjectServer
	Setting *fakeSettingsServer
	AppSet  *fakeAppSetServer
}

// startFakeArgoCD starts a bufconn gRPC server with all four fake ArgoCD
// services, dials it, and returns the fakes (for assertions) and the
// client stubs (for EventConfig.ArgoCD). Server and connection are
// cleaned up via t.Cleanup.
func startFakeArgoCD(t *testing.T) (*FakeArgoCD, *argocd.ArgoCDClients) {
	t.Helper()

	fake := &FakeArgoCD{
		App:     &fakeAppServer{apps: make(map[string]*argoappv1.Application)},
		Project: &fakeProjectServer{},
		Setting: &fakeSettingsServer{},
		AppSet:  &fakeAppSetServer{},
	}

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	application.RegisterApplicationServiceServer(srv, fake.App)
	projectpkg.RegisterProjectServiceServer(srv, fake.Project)
	settings.RegisterSettingsServiceServer(srv, fake.Setting)
	applicationsetpkg.RegisterApplicationSetServiceServer(srv, fake.AppSet)

	go srv.Serve(lis) //nolint:errcheck

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.DialContext(context.Background())
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dialing fake ArgoCD: %v", err)
	}

	t.Cleanup(func() {
		conn.Close()
		srv.Stop()
	})

	clients := &argocd.ArgoCDClients{
		App:     application.NewApplicationServiceClient(conn),
		Project: projectpkg.NewProjectServiceClient(conn),
		Setting: settings.NewSettingsServiceClient(conn),
		AppSet:  applicationsetpkg.NewApplicationSetServiceClient(conn),
	}
	return fake, clients
}

// newTestApp creates a minimal ArgoCD Application suitable for discovery
// via the manifest-generate-paths annotation.
func newTestApp(name, repoURL, componentPath string) *argoappv1.Application {
	return &argoappv1.Application{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "argocd",
			Annotations: map[string]string{
				"argocd.argoproj.io/manifest-generate-paths": componentPath,
			},
		},
		Spec: argoappv1.ApplicationSpec{
			Project: "default",
			Source: &argoappv1.ApplicationSource{
				RepoURL:        repoURL,
				Path:            componentPath,
				TargetRevision: "HEAD",
			},
			Destination: argoappv1.ApplicationDestination{
				Server:    "https://kubernetes.default.svc",
				Namespace: "default",
			},
			SyncPolicy: &argoappv1.SyncPolicy{},
		},
		Status: argoappv1.ApplicationStatus{
			Health: argoappv1.HealthStatus{Status: "Healthy"},
			Sync:   argoappv1.SyncStatus{Status: "Synced"},
		},
	}
}
