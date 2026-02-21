package argocd

import (
	"fmt"
	"log/slog"

	"github.com/argoproj/argo-cd/v2/pkg/apiclient"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/application"
	applicationsetpkg "github.com/argoproj/argo-cd/v2/pkg/apiclient/applicationset"
	projectpkg "github.com/argoproj/argo-cd/v2/pkg/apiclient/project"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/settings"
)

// ClientOptions holds the connection parameters for an ArgoCD server.
// Values are resolved by the caller (typically main); this package
// never reads environment variables.
type ClientOptions struct {
	ServerAddr string
	AuthToken  string
	Plaintext  bool
	Insecure   bool
}

// ArgoCDClients bundles the four gRPC service stubs needed to interact
// with an ArgoCD server.
type ArgoCDClients struct {
	App     application.ApplicationServiceClient
	Project projectpkg.ProjectServiceClient
	Setting settings.SettingsServiceClient
	AppSet  applicationsetpkg.ApplicationSetServiceClient
}

// NewArgoCDClients creates the four gRPC service stubs from the given
// connection options. Call this once at application startup and reuse
// the result.
func NewArgoCDClients(opts ClientOptions) (ArgoCDClients, error) {
	var ac ArgoCDClients
	slog.Debug("Creating ArgoCD clients", "server", opts.ServerAddr, "plaintext", opts.Plaintext, "insecure", opts.Insecure)

	clientOpts := &apiclient.ClientOptions{
		ServerAddr: opts.ServerAddr,
		AuthToken:  opts.AuthToken,
		PlainText:  opts.Plaintext,
		Insecure:   opts.Insecure,
	}

	client, err := apiclient.NewClient(clientOpts)
	if err != nil {
		return ac, fmt.Errorf("creating ArgoCD API client: %w", err)
	}

	_, ac.App, err = client.NewApplicationClient()
	if err != nil {
		return ac, fmt.Errorf("creating ArgoCD app client: %w", err)
	}

	_, ac.Project, err = client.NewProjectClient()
	if err != nil {
		return ac, fmt.Errorf("creating ArgoCD project client: %w", err)
	}

	_, ac.Setting, err = client.NewSettingsClient()
	if err != nil {
		return ac, fmt.Errorf("creating ArgoCD settings client: %w", err)
	}

	_, ac.AppSet, err = client.NewApplicationSetClient()
	if err != nil {
		return ac, fmt.Errorf("creating ArgoCD appSet client: %w", err)
	}

	slog.Debug("ArgoCD clients created")
	return ac, nil
}
