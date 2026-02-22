package telefonistka

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"text/template"

	"github.com/commercetools/telefonistka/argocd"
	"github.com/commercetools/telefonistka/gh"
	"github.com/spf13/cobra"
)

// This is still(https://github.com/spf13/cobra/issues/1862) the documented way to use cobra
func init() { //nolint:gochecknoinits
	var eventType string
	var eventFilePath string
	eventCmd := &cobra.Command{
		Use:   "event",
		Short: "Handles a GitHub event based on event JSON file",
		Long:  "Handles a GitHub event based on event JSON file.\nThis operation mode was was built with GitHub Actions in mind",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			event(eventType, eventFilePath)
		},
	}
	eventCmd.Flags().StringVarP(&eventType, "type", "t", getEnv("GITHUB_EVENT_NAME", ""), "Event type, defaults to GITHUB_EVENT_NAME env var")
	eventCmd.Flags().StringVarP(&eventFilePath, "file", "f", getEnv("GITHUB_EVENT_PATH", ""), "File path for event JSON, defaults to GITHUB_EVENT_PATH env var")
	rootCmd.AddCommand(eventCmd)
}

func event(eventType string, eventFilePath string) {
	clients := gh.NewClientProvider(
		128,
		gh.ClientConfig{
			AppID:      parseOptionalInt64(os.Getenv("GITHUB_APP_ID")),
			AppKeyPath: os.Getenv("GITHUB_APP_PRIVATE_KEY_PATH"),
			OAuthToken: os.Getenv("GITHUB_OAUTH_TOKEN"),
		},
		gh.ClientConfig{
			AppID:      parseOptionalInt64(os.Getenv("APPROVER_GITHUB_APP_ID")),
			AppKeyPath: os.Getenv("APPROVER_GITHUB_APP_PRIVATE_KEY_PATH"),
			OAuthToken: os.Getenv("APPROVER_GITHUB_OAUTH_TOKEN"),
		},
		gh.NewEndpoints(os.Getenv("GITHUB_HOST")),
	)

	var argoClients *argocd.Clients
	if addr := os.Getenv("ARGOCD_SERVER_ADDR"); addr != "" {
		plaintext, _ := strconv.ParseBool(os.Getenv("ARGOCD_PLAINTEXT"))
		insecure, _ := strconv.ParseBool(os.Getenv("ARGOCD_INSECURE"))
		ac, err := argocd.NewClients(argocd.ClientOptions{
			ServerAddr: addr,
			AuthToken:  os.Getenv("ARGOCD_TOKEN"),
			Plaintext:  plaintext,
			Insecure:   insecure,
		})
		if err != nil {
			slog.Error("Failed to create ArgoCD clients", "err", err)
			return
		}
		argoClients = &ac
	}

	var commitStatusURLTmpl *template.Template
	if p := os.Getenv("CUSTOM_COMMIT_STATUS_URL_TEMPLATE_PATH"); p != "" {
		commitStatusURLTmpl = template.Must(
			template.New(filepath.Base(p)).ParseFiles(p),
		)
	}

	cfg := gh.EventConfig{
		Clients:             clients,
		ArgoCD:              argoClients,
		TemplatesFS:         resolveTemplatesFS(),
		CommitStatusURLTmpl: commitStatusURLTmpl,
		HandleSelfComment:   os.Getenv("HANDLE_SELF_COMMENT") == "true",
	}

	slog.Info("Processing", "file", eventFilePath)
	payload, err := os.ReadFile(eventFilePath)
	if err != nil {
		panic(err)
	}
	gh.HandleEvent(context.Background(), cfg, eventType, nil, payload)
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
