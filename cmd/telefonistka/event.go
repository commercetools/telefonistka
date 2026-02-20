package telefonistka

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/commercetools/telefonistka/githubapi"
	lru "github.com/hashicorp/golang-lru/v2"
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
	clientCache, _ := lru.New[string, githubapi.GhClients](128)

	cfg := githubapi.EventConfig{
		ClientCache: clientCache,
		MainClient: githubapi.ClientConfig{
			AppID:      parseOptionalInt64(os.Getenv("GITHUB_APP_ID")),
			AppKeyPath: os.Getenv("GITHUB_APP_PRIVATE_KEY_PATH"),
			OAuthToken: os.Getenv("GITHUB_OAUTH_TOKEN"),
		},
		ApproverClient: githubapi.ClientConfig{
			AppID:      parseOptionalInt64(os.Getenv("APPROVER_GITHUB_APP_ID")),
			AppKeyPath: os.Getenv("APPROVER_GITHUB_APP_PRIVATE_KEY_PATH"),
			OAuthToken: os.Getenv("APPROVER_GITHUB_OAUTH_TOKEN"),
		},
		Endpoints:                   githubapi.NewGithubEndpoints(os.Getenv("GITHUB_HOST")),
		TemplatesFS:                 resolveTemplatesFS(),
		CommitStatusURLTemplatePath: os.Getenv("CUSTOM_COMMIT_STATUS_URL_TEMPLATE_PATH"),
		HandleSelfComment:           os.Getenv("HANDLE_SELF_COMMENT") == "true",
	}

	slog.Info("Proccesing", "file", eventFilePath)
	payload, err := os.ReadFile(eventFilePath)
	if err != nil {
		panic(err)
	}
	r, _ := http.NewRequest("POST", "", nil) //nolint:noctx
	r.Body = io.NopCloser(bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-GitHub-Event", eventType)
	githubapi.HandleEvent(context.Background(), cfg, r, payload)
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
