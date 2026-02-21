package telefonistka

import (
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"text/template"
	"time"

	"github.com/commercetools/telefonistka/argocd"
	"github.com/commercetools/telefonistka/githubapi"
	"github.com/commercetools/telefonistka/templates"
	"github.com/spf13/cobra"
)

func getCrucialEnv(key string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	slog.Error("Environment variable is required", "key", key)
	os.Exit(3)
	return ""
}

func parseOptionalInt64(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

func resolveTemplatesFS() fs.FS {
	if p := os.Getenv("TEMPLATES_PATH"); p != "" {
		return os.DirFS(p)
	}
	return templates.FS
}

var serveCmd = &cobra.Command{
	Use:   "server",
	Short: "Runs the web server that listens to GitHub webhooks",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		serve()
	},
}

// This is still(https://github.com/spf13/cobra/issues/1862) the documented way to use cobra
func init() { //nolint:gochecknoinits
	rootCmd.AddCommand(serveCmd)
}

func serve() {
	clients := githubapi.NewClientProvider(
		128,
		githubapi.ClientConfig{
			AppID:      parseOptionalInt64(os.Getenv("GITHUB_APP_ID")),
			AppKeyPath: os.Getenv("GITHUB_APP_PRIVATE_KEY_PATH"),
			OAuthToken: os.Getenv("GITHUB_OAUTH_TOKEN"),
		},
		githubapi.ClientConfig{
			AppID:      parseOptionalInt64(os.Getenv("APPROVER_GITHUB_APP_ID")),
			AppKeyPath: os.Getenv("APPROVER_GITHUB_APP_PRIVATE_KEY_PATH"),
			OAuthToken: os.Getenv("APPROVER_GITHUB_OAUTH_TOKEN"),
		},
		githubapi.NewGithubEndpoints(os.Getenv("GITHUB_HOST")),
	)

	var argoClients *argocd.ArgoCDClients
	if addr := os.Getenv("ARGOCD_SERVER_ADDR"); addr != "" {
		plaintext, _ := strconv.ParseBool(os.Getenv("ARGOCD_PLAINTEXT"))
		insecure, _ := strconv.ParseBool(os.Getenv("ARGOCD_INSECURE"))
		ac, err := argocd.NewArgoCDClients(argocd.ClientOptions{
			ServerAddr: addr,
			AuthToken:  os.Getenv("ARGOCD_TOKEN"),
			Plaintext:  plaintext,
			Insecure:   insecure,
		})
		if err != nil {
			slog.Error("Failed to create ArgoCD clients", "err", err)
			os.Exit(1)
		}
		argoClients = &ac
	}

	var commitStatusURLTmpl *template.Template
	if p := os.Getenv("CUSTOM_COMMIT_STATUS_URL_TEMPLATE_PATH"); p != "" {
		commitStatusURLTmpl = template.Must(
			template.New(filepath.Base(p)).ParseFiles(p),
		)
	}

	cfg := githubapi.EventConfig{
		Clients:             clients,
		ArgoCD:              argoClients,
		TemplatesFS:         resolveTemplatesFS(),
		CommitStatusURLTmpl: commitStatusURLTmpl,
		HandleSelfComment:   os.Getenv("HANDLE_SELF_COMMENT") == "true",
		WebhookSecret:       []byte(getCrucialEnv("GITHUB_WEBHOOK_SECRET")),
	}

	go githubapi.MainGhMetricsLoop(clients)

	srv := &http.Server{
		Handler:      githubapi.NewHandler(cfg),
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	slog.Info("server started")
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("ListenAndServe", "err", err)
		os.Exit(1)
	}
}
