package telefonistka

import (
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/alexliesenfeld/health"
	"github.com/commercetools/telefonistka/githubapi"
	"github.com/commercetools/telefonistka/templates"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

func handleWebhook(cfg githubapi.EventConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		err := githubapi.ReceiveWebhook(r, cfg)
		if err != nil {
			slog.Error("error handling webhook", "err", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func serve() {
	mainGhClientCache, _ := lru.New[string, githubapi.GhClientPair](128)
	prApproverGhClientCache, _ := lru.New[string, githubapi.GhClientPair](128)

	cfg := githubapi.EventConfig{
		MainClientCache:     mainGhClientCache,
		ApproverClientCache: prApproverGhClientCache,
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
		WebhookSecret:               []byte(getCrucialEnv("GITHUB_WEBHOOK_SECRET")),
	}

	livenessChecker := health.NewChecker() // No checks for the moment, other then the http server availability
	readinessChecker := health.NewChecker()

	go githubapi.MainGhMetricsLoop(mainGhClientCache)

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", handleWebhook(cfg))
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/live", health.NewHandler(livenessChecker))
	mux.Handle("/ready", health.NewHandler(readinessChecker))

	srv := &http.Server{
		Handler:      mux,
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
