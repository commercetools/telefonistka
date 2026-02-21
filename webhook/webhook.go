package webhook

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/alexliesenfeld/health"
	"github.com/commercetools/telefonistka/githubapi"
	prom "github.com/commercetools/telefonistka/prometheus"
	"github.com/google/go-github/v62/github"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config holds transport-layer configuration for the webhook HTTP server.
type Config struct {
	Event         githubapi.EventConfig
	WebhookSecret []byte
	Sync          bool // run HandleEvent synchronously (for testing)
}

// NewHandler returns an http.Handler that serves the webhook, health,
// and metrics endpoints. The caller is responsible for starting the
// server and any background goroutines (e.g. MainGhMetricsLoop).
func NewHandler(cfg Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", webhookHandler(cfg))
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/live", health.NewHandler(health.NewChecker()))
	mux.Handle("/ready", health.NewHandler(health.NewChecker()))
	return mux
}

func webhookHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		payload, err := github.ValidatePayload(r, cfg.WebhookSecret)
		if err != nil {
			slog.Error("error reading request body", "err", err)
			prom.InstrumentWebhookHit("validation_failed")
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		eventType := github.WebHookType(r)
		if cfg.Sync {
			githubapi.HandleEvent(r.Context(), cfg.Event, eventType, r.Header, payload)
		} else {
			go githubapi.HandleEvent(context.Background(), cfg.Event, eventType, r.Header, payload)
		}
		w.WriteHeader(http.StatusOK)
	}
}
