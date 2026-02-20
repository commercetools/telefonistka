package githubapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"maps"
	"slices"

	"github.com/commercetools/telefonistka/configuration"
	prom "github.com/commercetools/telefonistka/prometheus"
)

func generateListOfEndpoints(listOfChangedFiles []string, config *configuration.Config) []string {
	// Pre-compile regexes once instead of per-file.
	compiled := make([]*regexp.Regexp, len(config.WebhookEndpointRegexs))
	for i, r := range config.WebhookEndpointRegexs {
		compiled[i] = regexp.MustCompile(r.Expression)
	}

	endpoints := map[string]bool{} // using map for uniqueness
	for _, file := range listOfChangedFiles {
		for i, regex := range config.WebhookEndpointRegexs {
			if compiled[i].MatchString(file) {
				for _, replacement := range regex.Replacements {
					endpoints[compiled[i].ReplaceAllString(file, replacement)] = true
				}
				break
			}
		}
	}

	return slices.Collect(maps.Keys(endpoints))
}

func proxyRequest(ctx context.Context, skipTLSVerify bool, originalHttpRequest *http.Request, body []byte, endpoint string) {
	tr := &http.Transport{}
	if skipTLSVerify {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 - letting the user decide if they want to skip TLS verification, for some in-cluster scenarios its a reasonable compromise
		}
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequestWithContext(ctx, originalHttpRequest.Method, endpoint, bytes.NewBuffer(body))
	if err != nil {
		slog.Error("Error creating request to endpoint", "endpoint", endpoint, "err", err)
		return
	}
	req.Header = originalHttpRequest.Header.Clone()
	// Because payload and headers are passed as-is, I'm hoping webhook signature validation will "just work"

	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Error proxying request to endpoint", "endpoint", endpoint, "err", err)
		return
	}
	slog.Debug("Webhook successfully forwarded to endpoint", "endpoint", endpoint)
	defer resp.Body.Close()

	_ = prom.InstrumentProxyUpstreamRequest(resp)

	if !strings.HasPrefix(resp.Status, "2") {
		body, _ := io.ReadAll(resp.Body)
		slog.Error("Got non 2XX HTTP status from endpoint", "endpoint", endpoint, "status", resp.Status, "body", string(body))
	}
}

func handleProxyForward(ctx context.Context, config *configuration.Config, listOfChangedFiles []string, httpRequest *http.Request, payload []byte) {
	slog.Debug("Changed files in push event", "files", listOfChangedFiles)

	// TODO this need to be cached with TTL + invalidate if configfile in listOfChangedFiles?
	// This is possible because these webhooks are defined as "best effort" for the designed use case:
	// Speeding up ArgoCD reconcile loops
	endpoints := generateListOfEndpoints(listOfChangedFiles, config)

	var wg sync.WaitGroup
	for _, endpoint := range endpoints {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			proxyRequest(ctx, config.WhProxtSkipTLSVerifyUpstream, httpRequest, payload, endpoint)
		}(endpoint)
	}
	wg.Wait()
}
