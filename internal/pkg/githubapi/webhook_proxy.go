package githubapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/commercetools/telefonistka/internal/pkg/configuration"
	prom "github.com/commercetools/telefonistka/internal/pkg/prometheus"
	"github.com/google/go-github/v62/github"
	"golang.org/x/exp/maps"
)

func generateListOfChangedFiles(eventPayload *github.PushEvent) []string {
	fileList := map[string]bool{} // using map for uniqueness

	for _, commit := range eventPayload.Commits {
		for _, file := range commit.Added {
			fileList[file] = true
		}
		for _, file := range commit.Modified {
			fileList[file] = true
		}
		for _, file := range commit.Removed {
			fileList[file] = true
		}
	}

	return maps.Keys(fileList)
}

func generateListOfEndpoints(listOfChangedFiles []string, config *configuration.Config) []string {
	endpoints := map[string]bool{} // using map for uniqueness
	for _, file := range listOfChangedFiles {
		for _, regex := range config.WebhookEndpointRegexs {
			m := regexp.MustCompile(regex.Expression)

			if m.MatchString(file) {
				for _, replacement := range regex.Replacements {
					endpoints[m.ReplaceAllString(file, replacement)] = true
				}
				break
			}
		}
	}

	return maps.Keys(endpoints)
}

func proxyRequest(ctx context.Context, skipTLSVerify bool, originalHttpRequest *http.Request, body []byte, endpoint string, responses chan<- string) {
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
		responses <- fmt.Sprintf("Failed to create request to %s", endpoint)
		return
	}
	req.Header = originalHttpRequest.Header.Clone()
	// Because payload and headers are passed as-is, I'm hoping webhook signature validation will "just work"

	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Error proxying request to endpoint", "endpoint", endpoint, "err", err)
		responses <- fmt.Sprintf("Failed to proxy request to %s", endpoint)
		return
	} else {
		slog.Debug("Webhook successfully forwarded to endpoint", "endpoint", endpoint)
	}
	defer resp.Body.Close()

	_ = prom.InstrumentProxyUpstreamRequest(resp)

	respBody, err := io.ReadAll(resp.Body)

	if !strings.HasPrefix(resp.Status, "2") {
		slog.Error("Got non 2XX HTTP status from endpoint", "endpoint", endpoint, "status", resp.Status, "body", body)
	}

	if err != nil {
		slog.Error("Error reading response body from endpoint", "endpoint", endpoint, "err", err)
		responses <- fmt.Sprintf("Failed to read response from %s", endpoint)
		return
	}

	responses <- string(respBody)
}

func handlePushEvent(ctx context.Context, eventPayload *github.PushEvent, httpRequest *http.Request, payload []byte, ghPrClientDetails GhPrClientDetails) {
	listOfChangedFiles := generateListOfChangedFiles(eventPayload)
	slog.Debug("Changed files in push event", "files", listOfChangedFiles)

	defaultBranch := eventPayload.Repo.DefaultBranch

	if *eventPayload.Ref == "refs/heads/"+*defaultBranch {
		// TODO this need to be cached with TTL + invalidate if configfile in listOfChangedFiles?
		// This is possible because these webhooks are defined as "best effort" for the designed use case:
		// Speeding up ArgoCD reconcile loops
		config, _ := GetInRepoConfig(ctx, ghPrClientDetails, *defaultBranch)
		endpoints := generateListOfEndpoints(listOfChangedFiles, config)

		// Create a channel to receive responses from the goroutines
		responses := make(chan string)

		// Use a buffered channel with the same size as the number of endpoints
		// to prevent goroutines from blocking in case of slow endpoints
		results := make(chan string, len(endpoints))

		// Start a goroutine for each endpoint
		for _, endpoint := range endpoints {
			go proxyRequest(ctx, config.WhProxtSkipTLSVerifyUpstream, httpRequest, payload, endpoint, responses)
		}

		// Wait for all goroutines to finish and collect the responses
		for i := 0; i < len(endpoints); i++ {
			result := <-responses
			results <- result
		}

		close(responses)
		close(results)
	}
}
