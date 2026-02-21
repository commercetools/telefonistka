package githubapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/go-github/v62/github"
)

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// failingClients returns an EventConfig whose ClientProvider has no
// credentials. ForOwner will return ErrNoCredentials, exercising
// event dispatch without triggering real GitHub API calls.
func failingClients() EventConfig {
	return EventConfig{
		Clients: NewClientProvider(1, ClientConfig{}, ClientConfig{}, GithubEndpoints{}),
	}
}

func TestHandleEvent(t *testing.T) {
	t.Parallel()
	cfg := failingClients()

	tests := map[string]struct {
		eventType string
		payload   []byte
	}{
		"push event routes without panic": {
			eventType: "push",
			payload: mustMarshal(t, &github.PushEvent{
				Ref: github.String("refs/heads/main"),
				Repo: &github.PushEventRepository{
					Owner:         &github.User{Login: github.String("test-owner")},
					Name:          github.String("test-repo"),
					DefaultBranch: github.String("main"),
				},
			}),
		},
		"pull_request event routes without panic": {
			eventType: "pull_request",
			payload: mustMarshal(t, &github.PullRequestEvent{
				Action: github.String("opened"),
				Repo: &github.Repository{
					Owner:         &github.User{Login: github.String("test-owner")},
					Name:          github.String("test-repo"),
					DefaultBranch: github.String("main"),
				},
				PullRequest: &github.PullRequest{
					Number: github.Int(1),
					User:   &github.User{Login: github.String("author")},
					Head: &github.PullRequestBranch{
						SHA: github.String("abc123"),
						Ref: github.String("feature"),
					},
				},
			}),
		},
		"issue_comment event routes without panic": {
			eventType: "issue_comment",
			payload: mustMarshal(t, &github.IssueCommentEvent{
				Action: github.String("created"),
				Repo: &github.Repository{
					Owner:         &github.User{Login: github.String("test-owner")},
					Name:          github.String("test-repo"),
					DefaultBranch: github.String("main"),
				},
				Issue:   &github.Issue{Number: github.Int(1), User: &github.User{Login: github.String("user")}},
				Comment: &github.IssueComment{Body: github.String("hello"), User: &github.User{Login: github.String("commenter")}},
				Sender:  &github.User{Login: github.String("sender")},
			}),
		},
		"unknown event type is silently ignored": {
			eventType: "deployment",
			payload:   []byte(`{}`),
		},
		"malformed payload does not panic": {
			eventType: "push",
			payload:   []byte(`{invalid json`),
		},
		"empty event type does not panic": {
			eventType: "",
			payload:   []byte(`{}`),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			HandleEvent(t.Context(), cfg, tc.eventType, nil, tc.payload)
		})
	}
}

func TestHandleEventWithHeaders(t *testing.T) {
	t.Parallel()
	cfg := failingClients()

	headers := http.Header{
		"X-Hub-Signature-256": []string{"sha256=abc"},
		"Content-Type":        []string{"application/json"},
	}

	// Push event with headers — exercises the proxy path (which
	// no-ops because config has no WebhookEndpointRegexs).
	HandleEvent(t.Context(), cfg, "push", headers, mustMarshal(t, &github.PushEvent{
		Ref: github.String("refs/heads/main"),
		Repo: &github.PushEventRepository{
			Owner:         &github.User{Login: github.String("owner")},
			Name:          github.String("repo"),
			DefaultBranch: github.String("main"),
		},
	}))
}
