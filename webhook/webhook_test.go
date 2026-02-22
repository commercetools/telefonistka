package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/commercetools/telefonistka/gh"
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

// signPayload computes the X-Hub-Signature-256 header value for a
// webhook payload signed with the given secret.
func signPayload(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func postWebhook(t *testing.T, url string, eventType string, secret, payload []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+"/webhook", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", eventType)
	if secret != nil {
		req.Header.Set("X-Hub-Signature-256", signPayload(secret, payload))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func newTestEventConfig() gh.EventConfig {
	return gh.EventConfig{
		Clients: gh.NewClientProvider(1, gh.ClientConfig{}, gh.ClientConfig{}, gh.Endpoints{}),
	}
}

func TestWebhookEndpoint(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret")
	cfg := Config{
		Event:         newTestEventConfig(),
		WebhookSecret: secret,
		Sync:          true,
	}

	srv := httptest.NewServer(NewHandler(cfg))
	t.Cleanup(srv.Close)

	tests := map[string]struct {
		eventType  string
		payload    []byte
		sign       bool
		wantStatus int
	}{
		"valid push event returns 200": {
			eventType: "push",
			payload: mustMarshal(t, &github.PushEvent{
				Ref: github.String("refs/heads/main"),
				Repo: &github.PushEventRepository{
					Owner:         &github.User{Login: github.String("owner")},
					Name:          github.String("repo"),
					DefaultBranch: github.String("main"),
				},
			}),
			sign:       true,
			wantStatus: http.StatusOK,
		},
		"valid pull_request event returns 200": {
			eventType: "pull_request",
			payload: mustMarshal(t, &github.PullRequestEvent{
				Action: github.String("opened"),
				Repo: &github.Repository{
					Owner:         &github.User{Login: github.String("owner")},
					Name:          github.String("repo"),
					DefaultBranch: github.String("main"),
				},
				PullRequest: &github.PullRequest{
					Number: github.Int(1),
					User:   &github.User{Login: github.String("author")},
					Head:   &github.PullRequestBranch{SHA: github.String("abc"), Ref: github.String("feat")},
				},
			}),
			sign:       true,
			wantStatus: http.StatusOK,
		},
		"missing signature returns 400": {
			eventType:  "push",
			payload:    []byte(`{}`),
			sign:       false,
			wantStatus: http.StatusBadRequest,
		},
		"wrong signature returns 400": {
			eventType:  "push",
			payload:    []byte(`{}`),
			sign:       true, // will be signed, but we tamper below
			wantStatus: http.StatusBadRequest,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var signSecret []byte
			if tc.sign {
				signSecret = secret
			}

			// For the "wrong signature" case, sign with a different secret.
			if name == "wrong signature returns 400" {
				signSecret = []byte("wrong-secret")
			}

			resp := postWebhook(t, srv.URL, tc.eventType, signSecret, tc.payload)
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
		})
	}
}

func TestHealthEndpoints(t *testing.T) {
	t.Parallel()
	cfg := Config{Event: newTestEventConfig()}
	srv := httptest.NewServer(NewHandler(cfg))
	t.Cleanup(srv.Close)

	for _, path := range []string{"/live", "/ready"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			resp, err := http.Get(srv.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("GET %s status = %d, want 200", path, resp.StatusCode)
			}
		})
	}
}

func TestMetricsEndpoint(t *testing.T) {
	t.Parallel()
	cfg := Config{Event: newTestEventConfig()}
	srv := httptest.NewServer(NewHandler(cfg))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /metrics status = %d, want 200", resp.StatusCode)
	}
}

func TestWebhookSync(t *testing.T) {
	t.Parallel()
	secret := []byte("sync-test")
	cfg := Config{
		Event:         newTestEventConfig(),
		WebhookSecret: secret,
		Sync:          true,
	}

	handler := NewHandler(cfg)
	payload := mustMarshal(t, &github.IssueCommentEvent{
		Action: github.String("created"),
		Repo: &github.Repository{
			Owner:         &github.User{Login: github.String("owner")},
			Name:          github.String("repo"),
			DefaultBranch: github.String("main"),
		},
		Issue:   &github.Issue{Number: github.Int(1), User: &github.User{Login: github.String("u")}},
		Comment: &github.IssueComment{Body: github.String("test"), User: &github.User{Login: github.String("c")}},
		Sender:  &github.User{Login: github.String("s")},
	})

	// Use httptest.NewRecorder for an in-process test (no TCP).
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "issue_comment")
	req.Header.Set("X-Hub-Signature-256", signPayload(secret, payload))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestUnknownRoute(t *testing.T) {
	t.Parallel()
	cfg := Config{Event: newTestEventConfig()}
	handler := NewHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}
