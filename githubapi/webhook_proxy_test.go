package githubapi

// @Title
// @Description
// @Author
// @Update
import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	cfg "github.com/commercetools/telefonistka/configuration"
	"github.com/go-test/deep"
	"github.com/google/go-github/v62/github"
)

func TestGenerateListOfEndpoints(t *testing.T) {
	t.Parallel()
	config := &cfg.Config{
		WebhookEndpointRegexs: []cfg.WebhookEndpointRegex{
			{
				Expression: `^workspace\/[^/]*\/.*`,
				Replacements: []string{
					`https://blabla.com/webhook`,
				},
			},
			{
				Expression: `^clusters\/([^/]*)\/([^/]*)\/([^/]*)\/.*`,
				Replacements: []string{
					`https://ingress-a-${1}-${2}-${3}.example.com/webhook`,
					`https://ingress-b-${1}-${2}-${3}.example.com/webhook`,
				},
			},
		},
	}
	listOfFiles := []string{
		"workspace/csi-verify/values/global.yaml",
		"clusters/sdeprod/dsm1/c1/csi-verify/values/global.yaml",
	}

	endpoints := generateListOfEndpoints(listOfFiles, config)
	expectedEndpoints := []string{
		"https://blabla.com/webhook",
		"https://ingress-a-sdeprod-dsm1-c1.example.com/webhook",
		"https://ingress-b-sdeprod-dsm1-c1.example.com/webhook",
	}

	slices.Sort(endpoints)
	slices.Sort(expectedEndpoints)
	if diff := deep.Equal(endpoints, expectedEndpoints); diff != nil {
		t.Error(diff)
	}
}

func TestGenerateListOfChangedFiles(t *testing.T) {
	t.Parallel()
	eventPayload := &github.PushEvent{
		Commits: []*github.HeadCommit{
			{
				Added: []string{
					"workspace/csi-verify/values/global-new.yaml",
				},
				Removed: []string{
					"workspace/csi-verify/values/global-old.yaml",
				},
				SHA: github.String("000001"),
			},
			{
				Modified: []string{
					"clusters/sdeprod/dsm1/c1/csi-verify/values/global.yaml",
				},
				SHA: github.String("000002"),
			},
		},
	}

	listOfFiles := generateListOfChangedFiles(eventPayload)
	expectedListOfFiles := []string{
		"workspace/csi-verify/values/global-new.yaml",
		"workspace/csi-verify/values/global-old.yaml",
		"clusters/sdeprod/dsm1/c1/csi-verify/values/global.yaml",
	}

	slices.Sort(listOfFiles)
	slices.Sort(expectedListOfFiles)

	if diff := deep.Equal(listOfFiles, expectedListOfFiles); diff != nil {
		t.Error(diff)
	}
}

func TestProxyRequestForwardsHeaders(t *testing.T) {
	t.Parallel()

	var gotMethod string
	var gotBody []byte
	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotHeaders = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	headers := http.Header{
		"X-Hub-Signature-256": []string{"sha256=abc123"},
		"X-Github-Event":      []string{"push"},
		"Content-Type":        []string{"application/json"},
	}
	payload := []byte(`{"ref":"refs/heads/main"}`)

	proxyRequest(t.Context(), false, headers, payload, srv.URL)

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want %q", gotMethod, http.MethodPost)
	}
	if got := gotHeaders.Get("X-Hub-Signature-256"); got != "sha256=abc123" {
		t.Errorf("signature header = %q, want %q", got, "sha256=abc123")
	}
	if got := gotHeaders.Get("X-Github-Event"); got != "push" {
		t.Errorf("event header = %q, want %q", got, "push")
	}
	if got := string(gotBody); got != string(payload) {
		t.Errorf("body = %q, want %q", got, string(payload))
	}
}

func TestProxyRequestDoesNotMutateOriginalHeaders(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mutate the received request header — should not affect original.
		r.Header.Set("X-Injected", "bad")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	original := http.Header{
		"X-Hub-Signature-256": []string{"sha256=test"},
	}

	proxyRequest(t.Context(), false, original, []byte(`{}`), srv.URL)

	if original.Get("X-Injected") != "" {
		t.Error("original headers were mutated by proxy")
	}
}

func TestProxyRequestNilHeaders(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// nil headers should not panic — this is the CLI path.
	proxyRequest(t.Context(), false, nil, []byte(`{}`), srv.URL)
}
