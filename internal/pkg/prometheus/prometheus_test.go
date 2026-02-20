package prometheus

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/go-test/deep"
	"github.com/google/go-github/v62/github"
	"github.com/prometheus/client_golang/prometheus"
)

func TestUserGetUrl(t *testing.T) {
	t.Parallel()
	expectedLabels := prometheus.Labels{
		"api_group": "user",
		"api_path":  "",
		"repo_slug": "",
		"status":    "404",
		"method":    "GET",
	}
	instrumentGhCallTestHelper(t, "/api/v3/user", expectedLabels)
}

func TestRepoGetUrl(t *testing.T) {
	t.Parallel()
	expectedLabels := prometheus.Labels{
		"api_group": "repos",
		"api_path":  "",
		"repo_slug": "shared/k8s-helmfile",
		"status":    "404",
		"method":    "GET",
	}
	instrumentGhCallTestHelper(t, "/api/v3/repos/shared/k8s-helmfile", expectedLabels)
}

func TestContentUrl(t *testing.T) {
	t.Parallel()
	expectedLabels := prometheus.Labels{
		"api_group": "repos",
		"api_path":  "contents",
		"repo_slug": "shared/k8s-helmfile",
		"status":    "404",
		"method":    "GET",
	}
	instrumentGhCallTestHelper(t, "/api/v3/repos/shared/k8s-helmfile/contents/workspace/telefonistka/telefonistka.yaml", expectedLabels)
}

func TestPullUrl(t *testing.T) {
	t.Parallel()
	expectedLabels := prometheus.Labels{
		"api_group": "repos",
		"api_path":  "pulls",
		"repo_slug": "AnOwner/Arepo",
		"status":    "404",
		"method":    "GET",
	}
	instrumentGhCallTestHelper(t, "/repos/AnOwner/Arepo/pulls/33", expectedLabels)
}

func TestShortUrl(t *testing.T) {
	t.Parallel()
	expectedLabels := prometheus.Labels{
		"api_group": "repos",
		"api_path":  "contents",
		"repo_slug": "AnOwner/Arepo",
		"status":    "404",
		"method":    "GET",
	}
	instrumentGhCallTestHelper(t, "/repos/AnOwner/Arepo/contents/telefonistka.yaml", expectedLabels)
}

func TestApiUrl(t *testing.T) {
	t.Parallel()
	expectedLabels := prometheus.Labels{
		"api_group": "repos",
		"api_path":  "contents",
		"repo_slug": "AnOwner/Arepo",
		"status":    "404",
		"method":    "GET",
	}
	instrumentGhCallTestHelper(t, "/api/v3/repos/AnOwner/Arepo/contents/telefonistka.yaml", expectedLabels)
}

func TestInstrumentProxyUpstreamRequestLables(t *testing.T) {
	t.Parallel()

	mockURL, _ := url.Parse("https://argocd.example.com/webhook")

	httpReq := &http.Request{
		URL:    mockURL,
		Method: "POST",
	}

	httpResp := &http.Response{
		Request:    httpReq,
		StatusCode: 200,
	}

	expectedLabels := prometheus.Labels{
		"status": "200",
		"method": "POST",
		"url":    "https://argocd.example.com/webhook",
	}
	labels := InstrumentProxyUpstreamRequest(httpResp)
	if diff := deep.Equal(expectedLabels, labels); diff != nil {
		t.Error(diff)
	}
}

func TestInstrumentGhCallNilResponse(t *testing.T) {
	t.Parallel()
	got := InstrumentGhCall(nil)
	if len(got) != 0 {
		t.Errorf("InstrumentGhCall(nil) = %v, want empty labels", got)
	}
}

func TestInstrumentProxyUpstreamRequestNilResponse(t *testing.T) {
	t.Parallel()
	got := InstrumentProxyUpstreamRequest(nil)
	if len(got) != 0 {
		t.Errorf("InstrumentProxyUpstreamRequest(nil) = %v, want empty labels", got)
	}
}

func TestIncCommitStatusUpdateCounter(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("IncCommitStatusUpdateCounter panicked: %v", r)
		}
	}()
	IncCommitStatusUpdateCounter("owner/repo", "success")
}

func TestInstrumentWebhookHit(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("InstrumentWebhookHit panicked: %v", r)
		}
	}()
	InstrumentWebhookHit("success")
}

func TestPublishPrMetrics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PublishPrMetrics panicked: %v", r)
		}
	}()
	PublishPrMetrics(PrCounters{OpenPrs: 5, OpenPromotionPrs: 2, PrWithStaleChecks: 1}, "owner/repo")
}

func instrumentGhCallTestHelper(t *testing.T, httpURL string, expectedLabels prometheus.Labels) {
	t.Helper()
	mockURL, _ := url.Parse("https://github.com/api/v3/content/foo/bar/file.txt")

	httpReq := &http.Request{
		URL:    mockURL,
		Method: "GET",
	}

	httpResp := &http.Response{
		Request:    httpReq,
		StatusCode: 404,
	}

	resp := &github.Response{
		Response: httpResp,
	}
	resp.Request.URL.Path = httpURL
	labels := InstrumentGhCall(resp)

	if diff := deep.Equal(expectedLabels, labels); diff != nil {
		t.Error(diff)
	}
}
