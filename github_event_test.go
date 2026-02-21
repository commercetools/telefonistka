package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/commercetools/telefonistka/githubapi"
	"github.com/commercetools/telefonistka/templates"
	"github.com/google/go-github/v62/github"
)

func checkGithubTokenDeleteRepoScope(t *testing.T) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com", http.NoBody)
	checkErr(t, err)
	req.Header.Set("Authorization", "token "+os.Getenv("GITHUB_TOKEN"))
	res, err := http.DefaultTransport.RoundTrip(req)
	checkErr(t, err)
	res.Body.Close()
	if !strings.Contains(res.Header.Get("x-oauth-scopes"), "delete_repo") {
		t.Fatal("Set delete_repo scope on your GITHUB_TOKEN to automatically clean up using `gh auth refresh --scopes delete_repo`")
	}
}

func newEventConfig(t *testing.T) githubapi.EventConfig {
	t.Helper()
	token := os.Getenv("GITHUB_TOKEN")
	clients := githubapi.NewClientProvider(1,
		githubapi.ClientConfig{OAuthToken: token},
		githubapi.ClientConfig{OAuthToken: token},
		githubapi.GithubEndpoints{},
	)
	return githubapi.EventConfig{
		Clients:           clients,
		TemplatesFS:       templates.FS,
		HandleSelfComment: true,
	}
}

func marshalPREvent(t *testing.T, repo *github.Repository, pr *github.PullRequest, action string) []byte {
	t.Helper()
	event := github.PullRequestEvent{
		Action: github.String(action),
		Repo: &github.Repository{
			Owner:         &github.User{Login: github.String(repo.GetOwner().GetLogin())},
			Name:          github.String(repo.GetName()),
			HTMLURL:       github.String(repo.GetHTMLURL()),
			DefaultBranch: github.String("main"),
		},
		PullRequest: pr,
	}
	payload, err := json.Marshal(event)
	checkErr(t, err)
	return payload
}

func TestPromotionPRCreated(t *testing.T) {
	t.Parallel()
	if os.Getenv("GITHUB_TOKEN") == "" {
		t.Skip("GITHUB_TOKEN not set")
	}
	checkGithubTokenDeleteRepoScope(t)
	slog.SetDefault(newTestLogger(t))

	gh := newGithubClient(t)
	repo := createRepository(t, gh)

	// Push initial state to main.
	initial := createCommit(t, gh, repo, "heads/main", "Initial state",
		os.DirFS(path.Join("testdata", t.Name(), "start")))
	updateRef(t, gh, repo, "heads/main", initial.GetSHA())

	// Create branch and push the PR change.
	createBranch(t, gh, repo, initial, "upgrade")
	prCommit := createCommit(t, gh, repo, "heads/upgrade", "Upgrade demo",
		os.DirFS(path.Join("testdata", t.Name(), "pr")))

	// Create and merge the PR.
	pr := createPR(t, gh, repo, &TestPR{
		Title: "Upgrade demo",
		Ref:   "upgrade",
		Base:  "main",
		Body:  "Upgrading to v1.1.0",
	})
	_, _, err := gh.PullRequests.Merge(t.Context(),
		repo.GetOwner().GetLogin(), repo.GetName(),
		pr.GetNumber(), "Merge upgrade", nil)
	checkErr(t, err)

	// Build the webhook payload with the merged PR details.
	mergedPR := &github.PullRequest{
		Number: pr.Number,
		User:   pr.User,
		Head: &github.PullRequestBranch{
			SHA: github.String(prCommit.GetSHA()),
			Ref: github.String("upgrade"),
		},
		Merged: github.Bool(true),
	}
	payload := marshalPREvent(t, repo, mergedPR, "closed")

	cfg := newEventConfig(t)
	githubapi.HandleEvent(t.Context(), cfg, "pull_request", nil, payload)

	// Assert: a promotion PR was created.
	prs, _, err := gh.PullRequests.List(t.Context(),
		repo.GetOwner().GetLogin(), repo.GetName(),
		&github.PullRequestListOptions{State: "open"})
	checkErr(t, err)

	var found bool
	for _, p := range prs {
		if strings.Contains(p.GetTitle(), "Promotion") {
			found = true
			t.Logf("Found promotion PR: %s", p.GetHTMLURL())
			break
		}
	}
	if !found {
		t.Error("expected a promotion PR to be created")
	}

	// Assert: commit status set to success.
	statuses, _, err := gh.Repositories.ListStatuses(t.Context(),
		repo.GetOwner().GetLogin(), repo.GetName(),
		prCommit.GetSHA(), nil)
	checkErr(t, err)

	var statusOK bool
	for _, s := range statuses {
		if s.GetContext() == "telefonistka" && s.GetState() == "success" {
			statusOK = true
			break
		}
	}
	if !statusOK {
		t.Error("expected telefonistka commit status to be success")
	}
}

func TestChangedPRDriftDetection(t *testing.T) {
	t.Parallel()
	if os.Getenv("GITHUB_TOKEN") == "" {
		t.Skip("GITHUB_TOKEN not set")
	}
	checkGithubTokenDeleteRepoScope(t)
	slog.SetDefault(newTestLogger(t))

	gh := newGithubClient(t)
	repo := createRepository(t, gh)

	// Push initial state with drift (workspace != live).
	initial := createCommit(t, gh, repo, "heads/main", "Initial state with drift",
		os.DirFS(path.Join("testdata", t.Name(), "start")))
	updateRef(t, gh, repo, "heads/main", initial.GetSHA())

	// Create branch and push a change to workspace.
	createBranch(t, gh, repo, initial, "feature")
	prCommit := createCommit(t, gh, repo, "heads/feature", "Update workspace",
		os.DirFS(path.Join("testdata", t.Name(), "pr")))

	// Create PR (do not merge).
	pr := createPR(t, gh, repo, &TestPR{
		Title: "Feature update",
		Ref:   "feature",
		Base:  "main",
		Body:  "Updating workspace values",
	})

	// Build the webhook payload for an opened PR event.
	openedPR := &github.PullRequest{
		Number: pr.Number,
		User:   pr.User,
		Head: &github.PullRequestBranch{
			SHA: github.String(prCommit.GetSHA()),
			Ref: github.String("feature"),
		},
	}
	payload := marshalPREvent(t, repo, openedPR, "opened")

	cfg := newEventConfig(t)
	githubapi.HandleEvent(t.Context(), cfg, "pull_request", nil, payload)

	// Assert: commit status set to success.
	statuses, _, err := gh.Repositories.ListStatuses(t.Context(),
		repo.GetOwner().GetLogin(), repo.GetName(),
		prCommit.GetSHA(), nil)
	checkErr(t, err)

	var statusOK bool
	for _, s := range statuses {
		if s.GetContext() == "telefonistka" && s.GetState() == "success" {
			statusOK = true
			break
		}
	}
	if !statusOK {
		t.Error("expected telefonistka commit status to be success")
	}

	// Assert: drift comment exists on the PR.
	comments, _, err := gh.Issues.ListComments(t.Context(),
		repo.GetOwner().GetLogin(), repo.GetName(),
		pr.GetNumber(), nil)
	checkErr(t, err)

	var driftCommented bool
	for _, c := range comments {
		if strings.Contains(c.GetBody(), "workspace/demo") && strings.Contains(c.GetBody(), "live/demo") {
			driftCommented = true
			break
		}
	}
	if !driftCommented {
		t.Error("expected a drift detection comment on the PR")
	}
}

func TestChangedPRArgoCDDiff(t *testing.T) {
	t.Parallel()
	if os.Getenv("GITHUB_TOKEN") == "" {
		t.Skip("GITHUB_TOKEN not set")
	}
	checkGithubTokenDeleteRepoScope(t)
	slog.SetDefault(newTestLogger(t))

	gh := newGithubClient(t)
	repo := createRepository(t, gh)

	// Push initial state with drift and ArgoCD diff enabled.
	initial := createCommit(t, gh, repo, "heads/main", "Initial state with drift",
		os.DirFS(path.Join("testdata", t.Name(), "start")))
	updateRef(t, gh, repo, "heads/main", initial.GetSHA())

	// Create branch and push a change to workspace.
	createBranch(t, gh, repo, initial, "feature")
	prCommit := createCommit(t, gh, repo, "heads/feature", "Update workspace",
		os.DirFS(path.Join("testdata", t.Name(), "pr")))

	// Create PR (do not merge).
	pr := createPR(t, gh, repo, &TestPR{
		Title: "Feature update",
		Ref:   "feature",
		Base:  "main",
		Body:  "Updating workspace values",
	})

	// Start fake ArgoCD gRPC server and add an app matching the component path.
	fake, argoClients := startFakeArgoCD(t)
	fake.App.addApp(newTestApp("demo-app", repo.GetHTMLURL(), "workspace/demo"))

	// Build the webhook payload for an opened PR event.
	openedPR := &github.PullRequest{
		Number: pr.Number,
		User:   pr.User,
		Head: &github.PullRequestBranch{
			SHA: github.String(prCommit.GetSHA()),
			Ref: github.String("feature"),
		},
	}
	payload := marshalPREvent(t, repo, openedPR, "opened")

	cfg := newEventConfig(t)
	cfg.ArgoCD = argoClients
	githubapi.HandleEvent(t.Context(), cfg, "pull_request", nil, payload)

	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()

	// Assert: commit status set to success.
	statuses, _, err := gh.Repositories.ListStatuses(t.Context(), owner, name, prCommit.GetSHA(), nil)
	checkErr(t, err)

	var statusOK bool
	for _, s := range statuses {
		if s.GetContext() == "telefonistka" && s.GetState() == "success" {
			statusOK = true
			break
		}
	}
	if !statusOK {
		t.Error("expected telefonistka commit status to be success")
	}

	// Assert: drift comment exists on the PR.
	comments, _, err := gh.Issues.ListComments(t.Context(), owner, name, pr.GetNumber(), nil)
	checkErr(t, err)

	var driftCommented, argoDiffCommented bool
	for _, c := range comments {
		body := c.GetBody()
		if strings.Contains(body, "workspace/demo") && strings.Contains(body, "live/demo") {
			driftCommented = true
		}
		if strings.Contains(body, "Diff of ArgoCD applications") {
			argoDiffCommented = true
		}
	}
	if !driftCommented {
		t.Error("expected a drift detection comment on the PR")
	}
	if !argoDiffCommented {
		t.Error("expected an ArgoCD diff comment on the PR")
	}

	// Assert: PR labeled "noop" (empty diff).
	prDetail, _, err := gh.PullRequests.Get(t.Context(), owner, name, pr.GetNumber())
	checkErr(t, err)

	var hasNoop bool
	for _, l := range prDetail.Labels {
		if l.GetName() == "noop" {
			hasNoop = true
			break
		}
	}
	if !hasNoop {
		t.Error("expected PR to have 'noop' label from empty ArgoCD diff")
	}
}

func TestMergedPRArgoCDRevisionSync(t *testing.T) {
	t.Parallel()
	if os.Getenv("GITHUB_TOKEN") == "" {
		t.Skip("GITHUB_TOKEN not set")
	}
	checkGithubTokenDeleteRepoScope(t)
	slog.SetDefault(newTestLogger(t))

	gh := newGithubClient(t)
	repo := createRepository(t, gh)

	// Push initial state to main (in sync).
	initial := createCommit(t, gh, repo, "heads/main", "Initial state",
		os.DirFS(path.Join("testdata", t.Name(), "start")))
	updateRef(t, gh, repo, "heads/main", initial.GetSHA())

	// Create branch and push the PR change.
	createBranch(t, gh, repo, initial, "upgrade")
	prCommit := createCommit(t, gh, repo, "heads/upgrade", "Upgrade demo",
		os.DirFS(path.Join("testdata", t.Name(), "pr")))

	// Create and merge the PR.
	pr := createPR(t, gh, repo, &TestPR{
		Title: "Upgrade demo",
		Ref:   "upgrade",
		Base:  "main",
		Body:  "Upgrading to v1.1.0",
	})
	_, _, err := gh.PullRequests.Merge(t.Context(),
		repo.GetOwner().GetLogin(), repo.GetName(),
		pr.GetNumber(), "Merge upgrade", nil)
	checkErr(t, err)

	// Start fake ArgoCD gRPC server.
	// Set TargetRevision to a non-HEAD value so the patch actually fires.
	fake, argoClients := startFakeArgoCD(t)
	app := newTestApp("demo-app", repo.GetHTMLURL(), "workspace/demo")
	app.Spec.Source.TargetRevision = "upgrade"
	fake.App.addApp(app)

	// Build the webhook payload with the merged PR details.
	mergedPR := &github.PullRequest{
		Number: pr.Number,
		User:   pr.User,
		Head: &github.PullRequestBranch{
			SHA: github.String(prCommit.GetSHA()),
			Ref: github.String("upgrade"),
		},
		Merged: github.Bool(true),
	}
	payload := marshalPREvent(t, repo, mergedPR, "closed")

	cfg := newEventConfig(t)
	cfg.ArgoCD = argoClients
	githubapi.HandleEvent(t.Context(), cfg, "pull_request", nil, payload)

	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()

	// Assert: a promotion PR was created.
	prs, _, err := gh.PullRequests.List(t.Context(), owner, name,
		&github.PullRequestListOptions{State: "open"})
	checkErr(t, err)

	var found bool
	for _, p := range prs {
		if strings.Contains(p.GetTitle(), "Promotion") {
			found = true
			t.Logf("Found promotion PR: %s", p.GetHTMLURL())
			break
		}
	}
	if !found {
		t.Error("expected a promotion PR to be created")
	}

	// Assert: commit status set to success.
	statuses, _, err := gh.Repositories.ListStatuses(t.Context(), owner, name, prCommit.GetSHA(), nil)
	checkErr(t, err)

	var statusOK bool
	for _, s := range statuses {
		if s.GetContext() == "telefonistka" && s.GetState() == "success" {
			statusOK = true
			break
		}
	}
	if !statusOK {
		t.Error("expected telefonistka commit status to be success")
	}

	// Assert: fake ArgoCD received a Patch call to set targetRevision to HEAD.
	patches := fake.App.Patches()
	if len(patches) == 0 {
		t.Fatal("expected ArgoCD App.Patch to be called for revision sync")
	}
	var patchedToHEAD bool
	for _, p := range patches {
		if strings.Contains(p.GetPatch(), `"HEAD"`) {
			patchedToHEAD = true
			break
		}
	}
	if !patchedToHEAD {
		t.Errorf("expected ArgoCD app targetRevision to be patched to HEAD, got patches: %v", patches)
	}
}
