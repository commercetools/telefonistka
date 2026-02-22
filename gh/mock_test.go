package gh

import (
	"context"
	"net/http"
	"net/url"

	"github.com/google/go-github/v62/github"
	"github.com/shurcooL/githubv4"
)

// ghResp returns a *github.Response suitable for prom.InstrumentGhCall.
func ghResp(statusCode int) *github.Response {
	return &github.Response{
		Response: &http.Response{
			StatusCode: statusCode,
			Request:    &http.Request{URL: &url.URL{Path: "/repos/owner/repo/contents/path"}},
		},
	}
}

// mockRepoService implements repoService for testing.
type mockRepoService struct {
	getContentsFn  func(ctx context.Context, owner, repo, path string, opts *github.RepositoryContentGetOptions) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error)
createStatusFn func(ctx context.Context, owner, repo, ref string, status *github.RepoStatus) (*github.RepoStatus, *github.Response, error)
	listStatusesFn func(ctx context.Context, owner, repo, ref string, opts *github.ListOptions) ([]*github.RepoStatus, *github.Response, error)
}

func (m *mockRepoService) GetContents(ctx context.Context, owner, repo, path string, opts *github.RepositoryContentGetOptions) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error) {
	return m.getContentsFn(ctx, owner, repo, path, opts)
}

func (m *mockRepoService) CreateStatus(ctx context.Context, owner, repo, ref string, status *github.RepoStatus) (*github.RepoStatus, *github.Response, error) {
	return m.createStatusFn(ctx, owner, repo, ref, status)
}

func (m *mockRepoService) ListStatuses(ctx context.Context, owner, repo, ref string, opts *github.ListOptions) ([]*github.RepoStatus, *github.Response, error) {
	return m.listStatusesFn(ctx, owner, repo, ref, opts)
}

// mockPullRequestService implements pullRequestService for testing.
type mockPullRequestService struct {
	createFn       func(ctx context.Context, owner, repo string, pull *github.NewPullRequest) (*github.PullRequest, *github.Response, error)
	getFn          func(ctx context.Context, owner, repo string, number int) (*github.PullRequest, *github.Response, error)
	mergeFn        func(ctx context.Context, owner, repo string, number int, commitMessage string, options *github.PullRequestOptions) (*github.PullRequestMergeResult, *github.Response, error)
	listFilesFn    func(ctx context.Context, owner, repo string, number int, opts *github.ListOptions) ([]*github.CommitFile, *github.Response, error)
	createReviewFn func(ctx context.Context, owner, repo string, number int, review *github.PullRequestReviewRequest) (*github.PullRequestReview, *github.Response, error)
}

func (m *mockPullRequestService) Create(ctx context.Context, owner, repo string, pull *github.NewPullRequest) (*github.PullRequest, *github.Response, error) {
	return m.createFn(ctx, owner, repo, pull)
}

func (m *mockPullRequestService) Get(ctx context.Context, owner, repo string, number int) (*github.PullRequest, *github.Response, error) {
	return m.getFn(ctx, owner, repo, number)
}

func (m *mockPullRequestService) Merge(ctx context.Context, owner, repo string, number int, commitMessage string, options *github.PullRequestOptions) (*github.PullRequestMergeResult, *github.Response, error) {
	return m.mergeFn(ctx, owner, repo, number, commitMessage, options)
}

func (m *mockPullRequestService) ListFiles(ctx context.Context, owner, repo string, number int, opts *github.ListOptions) ([]*github.CommitFile, *github.Response, error) {
	return m.listFilesFn(ctx, owner, repo, number, opts)
}

func (m *mockPullRequestService) CreateReview(ctx context.Context, owner, repo string, number int, review *github.PullRequestReviewRequest) (*github.PullRequestReview, *github.Response, error) {
	return m.createReviewFn(ctx, owner, repo, number, review)
}

// mockIssueService implements issueService for testing.
type mockIssueService struct {
	createCommentFn func(ctx context.Context, owner, repo string, number int, comment *github.IssueComment) (*github.IssueComment, *github.Response, error)
	addLabelsFn     func(ctx context.Context, owner, repo string, number int, labels []string) ([]*github.Label, *github.Response, error)
	addAssigneesFn  func(ctx context.Context, owner, repo string, number int, assignees []string) (*github.Issue, *github.Response, error)
}

func (m *mockIssueService) CreateComment(ctx context.Context, owner, repo string, number int, comment *github.IssueComment) (*github.IssueComment, *github.Response, error) {
	return m.createCommentFn(ctx, owner, repo, number, comment)
}

func (m *mockIssueService) AddLabelsToIssue(ctx context.Context, owner, repo string, number int, labels []string) ([]*github.Label, *github.Response, error) {
	return m.addLabelsFn(ctx, owner, repo, number, labels)
}

func (m *mockIssueService) AddAssignees(ctx context.Context, owner, repo string, number int, assignees []string) (*github.Issue, *github.Response, error) {
	return m.addAssigneesFn(ctx, owner, repo, number, assignees)
}

// mockGitService implements gitService for testing.
type mockGitService struct {
	getRefFn       func(ctx context.Context, owner, repo, ref string) (*github.Reference, *github.Response, error)
	createTreeFn   func(ctx context.Context, owner, repo, baseTree string, entries []*github.TreeEntry) (*github.Tree, *github.Response, error)
	getCommitFn    func(ctx context.Context, owner, repo, sha string) (*github.Commit, *github.Response, error)
	createCommitFn func(ctx context.Context, owner, repo string, commit *github.Commit, opts *github.CreateCommitOptions) (*github.Commit, *github.Response, error)
	createRefFn    func(ctx context.Context, owner, repo string, ref *github.Reference) (*github.Reference, *github.Response, error)
}

func (m *mockGitService) GetRef(ctx context.Context, owner, repo, ref string) (*github.Reference, *github.Response, error) {
	return m.getRefFn(ctx, owner, repo, ref)
}

func (m *mockGitService) CreateTree(ctx context.Context, owner, repo, baseTree string, entries []*github.TreeEntry) (*github.Tree, *github.Response, error) {
	return m.createTreeFn(ctx, owner, repo, baseTree, entries)
}

func (m *mockGitService) GetCommit(ctx context.Context, owner, repo, sha string) (*github.Commit, *github.Response, error) {
	return m.getCommitFn(ctx, owner, repo, sha)
}

func (m *mockGitService) CreateCommit(ctx context.Context, owner, repo string, commit *github.Commit, opts *github.CreateCommitOptions) (*github.Commit, *github.Response, error) {
	return m.createCommitFn(ctx, owner, repo, commit, opts)
}

func (m *mockGitService) CreateRef(ctx context.Context, owner, repo string, ref *github.Reference) (*github.Reference, *github.Response, error) {
	return m.createRefFn(ctx, owner, repo, ref)
}

// mockGraphQLClient implements graphQLClient for testing.
type mockGraphQLClient struct {
	queryFn  func(ctx context.Context, q any, variables map[string]any) error
	mutateFn func(ctx context.Context, m any, input githubv4.Input, variables map[string]any) error
}

func (m *mockGraphQLClient) Query(ctx context.Context, q any, variables map[string]any) error {
	return m.queryFn(ctx, q, variables)
}

func (m *mockGraphQLClient) Mutate(ctx context.Context, mutation any, input githubv4.Input, variables map[string]any) error {
	return m.mutateFn(ctx, mutation, input, variables)
}

