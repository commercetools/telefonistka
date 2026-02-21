package githubapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"log/slog"
	"regexp"
	"text/template"

	"github.com/commercetools/telefonistka/argocd"
	"github.com/commercetools/telefonistka/configuration"
	"github.com/google/go-github/v62/github"
	"github.com/shurcooL/githubv4"
)

// ClientConfig holds pre-resolved credentials for one GitHub client pair.
type ClientConfig struct {
	AppID      int64  // 0 → use OAuthToken
	AppKeyPath string
	OAuthToken string
}

// GithubEndpoints holds resolved GitHub API base URLs.
// Zero value means public github.com.
type GithubEndpoints struct {
	RestURL    string // e.g. "https://ghes.example.com/api/v3"
	GraphqlURL string // e.g. "https://ghes.example.com/api/graphql"
}

// NewGithubEndpoints computes REST and GraphQL URLs from a hostname.
// Empty host means public github.com (zero-value endpoints).
func NewGithubEndpoints(host string) GithubEndpoints {
	if host == "" {
		return GithubEndpoints{}
	}
	return GithubEndpoints{
		RestURL:    "https://" + host + "/api/v3",
		GraphqlURL: "https://" + host + "/api/graphql",
	}
}

// EventConfig holds all externally-resolved configuration for event handling.
type EventConfig struct {
	Clients             *ClientProvider
	ArgoCD              *argocd.ArgoCDClients // nil when ArgoCD is not configured
	TemplatesFS         fs.FS
	CommitStatusURLTmpl *template.Template // nil → use default URL
	HandleSelfComment   bool
	WebhookSecret       []byte
	Sync                bool // run HandleEvent synchronously (for testing)
}

type repoService interface {
	GetContents(ctx context.Context, owner, repo, path string, opts *github.RepositoryContentGetOptions) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error)
CreateStatus(ctx context.Context, owner, repo, ref string, status *github.RepoStatus) (*github.RepoStatus, *github.Response, error)
	ListStatuses(ctx context.Context, owner, repo, ref string, opts *github.ListOptions) ([]*github.RepoStatus, *github.Response, error)
}

type pullRequestService interface {
	Create(ctx context.Context, owner, repo string, pull *github.NewPullRequest) (*github.PullRequest, *github.Response, error)
	Get(ctx context.Context, owner, repo string, number int) (*github.PullRequest, *github.Response, error)
	Merge(ctx context.Context, owner, repo string, number int, commitMessage string, options *github.PullRequestOptions) (*github.PullRequestMergeResult, *github.Response, error)
	ListFiles(ctx context.Context, owner, repo string, number int, opts *github.ListOptions) ([]*github.CommitFile, *github.Response, error)
	CreateReview(ctx context.Context, owner, repo string, number int, review *github.PullRequestReviewRequest) (*github.PullRequestReview, *github.Response, error)
}

type issueService interface {
	CreateComment(ctx context.Context, owner, repo string, number int, comment *github.IssueComment) (*github.IssueComment, *github.Response, error)
	AddLabelsToIssue(ctx context.Context, owner, repo string, number int, labels []string) ([]*github.Label, *github.Response, error)
	AddAssignees(ctx context.Context, owner, repo string, number int, assignees []string) (*github.Issue, *github.Response, error)
}

type gitService interface {
	GetRef(ctx context.Context, owner, repo, ref string) (*github.Reference, *github.Response, error)
	CreateTree(ctx context.Context, owner, repo, baseTree string, entries []*github.TreeEntry) (*github.Tree, *github.Response, error)
	GetCommit(ctx context.Context, owner, repo, sha string) (*github.Commit, *github.Response, error)
	CreateCommit(ctx context.Context, owner, repo string, commit *github.Commit, opts *github.CreateCommitOptions) (*github.Commit, *github.Response, error)
	CreateRef(ctx context.Context, owner, repo string, ref *github.Reference) (*github.Reference, *github.Response, error)
}

type graphQLClient interface {
	Query(ctx context.Context, q any, variables map[string]any) error
	Mutate(ctx context.Context, m any, input githubv4.Input, variables map[string]any) error
}

var prMetadataRegex = regexp.MustCompile(`<!--\|.*\|(.*)\|-->`)

type promotionInstanceMetaData struct {
	SourcePath  string   `json:"sourcePath"`
	TargetPaths []string `json:"targetPaths"`
}

// RepoRef identifies a GitHub repository.
type RepoRef struct {
	Owner         string
	Repo          string
	RepoURL       string
	DefaultBranch string
}

// PRRef identifies a pull request within a repository.
type PRRef struct {
	PrNumber int
	PrAuthor string
	PrSHA    string
	Ref      string
}

type Context struct {
	RepoRef
	PRRef

	Repositories repoService        `json:"-"`
	PullRequests pullRequestService `json:"-"`
	Issues       issueService       `json:"-"`
	Git          gitService         `json:"-"`
	GraphQL      graphQLClient      `json:"-"`
	ApproverPRs  pullRequestService `json:"-"`

	PrLogger   *slog.Logger             `json:"-"`
	Labels     []*github.Label
	PrMetadata prMetadata
	Config     *configuration.Config    `json:"-"`
}

func (c *Context) getPrMetadata(ctx context.Context, prBody string) {
	serializedPrMetadata := prMetadataRegex.FindStringSubmatch(prBody)
	if len(serializedPrMetadata) == 2 {
		if serializedPrMetadata[1] != "" {
			c.PrLogger.Info("Found PR metadata")
			err := c.PrMetadata.deserialize(serializedPrMetadata[1])
			if err != nil {
				c.PrLogger.Error("Failed to parse PR metadata", "err", err)
			}
		}
	}
}

func (c *Context) getBlameURLPrefix() string {
	return c.RepoURL + "/blame"
}

type prMetadata struct {
	OriginalPrAuthor          string                            `json:"originalPrAuthor"`
	OriginalPrNumber          int                               `json:"originalPrNumber"`
	PromotedPaths             []string                          `json:"promotedPaths"`
	PreviousPromotionMetadata map[int]promotionInstanceMetaData `json:"previousPromotionPaths"`
}

func (pm prMetadata) serialize() (string, error) {
	pmJson, err := json.Marshal(pm)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pmJson), nil
}

func (pm *prMetadata) deserialize(s string) error {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	err = json.Unmarshal(decoded, pm)
	return err
}

