package githubapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/commercetools/telefonistka/configuration"
	prom "github.com/commercetools/telefonistka/prometheus"
	"github.com/google/go-github/v62/github"
	"github.com/shurcooL/githubv4"
)

type repoService interface {
	GetContents(ctx context.Context, owner, repo, path string, opts *github.RepositoryContentGetOptions) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error)
	Get(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error)
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

const githubPublicBaseURL = "https://github.com"

type promotionInstanceMetaData struct {
	SourcePath  string   `json:"sourcePath"`
	TargetPaths []string `json:"targetPaths"`
}

type Context struct {
	Repositories repoService        `json:"-"`
	PullRequests pullRequestService `json:"-"`
	Issues       issueService       `json:"-"`
	Git          gitService         `json:"-"`
	GraphQL      graphQLClient      `json:"-"`
	ApproverPRs  pullRequestService `json:"-"`

	DefaultBranch string
	Owner         string
	Repo          string
	PrAuthor      string
	PrNumber      int
	PrSHA         string
	Ref           string
	RepoURL       string
	PrLogger      *slog.Logger `json:"-"`
	Labels        []*github.Label
	PrMetadata    prMetadata
	Config        *configuration.Config
}

func (c *Context) getPrMetadata(ctx context.Context, prBody string) {
	prMetadataRegex := regexp.MustCompile(`<!--\|.*\|(.*)\|-->`)
	serializedPrMetadata := prMetadataRegex.FindStringSubmatch(prBody)
	if len(serializedPrMetadata) == 2 {
		if serializedPrMetadata[1] != "" {
			c.PrLogger.Info("Found PR metadata")
			err := c.PrMetadata.DeSerialize(serializedPrMetadata[1])
			if err != nil {
				c.PrLogger.Error("Fail to parser PR metadata", "err", err)
			}
		}
	}
}

func (c *Context) getBlameURLPrefix(ctx context.Context) string {
	githubHost := getEnv("GITHUB_HOST", "")
	if githubHost == "" {
		githubHost = githubPublicBaseURL
	}
	return fmt.Sprintf("%s/%s/%s/blame", githubHost, c.Owner, c.Repo)
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

func (pm *prMetadata) DeSerialize(s string) error {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	err = json.Unmarshal(decoded, pm)
	return err
}

func (p *Context) GetDefaultBranch(ctx context.Context) (string, error) {
	if p.DefaultBranch == "" {
		repo, resp, err := p.Repositories.Get(ctx, p.Owner, p.Repo)
		if err != nil {
			p.PrLogger.Error("Could not get repo default branch", "err", err, "resp", resp)
			return "", err
		}
		prom.InstrumentGhCall(resp)
		p.DefaultBranch = repo.GetDefaultBranch()
		return repo.GetDefaultBranch(), err
	} else {
		return p.DefaultBranch, nil
	}
}
