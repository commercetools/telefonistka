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
)

const githubPublicBaseURL = "https://github.com"

type promotionInstanceMetaData struct {
	SourcePath  string   `json:"sourcePath"`
	TargetPaths []string `json:"targetPaths"`
}

type Context struct {
	GhClientPair *GhClientPair `json:"-"`
	Approver     *GhClientPair `json:"-"`
	// This whole struct describe the metadata of the PR, so it makes sense to share the context with everything to generate HTTP calls related to that PR, right?
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
		repo, resp, err := p.GhClientPair.v3Client.Repositories.Get(ctx, p.Owner, p.Repo)
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
