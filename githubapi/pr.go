package githubapi

import (
	"context"
	"strings"

	"github.com/cenkalti/backoff/v4"
	prom "github.com/commercetools/telefonistka/prometheus"
	"github.com/google/go-github/v62/github"
)

func createPrObject(ctx context.Context, c Context, newBranchRef string, newPrTitle string, newPrBody string, defaultBranch string, assignee string) (*github.PullRequest, error) {
	newPrConfig := &github.NewPullRequest{
		Body:  github.String(newPrBody),
		Title: github.String(newPrTitle),
		Base:  github.String(defaultBranch),
		Head:  github.String(newBranchRef),
	}

	pull, resp, err := c.PullRequests.Create(ctx, c.Owner, c.Repo, newPrConfig)
	prom.InstrumentGhCall(resp)
	if err != nil {
		c.PrLogger.Error("Could not create GitHub PR", "err", err, "resp", resp)
		return nil, err
	}
	c.PrLogger.Info("PR opened")

	prLables, resp, err := c.Issues.AddLabelsToIssue(ctx, c.Owner, c.Repo, *pull.Number, []string{"promotion"})
	prom.InstrumentGhCall(resp)
	if err != nil {
		c.PrLogger.Error("Could not label GitHub PR", "err", err, "resp", resp)
		return pull, err
	}
	c.PrLogger.Debug("PR labeled", "labels", prLables)

	_, resp, err = c.Issues.AddAssignees(ctx, c.Owner, c.Repo, *pull.Number, []string{assignee})
	prom.InstrumentGhCall(resp)
	if err != nil {
		c.PrLogger.Warn("Could not set assignee on PR", "user", assignee, "err", err)
	} else {
		c.PrLogger.Debug("User was set as assignee on PR", "user", assignee)
	}

	return pull, nil
}

func mergePr(ctx context.Context, c Context) error {
	operation := func() error {
		_, resp, err := c.PullRequests.Merge(ctx, c.Owner, c.Repo, c.PrNumber, "Auto-merge", nil)
		prom.InstrumentGhCall(resp)
		if err != nil {
			if isMergeErrorRetryable(err.Error()) {
				c.PrLogger.Warn("Failed to merge PR: transient error", "err", err)
				return err
			}
			c.PrLogger.Error("Failed to merge PR", "err", err)
			return backoff.Permanent(err)
		}
		return nil
	}

	// Using default values, see https://pkg.go.dev/github.com/cenkalti/backoff#pkg-constants
	err := backoff.Retry(operation, backoff.NewExponentialBackOff())
	if err != nil {
		c.PrLogger.Error("Failed to merge PR: backoff failed", "err", err)
	}

	return err
}

func isMergeErrorRetryable(errMessage string) bool {
	return strings.Contains(errMessage, "405") && strings.Contains(errMessage, "try the merge again")
}

func approvePr(ctx context.Context, c Context) error {
	if !c.Config.AutoApprovePromotionPrs {
		return nil
	}

	reviewRequest := &github.PullRequestReviewRequest{
		Event: github.String("APPROVE"),
	}

	_, resp, err := c.ApproverPRs.CreateReview(ctx, c.Owner, c.Repo, c.PrNumber, reviewRequest)
	prom.InstrumentGhCall(resp)
	if err != nil {
		c.PrLogger.Error("Could not create review", "err", err, "resp", resp)
		return err
	}

	return nil
}

func (p Context) commentOnPr(ctx context.Context, commentBody string) error {
	commentBody = "<!-- telefonistka_tag -->\n" + commentBody

	comment := &github.IssueComment{Body: &commentBody}
	_, resp, err := p.Issues.CreateComment(ctx, p.Owner, p.Repo, p.PrNumber, comment)
	prom.InstrumentGhCall(resp)
	if err != nil {
		p.PrLogger.Error("Could not comment in PR", "err", err, "resp", resp)
	}
	return err
}

func commentPlanInPR(ctx context.Context, c Context, promotions map[string]promotionInstance) {
	templateOutput, err := executeTemplate("dryRunMsg", "dry-run-pr-comment.gotmpl", promotions)
	if err != nil {
		c.PrLogger.Error("Failed to generate dry-run comment template", "err", err)
		return
	}
	c.commentOnPr(ctx, templateOutput)
}
