package githubapi

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/commercetools/telefonistka/argocd"
	prom "github.com/commercetools/telefonistka/prometheus"
	"github.com/google/go-github/v62/github"
)

// ReceiveWebhook validates the webhook payload and spawns a goroutine to handle the event.
func ReceiveWebhook(r *http.Request, cfg EventConfig) error {
	payload, err := github.ValidatePayload(r, cfg.WebhookSecret)
	if err != nil {
		slog.Error("error reading request body", "err", err)
		prom.InstrumentWebhookHit("validation_failed")
		return err
	}

	go HandleEvent(context.Background(), cfg, r, payload)
	return nil
}

func HandleEvent(ctx context.Context, cfg EventConfig, r *http.Request, payload []byte) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Recovered", "err", r)
		}
	}()

	eventType := github.WebHookType(r)
	e, err := github.ParseWebHook(eventType, payload)
	if err != nil {
		slog.Error("could not parse webhook", "err", err)
		prom.InstrumentWebhookHit("parsing_failed")
		return
	}
	prom.InstrumentWebhookHit("successful")

	// We don't use the request context as it might have a short deadline and we don't want to stop event handling based on that
	// But we do want to stop the event handling after a certain point, so:
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	switch event := e.(type) {
	case *github.PushEvent:
		handlePushEvent(ctx, cfg, event, r, payload)
	case *github.PullRequestEvent:
		handlePullRequestEvent(ctx, cfg, event)
	case *github.IssueCommentEvent:
		handleIssueCommentEvent(ctx, cfg, event)
	}
}

func handlePushEvent(ctx context.Context, cfg EventConfig, event *github.PushEvent, r *http.Request, payload []byte) {
	repoOwner := event.GetRepo().GetOwner().GetLogin()

	clients, err := cfg.Clients.ForOwner(ctx, repoOwner)
	if err != nil {
		slog.Error("Failed to get GitHub clients", "owner", repoOwner, "err", err)
		return
	}

	c := Context{
		RepoRef: RepoRef{
			Owner:         repoOwner,
			Repo:          event.GetRepo().GetName(),
			RepoURL:       event.GetRepo().GetHTMLURL(),
			DefaultBranch: event.GetRepo().GetDefaultBranch(),
		},
		Repositories: clients.Main.v3Client.Repositories,
	}
	c.PrLogger = slog.Default().With("context", c)

	if event.GetRef() != "refs/heads/"+c.DefaultBranch {
		return
	}

	config, _ := getInRepoConfig(ctx, c)
	c.Config = config

	c.PrLogger.Info("Handling event", "type", fmt.Sprintf("%T", event))
	handleProxyForward(ctx, config, generateListOfChangedFiles(event), r, payload)
}

func handlePullRequestEvent(ctx context.Context, cfg EventConfig, event *github.PullRequestEvent) {
	repoOwner := event.GetRepo().GetOwner().GetLogin()

	clients, err := cfg.Clients.ForOwner(ctx, repoOwner)
	if err != nil {
		slog.Error("Failed to get GitHub clients", "owner", repoOwner, "err", err)
		return
	}

	c := Context{
		RepoRef: RepoRef{
			Owner:         repoOwner,
			Repo:          event.GetRepo().GetName(),
			RepoURL:       event.GetRepo().GetHTMLURL(),
			DefaultBranch: event.GetRepo().GetDefaultBranch(),
		},
		PRRef: PRRef{
			PrNumber: event.GetPullRequest().GetNumber(),
			PrAuthor: event.GetPullRequest().GetUser().GetLogin(),
			PrSHA:    event.GetPullRequest().GetHead().GetSHA(),
			Ref:      event.GetPullRequest().GetHead().GetRef(),
		},
		Labels: event.GetPullRequest().Labels,
	}
	clients.setServices(&c)
	c.PrLogger = slog.Default().With("context", c)

	config, err := getInRepoConfig(ctx, c)
	if err != nil {
		_ = c.commentOnPr(ctx, fmt.Sprintf("Failed to get configuration\n```\n%s\n```\n", err))
		c.PrLogger.Error("Failed to get config", "err", err)
		return
	}
	c.Config = config

	c.getPrMetadata(ctx, event.GetPullRequest().GetBody())

	c.PrLogger.Info("Handling event", "type", fmt.Sprintf("%T", event))
	switch {
	case event.GetAction() == "closed" && event.GetPullRequest().GetMerged():
		handlePREvent(ctx, "merged", c, cfg.TemplatesFS, cfg.CommitStatusURLTemplatePath)
	case event.GetAction() == "opened" || event.GetAction() == "reopened" || event.GetAction() == "synchronize":
		handlePREvent(ctx, "changed", c, cfg.TemplatesFS, cfg.CommitStatusURLTemplatePath)
	case event.GetAction() == "labeled" && doesPRHaveLabel(event.GetPullRequest().Labels, "show-plan"):
		handlePREvent(ctx, "show-plan", c, cfg.TemplatesFS, cfg.CommitStatusURLTemplatePath)
	}
}

func handleIssueCommentEvent(ctx context.Context, cfg EventConfig, event *github.IssueCommentEvent) {
	repoOwner := event.GetRepo().GetOwner().GetLogin()
	clients, err := cfg.Clients.ForOwner(ctx, repoOwner)
	if err != nil {
		slog.Error("Failed to get GitHub clients", "owner", repoOwner, "err", err)
		return
	}

	botIdentity, _ := getBotIdentity(ctx, clients.Main.v4Client)

	// Ignore comment events sent by the bot (this is about who trigger the event not who wrote the comment)
	//
	// Allowing override makes it easier to test locally using a personal
	// token. In those cases Telefonistka can be run with
	// HANDLE_SELF_COMMENT=true to handle comments made manually.
	if !cfg.HandleSelfComment && event.GetSender().GetLogin() == botIdentity {
		slog.Debug("Ignoring self comment")
		return
	}
	c := Context{
		RepoRef: RepoRef{
			Owner:         repoOwner,
			Repo:          event.GetRepo().GetName(),
			RepoURL:       event.GetRepo().GetHTMLURL(),
			DefaultBranch: event.GetRepo().GetDefaultBranch(),
		},
		PRRef: PRRef{
			PrNumber: event.GetIssue().GetNumber(),
			PrAuthor: event.GetIssue().GetUser().GetLogin(),
		},
		Labels: event.GetIssue().Labels,
	}
	clients.setServices(&c)
	c.PrLogger = slog.Default().With("context", c)

	config, err := getInRepoConfig(ctx, c)
	if err != nil {
		c.PrLogger.Error("Failed to get config", "err", err)
		return
	}
	c.Config = config
	c.getPrMetadata(ctx, event.GetIssue().GetBody())

	// Check if this comment has an attached PR. If it does not we want to skip moving along.
	pr, resp, err := c.PullRequests.Get(ctx, c.Owner, c.Repo, event.GetIssue().GetNumber())
	prom.InstrumentGhCall(resp)
	if pr == nil || err != nil {
		c.PrLogger.Debug("Issue is not a PR")
		return
	}

	// Comment events don't have Ref/SHA in payload, enrich from the PR.
	c.Ref = pr.GetHead().GetRef()
	c.PrSHA = pr.GetHead().GetSHA()

	c.PrLogger.Info("Handling event", "type", fmt.Sprintf("%T", event))
	if event.GetAction() == "created" && isRetriggerComment(event.GetComment().GetBody()) {
		handlePREvent(ctx, "retriggered", c, cfg.TemplatesFS, cfg.CommitStatusURLTemplatePath)
		return
	}

	if err := handleCommentPrEvent(ctx, c, event, botIdentity); err != nil {
		c.PrLogger.Error("Failed to handle comment event", "err", err)
	}
}

func handlePREvent(ctx context.Context, stat string, c Context, templatesFS fs.FS, commitStatusURLTemplatePath string) {
	setCommitStatus(ctx, c, "pending", commitStatusURLTemplatePath)

	var err error

	defer func() {
		if err != nil {
			setCommitStatus(ctx, c, "error", commitStatusURLTemplatePath)
			return
		}
		setCommitStatus(ctx, c, "success", commitStatusURLTemplatePath)
	}()

	switch stat {
	case "merged":
		err = handleMergedPrEvent(ctx, c, templatesFS)
	case "changed", "retriggered":
		err = handleChangedPREvent(ctx, c, templatesFS)
	case "show-plan":
		err = handleShowPlanPREvent(ctx, c, templatesFS)
	}

	if err != nil {
		c.PrLogger.Error("Handling of PR event failed", "err", err)
	}
}

func handleShowPlanPREvent(ctx context.Context, c Context, templatesFS fs.FS) error {
	promotions, err := generatePromotionPlan(ctx, c, c.Ref)
	if err != nil {
		return err
	}
	commentPlanInPR(ctx, c, promotions, templatesFS)
	return nil
}

func handleChangedPREvent(ctx context.Context, c Context, templatesFS fs.FS) error {
	if err := minimizeStalePRComments(ctx, c); err != nil {
		return fmt.Errorf("minimizing stale PR comments: %w", err)
	}

	if err := commentDiff(ctx, c); err != nil {
		return fmt.Errorf("failed to comment diff: %w", err)
	}

	if err := detectDrift(ctx, c, templatesFS); err != nil {
		return fmt.Errorf("detecting drift: %w", err)
	}

	return nil
}

// handleMergedPrEvent processes a PR that has been merged, generating promotions and opening new PRs for each.
func handleMergedPrEvent(ctx context.Context, c Context, templatesFS fs.FS) error {
	var err error

	// configBranch = default branch as the PR is closed at this and its branch deleted.
	// If we'll ever want to generate this plan on an unmerged PR the PR branch (c.Ref) should be used
	promotions, err := generatePromotionPlan(ctx, c, c.DefaultBranch)
	if err != nil {
		return fmt.Errorf("generating promotion plan: %w", err)
	}
	if !c.Config.DryRunMode {
		for _, promotion := range promotions {
			// TODO this whole part shouldn't be in main, but I need to refactor some circular dep's

			// because I use GitHub low level (tree) API the order of operation is somewhat different compared to regular git CLI flow:
			// I create the sync commit against HEAD, create a new branch based on that commit and finally open a PR based on that branch

			var treeEntries []*github.TreeEntry
			for trgt, src := range promotion.ComputedSyncPaths {
				err = generateSyncTreeEntriesForCommit(ctx, &treeEntries, c, src, trgt, c.DefaultBranch)
				if err != nil {
					c.PrLogger.Error("Failed to generate treeEntries", "source", src, "target", trgt, "err", err)
				} else {
					c.PrLogger.Debug("Generated treeEntries for source and target", "source", src, "target", trgt)
				}
			}

			if len(treeEntries) < 1 {
				c.PrLogger.Info("TreeEntries list is empty")
				continue
			}

			commit, err := createCommit(ctx, c, treeEntries, c.DefaultBranch, "Syncing from "+promotion.Metadata.SourcePath)
			if err != nil {
				c.PrLogger.Error("Commit creation failed", "err", err)
				return err
			}

			newBranchName := generateSafePromotionBranchName(ctx, c.PrNumber, c.Ref, promotion.Metadata.TargetPaths)

			newBranchRef, err := createBranch(ctx, c, commit, newBranchName)
			if err != nil {
				c.PrLogger.Error("Branch creation failed", "err", err)
				return err
			}

			components := strings.Join(promotion.Metadata.ComponentNames, ",")
			newPrTitle := fmt.Sprintf("🚀 Promotion: %s ➡️  %s", components, promotion.Metadata.TargetDescription)

			var originalPrAuthor string
			// If the triggering PR was opened manually and it doesn't include in-body metadata, use the PR author
			// If the triggering PR as opened by Telefonistka and it has in-body metadata, fetch the original author from there
			if c.PrMetadata.OriginalPrAuthor != "" {
				originalPrAuthor = c.PrMetadata.OriginalPrAuthor
			} else {
				originalPrAuthor = c.PrAuthor
			}

			newPrBody := generatePromotionPrBody(ctx, c, components, promotion, originalPrAuthor)

			pull, err := createPrObject(ctx, c, newBranchRef, newPrTitle, newPrBody, c.DefaultBranch, originalPrAuthor)
			if err != nil {
				c.PrLogger.Error("PR opening failed", "err", err)
				return err
			}

			if err := approvePr(ctx, c); err != nil {
				c.PrLogger.Error("PR auto approval failed", "err", err)
				return err
			}

			if promotion.Metadata.AutoMerge {
				c.PrLogger.Info("Auto-merging PR")
				templateData := map[string]interface{}{
					"prNumber": pull.GetNumber(),
				}

				templateOutput, err := executeTemplate(templatesFS, "autoMerge", "auto-merge-comment.gotmpl", templateData)
				if err != nil {
					return err
				}

				if err := c.commentOnPr(ctx, templateOutput); err != nil {
					return err
				}

				err = mergePr(ctx, c)
				if err != nil {
					c.PrLogger.Error("PR auto merge failed", "err", err)
					return err
				}
			}
		}
	} else {
		commentPlanInPR(ctx, c, promotions, templatesFS)
	}

	if c.Config.Argocd.AllowSyncfromBranchPathRegex != "" {
		componentPathList, err := generateListOfChangedComponentPaths(ctx, c)
		if err != nil {
			c.PrLogger.Error("Failed to get list of changed components for setting ArgoCD app targetRef to HEAD", "err", err)
		}
		for _, componentPath := range componentPathList {
			if isSyncFromBranchAllowedForThisPath(c.Config.Argocd.AllowSyncfromBranchPathRegex, componentPath) {
				c.PrLogger.Info("Ensuring ArgoCD app is set to HEAD", "path", componentPath)
				err := argocd.SetArgoCDAppRevision(ctx, componentPath, "HEAD", c.RepoURL, c.Config.Argocd.UseSHALabelForAppDiscovery)
				if err != nil {
					c.PrLogger.Error("Failed to set ArgoCD app to HEAD", "path", componentPath, "err", err)
				}
			}
		}
	}

	return err
}

func handleCommentPrEvent(ctx context.Context, c Context, ce *github.IssueCommentEvent, botIdentity string) error {
	// This part should only happen on edits of bot comments on open PRs (I'm not testing Issue vs PR as Telefonistka only creates PRs at this point)
	if ce.GetAction() == "edited" && ce.GetComment().GetUser().GetLogin() == botIdentity && ce.GetIssue().GetState() == "open" {
		const checkboxIdentifier = "telefonistka-argocd-branch-sync"
		checkboxWaschecked, checkboxIsChecked := analyzeCommentUpdateCheckBox(ce.GetComment().GetBody(), ce.GetChanges().GetBody().GetFrom(), checkboxIdentifier)
		if !checkboxWaschecked && checkboxIsChecked {
			c.PrLogger.Info("Sync Checkbox was checked")
			if c.Config.Argocd.AllowSyncfromBranchPathRegex != "" {
				componentPathList, err := generateListOfChangedComponentPaths(ctx, c)
				if err != nil {
					c.PrLogger.Error("Failed to get list of changed components", "err", err)
				}

				for _, componentPath := range componentPathList {
					if isSyncFromBranchAllowedForThisPath(c.Config.Argocd.AllowSyncfromBranchPathRegex, componentPath) {
						err := argocd.SetArgoCDAppRevision(ctx, componentPath, c.Ref, c.RepoURL, c.Config.Argocd.UseSHALabelForAppDiscovery)
						if err != nil {
							c.PrLogger.Error("Failed to sync ArgoCD app from branch", "err", err)
						}
					}
				}
			}
		}
	}

	// I should probably deprecate this whole part altogether - it was designed to solve a *very* specific problem that is probably no longer relevant with GitHub Rulesets
	// The only reason I'm keeping it is that I don't have a clear feature deprecation policy and if I do remove it should be in a distinct PR
	for commentSubstring, commitStatusContext := range c.Config.ToggleCommitStatus {
		if strings.Contains(ce.GetComment().GetBody(), "/"+commentSubstring) {
			err := c.toggleCommitStatus(ctx, commitStatusContext, ce.GetSender().GetName())
			if err != nil {
				c.PrLogger.Error("Failed to toggle commit status context", "context", commitStatusContext, "err", err)
				return err
			}
			c.PrLogger.Info("Toggled status", "context", commitStatusContext)
		}
	}

	return nil
}

func analyzeCommentUpdateCheckBox(newBody string, oldBody string, checkboxIdentifier string) (wasCheckedBefore bool, isCheckedNow bool) {
	checkboxPattern := fmt.Sprintf(`(?m)^\s*-\s*\[(.)\]\s*<!-- %s -->.*$`, checkboxIdentifier)
	checkBoxRegex := regexp.MustCompile(checkboxPattern)
	oldMatch := checkBoxRegex.FindStringSubmatch(oldBody)
	newMatch := checkBoxRegex.FindStringSubmatch(newBody)

	if len(newMatch) < 2 || len(oldMatch) < 2 {
		return false, false
	}
	return oldMatch[1] == "x", newMatch[1] == "x"
}

func isSyncFromBranchAllowedForThisPath(allowedPathRegex string, path string) bool {
	allowedPathsRegex := regexp.MustCompile(allowedPathRegex)
	return allowedPathsRegex.MatchString(path)
}

func isRetriggerComment(body string) bool {
	return strings.TrimSpace(body) == "/retrigger"
}

func doesPRHaveLabel(labels []*github.Label, name string) bool {
	for _, l := range labels {
		if l.GetName() == name {
			return true
		}
	}
	return false
}

func generateListOfChangedFiles(eventPayload *github.PushEvent) []string {
	fileList := map[string]bool{} // using map for uniqueness

	for _, commit := range eventPayload.Commits {
		for _, file := range commit.Added {
			fileList[file] = true
		}
		for _, file := range commit.Modified {
			fileList[file] = true
		}
		for _, file := range commit.Removed {
			fileList[file] = true
		}
	}

	return slices.Collect(maps.Keys(fileList))
}
