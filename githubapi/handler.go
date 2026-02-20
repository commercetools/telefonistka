package githubapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"maps"
	"slices"

	"github.com/commercetools/telefonistka/argocd"
	prom "github.com/commercetools/telefonistka/prometheus"
	"github.com/google/go-github/v62/github"
	lru "github.com/hashicorp/golang-lru/v2"
)

// ReceiveWebhook validates the webhook payload and spawns a goroutine to handle the event.
func ReceiveWebhook(r *http.Request, mainGhClientCache *lru.Cache[string, GhClientPair], prApproverGhClientCache *lru.Cache[string, GhClientPair], githubWebhookSecret []byte) error {
	payload, err := github.ValidatePayload(r, githubWebhookSecret)
	if err != nil {
		slog.Error("error reading request body", "err", err)
		prom.InstrumentWebhookHit("validation_failed")
		return err
	}

	go HandleEvent(context.Background(), mainGhClientCache, prApproverGhClientCache, r, payload)
	return nil
}

func HandleEvent(ctx context.Context, mainGhClientCache *lru.Cache[string, GhClientPair], prApproverGhClientCache *lru.Cache[string, GhClientPair], r *http.Request, payload []byte) {
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
	var mainGithubClientPair GhClientPair
	var approverGithubClientPair GhClientPair

	switch event := e.(type) {
	case *github.PushEvent:
		// this is a commit push, do something with it?
		repoOwner := event.GetRepo().GetOwner().GetLogin()

		mainGithubClientPair.GetAndCache(mainGhClientCache, "GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_OAUTH_TOKEN", repoOwner, ctx)

		c := Context{
			Repositories: mainGithubClientPair.v3Client.Repositories,
			Owner:        repoOwner,
			Repo:         event.GetRepo().GetName(),
			RepoURL:      event.GetRepo().GetHTMLURL(),
		}

		prLogger := slog.Default().With(
			"context", c,
		)

		c.PrLogger = prLogger

		defaultBranch := event.GetRepo().GetDefaultBranch()

		if event.GetRef() != "refs/heads/"+defaultBranch {
			return
		}

		config, _ := getInRepoConfig(ctx, c)
		c.Config = config
		listOfChangedFiles := generateListOfChangedFiles(event)

		c.PrLogger.Info("Handling event", "type", fmt.Sprintf("%T", event))
		handleProxyForward(ctx, config, listOfChangedFiles, r, payload)
	case *github.PullRequestEvent:
		repoOwner := event.GetRepo().GetOwner().GetLogin()

		mainGithubClientPair.GetAndCache(mainGhClientCache, "GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_OAUTH_TOKEN", repoOwner, ctx)
		approverGithubClientPair.GetAndCache(prApproverGhClientCache, "APPROVER_GITHUB_APP_ID", "APPROVER_GITHUB_APP_PRIVATE_KEY_PATH", "APPROVER_GITHUB_OAUTH_TOKEN", repoOwner, ctx)

		c := Context{
			Repositories: mainGithubClientPair.v3Client.Repositories,
			PullRequests: mainGithubClientPair.v3Client.PullRequests,
			Issues:       mainGithubClientPair.v3Client.Issues,
			Git:          mainGithubClientPair.v3Client.Git,
			GraphQL:      mainGithubClientPair.v4Client,
			ApproverPRs:  approverGithubClientPair.v3Client.PullRequests,

			Labels:        event.GetPullRequest().Labels,
			Owner:         repoOwner,
			Repo:          event.GetRepo().GetName(),
			RepoURL:       event.GetRepo().GetHTMLURL(),
			PrNumber:      event.GetPullRequest().GetNumber(),
			Ref:           event.GetPullRequest().GetHead().GetRef(),
			PrAuthor:      event.GetPullRequest().GetUser().GetLogin(),
			PrSHA:         event.GetPullRequest().GetHead().GetSHA(),
			DefaultBranch: event.GetRepo().GetDefaultBranch(),
		}

		prLogger := slog.Default().With(
			"context", c,
		)

		c.PrLogger = prLogger

		config, err := getInRepoConfig(ctx, c)
		if err != nil {
			_ = c.commentOnPr(ctx, fmt.Sprintf("Failed to get configuration\n```\n%s\n```\n", err))
			prLogger.Error("Failed to get config", "err", err)
			return
		}

		c.Config = config

		c.getPrMetadata(ctx, event.GetPullRequest().GetBody())

		c.PrLogger.Info("Handling event", "type", fmt.Sprintf("%T", event))
		switch {
		case event.GetAction() == "closed" && event.GetPullRequest().GetMerged():
			handlePREvent(ctx, "merged", c)
		case event.GetAction() == "opened" || event.GetAction() == "reopened" || event.GetAction() == "synchronize":
			handlePREvent(ctx, "changed", c)
		case event.GetAction() == "labeled" && doesPRHaveLabel(event.GetPullRequest().Labels, "show-plan"):
			handlePREvent(ctx, "show-plan", c)
		}

	case *github.IssueCommentEvent:
		repoOwner := event.GetRepo().GetOwner().GetLogin()
		mainGithubClientPair.GetAndCache(mainGhClientCache, "GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_OAUTH_TOKEN", repoOwner, ctx)
		approverGithubClientPair.GetAndCache(prApproverGhClientCache, "APPROVER_GITHUB_APP_ID", "APPROVER_GITHUB_APP_PRIVATE_KEY_PATH", "APPROVER_GITHUB_OAUTH_TOKEN", repoOwner, ctx)

		botIdentity, _ := getBotIdentity(ctx, mainGithubClientPair.v4Client)

		// Ignore comment events sent by the bot (this is about who trigger the event not who wrote the comment)
		//
		// Allowing override makes it easier to test locally using a personal
		// token. In those cases Telefonistka can be run with
		// HANDLE_SELF_COMMENT=true to handle comments made manually.
		handleSelf, _ := strconv.ParseBool(os.Getenv("HANDLE_SELF_COMMENT"))
		if !handleSelf && event.GetSender().GetLogin() == botIdentity {
			slog.Debug("Ignoring self comment")
			return
		}
		c := Context{
			Repositories: mainGithubClientPair.v3Client.Repositories,
			PullRequests: mainGithubClientPair.v3Client.PullRequests,
			Issues:       mainGithubClientPair.v3Client.Issues,
			Git:          mainGithubClientPair.v3Client.Git,
			GraphQL:      mainGithubClientPair.v4Client,
			ApproverPRs:  approverGithubClientPair.v3Client.PullRequests,

			Owner:         repoOwner,
			Repo:          event.GetRepo().GetName(),
			RepoURL:       event.GetRepo().GetHTMLURL(),
			PrNumber:      event.GetIssue().GetNumber(),
			PrAuthor:      event.GetIssue().GetUser().GetLogin(),
			Labels:        event.GetIssue().Labels,
			DefaultBranch: event.GetRepo().GetDefaultBranch(),
		}

		prLogger := slog.Default().With(
			"context", c,
		)

		c.PrLogger = prLogger

		config, err := getInRepoConfig(ctx, c)
		if err != nil {
			prLogger.Error("Failed to get config", "err", err)
			return
		}
		c.Config = config
		c.getPrMetadata(ctx, event.GetIssue().GetBody())

		issue := event.GetIssue()
		owner := c.Owner
		repo := c.Repo

		// Check if this comment has an attached PR. If it does not we want to skip moving along.
		pr, resp, err := c.PullRequests.Get(ctx, owner, repo, issue.GetNumber())
		prom.InstrumentGhCall(resp)
		if pr == nil || err != nil {
			c.PrLogger.Debug("Issue is not a PR")
			return
		}

		// Comment events doesn't have Ref/SHA in payload, enriching the object:
		c.Ref = pr.GetHead().GetRef()
		c.PrSHA = pr.GetHead().GetSHA()

		c.PrLogger.Info("Handling event", "type", fmt.Sprintf("%T", event))
		retrigger := event.GetAction() == "created" && isRetriggerComment(event.GetComment().GetBody())
		if retrigger {
			handlePREvent(ctx, "retriggered", c)
			return
		}

		if err := handleCommentPrEvent(ctx, c, event, botIdentity); err != nil {
			prLogger.Error("Failed to handle comment event", "err", err)
		}
	default:
		return
	}
}

func handlePREvent(ctx context.Context, stat string, c Context) {
	setCommitStatus(ctx, c, "pending")

	var err error

	defer func() {
		if err != nil {
			setCommitStatus(ctx, c, "error")
			return
		}
		setCommitStatus(ctx, c, "success")
	}()

	switch stat {
	case "merged":
		err = handleMergedPrEvent(ctx, c)
	case "changed", "retriggered":
		err = handleChangedPREvent(ctx, c)
	case "show-plan":
		err = handleShowPlanPREvent(ctx, c)
	}

	if err != nil {
		c.PrLogger.Error("Handling of PR event failed", "err", err)
	}
}

func handleShowPlanPREvent(ctx context.Context, c Context) error {
	promotions, err := generatePromotionPlan(ctx, c, c.Ref)
	if err != nil {
		return err
	}
	commentPlanInPR(ctx, c, promotions)
	return nil
}

func handleChangedPREvent(ctx context.Context, c Context) error {

	if err := minimizeStalePRComments(ctx, c); err != nil {
		return fmt.Errorf("minimizing stale PR comments: %w", err)
	}

	if err := commentDiff(ctx, c); err != nil {
		return fmt.Errorf("failed to comment diff: %w", err)
	}

	if err := detectDrift(ctx, c); err != nil {
		return fmt.Errorf("detecting drift: %w", err)
	}

	return nil
}

// handleMergedPrEvent
func handleMergedPrEvent(ctx context.Context, c Context) error {
	var err error

	// configBranch = default branch as the PR is closed at this and its branch deleted.
	// If we'l ever want to generate this plan on an unmerged PR the PR branch (c.Ref) should be used
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

				templateOutput, err := executeTemplate("autoMerge", "auto-merge-comment.gotmpl", templateData)
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
		commentPlanInPR(ctx, c, promotions)
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
	var err error
	// This part should only happen on edits of bot comments on open PRs (I'm not testing Issue vs PR as Telefonsitka only creates PRs at this point)
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

	// I should probably deprecated this whole part altogether - it was designed to solve a *very* specific problem that is probably no longer relevant with GitHub Rulesets
	// The only reason I'm keeping it is that I don't have a clear feature depreciation policy and if I do remove it should be in a distinct PR
	for commentSubstring, commitStatusContext := range c.Config.ToggleCommitStatus {
		if strings.Contains(ce.GetComment().GetBody(), "/"+commentSubstring) {
			err := c.toggleCommitStatus(ctx, commitStatusContext, ce.GetSender().GetName())
			if err != nil {
				c.PrLogger.Error("Failed to toggle s context", "context", commitStatusContext, "err", err)
				return err
			}
			c.PrLogger.Info("Toggled status", "context", commitStatusContext)
		}
	}

	return err
}

func analyzeCommentUpdateCheckBox(newBody string, oldBody string, checkboxIdentifier string) (wasCheckedBefore bool, isCheckedNow bool) {
	checkboxPattern := fmt.Sprintf(`(?m)^\s*-\s*\[(.)\]\s*<!-- %s -->.*$`, checkboxIdentifier)
	checkBoxRegex := regexp.MustCompile(checkboxPattern)
	oldCheckBoxContent := checkBoxRegex.FindStringSubmatch(oldBody)
	newCheckBoxContent := checkBoxRegex.FindStringSubmatch(newBody)

	// I'm grabbing the second group of the regex, which is the checkbox content (either "x" or " ")
	// The first element of the result is the whole match
	if len(newCheckBoxContent) < 2 || len(oldCheckBoxContent) < 2 {
		return false, false
	}
	if len(newCheckBoxContent) >= 2 {
		if newCheckBoxContent[1] == "x" {
			isCheckedNow = true
		}
	}

	if len(oldCheckBoxContent) >= 2 {
		if oldCheckBoxContent[1] == "x" {
			wasCheckedBefore = true
		}
	}

	return
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
