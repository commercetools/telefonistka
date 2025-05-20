package githubapi

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha1" //nolint:gosec // G505: Blocklisted import crypto/sha1: weak cryptographic primitive (gosec), this is not a cryptographic use case
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/commercetools/telefonistka/internal/pkg/argocd"
	"github.com/commercetools/telefonistka/internal/pkg/configuration"
	cfg "github.com/commercetools/telefonistka/internal/pkg/configuration"
	prom "github.com/commercetools/telefonistka/internal/pkg/prometheus"
	"github.com/google/go-github/v62/github"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/nao1215/markdown"
	"golang.org/x/exp/maps"
)

const (
	githubCommentMaxSize = 65536
	githubPublicBaseURL  = "https://github.com"
)

type DiffCommentData struct {
	DiffOfChangedComponents   []argocd.DiffResult
	DisplaySyncBranchCheckBox bool
	BranchName                string
}

type promotionInstanceMetaData struct {
	SourcePath  string   `json:"sourcePath"`
	TargetPaths []string `json:"targetPaths"`
}

type Context struct {
	GhClientPair *GhClientPair
	// This whole struct describe the metadata of the PR, so it makes sense to share the context with everything to generate HTTP calls related to that PR, right?
	DefaultBranch string
	Owner         string
	Repo          string
	PrAuthor      string
	PrNumber      int
	PrSHA         string
	Ref           string
	RepoURL       string
	PrLogger      *slog.Logger
	Labels        []*github.Label
	PrMetadata    prMetadata
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

func (ghPrClientDetails *Context) getPrMetadata(ctx context.Context, prBody string) {
	prMetadataRegex := regexp.MustCompile(`<!--\|.*\|(.*)\|-->`)
	serializedPrMetadata := prMetadataRegex.FindStringSubmatch(prBody)
	if len(serializedPrMetadata) == 2 {
		if serializedPrMetadata[1] != "" {
			ghPrClientDetails.PrLogger.Info("Found PR metadata")
			err := ghPrClientDetails.PrMetadata.DeSerialize(serializedPrMetadata[1])
			if err != nil {
				ghPrClientDetails.PrLogger.Error("Fail to parser PR metadata", "err", err)
			}
		}
	}
}

func (ghPrClientDetails *Context) getBlameURLPrefix(ctx context.Context) string {
	githubHost := getEnv("GITHUB_HOST", "")
	if githubHost == "" {
		githubHost = githubPublicBaseURL
	}
	return fmt.Sprintf("%s/%s/%s/blame", githubHost, ghPrClientDetails.Owner, ghPrClientDetails.Repo)
}

// shouldSyncBranchCheckBoxBeDisplayed checks if the sync branch checkbox should be displayed in the PR comment.
// The checkbox should be displayed if:
// - The component is allowed to be synced from a branch(based on Telefonsitka configuration)
// - The relevant app is not new, temporary app that was created just to generate the diff
func shouldSyncBranchCheckBoxBeDisplayed(ctx context.Context, componentPathList []string, allowSyncfromBranchPathRegex string, diffOfChangedComponents []argocd.DiffResult) bool {
	for _, componentPath := range componentPathList {
		// First we check if the component is allowed to be synced from a branch
		if !isSyncFromBranchAllowedForThisPath(allowSyncfromBranchPathRegex, componentPath) {
			continue
		}

		// Then we check the relevant app is not new, temporary app.
		// We don't support syncing new apps from branches
		for _, diffOfChangedComponent := range diffOfChangedComponents {
			if diffOfChangedComponent.ComponentPath == componentPath && !diffOfChangedComponent.AppWasTemporarilyCreated && !diffOfChangedComponent.AppSyncedFromPRBranch {
				return true
			}
		}
	}
	return false
}

func HandlePREvent(ctx context.Context, stat string, ghPrClientDetails Context, approverGithubClientPair GhClientPair, config *configuration.Config) {
	SetCommitStatus(ctx, ghPrClientDetails, "pending")

	var err error

	defer func() {
		if err != nil {
			SetCommitStatus(ctx, ghPrClientDetails, "error")
			return
		}
		SetCommitStatus(ctx, ghPrClientDetails, "success")
	}()

	switch stat {
	case "merged":
		err = handleMergedPrEvent(ctx, ghPrClientDetails, approverGithubClientPair.v3Client, config)
	case "changed":
		err = handleChangedPREvent(ctx, *ghPrClientDetails.GhClientPair, ghPrClientDetails, ghPrClientDetails.PrNumber, ghPrClientDetails.Labels, config)
	case "show-plan":
		err = handleShowPlanPREvent(ctx, ghPrClientDetails, config)
	}

	if err != nil {
		ghPrClientDetails.PrLogger.Error("Handling of PR event failed", "err", err)
	}
}

func handleShowPlanPREvent(ctx context.Context, ghPrClientDetails Context, config *configuration.Config) error {
	ghPrClientDetails.PrLogger.Info("Found show-plan label, posting plan")
	promotions, err := GeneratePromotionPlan(ctx, ghPrClientDetails, config, ghPrClientDetails.Ref)
	if err != nil {
		return err
	}
	commentPlanInPR(ctx, ghPrClientDetails, promotions)
	return nil
}

func handleChangedPREvent(ctx context.Context, mainGithubClientPair GhClientPair, ghPrClientDetails Context, prNumber int, prLabels []*github.Label, config *configuration.Config) error {
	botIdentity, _ := GetBotGhIdentity(ctx, mainGithubClientPair.v4Client)
	err := MinimizeStalePRComments(ctx, ghPrClientDetails, botIdentity)
	if err != nil {
		return fmt.Errorf("minimizing stale PR comments: %w", err)
	}
	if config.Argocd.CommentDiffonPR {
		componentPathList, err := generateListOfChangedComponentPaths(ctx, ghPrClientDetails, config)
		if err != nil {
			return fmt.Errorf("generate list of changed components: %w", err)
		}

		// Building a map component's path and a boolean value that indicates if we should diff it not.
		// I'm avoiding doing this in the ArgoCD package to avoid circular dependencies and keep package scope clean
		componentsToDiff := map[string]bool{}
		for _, componentPath := range componentPathList {
			c, err := getComponentConfig(ctx, ghPrClientDetails, componentPath, ghPrClientDetails.Ref)
			if err != nil {
				return fmt.Errorf("get component (%s) config:  %w", componentPath, err)
			}
			componentsToDiff[componentPath] = true
			if c.DisableArgoCDDiff {
				componentsToDiff[componentPath] = false
				ghPrClientDetails.PrLogger.Debug("ArgoCD diff disabled for path", "path", componentPath)
			}
		}
		argoClients, err := argocd.CreateArgoCdClients()
		if err != nil {
			return fmt.Errorf("error creating ArgoCD clients: %w", err)
		}

		hasComponentDiff, hasComponentDiffErrors, diffOfChangedComponents, err := argocd.GenerateDiffOfChangedComponents(ctx, componentsToDiff, ghPrClientDetails.Ref, ghPrClientDetails.RepoURL, config.Argocd.UseSHALabelForAppDiscovery, config.Argocd.CreateTempAppObjectFroNewApps, argoClients)
		if err != nil {
			return fmt.Errorf("getting diff information: %w", err)
		}
		ghPrClientDetails.PrLogger.Debug("Successfully got ArgoCD diff(comparing live objects against objects rendered form git ref)", "ref", ghPrClientDetails.Ref)
		if !hasComponentDiffErrors && !hasComponentDiff {
			ghPrClientDetails.PrLogger.Debug("ArgoCD diff is empty, this PR will not change cluster state")
			prLables, resp, err := ghPrClientDetails.GhClientPair.v3Client.Issues.AddLabelsToIssue(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, prNumber, []string{"noop"})
			prom.InstrumentGhCall(resp)
			if err != nil {
				ghPrClientDetails.PrLogger.Error("Could not label GitHub PR", "err", err, "resp", resp)
			} else {
				ghPrClientDetails.PrLogger.Debug("PR labeled", "labels", prLables)
			}
			// If the PR is a promotion PR and the diff is empty, we can auto-merge it
			// "len(componentPathList) > 0"  validates we are not auto-merging a PR that we failed to understand which apps it affects
			if DoesPrHasLabel(prLabels, "promotion") && config.Argocd.AutoMergeNoDiffPRs && len(componentPathList) > 0 {
				ghPrClientDetails.PrLogger.Info("Auto-merging (no diff) PR")
				err := MergePr(ctx, ghPrClientDetails, prNumber)
				if err != nil {
					return fmt.Errorf("PR auto merge: %w", err)
				}
			}
		}

		if len(diffOfChangedComponents) > 0 {
			diffCommentData := DiffCommentData{
				DiffOfChangedComponents: diffOfChangedComponents,
				BranchName:              ghPrClientDetails.Ref,
			}

			diffCommentData.DisplaySyncBranchCheckBox = shouldSyncBranchCheckBoxBeDisplayed(ctx, componentPathList, config.Argocd.AllowSyncfromBranchPathRegex, diffOfChangedComponents)
			componentsToDiffJSON, _ := json.Marshal(componentsToDiff)
			slog.Info("Generating ArgoCD Diff Comment for components", "components", string(componentsToDiffJSON), "diff_element_length", len(diffCommentData.DiffOfChangedComponents))
			comments, err := generateArgoCdDiffComments(diffCommentData, githubCommentMaxSize)
			if err != nil {
				return fmt.Errorf("generate diff comment: %w", err)
			}
			for _, comment := range comments {
				err = commentPR(ctx, ghPrClientDetails, comment)
				if err != nil {
					return fmt.Errorf("commenting on PR: %w", err)
				}
			}
		} else {
			ghPrClientDetails.PrLogger.Debug("Diff not find affected ArogCD apps")
		}
	}
	err = DetectDrift(ctx, ghPrClientDetails)
	if err != nil {
		return fmt.Errorf("detecting drift: %w", err)
	}
	return nil
}

func buildArgoCdDiffComment(diffCommentData DiffCommentData, beConcise bool, partNumber int, totalParts int) (string, error) {
	buf := new(bytes.Buffer)
	md := markdown.NewMarkdown(buf)
	const argoSmallLogo = `<img src="https://argo-cd.readthedocs.io/en/stable/assets/favicon.png" width="20"/>`
	if partNumber != 0 {
		md.PlainTextf("Component %d/%d: %s (Split for comment size)\n", partNumber, totalParts, diffCommentData.DiffOfChangedComponents[0].ComponentPath)
	}
	if !beConcise {
		md.PlainText("Diff of ArgoCD applications:\n")
	} else {
		md.PlainText("Diff of ArgoCD applications (concise view, full diff didn't fit GH comment):\n")
	}
	for _, appDiffResult := range diffCommentData.DiffOfChangedComponents {
		if appDiffResult.DiffError != nil {
			md.Cautionf("%s (%s) ", markdown.Bold("Error getting diff from ArgoCD"), markdown.Code(appDiffResult.ComponentPath))
			md.PlainTextf("Please check the App Conditions of %s %s for more details.", argoSmallLogo, markdown.Bold(markdown.Link(appDiffResult.ArgoCdAppName, appDiffResult.ArgoCdAppURL)))
			if appDiffResult.AppWasTemporarilyCreated {
				md.Warning("For investigation we kept the temporary application, please make sure to clean it up later!")
			}
			md.CodeBlocks(markdown.SyntaxHighlightNone, appDiffResult.DiffError.Error())
		} else {
			md.PlainTextf("%s %s @ %s", argoSmallLogo, markdown.Bold(markdown.Link(appDiffResult.ArgoCdAppName, appDiffResult.ArgoCdAppURL)), markdown.Code(appDiffResult.ComponentPath))

			// If the app was temporarily created, we should inform the user about it, if not we should inform about "unusual" health and sync status
			if appDiffResult.AppWasTemporarilyCreated {
				md.Note("Telefonistka has temporarily created an ArgoCD app object to render manifest previews.  \n> Please be aware:  \n> * The app will only appear in the ArgoCD UI for a few seconds.")
			} else {
				if appDiffResult.ArgoCdAppHealthStatus != "Healthy" {
					md.Cautionf("The ArgoCD app health status is currently %s", appDiffResult.ArgoCdAppHealthStatus)
				}
				if appDiffResult.ArgoCdAppSyncStatus != "Synced" {
					md.Warningf("The ArgoCD app sync status is currently %s", appDiffResult.ArgoCdAppSyncStatus)
				}
				if !appDiffResult.ArgoCdAppAutoSyncEnabled {
					md.Note("This ArgoCD app is doesn't have `auto-sync` enabled, merging this PR will **not** apply changes to cluster without additional actions.")
				}
			}
			if appDiffResult.HasDiff {
				md.PlainText("\n<details><summary>ArgoCD Diff(Click to expand):</summary>\n\n```diff\n")
				for _, objectDiff := range appDiffResult.DiffElements {
					if objectDiff.Diff != "" {
						if !beConcise {
							md.PlainTextf("%s/%s/%s:\n%s", objectDiff.ObjectNamespace, objectDiff.ObjectKind, objectDiff.ObjectName, objectDiff.Diff)
						} else {
							md.PlainTextf("%s/%s/%s", objectDiff.ObjectNamespace, objectDiff.ObjectKind, objectDiff.ObjectName)
						}
					}
				}
				md.PlainText("\n\n```\n\n</details>\n")
			} else {
				if appDiffResult.AppSyncedFromPRBranch {
					md.Note("The app already has this branch set as the source target revision, and autosync is enabled. Diff calculation was skipped.")
				} else {
					md.PlainText("No diff 🤷")
				}
			}
		}
	}
	if diffCommentData.DisplaySyncBranchCheckBox {
		md.PlainTextf("- [ ] <!-- telefonistka-argocd-branch-sync --> Set ArgoCD apps Target Revision to `%s`", diffCommentData.BranchName)
	}
	err := md.Build()
	return buf.String(), err
}

func generateArgoCdDiffComments(diffCommentData DiffCommentData, githubCommentMaxSize int) (comments []string, err error) {
	commentBody, err := buildArgoCdDiffComment(diffCommentData, false, 0, 0)
	if err != nil {
		slog.Error("Failed to build ArgoCD diff comment", "err", err)
		return comments, err
	}

	// Happy path, the diff comment is small enough to be posted in one comment
	if len(commentBody) < githubCommentMaxSize {
		comments = append(comments, commentBody)
		return comments, nil
	}

	// If the diff comment is too large, we'll split it into multiple comments, one per component
	totalComponents := len(diffCommentData.DiffOfChangedComponents)
	for i, singleComponentDiff := range diffCommentData.DiffOfChangedComponents {
		componentTemplateData := diffCommentData
		componentTemplateData.DiffOfChangedComponents = []argocd.DiffResult{singleComponentDiff}
		commentBody, err := buildArgoCdDiffComment(diffCommentData, false, i+1, totalComponents)
		if err != nil {
			slog.Error("Failed to build ArgoCD diff comment", "err", err)
			return comments, err
		}

		// Even per component comments can be too large, in that case we'll just use the concise template
		// Somewhat Happy path, the per-component diff comment is small enough to be posted in one comment
		if len(commentBody) < githubCommentMaxSize {
			comments = append(comments, commentBody)
			continue
		}

		// now we don't have much choice, this is the saddest path, we'll use the concise template
		commentBody, err = buildArgoCdDiffComment(diffCommentData, true, i+1, totalComponents)
		if err != nil {
			slog.Error("Failed to build ArgoCD diff comment", "err", err)
			return comments, err
		}
		comments = append(comments, commentBody)
	}

	return comments, nil
}

// ReciveEventFile this one is similar to ReciveWebhook but it's used for CLI triggering, i  simulates a webhook event to use the same code path as the webhook handler.
func ReciveEventFile(eventType string, eventFilePath string, mainGhClientCache *lru.Cache[string, GhClientPair], prApproverGhClientCache *lru.Cache[string, GhClientPair]) {
	slog.Info("Event", "type", eventType)
	slog.Info("Proccesing", "file", eventFilePath)

	payload, err := os.ReadFile(eventFilePath)
	if err != nil {
		panic(err)
	}
	eventPayloadInterface, err := github.ParseWebHook(eventType, payload)
	if err != nil {
		slog.Error("could not parse webhook", "err", err)
		prom.InstrumentWebhookHit("parsing_failed")
		return
	}
	r, _ := http.NewRequest("POST", "", nil) //nolint:noctx
	r.Body = io.NopCloser(bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-GitHub-Event", eventType)

	handleEvent(eventPayloadInterface, mainGhClientCache, prApproverGhClientCache, r, payload)
}

// ReciveWebhook is the main entry point for the webhook handling it starts parases the webhook payload and start a thread to handle the event success/failure are dependant on the payload parsing only
func ReciveWebhook(r *http.Request, mainGhClientCache *lru.Cache[string, GhClientPair], prApproverGhClientCache *lru.Cache[string, GhClientPair], githubWebhookSecret []byte) error {
	payload, err := github.ValidatePayload(r, githubWebhookSecret)
	if err != nil {
		slog.Error("error reading request body", "err", err)
		prom.InstrumentWebhookHit("validation_failed")
		return err
	}
	eventType := github.WebHookType(r)

	eventPayloadInterface, err := github.ParseWebHook(eventType, payload)
	if err != nil {
		slog.Error("could not parse webhook", "err", err)
		prom.InstrumentWebhookHit("parsing_failed")
		return err
	}
	prom.InstrumentWebhookHit("successful")

	go handleEvent(eventPayloadInterface, mainGhClientCache, prApproverGhClientCache, r, payload)
	return nil
}

func handleEvent(eventPayloadInterface interface{}, mainGhClientCache *lru.Cache[string, GhClientPair], prApproverGhClientCache *lru.Cache[string, GhClientPair], r *http.Request, payload []byte) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Recovered", "err", r)
		}
	}()

	// We don't use the request context as it might have a short deadline and we don't want to stop event handling based on that
	// But we do want to stop the event handling after a certain point, so:
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var mainGithubClientPair GhClientPair
	var approverGithubClientPair GhClientPair

	slog.Info("Handling event type", "type", fmt.Sprintf("%T", eventPayloadInterface))

	switch eventPayload := eventPayloadInterface.(type) {
	case *github.PushEvent:
		// this is a commit push, do something with it?
		repoOwner := eventPayload.GetRepo().GetOwner().GetLogin()

		mainGithubClientPair.GetAndCache(mainGhClientCache, "GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_OAUTH_TOKEN", repoOwner, ctx)

		prLogger := slog.Default().With(
			"event", eventPayload,
		)

		ghPrClientDetails := Context{
			GhClientPair: &mainGithubClientPair,
			Owner:        repoOwner,
			Repo:         eventPayload.GetRepo().GetName(),
			RepoURL:      eventPayload.GetRepo().GetHTMLURL(),
			PrLogger:     prLogger,
		}

		defaultBranch := eventPayload.GetRepo().GetDefaultBranch()

		if eventPayload.GetRef() != "refs/heads/"+defaultBranch {
			return
		}

		config, _ := GetInRepoConfig(ctx, ghPrClientDetails, defaultBranch)
		listOfChangedFiles := generateListOfChangedFiles(eventPayload)

		handleProxyForward(ctx, config, listOfChangedFiles, r, payload)
	case *github.PullRequestEvent:
		slog.Info("is PullRequestEvent", "action", eventPayload.GetAction())

		prLogger := slog.Default().With(
			"event", eventPayload,
		)

		repoOwner := eventPayload.GetRepo().GetOwner().GetLogin()

		mainGithubClientPair.GetAndCache(mainGhClientCache, "GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_OAUTH_TOKEN", repoOwner, ctx)
		approverGithubClientPair.GetAndCache(prApproverGhClientCache, "APPROVER_GITHUB_APP_ID", "APPROVER_GITHUB_APP_PRIVATE_KEY_PATH", "APPROVER_GITHUB_OAUTH_TOKEN", repoOwner, ctx)

		ghPrClientDetails := Context{
			GhClientPair:  &mainGithubClientPair,
			Labels:        eventPayload.GetPullRequest().Labels,
			Owner:         repoOwner,
			Repo:          eventPayload.GetRepo().GetName(),
			RepoURL:       eventPayload.GetRepo().GetHTMLURL(),
			PrNumber:      eventPayload.GetPullRequest().GetNumber(),
			Ref:           eventPayload.GetPullRequest().GetHead().GetRef(),
			PrAuthor:      eventPayload.GetPullRequest().GetUser().GetLogin(),
			PrLogger:      prLogger,
			PrSHA:         eventPayload.GetPullRequest().GetHead().GetSHA(),
			DefaultBranch: eventPayload.GetRepo().GetDefaultBranch(),
		}

		config, err := GetInRepoConfig(ctx, ghPrClientDetails, ghPrClientDetails.DefaultBranch)
		if err != nil {
			_ = ghPrClientDetails.CommentOnPr(ctx, fmt.Sprintf("Failed to get configuration\n```\n%s\n```\n", err))
			prLogger.Error("Failed to get config", "err", err)
			return
		}

		ghPrClientDetails.getPrMetadata(ctx, eventPayload.GetPullRequest().GetBody())

		switch {
		case eventPayload.GetAction() == "closed" && eventPayload.GetPullRequest().GetMerged():
			HandlePREvent(ctx, "merged", ghPrClientDetails, approverGithubClientPair, config)
		case eventPayload.GetAction() == "opened" || eventPayload.GetAction() == "reopened" || eventPayload.GetAction() == "synchronize":
			HandlePREvent(ctx, "changed", ghPrClientDetails, approverGithubClientPair, config)
		case eventPayload.GetAction() == "labeled" && DoesPrHasLabel(eventPayload.GetPullRequest().Labels, "show-plan"):
			HandlePREvent(ctx, "show-plan", ghPrClientDetails, approverGithubClientPair, config)
		}

	case *github.IssueCommentEvent:
		repoOwner := eventPayload.GetRepo().GetOwner().GetLogin()
		mainGithubClientPair.GetAndCache(mainGhClientCache, "GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_OAUTH_TOKEN", repoOwner, ctx)
		approverGithubClientPair.GetAndCache(prApproverGhClientCache, "APPROVER_GITHUB_APP_ID", "APPROVER_GITHUB_APP_PRIVATE_KEY_PATH", "APPROVER_GITHUB_OAUTH_TOKEN", repoOwner, ctx)

		botIdentity, _ := GetBotGhIdentity(ctx, mainGithubClientPair.v4Client)
		prLogger := slog.Default().With(
			"event", eventPayload,
		)
		// Ignore comment events sent by the bot (this is about who trigger the event not who wrote the comment)
		//
		// Allowing override makes it easier to test locally using a personal
		// token. In those cases Telefonistka can be run with
		// HANDLE_SELF_COMMENT=true to handle comments made manually.
		handleSelf, _ := strconv.ParseBool(os.Getenv("HANDLE_SELF_COMMENT"))
		if !handleSelf || eventPayload.GetSender().GetLogin() == botIdentity {
			slog.Debug("Ignoring self comment")
			return
		}
		ghPrClientDetails := Context{
			GhClientPair: &mainGithubClientPair,
			Owner:        repoOwner,
			Repo:         eventPayload.GetRepo().GetName(),
			RepoURL:      eventPayload.GetRepo().GetHTMLURL(),
			PrNumber:     eventPayload.GetIssue().GetNumber(),
			PrAuthor:     eventPayload.GetIssue().GetUser().GetLogin(),
			PrLogger:     prLogger,
			Labels:       eventPayload.GetIssue().Labels,
		}
		defaultBranch, _ := ghPrClientDetails.GetDefaultBranch(ctx)
		config, err := GetInRepoConfig(ctx, ghPrClientDetails, defaultBranch)
		if err != nil {
			prLogger.Error("Failed to get config", "err", err)
			return
		}
		ghPrClientDetails.getPrMetadata(ctx, eventPayload.GetIssue().GetBody())

		issue := eventPayload.GetIssue()
		owner := ghPrClientDetails.Owner
		repo := ghPrClientDetails.Repo

		// Check if this comment has an attached PR. If it does not we want to skip moving along.
		pr, err := getPR(ctx, ghPrClientDetails.GhClientPair.v3Client.PullRequests, owner, repo, issue.GetNumber())
		if pr == nil || err != nil {
			ghPrClientDetails.PrLogger.Debug("Issue is not a PR")
			return
		}

		// Comment events doesn't have Ref/SHA in payload, enriching the object:
		ghPrClientDetails.Ref = pr.GetHead().GetRef()
		ghPrClientDetails.PrSHA = pr.GetHead().GetSHA()

		retrigger := eventPayload.GetAction() == "created" && isRetriggerComment(eventPayload.GetComment().GetBody())
		if retrigger {
			HandlePREvent(ctx, "changed", ghPrClientDetails, approverGithubClientPair, config)
			return
		}

		if err := handleCommentPrEvent(ctx, ghPrClientDetails, eventPayload, botIdentity, config); err != nil {
			prLogger.Error("Failed to handle comment event", "err", err)
		}
	default:
		return
	}
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

func getPR(ctx context.Context, c *github.PullRequestsService, owner, repo string, number int) (*github.PullRequest, error) {
	pr, res, err := c.Get(ctx, owner, repo, number)
	prom.InstrumentGhCall(res)
	return pr, err
}

func handleCommentPrEvent(ctx context.Context, ghPrClientDetails Context, ce *github.IssueCommentEvent, botIdentity string, config *configuration.Config) error {
	var err error
	// This part should only happen on edits of bot comments on open PRs (I'm not testing Issue vs PR as Telefonsitka only creates PRs at this point)
	if ce.GetAction() == "edited" && ce.GetComment().GetUser().GetLogin() == botIdentity && ce.GetIssue().GetState() == "open" {
		const checkboxIdentifier = "telefonistka-argocd-branch-sync"
		checkboxWaschecked, checkboxIsChecked := analyzeCommentUpdateCheckBox(ce.GetComment().GetBody(), ce.GetChanges().GetBody().GetFrom(), checkboxIdentifier)
		if !checkboxWaschecked && checkboxIsChecked {
			ghPrClientDetails.PrLogger.Info("Sync Checkbox was checked")
			if config.Argocd.AllowSyncfromBranchPathRegex != "" {
				componentPathList, err := generateListOfChangedComponentPaths(ctx, ghPrClientDetails, config)
				if err != nil {
					ghPrClientDetails.PrLogger.Error("Failed to get list of changed components", "err", err)
				}

				for _, componentPath := range componentPathList {
					if isSyncFromBranchAllowedForThisPath(config.Argocd.AllowSyncfromBranchPathRegex, componentPath) {
						err := argocd.SetArgoCDAppRevision(ctx, componentPath, ghPrClientDetails.Ref, ghPrClientDetails.RepoURL, config.Argocd.UseSHALabelForAppDiscovery)
						if err != nil {
							ghPrClientDetails.PrLogger.Error("Failed to sync ArgoCD app from branch", "err", err)
						}
					}
				}
			}
		}
	}

	// I should probably deprecated this whole part altogether - it was designed to solve a *very* specific problem that is probably no longer relevant with GitHub Rulesets
	// The only reason I'm keeping it is that I don't have a clear feature depreciation policy and if I do remove it should be in a distinct PR
	for commentSubstring, commitStatusContext := range config.ToggleCommitStatus {
		if strings.Contains(ce.GetComment().GetBody(), "/"+commentSubstring) {
			err := ghPrClientDetails.ToggleCommitStatus(ctx, commitStatusContext, ce.GetSender().GetName())
			if err != nil {
				ghPrClientDetails.PrLogger.Error("Failed to toggle s context", "context", commitStatusContext, "err", err)
				break
			} else {
				ghPrClientDetails.PrLogger.Info("Toggled status", "context", commitStatusContext)
			}
		}
	}

	return err
}

func commentPlanInPR(ctx context.Context, ghPrClientDetails Context, promotions map[string]PromotionInstance) {
	templateOutput, err := executeTemplate("dryRunMsg", defaultTemplatesFullPath("dry-run-pr-comment.gotmpl"), promotions)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Failed to generate dry-run comment template", "err", err)
		return
	}
	_ = commentPR(ctx, ghPrClientDetails, templateOutput)
}

func executeTemplate(templateName string, templateFile string, data interface{}) (string, error) {
	var templateOutput bytes.Buffer
	messageTemplate, err := template.New(templateName).ParseFiles(templateFile)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}
	err = messageTemplate.ExecuteTemplate(&templateOutput, templateName, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}
	return templateOutput.String(), nil
}

func defaultTemplatesFullPath(templateFile string) string {
	return filepath.Join(getEnv("TEMPLATES_PATH", "templates/") + templateFile)
}

func commentPR(ctx context.Context, ghPrClientDetails Context, commentBody string) error {
	err := ghPrClientDetails.CommentOnPr(ctx, commentBody)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Failed to comment in PR", "err", err)
		return err
	}
	return nil
}

func BumpVersion(ctx context.Context, ghPrClientDetails Context, defaultBranch string, filePath string, newFileContent string, triggeringRepo string, triggeringRepoSHA string, triggeringActor string, autoMerge bool) error {
	var treeEntries []*github.TreeEntry

	generateBumpTreeEntiesForCommit(&treeEntries, ghPrClientDetails, defaultBranch, filePath, newFileContent)

	commit, err := createCommit(ctx, ghPrClientDetails, treeEntries, defaultBranch, "Bumping version @ "+filePath)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Commit creation failed", "err", err)
		return err
	}
	newBranchRef, err := createBranch(ctx, ghPrClientDetails, commit, "artifact_version_bump/"+triggeringRepo+"/"+triggeringRepoSHA) // TODO figure out branch name!!!!
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Branch creation failed", "err", err)
		return err
	}

	newPrTitle := triggeringRepo + "🚠 Bumping version @ " + filePath
	newPrBody := fmt.Sprintf("Bumping version triggered by %s@%s", triggeringRepo, triggeringRepoSHA)
	pr, err := createPrObject(ctx, ghPrClientDetails, newBranchRef, newPrTitle, newPrBody, defaultBranch, triggeringActor)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("PR opening failed", "err", err)
		return err
	}

	ghPrClientDetails.PrLogger.Info("New PR URL", "url", pr.GetHTMLURL())

	if autoMerge {
		ghPrClientDetails.PrLogger.Info("Auto-merging PR")
		err := MergePr(ctx, ghPrClientDetails, pr.GetNumber())
		if err != nil {
			ghPrClientDetails.PrLogger.Error("PR auto merge failed", "err", err)
			return err
		}
	}

	return nil
}

func handleMergedPrEvent(ctx context.Context, ghPrClientDetails Context, prApproverGithubClient *github.Client, config *configuration.Config) error {
	var err error

	// configBranch = default branch as the PR is closed at this and its branch deleted.
	// If we'l ever want to generate this plan on an unmerged PR the PR branch (ghPrClientDetails.Ref) should be used
	promotions, _ := GeneratePromotionPlan(ctx, ghPrClientDetails, config, ghPrClientDetails.DefaultBranch)
	if !config.DryRunMode {
		for _, promotion := range promotions {
			// TODO this whole part shouldn't be in main, but I need to refactor some circular dep's

			// because I use GitHub low level (tree) API the order of operation is somewhat different compared to regular git CLI flow:
			// I create the sync commit against HEAD, create a new branch based on that commit and finally open a PR based on that branch

			var treeEntries []*github.TreeEntry
			for trgt, src := range promotion.ComputedSyncPaths {
				err = GenerateSyncTreeEntriesForCommit(ctx, &treeEntries, ghPrClientDetails, src, trgt, ghPrClientDetails.DefaultBranch)
				if err != nil {
					ghPrClientDetails.PrLogger.Error("Failed to generate treeEntries", "source", src, "target", trgt, "err", err)
				} else {
					ghPrClientDetails.PrLogger.Debug("Generated treeEntries for source and target", "source", src, "target", trgt)
				}
			}

			if len(treeEntries) < 1 {
				ghPrClientDetails.PrLogger.Info("TreeEntries list is empty")
				continue
			}

			commit, err := createCommit(ctx, ghPrClientDetails, treeEntries, ghPrClientDetails.DefaultBranch, "Syncing from "+promotion.Metadata.SourcePath)
			if err != nil {
				ghPrClientDetails.PrLogger.Error("Commit creation failed", "err", err)
				return err
			}

			newBranchName := generateSafePromotionBranchName(ctx, ghPrClientDetails.PrNumber, ghPrClientDetails.Ref, promotion.Metadata.TargetPaths)

			newBranchRef, err := createBranch(ctx, ghPrClientDetails, commit, newBranchName)
			if err != nil {
				ghPrClientDetails.PrLogger.Error("Branch creation failed", "err", err)
				return err
			}

			components := strings.Join(promotion.Metadata.ComponentNames, ",")
			newPrTitle := fmt.Sprintf("🚀 Promotion: %s ➡️  %s", components, promotion.Metadata.TargetDescription)

			var originalPrAuthor string
			// If the triggering PR was opened manually and it doesn't include in-body metadata, use the PR author
			// If the triggering PR as opened by Telefonistka and it has in-body metadata, fetch the original author from there
			if ghPrClientDetails.PrMetadata.OriginalPrAuthor != "" {
				originalPrAuthor = ghPrClientDetails.PrMetadata.OriginalPrAuthor
			} else {
				originalPrAuthor = ghPrClientDetails.PrAuthor
			}

			newPrBody := generatePromotionPrBody(ctx, ghPrClientDetails, components, promotion, originalPrAuthor)

			pull, err := createPrObject(ctx, ghPrClientDetails, newBranchRef, newPrTitle, newPrBody, ghPrClientDetails.DefaultBranch, originalPrAuthor)
			if err != nil {
				ghPrClientDetails.PrLogger.Error("PR opening failed", "err", err)
				return err
			}
			if config.AutoApprovePromotionPrs {
				err := ApprovePr(ctx, prApproverGithubClient, ghPrClientDetails, pull.GetNumber())
				if err != nil {
					ghPrClientDetails.PrLogger.Error("PR auto approval failed", "err", err)
					return err
				}
			}
			if promotion.Metadata.AutoMerge {
				ghPrClientDetails.PrLogger.Info("Auto-merging PR")
				templateData := map[string]interface{}{
					"prNumber": pull.GetNumber(),
				}
				templateOutput, err := executeTemplate("autoMerge", defaultTemplatesFullPath("auto-merge-comment.gotmpl"), templateData)
				if err != nil {
					return err
				}
				err = commentPR(ctx, ghPrClientDetails, templateOutput)
				if err != nil {
					return err
				}

				err = MergePr(ctx, ghPrClientDetails, pull.GetNumber())
				if err != nil {
					ghPrClientDetails.PrLogger.Error("PR auto merge failed", "err", err)
					return err
				}
			}
		}
	} else {
		commentPlanInPR(ctx, ghPrClientDetails, promotions)
	}

	if config.Argocd.AllowSyncfromBranchPathRegex != "" {
		componentPathList, err := generateListOfChangedComponentPaths(ctx, ghPrClientDetails, config)
		if err != nil {
			ghPrClientDetails.PrLogger.Error("Failed to get list of changed components for setting ArgoCD app targetRef to HEAD", "err", err)
		}
		for _, componentPath := range componentPathList {
			if isSyncFromBranchAllowedForThisPath(config.Argocd.AllowSyncfromBranchPathRegex, componentPath) {
				ghPrClientDetails.PrLogger.Info("Ensuring ArgoCD app is set to HEAD", "path", componentPath)
				err := argocd.SetArgoCDAppRevision(ctx, componentPath, "HEAD", ghPrClientDetails.RepoURL, config.Argocd.UseSHALabelForAppDiscovery)
				if err != nil {
					ghPrClientDetails.PrLogger.Error("Failed to set ArgoCD app to HEAD", "path", componentPath, "err", err)
				}
			}
		}
	}

	return err
}

// Creating a unique branch name based on the PR number, PR ref and the promotion target paths
// Max length of branch name is 250 characters
func generateSafePromotionBranchName(ctx context.Context, prNumber int, originalBranchName string, targetPaths []string) string {
	targetPathsBa := []byte(strings.Join(targetPaths, "_"))
	hasher := sha1.New() //nolint:gosec // G505: Blocklisted import crypto/sha1: weak cryptographic primitive (gosec), this is not a cryptographic use case
	hasher.Write(targetPathsBa)
	uniqBranchNameSuffix := firstN(hex.EncodeToString(hasher.Sum(nil)), 12)
	safeOriginalBranchName := firstN(strings.Replace(originalBranchName, "/", "-", -1), 200)
	return fmt.Sprintf("promotions/%v-%v-%v", prNumber, safeOriginalBranchName, uniqBranchNameSuffix)
}

func firstN(str string, n int) string {
	v := []rune(str)
	if n >= len(v) {
		return str
	}
	return string(v[:n])
}

func MergePr(ctx context.Context, details Context, number int) error {
	operation := func() error {
		err := tryMergePR(ctx, details, number)
		if err != nil {
			if isMergeErrorRetryable(err.Error()) {
				if err != nil {
					details.PrLogger.Warn("Failed to merge PR: transient error", "err", err)
				}
				return err
			}
			details.PrLogger.Error("Failed to merge PR", "err", err)
			return backoff.Permanent(err)
		}
		return nil
	}

	// Using default values, see https://pkg.go.dev/github.com/cenkalti/backoff#pkg-constants
	err := backoff.Retry(operation, backoff.NewExponentialBackOff())
	if err != nil {
		details.PrLogger.Error("Failed to merge PR: backoff failed", "err", err)
	}

	return err
}

func tryMergePR(ctx context.Context, details Context, number int) error {
	_, resp, err := details.GhClientPair.v3Client.PullRequests.Merge(ctx, details.Owner, details.Repo, number, "Auto-merge", nil)
	prom.InstrumentGhCall(resp)
	return err
}

func isMergeErrorRetryable(errMessage string) bool {
	return strings.Contains(errMessage, "405") && strings.Contains(errMessage, "try the merge again")
}

func (pm *prMetadata) DeSerialize(s string) error {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	err = json.Unmarshal(decoded, pm)
	return err
}

func (p Context) CommentOnPr(ctx context.Context, commentBody string) error {
	commentBody = "<!-- telefonistka_tag -->\n" + commentBody

	comment := &github.IssueComment{Body: &commentBody}
	_, resp, err := p.GhClientPair.v3Client.Issues.CreateComment(ctx, p.Owner, p.Repo, p.PrNumber, comment)
	prom.InstrumentGhCall(resp)
	if err != nil {
		p.PrLogger.Error("Could not comment in PR", "err", err, "resp", resp)
	}
	return err
}

func DoesPrHasLabel(labels []*github.Label, name string) bool {
	for _, l := range labels {
		if l.GetName() == name {
			return true
		}
	}
	return false
}

func (p *Context) ToggleCommitStatus(ctx context.Context, context string, user string) error {
	var r error
	listOpts := &github.ListOptions{}

	initialStatuses, resp, err := p.GhClientPair.v3Client.Repositories.ListStatuses(ctx, p.Owner, p.Repo, p.Ref, listOpts)
	prom.InstrumentGhCall(resp)
	if err != nil {
		p.PrLogger.Error("Failed to fetch  existing statuses for commit", "commit", p.Ref, "err", err)
		r = err
	}

	for _, commitStatus := range initialStatuses {
		if commitStatus.GetContext() == context {
			if commitStatus.GetState() != "success" {
				p.PrLogger.Info("User toggled state to success", "user", user, "context", context, "state", commitStatus.GetState())
				commitStatus.State = github.String("success")
				_, resp, err := p.GhClientPair.v3Client.Repositories.CreateStatus(ctx, p.Owner, p.Repo, p.PrSHA, commitStatus)
				prom.InstrumentGhCall(resp)
				if err != nil {
					p.PrLogger.Error("Failed to create context", "context", context, "err", err)
					r = err
				}
			} else {
				p.PrLogger.Info("User toggled state to failure", "user", user, "context", context, "state", commitStatus.GetState())
				commitStatus.State = github.String("failure")
				_, resp, err := p.GhClientPair.v3Client.Repositories.CreateStatus(ctx, p.Owner, p.Repo, p.PrSHA, commitStatus)
				prom.InstrumentGhCall(resp)
				if err != nil {
					p.PrLogger.Error("Failed to create context", "context", context, "err", err)
					r = err
				}
			}
			break
		}
	}

	return r
}

func SetCommitStatus(_ context.Context, ghPrClientDetails Context, state string) {
	// TODO change all these values
	tcontext := "telefonistka"
	avatarURL := "https://avatars.githubusercontent.com/u/1616153?s=64"
	description := "Telefonistka GitOps Bot"
	tmplFile := os.Getenv("CUSTOM_COMMIT_STATUS_URL_TEMPLATE_PATH")

	targetURL := commitStatusTargetURL(time.Now(), tmplFile)

	commitStatus := &github.RepoStatus{
		TargetURL:   &targetURL,
		Description: &description,
		State:       &state,
		Context:     &tcontext,
		AvatarURL:   &avatarURL,
	}
	ghPrClientDetails.PrLogger.Debug("Setting commit status", "commit", ghPrClientDetails.PrSHA, "status", state)

	// use a separate context to avoid event processing timeout to cause
	// failures in updating the commit status
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_, resp, err := ghPrClientDetails.GhClientPair.v3Client.Repositories.CreateStatus(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, ghPrClientDetails.PrSHA, commitStatus)
	prom.InstrumentGhCall(resp)
	repoSlug := ghPrClientDetails.Owner + "/" + ghPrClientDetails.Repo
	prom.IncCommitStatusUpdateCounter(repoSlug, state)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Failed to set commit status", "err", err, "resp", resp)
	}
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

func generateDeletionTreeEntries(ctx context.Context, ghPrClientDetails *Context, path *string, branch *string, treeEntries *[]*github.TreeEntry) error {
	// GH tree API doesn't allow deletion a whole dir, so this recursive function traverse the whole tree
	// and create a tree entry array that would delete all the files in that path
	getContentOpts := &github.RepositoryContentGetOptions{
		Ref: *branch,
	}
	_, directoryContent, resp, err := ghPrClientDetails.GhClientPair.v3Client.Repositories.GetContents(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, *path, getContentOpts)
	prom.InstrumentGhCall(resp)
	if resp.StatusCode == 404 {
		ghPrClientDetails.PrLogger.Info("Skipping deletion of non-existing path", "path", *path)
		return nil
	} else if err != nil {
		ghPrClientDetails.PrLogger.Error("Could not fetch content", "path", *path, "err", err, "resp", resp)
		return err
	}
	for _, elementInDir := range directoryContent {
		if elementInDir.GetType() == "file" {
			treeEntry := github.TreeEntry{ // https://docs.github.com/en/rest/git/trees?apiVersion=2022-11-28#create-a-tree
				Path:    elementInDir.Path,
				Mode:    github.String("100644"),
				Type:    github.String("blob"),
				SHA:     nil,
				Content: nil,
			}
			*treeEntries = append(*treeEntries, &treeEntry)
		} else if elementInDir.GetType() == "dir" {
			err := generateDeletionTreeEntries(ctx, ghPrClientDetails, elementInDir.Path, branch, treeEntries)
			if err != nil {
				return err
			}
		} else {
			ghPrClientDetails.PrLogger.Info("Ignoring type for path", "type", elementInDir.GetType(), "path", elementInDir.GetPath())
		}
	}
	return nil
}

func generateBumpTreeEntiesForCommit(treeEntries *[]*github.TreeEntry, ghPrClientDetails Context, defaultBranch string, filePath string, fileContent string) {
	treeEntry := github.TreeEntry{
		Path:    github.String(filePath),
		Mode:    github.String("100644"),
		Type:    github.String("blob"),
		Content: github.String(fileContent),
	}
	*treeEntries = append(*treeEntries, &treeEntry)
}

func getDirecotyGitObjectSha(ctx context.Context, ghPrClientDetails Context, dirPath string, branch string) (string, error) {
	repoContentGetOptions := github.RepositoryContentGetOptions{
		Ref: branch,
	}

	direcotyGitObjectSha := ""
	// in GH API/go-github, to get directory SHA you need to scan the whole parent Dir 🤷
	_, directoryContent, resp, err := ghPrClientDetails.GhClientPair.v3Client.Repositories.GetContents(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, path.Dir(dirPath), &repoContentGetOptions)
	prom.InstrumentGhCall(resp)
	if err != nil && resp.StatusCode != 404 {
		ghPrClientDetails.PrLogger.Error("Could not fetch source directory SHA", "err", err, "resp", resp)
		return "", err
	} else if err == nil { // scaning the parent dir
		for _, dirElement := range directoryContent {
			if dirElement.GetPath() == dirPath {
				direcotyGitObjectSha = dirElement.GetSHA()
				break
			}
		}
	} // leaving out statusCode 404, this means the whole parent dir is missing, but the behavior is similar to the case we didn't find the dir

	return direcotyGitObjectSha, nil
}

func GenerateSyncTreeEntriesForCommit(ctx context.Context, treeEntries *[]*github.TreeEntry, ghPrClientDetails Context, sourcePath string, targetPath string, defaultBranch string) error {
	sourcePathSHA, err := getDirecotyGitObjectSha(ctx, ghPrClientDetails, sourcePath, defaultBranch)

	if sourcePathSHA == "" {
		ghPrClientDetails.PrLogger.Info("Source directory wasn't found, assuming a deletion PR")
		err := generateDeletionTreeEntries(ctx, &ghPrClientDetails, &targetPath, &defaultBranch, treeEntries)
		if err != nil {
			ghPrClientDetails.PrLogger.Error("Failed to build deletion tree", "err", err)
			return err
		}
	} else {
		syncTreeEntry := github.TreeEntry{
			Path: github.String(targetPath),
			Mode: github.String("040000"),
			Type: github.String("tree"),
			SHA:  github.String(sourcePathSHA),
		}
		*treeEntries = append(*treeEntries, &syncTreeEntry)

		// Aperntly... the way we sync directories(set the target dir git tree object SHA) doesn't delete files!!!! GH just "merges" the old and new tree objects.
		// So for now, I'll just go over all the files and add explicitly add  delete tree  entries  :(
		// TODO compare sourcePath targetPath Git object SHA to avoid costly tree compare where possible?
		sourceFilesSHAs := make(map[string]string)
		targetFilesSHAs := make(map[string]string)
		generateFlatMapfromFileTree(ctx, &ghPrClientDetails, &sourcePath, &sourcePath, &defaultBranch, sourceFilesSHAs)
		generateFlatMapfromFileTree(ctx, &ghPrClientDetails, &targetPath, &targetPath, &defaultBranch, targetFilesSHAs)

		for filename := range targetFilesSHAs {
			if _, found := sourceFilesSHAs[filename]; !found {
				ghPrClientDetails.PrLogger.Debug("File was NOT found on source path, marking as a deletion!", "file", filename, "source", sourcePath)
				fileDeleteTreeEntry := github.TreeEntry{
					Path:    github.String(targetPath + "/" + filename),
					Mode:    github.String("100644"),
					Type:    github.String("blob"),
					SHA:     nil, // this is how you delete a file https://docs.github.com/en/rest/git/trees?apiVersion=2022-11-28#create-a-tree
					Content: nil,
				}
				*treeEntries = append(*treeEntries, &fileDeleteTreeEntry)
			}
		}
	}

	return err
}

func createCommit(ctx context.Context, ghPrClientDetails Context, treeEntries []*github.TreeEntry, defaultBranch string, commitMsg string) (*github.Commit, error) {
	// To avoid cloning the repo locally, I'm using GitHub low level GIT Tree API to sync the source folder "over" the target folders
	// This works by getting the source dir git object SHA, and overwriting(Git.CreateTree) the target directory git object SHA with the source's SHA.

	ref, resp, err := ghPrClientDetails.GhClientPair.v3Client.Git.GetRef(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, "heads/"+defaultBranch)
	prom.InstrumentGhCall(resp)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Failed to get main branch ref", "err", err)
		return nil, err
	}
	baseTreeSHA := ref.Object.SHA
	tree, resp, err := ghPrClientDetails.GhClientPair.v3Client.Git.CreateTree(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, *baseTreeSHA, treeEntries)
	prom.InstrumentGhCall(resp)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Failed to create Git Tree object", "err", err, "resp", resp)
		ghPrClientDetails.PrLogger.Error("These are the treeEntries", "entries", treeEntries)
		return nil, err
	}
	parentCommit, resp, err := ghPrClientDetails.GhClientPair.v3Client.Git.GetCommit(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, *baseTreeSHA)
	prom.InstrumentGhCall(resp)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Failed to get parent commit", "err", err)
		return nil, err
	}

	newCommitConfig := &github.Commit{
		Message: github.String(commitMsg),
		Parents: []*github.Commit{parentCommit},
		Tree:    tree,
	}

	commit, resp, err := ghPrClientDetails.GhClientPair.v3Client.Git.CreateCommit(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, newCommitConfig, nil)
	prom.InstrumentGhCall(resp)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Failed to create Git commit", "err", err) // TODO comment this error to PR
		return nil, err
	}

	return commit, err
}

func createBranch(ctx context.Context, ghPrClientDetails Context, commit *github.Commit, newBranchName string) (string, error) {
	newBranchRef := "refs/heads/" + newBranchName
	ghPrClientDetails.PrLogger.Info("New branch name", "name", newBranchName)

	newRefGitObjct := &github.GitObject{
		SHA: commit.SHA,
	}

	newRefConfig := &github.Reference{
		Ref:    github.String(newBranchRef),
		Object: newRefGitObjct,
	}

	_, resp, err := ghPrClientDetails.GhClientPair.v3Client.Git.CreateRef(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, newRefConfig)
	prom.InstrumentGhCall(resp)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Could not create Git Ref", "err", err, "resp", resp)
		return "", err
	}
	ghPrClientDetails.PrLogger.Info("New branch ref", "ref", newBranchRef)
	return newBranchRef, err
}

func generatePromotionPrBody(ctx context.Context, ghPrClientDetails Context, components string, promotion PromotionInstance, originalPrAuthor string) string {
	// newPrMetadata will be serialized and persisted in the PR body for use when the PR is merged
	var newPrMetadata prMetadata
	var newPrBody string

	newPrMetadata.OriginalPrAuthor = originalPrAuthor

	if ghPrClientDetails.PrMetadata.PreviousPromotionMetadata != nil {
		newPrMetadata.PreviousPromotionMetadata = ghPrClientDetails.PrMetadata.PreviousPromotionMetadata
	} else {
		newPrMetadata.PreviousPromotionMetadata = make(map[int]promotionInstanceMetaData)
	}

	newPrMetadata.PreviousPromotionMetadata[ghPrClientDetails.PrNumber] = promotionInstanceMetaData{
		TargetPaths: promotion.Metadata.TargetPaths,
		SourcePath:  promotion.Metadata.SourcePath,
	}
	// newPrMetadata.PreviousPromotionMetadata[ghPrClientDetails.PrNumber].TargetPaths = targetPaths
	// newPrMetadata.PreviousPromotionMetadata[ghPrClientDetails.PrNumber].SourcePath = sourcePath

	newPrMetadata.PromotedPaths = maps.Keys(promotion.ComputedSyncPaths)

	promotionSkipPaths := getPromotionSkipPaths(promotion)

	newPrBody = fmt.Sprintf("Promotion path(%s):\n\n", components)

	keys := make([]int, 0)
	for k := range newPrMetadata.PreviousPromotionMetadata {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	newPrBody = prBody(keys, newPrMetadata, newPrBody, promotionSkipPaths)

	prMetadataString, _ := newPrMetadata.serialize()

	newPrBody = newPrBody + "\n<!--|Telefonistka data, do not delete|" + prMetadataString + "|-->"

	return newPrBody
}

// getPromotionSkipPaths returns a map of paths that are marked as skipped for this promotion
// when we have multiple components, we are going to use the component that has the fewest skip paths
func getPromotionSkipPaths(promotion PromotionInstance) map[string]bool {
	perComponentSkippedTargetPaths := promotion.Metadata.PerComponentSkippedTargetPaths
	promotionSkipPaths := map[string]bool{}

	if len(perComponentSkippedTargetPaths) == 0 {
		return promotionSkipPaths
	}

	// if any promoted component is not in the perComponentSkippedTargetPaths
	// then that means we have a component that is promoted to all paths,
	// therefore, we return an empty promotionSkipPaths map to signify that
	// there are no paths that are skipped for this promotion
	for _, component := range promotion.Metadata.ComponentNames {
		if _, ok := perComponentSkippedTargetPaths[component]; !ok {
			return promotionSkipPaths
		}
	}

	// if we have one or more components then we are just going to
	// user the component that has the fewest skipPaths when
	// generating the promotion prBody. This way the promotion
	// body will error on the side of informing the user
	// of more promotion paths, rather than leaving some out.
	skipCounts := map[string]int{}
	for component, paths := range perComponentSkippedTargetPaths {
		skipCounts[component] = len(paths)
	}

	skipPaths := maps.Keys(skipCounts)
	slices.SortFunc(skipPaths, func(a, b string) int {
		return cmp.Compare(skipCounts[a], skipCounts[b])
	})

	componentWithFewestSkippedPaths := skipPaths[0]
	for _, p := range perComponentSkippedTargetPaths[componentWithFewestSkippedPaths] {
		promotionSkipPaths[p] = true
	}

	return promotionSkipPaths
}

func prBody(keys []int, newPrMetadata prMetadata, newPrBody string, promotionSkipPaths map[string]bool) string {
	const mkTab = "&nbsp;&nbsp;&nbsp;&nbsp;"
	sp := ""
	tp := ""

	for i, k := range keys {
		sp = newPrMetadata.PreviousPromotionMetadata[k].SourcePath
		x := filterSkipPaths(newPrMetadata.PreviousPromotionMetadata[k].TargetPaths, promotionSkipPaths)
		// sort the paths so that we have a predictable order for tests and better readability for users
		sort.Strings(x)
		tp = strings.Join(x, fmt.Sprintf("`  \n%s`", strings.Repeat(mkTab, i+1)))
		newPrBody = newPrBody + fmt.Sprintf("%s↘️  #%d  `%s` ➡️  \n%s`%s`  \n", strings.Repeat(mkTab, i), k, sp, strings.Repeat(mkTab, i+1), tp)
	}

	return newPrBody
}

// filterSkipPaths filters out the paths that are marked as skipped
func filterSkipPaths(targetPaths []string, promotionSkipPaths map[string]bool) []string {
	pathSkip := make(map[string]bool)
	for _, targetPath := range targetPaths {
		if _, ok := promotionSkipPaths[targetPath]; ok {
			pathSkip[targetPath] = true
		} else {
			pathSkip[targetPath] = false
		}
	}

	var paths []string

	for path, skip := range pathSkip {
		if !skip {
			paths = append(paths, path)
		}
	}

	return paths
}

func createPrObject(ctx context.Context, ghPrClientDetails Context, newBranchRef string, newPrTitle string, newPrBody string, defaultBranch string, assignee string) (*github.PullRequest, error) {
	newPrConfig := &github.NewPullRequest{
		Body:  github.String(newPrBody),
		Title: github.String(newPrTitle),
		Base:  github.String(defaultBranch),
		Head:  github.String(newBranchRef),
	}

	pull, resp, err := ghPrClientDetails.GhClientPair.v3Client.PullRequests.Create(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, newPrConfig)
	prom.InstrumentGhCall(resp)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Could not create GitHub PR", "err", err, "resp", resp)
		return nil, err
	} else {
		ghPrClientDetails.PrLogger.Info("PR opened")
	}

	prLables, resp, err := ghPrClientDetails.GhClientPair.v3Client.Issues.AddLabelsToIssue(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, *pull.Number, []string{"promotion"})
	prom.InstrumentGhCall(resp)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Could not label GitHub PR", "err", err, "resp", resp)
		return pull, err
	} else {
		ghPrClientDetails.PrLogger.Debug("PR labeled", "labels", prLables)
	}

	_, resp, err = ghPrClientDetails.GhClientPair.v3Client.Issues.AddAssignees(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, *pull.Number, []string{assignee})
	prom.InstrumentGhCall(resp)
	if err != nil {
		ghPrClientDetails.PrLogger.Warn("Could not set assignee on PR", "user", assignee, "err", err)
		// return pull, err
	} else {
		ghPrClientDetails.PrLogger.Debug("User was set as assignee on PR", "user", assignee)
	}

	return pull, nil // TODO
}

func ApprovePr(ctx context.Context, approverClient *github.Client, ghPrClientDetails Context, prNumber int) error {
	reviewRequest := &github.PullRequestReviewRequest{
		Event: github.String("APPROVE"),
	}

	_, resp, err := approverClient.PullRequests.CreateReview(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, prNumber, reviewRequest)
	prom.InstrumentGhCall(resp)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Could not create review", "err", err, "resp", resp)
		return err
	}

	return nil
}

func GetInRepoConfig(ctx context.Context, ghPrClientDetails Context, defaultBranch string) (*cfg.Config, error) {
	inRepoConfigFileContentString, _, err := GetFileContent(ctx, ghPrClientDetails, defaultBranch, "telefonistka.yaml")
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Could not get in-repo configuration", "err", err)
		inRepoConfigFileContentString = ""
	}
	c, err := cfg.ParseConfigFromYaml(inRepoConfigFileContentString)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Failed to parse configuration", "err", err)
	}
	return c, err
}

func GetFileContent(ctx context.Context, ghPrClientDetails Context, branch string, filePath string) (string, int, error) {
	rGetContentOps := github.RepositoryContentGetOptions{Ref: branch}
	fileContent, _, resp, err := ghPrClientDetails.GhClientPair.v3Client.Repositories.GetContents(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, filePath, &rGetContentOps)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Fail to get file", "err", err, "resp", resp)
		if resp == nil {
			return "", 0, err
		}
		prom.InstrumentGhCall(resp)
		return "", resp.StatusCode, err
	} else {
		prom.InstrumentGhCall(resp)
	}
	fileContentString, err := fileContent.GetContent()
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Fail to serlize file", "err", err)
		return "", resp.StatusCode, err
	}
	return fileContentString, resp.StatusCode, nil
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

	return maps.Keys(fileList)
}

// commitStatusTargetURL generates a target URL based on an optional
// template file specified by the environment variable CUSTOM_COMMIT_STATUS_URL_TEMPLATE_PATH.
// If the template file is not found or an error occurs during template execution,
// it returns a default URL.
// passed parameter commitTime can be used in the template as .CommitTime
func commitStatusTargetURL(commitTime time.Time, tmplFile string) string {
	const targetURL string = "https://github.com/commercetools/telefonistka"

	tmplName := filepath.Base(tmplFile)

	// dynamic parameters to be used in the template
	p := struct {
		CommitTime time.Time
	}{
		CommitTime: commitTime,
	}
	renderedURL, err := executeTemplate(tmplName, tmplFile, p)
	if err != nil {
		slog.Debug("Failed to render target URL template", "err", err)
		return targetURL
	}

	// trim any leading/trailing whitespace
	renderedURL = strings.TrimSpace(renderedURL)
	return renderedURL
}
