package gh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/commercetools/telefonistka/argocd"
	"github.com/commercetools/telefonistka/diff"
	prom "github.com/commercetools/telefonistka/prometheus"
	"github.com/google/go-github/v62/github"
	"github.com/nao1215/markdown"
)

const githubCommentMaxSize = 65536

// componentDiffResult holds the diff output for a single component.
type componentDiffResult struct {
	ComponentPath            string
	AppName                  string
	AppURL                   string
	DiffElements             []diff.Element
	DiffError                error
	AppWasTemporarilyCreated bool
	AppSyncedFromPRBranch    bool
	HealthStatus             string
	SyncStatus               string
	AutoSyncEnabled          bool
	IsRemoval                bool
}

type diffCommentData struct {
	DiffOfChangedComponents   []componentDiffResult
	DisplaySyncBranchCheckBox bool
	BranchName                string
}

// componentDiffReq describes one component to diff.
type componentDiffReq struct {
	path        string
	includeDiff bool
	isRemoval   bool
}

// shouldSyncBranchCheckBoxBeDisplayed checks if the sync branch checkbox should be displayed in the PR comment.
// The checkbox should be displayed if:
// - The component is allowed to be synced from a branch (based on Telefonistka configuration)
// - The relevant app is not new, temporary app that was created just to generate the diff
func shouldSyncBranchCheckBoxBeDisplayed(ctx context.Context, componentPathList []string, allowSyncfromBranchPathRegex string, diffOfChangedComponents []componentDiffResult) bool {
	for _, componentPath := range componentPathList {
		if !isSyncFromBranchAllowedForThisPath(allowSyncfromBranchPathRegex, componentPath) {
			continue
		}
		for _, diffOfChangedComponent := range diffOfChangedComponents {
			if diffOfChangedComponent.ComponentPath == componentPath && !diffOfChangedComponent.AppWasTemporarilyCreated && !diffOfChangedComponent.AppSyncedFromPRBranch {
				return true
			}
		}
	}
	return false
}

// diffComponentsFull orchestrates diffs for all components
// concurrently, using the argocd building blocks directly.
func diffComponentsFull(ctx context.Context, reqs []componentDiffReq, repo, prBranch string, ac argocd.Clients, cfg argocd.DiffConfig, logger *slog.Logger) ([]componentDiffResult, error) {
	server, err := argocd.FetchServerInfo(ctx, ac)
	if err != nil {
		return nil, err
	}

	ch := make(chan componentDiffResult, len(reqs))
	for _, req := range reqs {
		go func(req componentDiffReq) {
			r := componentDiffResult{
				ComponentPath: req.path,
				IsRemoval:     req.isRemoval,
			}

			info, err := argocd.EnsureApp(ctx, req.path, repo, prBranch, ac, cfg, logger)
			if err != nil {
				r.DiffError = err
				ch <- r
				return
			}
			defer info.Cleanup()

			r.AppWasTemporarilyCreated = info.TempCreated
			r.AppName = info.Name
			r.AppURL = server.AppURL(info.Name)
			r.HealthStatus = info.HealthStatus
			r.SyncStatus = info.SyncStatus
			r.AutoSyncEnabled = info.AutoSyncEnabled

			if info.TargetRevision == prBranch && info.AutoSyncEnabled {
				r.AppSyncedFromPRBranch = true
				ch <- r
				return
			}

			live, err := argocd.FetchLive(ctx, ac, info, logger)
			if err != nil {
				r.DiffError = err
				ch <- r
				return
			}

			var target argocd.ResourceSet
			if !req.isRemoval {
				target, err = argocd.FetchTarget(ctx, ac, info, prBranch, logger)
				if err != nil {
					r.DiffError = err
					ch <- r
					return
				}
			}

			pairs, err := argocd.PairResources(live, target, info, server)
			if err != nil {
				r.DiffError = err
				ch <- r
				return
			}

			for _, pair := range pairs {
				de, err := diff.FormatPairDiff(pair, req.includeDiff)
				if err != nil {
					r.DiffError = fmt.Errorf("formatting diff for %s/%s: %w", pair.Kind, pair.Name, err)
					ch <- r
					return
				}
				if de.Diff == "" {
					continue
				}
				r.DiffElements = append(r.DiffElements, de)
			}
			ch <- r
		}(req)
	}

	results := make([]componentDiffResult, 0, len(reqs))
	for range reqs {
		r := <-ch
		if r.DiffError != nil {
			logger.Error("generating diff", "component_path", r.ComponentPath, "err", r.DiffError)
		}
		results = append(results, r)
	}
	return results, nil
}

// isComponentRemoval checks whether the component directory exists
// at the PR branch ref. A 404 means the PR removes this component.
func isComponentRemoval(ctx context.Context, repos repoService, owner, repo, componentPath, ref string) bool {
	_, _, resp, _ := repos.GetContents(ctx, owner, repo, componentPath, &github.RepositoryContentGetOptions{Ref: ref})
	prom.InstrumentGhCall(resp)
	return resp != nil && resp.StatusCode == 404
}

func commentDiff(ctx context.Context, c Context, argoClients *argocd.Clients) error {
	c.PrLogger.Debug("Commenting ArgoCD diff")
	if !c.Config.Argocd.CommentDiffonPR || argoClients == nil {
		return nil
	}
	componentPathList, err := generateListOfChangedComponentPaths(ctx, c)
	if err != nil {
		return fmt.Errorf("generate list of changed components: %w", err)
	}

	var reqs []componentDiffReq
	for _, componentPath := range componentPathList {
		conf, err := getComponentConfig(ctx, c, componentPath, c.Ref)
		if err != nil {
			return fmt.Errorf("get component (%s) config:  %w", componentPath, err)
		}
		includeDiff := !conf.DisableArgoCDDiff
		if !includeDiff {
			c.PrLogger.Debug("ArgoCD diff disabled for path", "path", componentPath)
		}
		removal := isComponentRemoval(ctx, c.Repositories, c.Owner, c.Repo, componentPath, c.Ref)
		if removal {
			c.PrLogger.Info("Component directory absent on PR branch, treating as removal", "path", componentPath)
		}
		reqs = append(reqs, componentDiffReq{
			path:        componentPath,
			includeDiff: includeDiff,
			isRemoval:   removal,
		})
	}

	diffOfChangedComponents, err := diffComponentsFull(ctx, reqs, c.RepoURL, c.Ref, *argoClients, argocd.DiffConfig{
		UseSHALabel:    c.Config.Argocd.UseSHALabelForAppDiscovery,
		CreateTempApps: c.Config.Argocd.CreateTempAppObjectFroNewApps,
	}, c.PrLogger)
	if err != nil {
		return fmt.Errorf("getting diff information: %w", err)
	}
	c.PrLogger.Debug("Successfully got ArgoCD diff(comparing live objects against objects rendered form git ref)", "ref", c.Ref)

	var hasComponentDiff, hasComponentDiffErrors bool
	for _, r := range diffOfChangedComponents {
		if len(r.DiffElements) > 0 {
			hasComponentDiff = true
		}
		if r.DiffError != nil {
			hasComponentDiffErrors = true
		}
	}
	if !hasComponentDiffErrors && !hasComponentDiff {
		c.PrLogger.Debug("ArgoCD diff is empty, this PR will not change cluster state", "components_checked", len(reqs))
		prLabels, resp, err := c.Issues.AddLabelsToIssue(ctx, c.Owner, c.Repo, c.PrNumber, []string{"noop"})
		prom.InstrumentGhCall(resp)
		if err != nil {
			c.PrLogger.Error("Could not label GitHub PR", "err", err, "resp", resp)
		} else {
			c.PrLogger.Debug("PR labeled", "labels", prLabels)
		}
		if doesPRHaveLabel(c.Labels, "promotion") && c.Config.Argocd.AutoMergeNoDiffPRs && len(componentPathList) > 0 {
			c.PrLogger.Info("Auto-merging (no diff) PR")
			err := mergePr(ctx, c)
			if err != nil {
				return fmt.Errorf("PR auto merge: %w", err)
			}
		}
	}

	if len(diffOfChangedComponents) > 0 {
		data := diffCommentData{
			DiffOfChangedComponents: diffOfChangedComponents,
			BranchName:              c.Ref,
		}
		data.DisplaySyncBranchCheckBox = shouldSyncBranchCheckBoxBeDisplayed(ctx, componentPathList, c.Config.Argocd.AllowSyncfromBranchPathRegex, diffOfChangedComponents)
		componentsToDiffJSON, _ := json.Marshal(reqs)
		c.PrLogger.Info("Generating ArgoCD Diff Comment for components", "components", string(componentsToDiffJSON), "diff_element_length", len(data.DiffOfChangedComponents))
		comments, err := generateArgoCdDiffComments(data, githubCommentMaxSize)
		if err != nil {
			return fmt.Errorf("generate diff comment: %w", err)
		}
		for _, comment := range comments {
			err = c.commentOnPr(ctx, comment)
			if err != nil {
				return fmt.Errorf("commenting on PR: %w", err)
			}
		}
	} else {
		c.PrLogger.Debug("Did not find affected ArgoCD apps", "components_checked", len(componentPathList))
	}
	return nil
}

func buildArgoCdDiffComment(diffCommentData diffCommentData, beConcise bool, partNumber int, totalParts int) (string, error) {
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
			md.PlainTextf("Please check the App Conditions of %s %s for more details.", argoSmallLogo, markdown.Bold(markdown.Link(appDiffResult.AppName, appDiffResult.AppURL)))
			if appDiffResult.AppWasTemporarilyCreated {
				md.Note("A temporary ArgoCD application was created for this diff and has been cleaned up.")
			}
			md.CodeBlocks(markdown.SyntaxHighlightNone, appDiffResult.DiffError.Error())
		} else {
			md.PlainTextf("%s %s @ %s", argoSmallLogo, markdown.Bold(markdown.Link(appDiffResult.AppName, appDiffResult.AppURL)), markdown.Code(appDiffResult.ComponentPath))

			if appDiffResult.IsRemoval {
				md.Warningf("This component is being **removed**. All resources below will be deleted from the cluster.")
			}

			// If the app was temporarily created, we should inform the user about it, if not we should inform about "unusual" health and sync status
			if appDiffResult.AppWasTemporarilyCreated {
				md.Note("Telefonistka has temporarily created an ArgoCD app object to render manifest previews.  \n> Please be aware:  \n> * The app will only appear in the ArgoCD UI for a few seconds.")
			} else if !appDiffResult.IsRemoval {
				if appDiffResult.HealthStatus != "Healthy" {
					md.Cautionf("The ArgoCD app health status is currently %s", appDiffResult.HealthStatus)
				}
				if appDiffResult.SyncStatus != "Synced" {
					md.Warningf("The ArgoCD app sync status is currently %s", appDiffResult.SyncStatus)
				}
				if !appDiffResult.AutoSyncEnabled {
					md.Note("This ArgoCD app doesn't have `auto-sync` enabled, merging this PR will **not** apply changes to cluster without additional actions.")
				}
			}
			if len(appDiffResult.DiffElements) > 0 {
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
					md.PlainText("No diff \U0001F937")
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

func generateArgoCdDiffComments(diffCommentData diffCommentData, githubCommentMaxSize int) (comments []string, err error) {
	commentBody, err := buildArgoCdDiffComment(diffCommentData, false, 0, 0)
	if err != nil {
		return comments, fmt.Errorf("building full diff comment: %w", err)
	}

	// Happy path — the diff comment fits in one comment.
	if len(commentBody) < githubCommentMaxSize {
		comments = append(comments, commentBody)
		return comments, nil
	}

	// Comment is too large; split into one comment per component.
	totalComponents := len(diffCommentData.DiffOfChangedComponents)
	for i, singleComponentDiff := range diffCommentData.DiffOfChangedComponents {
		componentTemplateData := diffCommentData
		componentTemplateData.DiffOfChangedComponents = []componentDiffResult{singleComponentDiff}
		commentBody, err := buildArgoCdDiffComment(componentTemplateData, false, i+1, totalComponents)
		if err != nil {
			return comments, fmt.Errorf("building diff comment for component %d/%d: %w", i+1, totalComponents, err)
		}

		// Per-component comment fits — use it.
		if len(commentBody) < githubCommentMaxSize {
			comments = append(comments, commentBody)
			continue
		}

		// Last resort: concise template.
		commentBody, err = buildArgoCdDiffComment(componentTemplateData, true, i+1, totalComponents)
		if err != nil {
			return comments, fmt.Errorf("building concise diff comment for component %d/%d: %w", i+1, totalComponents, err)
		}
		comments = append(comments, commentBody)
	}

	return comments, nil
}
