package githubapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/commercetools/telefonistka/argocd"
	prom "github.com/commercetools/telefonistka/prometheus"
	"github.com/nao1215/markdown"
)

const githubCommentMaxSize = 65536

type diffCommentData struct {
	DiffOfChangedComponents   []argocd.DiffResult
	DisplaySyncBranchCheckBox bool
	BranchName                string
}

// shouldSyncBranchCheckBoxBeDisplayed checks if the sync branch checkbox should be displayed in the PR comment.
// The checkbox should be displayed if:
// - The component is allowed to be synced from a branch (based on Telefonistka configuration)
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

func commentDiff(ctx context.Context, c Context, argoClients *argocd.ArgoCDClients) error {
	if !c.Config.Argocd.CommentDiffonPR || argoClients == nil {
		return nil
	}
	componentPathList, err := generateListOfChangedComponentPaths(ctx, c)
	if err != nil {
		return fmt.Errorf("generate list of changed components: %w", err)
	}

	// Building a map of component paths to a boolean indicating whether we should diff them.
	// I'm avoiding doing this in the ArgoCD package to avoid circular dependencies and keep package scope clean
	componentsToDiff := map[string]bool{}
	for _, componentPath := range componentPathList {
		conf, err := getComponentConfig(ctx, c, componentPath, c.Ref)
		if err != nil {
			return fmt.Errorf("get component (%s) config:  %w", componentPath, err)
		}
		componentsToDiff[componentPath] = true
		if conf.DisableArgoCDDiff {
			componentsToDiff[componentPath] = false
			c.PrLogger.Debug("ArgoCD diff disabled for path", "path", componentPath)
		}
	}

	hasComponentDiff, hasComponentDiffErrors, diffOfChangedComponents, err := argocd.GenerateDiffOfChangedComponents(ctx, componentsToDiff, c.Ref, c.RepoURL, argocd.DiffConfig{
		UseSHALabel:    c.Config.Argocd.UseSHALabelForAppDiscovery,
		CreateTempApps: c.Config.Argocd.CreateTempAppObjectFroNewApps,
	}, *argoClients)
	if err != nil {
		return fmt.Errorf("getting diff information: %w", err)
	}
	c.PrLogger.Debug("Successfully got ArgoCD diff(comparing live objects against objects rendered form git ref)", "ref", c.Ref)
	if !hasComponentDiffErrors && !hasComponentDiff {
		c.PrLogger.Debug("ArgoCD diff is empty, this PR will not change cluster state")
		prLabels, resp, err := c.Issues.AddLabelsToIssue(ctx, c.Owner, c.Repo, c.PrNumber, []string{"noop"})
		prom.InstrumentGhCall(resp)
		if err != nil {
			c.PrLogger.Error("Could not label GitHub PR", "err", err, "resp", resp)
		} else {
			c.PrLogger.Debug("PR labeled", "labels", prLabels)
		}
		// If the PR is a promotion PR and the diff is empty, we can auto-merge it
		// "len(componentPathList) > 0"  validates we are not auto-merging a PR that we failed to understand which apps it affects
		if doesPRHaveLabel(c.Labels, "promotion") && c.Config.Argocd.AutoMergeNoDiffPRs && len(componentPathList) > 0 {
			c.PrLogger.Info("Auto-merging (no diff) PR")
			err := mergePr(ctx, c)
			if err != nil {
				return fmt.Errorf("PR auto merge: %w", err)
			}
		}
	}

	if len(diffOfChangedComponents) > 0 {
		diffCommentData := diffCommentData{
			DiffOfChangedComponents: diffOfChangedComponents,
			BranchName:              c.Ref,
		}

		diffCommentData.DisplaySyncBranchCheckBox = shouldSyncBranchCheckBoxBeDisplayed(ctx, componentPathList, c.Config.Argocd.AllowSyncfromBranchPathRegex, diffOfChangedComponents)
		componentsToDiffJSON, _ := json.Marshal(componentsToDiff)
		c.PrLogger.Info("Generating ArgoCD Diff Comment for components", "components", string(componentsToDiffJSON), "diff_element_length", len(diffCommentData.DiffOfChangedComponents))
		comments, err := generateArgoCdDiffComments(diffCommentData, githubCommentMaxSize)
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
		c.PrLogger.Debug("Did not find affected ArgoCD apps")
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
			md.PlainTextf("Please check the App Conditions of %s %s for more details.", argoSmallLogo, markdown.Bold(markdown.Link(appDiffResult.ArgoCdAppName, appDiffResult.ArgoCdAppURL)))
			if appDiffResult.AppWasTemporarilyCreated {
				md.Note("A temporary ArgoCD application was created for this diff and has been cleaned up.")
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
					md.Note("This ArgoCD app doesn't have `auto-sync` enabled, merging this PR will **not** apply changes to cluster without additional actions.")
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

func generateArgoCdDiffComments(diffCommentData diffCommentData, githubCommentMaxSize int) (comments []string, err error) {
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
		commentBody, err := buildArgoCdDiffComment(componentTemplateData, false, i+1, totalComponents)
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
		commentBody, err = buildArgoCdDiffComment(componentTemplateData, true, i+1, totalComponents)
		if err != nil {
			slog.Error("Failed to build ArgoCD diff comment", "err", err)
			return comments, err
		}
		comments = append(comments, commentBody)
	}

	return comments, nil
}
