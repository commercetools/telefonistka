package telefonistka

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/commercetools/telefonistka/internal/pkg/githubapi"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	"github.com/spf13/cobra"
)

// This is still(https://github.com/spf13/cobra/issues/1862) the documented way to use cobra
func init() { //nolint:gochecknoinits
	var targetRepo string
	var targetFile string
	var file string
	var githubHost string
	var triggeringRepo string
	var triggeringRepoSHA string
	var triggeringActor string
	var autoMerge bool
	eventCmd := &cobra.Command{
		Use:   "bump-overwrite",
		Short: "Bump artifact version based on provided file content.",
		Long:  "Bump artifact version based on provided file content.\nThis open a pull request in the target repo.",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			bumpVersionOverwrite(targetRepo, targetFile, file, githubHost, triggeringRepo, triggeringRepoSHA, triggeringActor, autoMerge)
		},
	}
	eventCmd.Flags().StringVarP(&targetRepo, "target-repo", "t", getEnv("TARGET_REPO", ""), "Target Git repository slug(e.g. org-name/repo-name), defaults to TARGET_REPO env var.")
	eventCmd.Flags().StringVarP(&targetFile, "target-file", "f", getEnv("TARGET_FILE", ""), "Target file path(from repo root), defaults to TARGET_FILE env var.")
	eventCmd.Flags().StringVarP(&file, "file", "c", "", "File that holds the content the target file will be overwritten with, like \"version.yaml\" or '<(echo -e \"image:\\n  tag: ${VERSION}\")'.")
	eventCmd.Flags().StringVarP(&githubHost, "github-host", "g", "", "GitHub instance HOSTNAME, defaults to \"github.com\". This is used for GitHub Enterprise Server instances.")
	eventCmd.Flags().StringVarP(&triggeringRepo, "triggering-repo", "p", getEnv("GITHUB_REPOSITORY", ""), "Github repo triggering the version bump(e.g. `octocat/Hello-World`) defaults to GITHUB_REPOSITORY env var.")
	eventCmd.Flags().StringVarP(&triggeringRepoSHA, "triggering-repo-sha", "s", getEnv("GITHUB_SHA", ""), "Git SHA of triggering repo, defaults to GITHUB_SHA env var.")
	eventCmd.Flags().StringVarP(&triggeringActor, "triggering-actor", "a", getEnv("GITHUB_ACTOR", ""), "GitHub user of the person/bot who triggered the bump, defaults to GITHUB_ACTOR env var.")
	eventCmd.Flags().BoolVar(&autoMerge, "auto-merge", false, "Automatically merges the created PR, defaults to false.")
	rootCmd.AddCommand(eventCmd)
}

func bumpVersionOverwrite(targetRepo string, targetFile string, file string, githubHost string, triggeringRepo string, triggeringRepoSHA string, triggeringActor string, autoMerge bool) {
	b, err := os.ReadFile(file)
	if err != nil {
		slog.Error("Failed to read file", "file", file, "err", err)
		os.Exit(1)
	}
	newFileContent := string(b)

	ctx := context.Background()
	var githubRestAltURL string

	if githubHost != "" {
		githubRestAltURL = "https://" + githubHost + "/api/v3"
		slog.Info("Github REST API endpoint is configured", "url", githubRestAltURL)
	}
	var mainGithubClientPair githubapi.GhClientPair
	mainGhClientCache, _ := lru.New[string, githubapi.GhClientPair](128)

	mainGithubClientPair.GetAndCache(mainGhClientCache, "GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_OAUTH_TOKEN", strings.Split(targetRepo, "/")[0], ctx)

	var ghPrClientDetails githubapi.GhPrClientDetails

	ghPrClientDetails.GhClientPair = &mainGithubClientPair
	ghPrClientDetails.Owner = strings.Split(targetRepo, "/")[0]
	ghPrClientDetails.Repo = strings.Split(targetRepo, "/")[1]
	ghPrClientDetails.PrLogger = slog.Default() // TODO what fields should be here?

	defaultBranch, _ := ghPrClientDetails.GetDefaultBranch(ctx)
	initialFileContent, statusCode, err := githubapi.GetFileContent(ctx, ghPrClientDetails, defaultBranch, targetFile)
	if statusCode == 404 {
		ghPrClientDetails.PrLogger.Info("File was not found", "file", targetFile)
	} else if err != nil {
		ghPrClientDetails.PrLogger.Error("Fail to fetch file content", "err", err)
		os.Exit(1)
	}

	edits := myers.ComputeEdits(span.URIFromPath(""), initialFileContent, newFileContent)
	ghPrClientDetails.PrLogger.Info("Diff", "diff", gotextdiff.ToUnified("Before", "After", initialFileContent, edits))

	err = githubapi.BumpVersion(ctx, ghPrClientDetails, "main", targetFile, newFileContent, triggeringRepo, triggeringRepoSHA, triggeringActor, autoMerge)
	if err != nil {
		slog.Error("Failed to bump version", "err", err)
		os.Exit(1)
	}
}
