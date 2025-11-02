package githubapi

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	prom "github.com/commercetools/telefonistka/internal/pkg/prometheus"
	"github.com/google/go-github/v62/github"
	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
)

func generateDiffOutput(ctx context.Context, c Context, sourceFilesSHAs map[string]string, targetFilesSHAs map[string]string, sourcePath string, targetPath string) (bool, string, error) {
	var hasDiff bool
	var diffOutput bytes.Buffer
	var filesWithDiff []string
	diffOutput.WriteString("\n```diff\n")

	// staring with collecting files with different content and file only present in the source dir
	for filename, sha := range sourceFilesSHAs {
		c.PrLogger.Debug("Looking at file", "file", filename)
		targetPathfileSha, found := targetFilesSHAs[filename]
		if !found {
			hasDiff = true
			diffOutput.WriteString(fmt.Sprintf("--- %s/%s (missing from target dir %s)\n", sourcePath, filename, targetPath))
			continue
		}

		if sha == targetPathfileSha {
			c.PrLogger.Debug("Source is identical to target", "source", sourcePath+"/"+filename, "target", targetPath+"/"+filename)
			continue
		}

		c.PrLogger.Debug("Source s is different from target", "source", sourcePath+"/"+filename, "target", targetPath+"/"+filename)
		hasDiff = true
		sourceFileContent, _, _ := GetFileContent(ctx, c, c.DefaultBranch, sourcePath+"/"+filename)
		targetFileContent, _, _ := GetFileContent(ctx, c, c.DefaultBranch, targetPath+"/"+filename)

		edits := myers.ComputeEdits(span.URIFromPath(filename), sourceFileContent, targetFileContent)
		diffOutput.WriteString(fmt.Sprint(gotextdiff.ToUnified(sourcePath+"/"+filename, targetPath+"/"+filename, sourceFileContent, edits)))
		filesWithDiff = append(filesWithDiff, sourcePath+"/"+filename)
	}

	// then going over the target to check files that only exists there
	for filename := range targetFilesSHAs {
		if _, found := sourceFilesSHAs[filename]; !found {
			diffOutput.WriteString(fmt.Sprintf("+++ %s/%s (missing from source dir %s)\n", targetPath, filename, sourcePath))
			hasDiff = true
		}
	}

	diffOutput.WriteString("\n```\n")

	if len(filesWithDiff) != 0 {
		diffOutput.WriteString("\n### Blame Links:\n")
		blameUrlPrefix := c.getBlameURLPrefix(ctx)

		for _, f := range filesWithDiff {
			diffOutput.WriteString("[" + f + "](" + blameUrlPrefix + "/HEAD/" + f + ")\n") // TODO consider switching HEAD to specific SHA
		}
	}

	return hasDiff, diffOutput.String(), nil
}

func CompareRepoDirectories(ctx context.Context, c Context, sourcePath string, targetPath string, defaultBranch string) (bool, string, error) {
	// Compares two directories content

	// comparing sourcePath targetPath Git object SHA to avoid costly tree compare:
	sourcePathGitObjectSha, err := getDirecotyGitObjectSha(ctx, c, sourcePath, defaultBranch)
	if err != nil {
		c.PrLogger.Error("Couldn't get source, Git object sha", "path", sourcePath, "err", err)
		return false, "", err
	}
	targetPathGitObjectSha, err := getDirecotyGitObjectSha(ctx, c, targetPath, defaultBranch)
	if err != nil {
		c.PrLogger.Error("Couldn't get targetv, Git object sha", "target", targetPath, "err", err)
		return false, "", err
	}

	if sourcePathGitObjectSha == targetPathGitObjectSha {
		c.PrLogger.Debug("Source and target git object SHA matched.", "source", sourcePath, "source_sha", sourcePathGitObjectSha, "target", targetPath, "target_sha", targetPathGitObjectSha)
		return false, "", nil
	} else {
		c.PrLogger.Debug("Source and target git object SHA didn't match! Will do a full tree compare",
			"source", sourcePath, "source_sha", sourcePathGitObjectSha, "target", targetPath, "target_sha", targetPathGitObjectSha)
		sourceFilesSHAs := make(map[string]string)
		targetFilesSHAs := make(map[string]string)
		hasDiff := false

		generateFlatMapfromFileTree(ctx, &c, &sourcePath, &sourcePath, &defaultBranch, sourceFilesSHAs)
		generateFlatMapfromFileTree(ctx, &c, &targetPath, &targetPath, &defaultBranch, targetFilesSHAs)
		// ghPrClientDetails.PrLogger.Infoln(sourceFilesSHAs)
		hasDiff, diffOutput, err := generateDiffOutput(ctx, c, sourceFilesSHAs, targetFilesSHAs, sourcePath, targetPath)

		return hasDiff, diffOutput, err
	}
}

func generateFlatMapfromFileTree(ctx context.Context, c *Context, workingPath *string, rootPath *string, branch *string, listOfFiles map[string]string) {
	getContentOpts := &github.RepositoryContentGetOptions{
		Ref: *branch,
	}
	_, directoryContent, resp, _ := c.GhClientPair.v3Client.Repositories.GetContents(ctx, c.Owner, c.Repo, *workingPath, getContentOpts)
	prom.InstrumentGhCall(resp)
	for _, elementInDir := range directoryContent {
		if *elementInDir.Type == "file" {
			relativeName := strings.TrimPrefix(*elementInDir.Path, *rootPath+"/")
			listOfFiles[relativeName] = *elementInDir.SHA
		} else if *elementInDir.Type == "dir" {
			generateFlatMapfromFileTree(ctx, c, elementInDir.Path, rootPath, branch, listOfFiles)
		} else {
			c.PrLogger.Info("Ignoring type for path", "type", *elementInDir.Type, "path", *elementInDir.Path)
		}
	}
}
