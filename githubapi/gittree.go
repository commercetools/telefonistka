package githubapi

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: Blocklisted import crypto/sha1: weak cryptographic primitive (gosec), this is not a cryptographic use case
	"encoding/hex"
	"fmt"
	"path"
	"strings"

	prom "github.com/commercetools/telefonistka/prometheus"
	"github.com/google/go-github/v62/github"
)

func generateSyncTreeEntriesForCommit(ctx context.Context, treeEntries *[]*github.TreeEntry, c Context, sourcePath string, targetPath string, defaultBranch string) error {
	sourcePathSHA, err := getDirectoryGitObjectSHA(ctx, c, sourcePath, defaultBranch)
	if err != nil {
		return fmt.Errorf("getting source directory SHA for %s: %w", sourcePath, err)
	}

	if sourcePathSHA == "" {
		c.PrLogger.Info("Source directory wasn't found, assuming a deletion PR")
		if err := generateDeletionTreeEntries(ctx, &c, targetPath, defaultBranch, treeEntries); err != nil {
			c.PrLogger.Error("Failed to build deletion tree", "err", err)
			return err
		}
		return nil
	}

	syncTreeEntry := github.TreeEntry{
		Path: github.String(targetPath),
		Mode: github.String("040000"),
		Type: github.String("tree"),
		SHA:  github.String(sourcePathSHA),
	}
	*treeEntries = append(*treeEntries, &syncTreeEntry)

	// The way we sync directories (set the target dir git tree object SHA) doesn't delete files.
	// GH just "merges" the old and new tree objects, so we explicitly add delete tree entries.
	sourceFilesSHAs := make(map[string]string)
	targetFilesSHAs := make(map[string]string)
	if err := generateFlatMapfromFileTree(ctx, &c, sourcePath, sourcePath, defaultBranch, sourceFilesSHAs); err != nil {
		return fmt.Errorf("listing source tree %s: %w", sourcePath, err)
	}
	if err := generateFlatMapfromFileTree(ctx, &c, targetPath, targetPath, defaultBranch, targetFilesSHAs); err != nil {
		return fmt.Errorf("listing target tree %s: %w", targetPath, err)
	}

	for filename := range targetFilesSHAs {
		if _, found := sourceFilesSHAs[filename]; !found {
			c.PrLogger.Debug("File was NOT found on source path, marking as a deletion!", "file", filename, "source", sourcePath)
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

	return nil
}

func generateDeletionTreeEntries(ctx context.Context, c *Context, path string, branch string, treeEntries *[]*github.TreeEntry) error {
	// GH tree API doesn't allow deleting a whole directory, so this recursive function traverses the whole tree
	// and create a tree entry array that would delete all the files in that path
	getContentOpts := &github.RepositoryContentGetOptions{
		Ref: branch,
	}
	_, directoryContent, resp, err := c.Repositories.GetContents(ctx, c.Owner, c.Repo, path, getContentOpts)
	prom.InstrumentGhCall(resp)
	if resp.StatusCode == 404 {
		c.PrLogger.Info("Skipping deletion of non-existing path", "path", path)
		return nil
	} else if err != nil {
		c.PrLogger.Error("Could not fetch content", "path", path, "err", err, "resp", resp)
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
			err := generateDeletionTreeEntries(ctx, c, elementInDir.GetPath(), branch, treeEntries)
			if err != nil {
				return err
			}
		} else {
			c.PrLogger.Info("Ignoring type for path", "type", elementInDir.GetType(), "path", elementInDir.GetPath())
		}
	}
	return nil
}

func getDirectoryGitObjectSHA(ctx context.Context, c Context, dirPath string, branch string) (string, error) {
	repoContentGetOptions := github.RepositoryContentGetOptions{
		Ref: branch,
	}

	directoryGitObjectSHA := ""
	// in GH API/go-github, to get directory SHA you need to scan the whole parent Dir 🤷
	_, directoryContent, resp, err := c.Repositories.GetContents(ctx, c.Owner, c.Repo, path.Dir(dirPath), &repoContentGetOptions)
	prom.InstrumentGhCall(resp)
	if err != nil && resp.StatusCode != 404 {
		c.PrLogger.Error("Could not fetch source directory SHA", "err", err, "resp", resp)
		return "", err
	} else if err == nil { // scanning the parent dir
		for _, dirElement := range directoryContent {
			if dirElement.GetPath() == dirPath {
				directoryGitObjectSHA = dirElement.GetSHA()
				break
			}
		}
	} // leaving out statusCode 404, this means the whole parent dir is missing, but the behavior is similar to the case we didn't find the dir

	return directoryGitObjectSHA, nil
}

func createCommit(ctx context.Context, c Context, treeEntries []*github.TreeEntry, defaultBranch string, commitMsg string) (*github.Commit, error) {
	// To avoid cloning the repo locally, I'm using GitHub low level GIT Tree API to sync the source folder "over" the target folders
	// This works by getting the source dir git object SHA, and overwriting(Git.CreateTree) the target directory git object SHA with the source's SHA.

	ref, resp, err := c.Git.GetRef(ctx, c.Owner, c.Repo, "heads/"+defaultBranch)
	prom.InstrumentGhCall(resp)
	if err != nil {
		c.PrLogger.Error("Failed to get main branch ref", "err", err)
		return nil, err
	}
	baseTreeSHA := ref.Object.SHA
	tree, resp, err := c.Git.CreateTree(ctx, c.Owner, c.Repo, *baseTreeSHA, treeEntries)
	prom.InstrumentGhCall(resp)
	if err != nil {
		c.PrLogger.Error("Failed to create Git Tree object", "err", err, "resp", resp)
		c.PrLogger.Error("These are the treeEntries", "entries", treeEntries)
		return nil, err
	}
	parentCommit, resp, err := c.Git.GetCommit(ctx, c.Owner, c.Repo, *baseTreeSHA)
	prom.InstrumentGhCall(resp)
	if err != nil {
		c.PrLogger.Error("Failed to get parent commit", "err", err)
		return nil, err
	}

	newCommitConfig := &github.Commit{
		Message: github.String(commitMsg),
		Parents: []*github.Commit{parentCommit},
		Tree:    tree,
	}

	commit, resp, err := c.Git.CreateCommit(ctx, c.Owner, c.Repo, newCommitConfig, nil)
	prom.InstrumentGhCall(resp)
	if err != nil {
		c.PrLogger.Error("Failed to create Git commit", "err", err) // TODO comment this error to PR
		return nil, err
	}

	return commit, err
}

func createBranch(ctx context.Context, c Context, commit *github.Commit, newBranchName string) (string, error) {
	newBranchRef := "refs/heads/" + newBranchName
	c.PrLogger.Info("New branch name", "name", newBranchName)

	newRefGitObject := &github.GitObject{
		SHA: commit.SHA,
	}

	newRefConfig := &github.Reference{
		Ref:    github.String(newBranchRef),
		Object: newRefGitObject,
	}

	_, resp, err := c.Git.CreateRef(ctx, c.Owner, c.Repo, newRefConfig)
	prom.InstrumentGhCall(resp)
	if err != nil {
		c.PrLogger.Error("Could not create Git Ref", "err", err, "resp", resp)
		return "", err
	}
	c.PrLogger.Info("New branch ref", "ref", newBranchRef)
	return newBranchRef, err
}

// generateSafePromotionBranchName creates a unique branch name based on the PR number, PR ref and the promotion
// target paths. Max length of branch name is 250 characters.
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
