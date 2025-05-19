package githubapi

import (
	"context"
	"strings"

	"github.com/shurcooL/githubv4"
)

// GetBotGhIdentity retrieves the self identity of the used credentials.
//
// Note that go-github is the preferred way of interacting with GitHub because
// of types and easy API mocking, however some functionality is not available
// in GH V3 rest API.
func GetBotGhIdentity(ctx context.Context, c *githubv4.Client) (string, error) {
	var query struct {
		Viewer struct {
			Login githubv4.String
		}
	}

	err := c.Query(ctx, &query, nil)
	if err != nil {
		return "", err
	}
	return string(query.Viewer.Login), nil
}

func MimizeStalePrComments(ctx context.Context, ghPrClientDetails GhPrClientDetails, botIdentity string) error {
	var getCommentNodeIdsQuery struct {
		Repository struct {
			PullRequest struct {
				Title    githubv4.String
				Comments struct {
					Edges []struct {
						Node struct {
							Id          githubv4.ID
							IsMinimized githubv4.Boolean
							Body        githubv4.String
							Author      struct {
								Login githubv4.String
							}
						}
					}
				} `graphql:"comments(last: 100)"`
			} `graphql:"pullRequest(number: $prNumber )"`
		} `graphql:"repository(owner: $owner, name: $repo)"`
	} // Mimizing stale comment is not crutial so only taking the last 100 comments, should cover most cases.
	// Would be nice if I could filter based on Author and isMinized here, in the query,  to get just the relevant ones,
	// but I don't think GH graphQL supports it, so for now I just filter in code, see conditioanl near the end of this function.

	getCommentNodeIdsParams := map[string]interface{}{
		"owner":    githubv4.String(ghPrClientDetails.Owner),
		"repo":     githubv4.String(ghPrClientDetails.Repo),
		"prNumber": githubv4.Int(ghPrClientDetails.PrNumber), //nolint:gosec // G115: type mismatch between shurcooL/githubv4 and google/go-github. Number taken from latter for use in query using former.
	}

	var minimizeCommentMutation struct {
		MinimizeComment struct {
			ClientMutationId githubv4.ID
			MinimizedComment struct {
				IsMinimized githubv4.Boolean
			}
		} `graphql:"minimizeComment(input: $input)"`
	}

	err := ghPrClientDetails.GhClientPair.v4Client.Query(ctx, &getCommentNodeIdsQuery, getCommentNodeIdsParams)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Failed to minimize stale comments", "err", err)
	}
	bi := githubv4.String(strings.TrimSuffix(botIdentity, "[bot]"))
	for _, prComment := range getCommentNodeIdsQuery.Repository.PullRequest.Comments.Edges {
		if !prComment.Node.IsMinimized && prComment.Node.Author.Login == bi {
			if strings.Contains(string(prComment.Node.Body), "<!-- telefonistka_tag -->") {
				ghPrClientDetails.PrLogger.Info("Minimizing Comment", "comment_id", prComment.Node.Id)
				minimizeCommentInput := githubv4.MinimizeCommentInput{
					SubjectID:        prComment.Node.Id,
					Classifier:       githubv4.ReportedContentClassifiers("OUTDATED"),
					ClientMutationID: &bi,
				}
				err := ghPrClientDetails.GhClientPair.v4Client.Mutate(ctx, &minimizeCommentMutation, minimizeCommentInput, nil)
				// As far as I can tell minimizeComment Github's grpahQL method doesn't accept list do doing one call per comment
				if err != nil {
					ghPrClientDetails.PrLogger.Error("Failed to minimize comment", "comment_id", prComment.Node.Id, "err", err)
					// Handle error.
				}
			} else {
				ghPrClientDetails.PrLogger.Debug("Ignoring comment without identification tag")
			}
		}
	}

	return err
}
