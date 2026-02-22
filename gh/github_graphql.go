package gh

import (
	"context"
	"strings"

	"github.com/shurcooL/githubv4"
)

// getBotIdentity retrieves the self identity of the used credentials.
//
// Note that go-github is the preferred way of interacting with GitHub because
// of types and easy API mocking, however some functionality is not available
// in GH V3 rest API.
func getBotIdentity(ctx context.Context, c graphQLClient) (string, error) {
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

func minimizeStalePRComments(ctx context.Context, c Context) error {
	c.PrLogger.Debug("Minimizing stale PR comments")
	botIdentity, err := getBotIdentity(ctx, c.GraphQL)
	if err != nil {
		c.PrLogger.Warn("fetching bot identity", "err", err)
	}
	comments, err := getUnminimizedComments(ctx, c)
	if err != nil {
		c.PrLogger.Error("Failed to get unminimized comments", "err", err)
		return err
	}

	botIdentity = strings.TrimSuffix(botIdentity, "[bot]")
	for _, comment := range comments {
		if shouldMinimize(comment, botIdentity) {
			c.PrLogger.Info("Minimizing Comment", "comment_id", comment.Id)
			err := minimizeComment(ctx, c, comment.Id)
			if err != nil {
				c.PrLogger.Error("Failed to minimize comment", "comment_id", comment.Id, "err", err)
				// Continue to next comment even if one fails
			}
		}
	}

	return nil
}

type prComment struct {
	Id          githubv4.ID
	IsMinimized githubv4.Boolean
	Body        githubv4.String
	Author      struct {
		Login githubv4.String
	}
}

func getUnminimizedComments(ctx context.Context, c Context) ([]prComment, error) {
	var query struct {
		Repository struct {
			PullRequest struct {
				Comments struct {
					Edges []struct {
						Node prComment
					}
				} `graphql:"comments(last: 100)"`
			} `graphql:"pullRequest(number: $prNumber)"`
		} `graphql:"repository(owner: $owner, name: $repo)"`
	}

	params := map[string]interface{}{
		"owner":    githubv4.String(c.Owner),
		"repo":     githubv4.String(c.Repo),
		"prNumber": githubv4.Int(c.PrNumber),
	}

	err := c.GraphQL.Query(ctx, &query, params)
	if err != nil {
		return nil, err
	}

	edges := query.Repository.PullRequest.Comments.Edges
	comments := make([]prComment, len(edges))
	for i, edge := range edges {
		comments[i] = edge.Node
	}

	return comments, nil
}

func shouldMinimize(comment prComment, botIdentity string) bool {
	return !bool(comment.IsMinimized) &&
		string(comment.Author.Login) == botIdentity &&
		strings.Contains(string(comment.Body), "<!-- telefonistka_tag -->")
}

func minimizeComment(ctx context.Context, c Context, commentId githubv4.ID) error {
	var mutation struct {
		MinimizeComment struct {
			MinimizedComment struct {
				IsMinimized githubv4.Boolean
			}
		} `graphql:"minimizeComment(input: $input)"`
	}

	input := githubv4.MinimizeCommentInput{
		SubjectID:  commentId,
		Classifier: githubv4.ReportedContentClassifiersOutdated,
	}

	return c.GraphQL.Mutate(ctx, &mutation, input, nil)
}
