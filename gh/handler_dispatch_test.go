package gh

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	cfg "github.com/commercetools/telefonistka/configuration"
	"github.com/commercetools/telefonistka/templates"
	"github.com/google/go-github/v62/github"
)

// testContext builds a Context with sensible mock defaults.
// All service mocks return success with empty results.
// Use opts to override specific fields.
func testContext(t *testing.T, opts ...func(*Context)) Context {
	t.Helper()
	c := Context{
		RepoRef: RepoRef{
			Owner:         "test-owner",
			Repo:          "test-repo",
			RepoURL:       "https://github.com/test-owner/test-repo",
			DefaultBranch: "main",
		},
		PRRef: PRRef{PrNumber: 1, PrAuthor: "author", PrSHA: "abc123", Ref: "feature"},
		Repositories: &mockRepoService{
			createStatusFn: func(_ context.Context, _, _, _ string, _ *github.RepoStatus) (*github.RepoStatus, *github.Response, error) {
				return &github.RepoStatus{}, ghResp(201), nil
			},
			getContentsFn: func(_ context.Context, _, _, _ string, _ *github.RepositoryContentGetOptions) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error) {
				return nil, nil, ghResp(404), nil
			},
		},
		PullRequests: &mockPullRequestService{
			listFilesFn: func(_ context.Context, _, _ string, _ int, _ *github.ListOptions) ([]*github.CommitFile, *github.Response, error) {
				return nil, ghResp(200), nil
			},
		},
		Issues: &mockIssueService{
			createCommentFn: func(_ context.Context, _, _ string, _ int, _ *github.IssueComment) (*github.IssueComment, *github.Response, error) {
				return &github.IssueComment{}, ghResp(201), nil
			},
		},
		GraphQL: &mockGraphQLClient{
			queryFn: func(_ context.Context, _ any, _ map[string]any) error {
				return nil
			},
		},
		PrLogger: slog.Default(),
		Config:   &cfg.Config{},
	}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// statusRecorder returns a createStatusFn that appends each state
// to the provided slice. Safe for concurrent use.
func statusRecorder(mu *sync.Mutex, states *[]string) func(context.Context, string, string, string, *github.RepoStatus) (*github.RepoStatus, *github.Response, error) {
	return func(_ context.Context, _, _, _ string, status *github.RepoStatus) (*github.RepoStatus, *github.Response, error) {
		mu.Lock()
		*states = append(*states, status.GetState())
		mu.Unlock()
		return status, ghResp(201), nil
	}
}

func TestHandlePREvent_StatusTransitions(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		stat       string
		opts       []func(*Context)
		wantStates []string
	}{
		"merged with no promotions": {
			stat:       "merged",
			wantStates: []string{"pending", "success"},
		},
		"changed with no changes": {
			stat:       "changed",
			wantStates: []string{"pending", "success"},
		},
		"show-plan with no promotions": {
			stat:       "show-plan",
			wantStates: []string{"pending", "success"},
		},
		"merged with ListFiles error": {
			stat: "merged",
			opts: []func(*Context){
				func(c *Context) {
					c.PullRequests = &mockPullRequestService{
						listFilesFn: func(_ context.Context, _, _ string, _ int, _ *github.ListOptions) ([]*github.CommitFile, *github.Response, error) {
							return nil, ghResp(500), errors.New("API error")
						},
					}
				},
			},
			wantStates: []string{"pending", "error"},
		},
		"unknown stat does not panic": {
			stat:       "unknown",
			wantStates: []string{"pending", "success"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var mu sync.Mutex
			var states []string
			opts := append(tc.opts, func(c *Context) {
				c.Repositories.(*mockRepoService).createStatusFn = statusRecorder(&mu, &states)
			})
			c := testContext(t, opts...)

			handlePREvent(t.Context(), tc.stat, c, templates.FS, nil, nil)

			mu.Lock()
			defer mu.Unlock()
			if len(states) != len(tc.wantStates) {
				t.Fatalf("got %d status updates %v, want %d %v", len(states), states, len(tc.wantStates), tc.wantStates)
			}
			for i, want := range tc.wantStates {
				if states[i] != want {
					t.Errorf("status[%d] = %q, want %q (full sequence: %v)", i, states[i], want, states)
				}
			}
		})
	}
}

func TestHandleMergedPrEvent_NoPromotions(t *testing.T) {
	t.Parallel()
	c := testContext(t)

	err := handleMergedPrEvent(t.Context(), c, templates.FS, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHandleMergedPrEvent_DryRun(t *testing.T) {
	t.Parallel()

	var commented bool
	c := testContext(t, func(c *Context) {
		c.Config = &cfg.Config{DryRunMode: true}
		c.Issues = &mockIssueService{
			createCommentFn: func(_ context.Context, _, _ string, _ int, _ *github.IssueComment) (*github.IssueComment, *github.Response, error) {
				commented = true
				return &github.IssueComment{}, ghResp(201), nil
			},
		}
	})

	err := handleMergedPrEvent(t.Context(), c, templates.FS, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !commented {
		t.Error("expected dry-run plan comment, got none")
	}
}

func TestHandleChangedPREvent(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		opts    []func(*Context)
		wantErr string
	}{
		"success with no changes": {},
		"minimize error propagates": {
			opts: []func(*Context){
				func(c *Context) {
					c.GraphQL = &mockGraphQLClient{
						queryFn: func(_ context.Context, _ any, _ map[string]any) error {
							return errors.New("graphql unavailable")
						},
					}
				},
			},
			wantErr: "minimizing stale PR comments",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := testContext(t, tc.opts...)

			err := handleChangedPREvent(t.Context(), c, templates.FS, nil)

			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if got := err.Error(); !strings.Contains(got, tc.wantErr) {
				t.Errorf("error = %q, want substring %q", got, tc.wantErr)
			}
		})
	}
}

func TestHandleShowPlanPREvent(t *testing.T) {
	t.Parallel()

	var commented bool
	c := testContext(t, func(c *Context) {
		c.Issues = &mockIssueService{
			createCommentFn: func(_ context.Context, _, _ string, _ int, _ *github.IssueComment) (*github.IssueComment, *github.Response, error) {
				commented = true
				return &github.IssueComment{}, ghResp(201), nil
			},
		}
	})

	err := handleShowPlanPREvent(t.Context(), c, templates.FS)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !commented {
		t.Error("expected plan comment, got none")
	}
}

func TestPrMetadataRoundTrip(t *testing.T) {
	t.Parallel()

	tests := map[string]prMetadata{
		"empty": {},
		"fully populated": {
			OriginalPrAuthor: "alice",
			OriginalPrNumber: 42,
			PromotedPaths:    []string{"env/staging", "env/prod"},
			PreviousPromotionMetadata: map[int]promotionInstanceMetaData{
				1: {SourcePath: "src", TargetPaths: []string{"dst"}},
			},
		},
	}

	for name, pm := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encoded, err := pm.serialize()
			if err != nil {
				t.Fatalf("serialize: %v", err)
			}

			var decoded prMetadata
			if err := decoded.deserialize(encoded); err != nil {
				t.Fatalf("deserialize: %v", err)
			}

			// Compare key fields.
			if decoded.OriginalPrAuthor != pm.OriginalPrAuthor {
				t.Errorf("OriginalPrAuthor = %q, want %q", decoded.OriginalPrAuthor, pm.OriginalPrAuthor)
			}
			if decoded.OriginalPrNumber != pm.OriginalPrNumber {
				t.Errorf("OriginalPrNumber = %d, want %d", decoded.OriginalPrNumber, pm.OriginalPrNumber)
			}
			if len(decoded.PromotedPaths) != len(pm.PromotedPaths) {
				t.Errorf("PromotedPaths len = %d, want %d", len(decoded.PromotedPaths), len(pm.PromotedPaths))
			}
			if len(decoded.PreviousPromotionMetadata) != len(pm.PreviousPromotionMetadata) {
				t.Errorf("PreviousPromotionMetadata len = %d, want %d", len(decoded.PreviousPromotionMetadata), len(pm.PreviousPromotionMetadata))
			}
		})
	}
}

