package githubapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/commercetools/telefonistka/configuration"
	"github.com/google/go-github/v62/github"
)

func TestCommentOnPr(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		apiErr  error
		body    string
		wantErr bool
	}{
		"success": {
			body: "hello world",
		},
		"prepends telefonistka tag": {
			body: "test body",
		},
		"API error": {
			body:    "fail",
			apiErr:  errors.New("forbidden"),
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var gotBody string
			var gotNumber int

			issues := &mockIssueService{
				createCommentFn: func(_ context.Context, _, _ string, number int, comment *github.IssueComment) (*github.IssueComment, *github.Response, error) {
					gotBody = comment.GetBody()
					gotNumber = number
					return comment, nil, tc.apiErr
				},
			}

			c := Context{
				Issues:   issues,
				Owner:    "owner",
				Repo:     "repo",
				PrNumber: 42,
				PrLogger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			err := c.commentOnPr(t.Context(), tc.body)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotNumber != 42 {
				t.Errorf("PR number: got %d, want 42", gotNumber)
			}
			if !strings.HasPrefix(gotBody, "<!-- telefonistka_tag -->") {
				t.Errorf("comment body missing telefonistka tag prefix: %q", gotBody)
			}
			if !strings.Contains(gotBody, tc.body) {
				t.Errorf("comment body missing original text %q in %q", tc.body, gotBody)
			}
		})
	}
}

func TestApprovePr(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		autoApprove bool
		apiErr      error
		wantCalled  bool
		wantErr     bool
	}{
		"auto-approve enabled": {
			autoApprove: true,
			wantCalled:  true,
		},
		"auto-approve disabled": {
			autoApprove: false,
			wantCalled:  false,
		},
		"API error": {
			autoApprove: true,
			apiErr:      errors.New("review failed"),
			wantCalled:  true,
			wantErr:     true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var called bool
			var gotEvent string

			approver := &mockPullRequestService{
				createReviewFn: func(_ context.Context, _, _ string, _ int, review *github.PullRequestReviewRequest) (*github.PullRequestReview, *github.Response, error) {
					called = true
					gotEvent = review.GetEvent()
					return nil, nil, tc.apiErr
				},
			}

			c := Context{
				ApproverPRs: approver,
				Owner:       "owner",
				Repo:        "repo",
				PrNumber:    42,
				PrLogger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
				Config: &configuration.Config{
					AutoApprovePromotionPrs: tc.autoApprove,
				},
			}

			err := ApprovePr(t.Context(), c)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if called != tc.wantCalled {
				t.Errorf("API called: got %v, want %v", called, tc.wantCalled)
			}
			if tc.wantCalled && gotEvent != "APPROVE" {
				t.Errorf("review event: got %q, want %q", gotEvent, "APPROVE")
			}
		})
	}
}

func TestMergePr(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mergeErr error
		wantErr  bool
	}{
		"success": {},
		"permanent error": {
			mergeErr: errors.New("merge conflict"),
			wantErr:  true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var gotNumber int

			prs := &mockPullRequestService{
				mergeFn: func(_ context.Context, _, _ string, number int, _ string, _ *github.PullRequestOptions) (*github.PullRequestMergeResult, *github.Response, error) {
					gotNumber = number
					return nil, nil, tc.mergeErr
				},
			}

			c := Context{
				PullRequests: prs,
				Owner:        "owner",
				Repo:         "repo",
				PrNumber:     99,
				PrLogger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			err := MergePr(t.Context(), c)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotNumber != 99 {
				t.Errorf("PR number: got %d, want 99", gotNumber)
			}
		})
	}
}

func TestCreatePrObject(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		createErr  error
		labelErr   error
		assignErr  error
		wantErr    bool
		wantPullNr int
	}{
		"success": {
			wantPullNr: 10,
		},
		"PR creation fails": {
			createErr: errors.New("create failed"),
			wantErr:   true,
		},
		"label fails": {
			labelErr:   errors.New("label failed"),
			wantErr:    true,
			wantPullNr: 10,
		},
		"assignee fails is non-fatal": {
			assignErr:  errors.New("assignee failed"),
			wantPullNr: 10,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var gotTitle string
			var labelsCalled, assigneesCalled bool

			pullNr := 10
			prs := &mockPullRequestService{
				createFn: func(_ context.Context, _, _ string, pr *github.NewPullRequest) (*github.PullRequest, *github.Response, error) {
					gotTitle = pr.GetTitle()
					if tc.createErr != nil {
						return nil, nil, tc.createErr
					}
					return &github.PullRequest{Number: &pullNr}, nil, nil
				},
			}

			issues := &mockIssueService{
				addLabelsFn: func(_ context.Context, _, _ string, _ int, labels []string) ([]*github.Label, *github.Response, error) {
					labelsCalled = true
					if tc.labelErr != nil {
						return nil, nil, tc.labelErr
					}
					return nil, nil, nil
				},
				addAssigneesFn: func(_ context.Context, _, _ string, _ int, assignees []string) (*github.Issue, *github.Response, error) {
					assigneesCalled = true
					return nil, nil, tc.assignErr
				},
			}

			c := Context{
				PullRequests: prs,
				Issues:       issues,
				Owner:        "owner",
				Repo:         "repo",
				PrLogger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			pull, err := createPrObject(t.Context(), c, "refs/heads/promo/1", "Promo Title", "body", "main", "alice")
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotTitle != "Promo Title" {
				t.Errorf("title: got %q, want %q", gotTitle, "Promo Title")
			}
			if pull.GetNumber() != tc.wantPullNr {
				t.Errorf("PR number: got %d, want %d", pull.GetNumber(), tc.wantPullNr)
			}
			if !labelsCalled {
				t.Error("expected AddLabelsToIssue to be called")
			}
			if tc.assignErr != nil && !assigneesCalled {
				t.Error("expected AddAssignees to be called")
			}
		})
	}
}
