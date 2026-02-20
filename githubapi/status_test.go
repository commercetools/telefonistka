package githubapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/go-github/v62/github"
)

func TestSetCommitStatus(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		state   string
		wantErr bool
	}{
		"pending": {state: "pending"},
		"success": {state: "success"},
		"error":   {state: "error"},
		"API failure is logged not returned": {
			state:   "pending",
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var gotState, gotRef string

			repos := &mockRepoService{
				createStatusFn: func(_ context.Context, _, _, ref string, status *github.RepoStatus) (*github.RepoStatus, *github.Response, error) {
					gotState = status.GetState()
					gotRef = ref
					if tc.wantErr {
						return nil, nil, errors.New("api error")
					}
					return status, nil, nil
				},
			}

			c := Context{
				Repositories: repos,
				Owner:        "owner",
				Repo:         "repo",
				PrSHA:        "abc123",
				PrLogger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			// SetCommitStatus doesn't return an error, it logs failures.
			setCommitStatus(t.Context(), c, tc.state)

			if gotRef != "abc123" {
				t.Errorf("ref: got %q, want %q", gotRef, "abc123")
			}
			if !tc.wantErr && gotState != tc.state {
				t.Errorf("state: got %q, want %q", gotState, tc.state)
			}
		})
	}
}

func TestToggleCommitStatus(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		existing  []*github.RepoStatus
		listErr   error
		createErr error
		context   string
		wantState string
		wantErr   bool
	}{
		"toggle failure to success": {
			existing: []*github.RepoStatus{
				{Context: github.String("ci/test"), State: github.String("failure")},
			},
			context:   "ci/test",
			wantState: "success",
		},
		"toggle success to failure": {
			existing: []*github.RepoStatus{
				{Context: github.String("ci/test"), State: github.String("success")},
			},
			context:   "ci/test",
			wantState: "failure",
		},
		"context not found": {
			existing: []*github.RepoStatus{
				{Context: github.String("other"), State: github.String("success")},
			},
			context:   "ci/test",
			wantState: "", // no toggle happens
		},
		"list error": {
			listErr: errors.New("list failed"),
			context: "ci/test",
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var createdState string

			repos := &mockRepoService{
				listStatusesFn: func(_ context.Context, _, _, _ string, _ *github.ListOptions) ([]*github.RepoStatus, *github.Response, error) {
					return tc.existing, nil, tc.listErr
				},
				createStatusFn: func(_ context.Context, _, _, _ string, status *github.RepoStatus) (*github.RepoStatus, *github.Response, error) {
					createdState = status.GetState()
					if tc.createErr != nil {
						return nil, nil, tc.createErr
					}
					return status, nil, nil
				},
			}

			c := &Context{
				Repositories: repos,
				Owner:        "owner",
				Repo:         "repo",
				Ref:          "refs/heads/main",
				PrSHA:        "abc123",
				PrLogger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			err := c.toggleCommitStatus(t.Context(), tc.context, "user")
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantState != "" && createdState != tc.wantState {
				t.Errorf("toggled state: got %q, want %q", createdState, tc.wantState)
			}
		})
	}
}
