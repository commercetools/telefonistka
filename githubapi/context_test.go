package githubapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/go-github/v62/github"
)

func TestGetDefaultBranch(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cached    string
		mockRepo *github.Repository
		mockErr  error
		want     string
		wantErr  bool
	}{
		"returns cached value without API call": {
			cached: "develop",
			want:   "develop",
		},
		"fetches from API when not cached": {
			mockRepo: &github.Repository{DefaultBranch: github.String("main")},
			want:     "main",
		},
		"API error": {
			mockErr: errors.New("not found"),
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var apiCalled bool

			repos := &mockRepoService{
				getFn: func(_ context.Context, _, _ string) (*github.Repository, *github.Response, error) {
					apiCalled = true
					return tc.mockRepo, nil, tc.mockErr
				},
			}

			c := &Context{
				Repositories:  repos,
				DefaultBranch: tc.cached,
				Owner:         "owner",
				Repo:          "repo",
				PrLogger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			got, err := c.GetDefaultBranch(t.Context())
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if tc.cached != "" && apiCalled {
				t.Error("API was called despite cached value")
			}
		})
	}
}
