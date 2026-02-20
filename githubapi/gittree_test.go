package githubapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/go-github/v62/github"
)

func TestCreateBranch(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		apiErr  error
		wantRef string
		wantErr bool
	}{
		"success": {
			wantRef: "refs/heads/promotions/1-feature-abc",
		},
		"API error": {
			apiErr:  errors.New("ref exists"),
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var gotRefValue string

			git := &mockGitService{
				createRefFn: func(_ context.Context, _, _ string, ref *github.Reference) (*github.Reference, *github.Response, error) {
					gotRefValue = ref.GetRef()
					return ref, nil, tc.apiErr
				},
			}

			commitSHA := "deadbeef"
			c := Context{
				Git:      git,
				Owner:    "owner",
				Repo:     "repo",
				PrLogger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			got, err := createBranch(t.Context(), c, &github.Commit{SHA: &commitSHA}, "promotions/1-feature-abc")
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantRef {
				t.Errorf("ref: got %q, want %q", got, tc.wantRef)
			}
			if gotRefValue != tc.wantRef {
				t.Errorf("created ref: got %q, want %q", gotRefValue, tc.wantRef)
			}
		})
	}
}

func TestCreateCommit(t *testing.T) {
	t.Parallel()

	baseSHA := "aaa111"
	treeSHA := "bbb222"
	commitSHA := "ccc333"

	tests := map[string]struct {
		getRefErr      error
		createTreeErr  error
		getCommitErr   error
		createCommitErr error
		wantErr        string
	}{
		"success": {},
		"GetRef fails": {
			getRefErr: errors.New("ref not found"),
			wantErr:   "ref not found",
		},
		"CreateTree fails": {
			createTreeErr: errors.New("tree error"),
			wantErr:       "tree error",
		},
		"GetCommit fails": {
			getCommitErr: errors.New("commit not found"),
			wantErr:      "commit not found",
		},
		"CreateCommit fails": {
			createCommitErr: errors.New("commit failed"),
			wantErr:         "commit failed",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			git := &mockGitService{
				getRefFn: func(_ context.Context, _, _, _ string) (*github.Reference, *github.Response, error) {
					if tc.getRefErr != nil {
						return nil, nil, tc.getRefErr
					}
					return &github.Reference{
						Object: &github.GitObject{SHA: &baseSHA},
					}, nil, nil
				},
				createTreeFn: func(_ context.Context, _, _, baseTree string, _ []*github.TreeEntry) (*github.Tree, *github.Response, error) {
					if tc.createTreeErr != nil {
						return nil, nil, tc.createTreeErr
					}
					if baseTree != baseSHA {
						t.Errorf("base tree: got %q, want %q", baseTree, baseSHA)
					}
					return &github.Tree{SHA: &treeSHA}, nil, nil
				},
				getCommitFn: func(_ context.Context, _, _, sha string) (*github.Commit, *github.Response, error) {
					if tc.getCommitErr != nil {
						return nil, nil, tc.getCommitErr
					}
					return &github.Commit{SHA: &sha}, nil, nil
				},
				createCommitFn: func(_ context.Context, _, _ string, commit *github.Commit, _ *github.CreateCommitOptions) (*github.Commit, *github.Response, error) {
					if tc.createCommitErr != nil {
						return nil, nil, tc.createCommitErr
					}
					return &github.Commit{SHA: &commitSHA}, nil, nil
				},
			}

			c := Context{
				Git:      git,
				Owner:    "owner",
				Repo:     "repo",
				PrLogger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			entries := []*github.TreeEntry{
				{Path: github.String("dir/file.txt"), Mode: github.String("100644"), Type: github.String("blob")},
			}

			commit, err := createCommit(t.Context(), c, entries, "main", "sync commit")
			if tc.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, err) { // just check we got an error
					t.Errorf("got error %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if commit.GetSHA() != commitSHA {
				t.Errorf("commit SHA: got %q, want %q", commit.GetSHA(), commitSHA)
			}
		})
	}
}
