package gh

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
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
				RepoRef: RepoRef{
					Owner:    "owner",
					Repo:     "repo",
				},
				Git:      git,
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
				RepoRef: RepoRef{
					Owner:    "owner",
					Repo:     "repo",
				},
				Git:      git,
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

func TestGetDirectoryGitObjectSHA(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		dirPath  string
		dirItems []*github.RepositoryContent
		apiErr   error
		respCode int
		wantSHA  string
		wantErr  bool
	}{
		"found in parent listing": {
			dirPath: "env/dev",
			dirItems: []*github.RepositoryContent{
				{Path: github.String("env/staging"), SHA: github.String("aaa")},
				{Path: github.String("env/dev"), SHA: github.String("bbb")},
			},
			respCode: 200,
			wantSHA:  "bbb",
		},
		"not found in parent listing": {
			dirPath: "env/dev",
			dirItems: []*github.RepositoryContent{
				{Path: github.String("env/staging"), SHA: github.String("aaa")},
			},
			respCode: 200,
			wantSHA:  "",
		},
		"parent dir missing (404)": {
			dirPath:  "env/dev",
			apiErr:   errors.New("not found"),
			respCode: 404,
			wantSHA:  "",
		},
		"API error (non-404)": {
			dirPath:  "env/dev",
			apiErr:   errors.New("server error"),
			respCode: 500,
			wantErr:  true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			repos := &mockRepoService{
				getContentsFn: func(_ context.Context, _, _, _ string, _ *github.RepositoryContentGetOptions) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error) {
					return nil, tc.dirItems, ghResp(tc.respCode), tc.apiErr
				},
			}

			c := Context{
				RepoRef: RepoRef{
					Owner:        "owner",
					Repo:         "repo",
				},
				Repositories: repos,
				PrLogger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			sha, err := getDirectoryGitObjectSHA(t.Context(), c, tc.dirPath, "main")
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sha != tc.wantSHA {
				t.Errorf("SHA: got %q, want %q", sha, tc.wantSHA)
			}
		})
	}
}

func TestGenerateDeletionTreeEntries(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// contents maps path → directory listing returned by GetContents
		contents map[string][]*github.RepositoryContent
		// respCodes maps path → HTTP status code
		respCodes map[string]int
		// errors maps path → error
		errors    map[string]error
		wantPaths []string
		wantErr   bool
	}{
		"flat directory": {
			contents: map[string][]*github.RepositoryContent{
				"target/app": {
					{Path: github.String("target/app/values.yaml"), Type: github.String("file")},
					{Path: github.String("target/app/chart.yaml"), Type: github.String("file")},
				},
			},
			respCodes: map[string]int{"target/app": 200},
			wantPaths: []string{"target/app/values.yaml", "target/app/chart.yaml"},
		},
		"nested directory": {
			contents: map[string][]*github.RepositoryContent{
				"target/app": {
					{Path: github.String("target/app/file.yaml"), Type: github.String("file")},
					{Path: github.String("target/app/sub"), Type: github.String("dir")},
				},
				"target/app/sub": {
					{Path: github.String("target/app/sub/nested.yaml"), Type: github.String("file")},
				},
			},
			respCodes: map[string]int{"target/app": 200, "target/app/sub": 200},
			wantPaths: []string{"target/app/file.yaml", "target/app/sub/nested.yaml"},
		},
		"path does not exist (404)": {
			respCodes: map[string]int{"target/app": 404},
			wantPaths: nil,
		},
		"API error": {
			respCodes: map[string]int{"target/app": 500},
			errors:    map[string]error{"target/app": errors.New("server error")},
			wantErr:   true,
		},
		"ignores non-file non-dir types": {
			contents: map[string][]*github.RepositoryContent{
				"target/app": {
					{Path: github.String("target/app/file.yaml"), Type: github.String("file")},
					{Path: github.String("target/app/link"), Type: github.String("symlink")},
				},
			},
			respCodes: map[string]int{"target/app": 200},
			wantPaths: []string{"target/app/file.yaml"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			repos := &mockRepoService{
				getContentsFn: func(_ context.Context, _, _, path string, _ *github.RepositoryContentGetOptions) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error) {
					code := tc.respCodes[path]
					if code == 0 {
						code = 200
					}
					return nil, tc.contents[path], ghResp(code), tc.errors[path]
				},
			}

			c := Context{
				RepoRef: RepoRef{
					Owner:        "owner",
					Repo:         "repo",
				},
				Repositories: repos,
				PrLogger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			var entries []*github.TreeEntry
			path := "target/app"
			branch := "main"
			err := generateDeletionTreeEntries(t.Context(), &c, path, branch, &entries)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var gotPaths []string
			for _, e := range entries {
				gotPaths = append(gotPaths, e.GetPath())
				if e.SHA != nil {
					t.Errorf("deletion entry for %q should have nil SHA", e.GetPath())
				}
			}

			slices.Sort(gotPaths)
			want := slices.Clone(tc.wantPaths)
			slices.Sort(want)

			if len(gotPaths) != len(want) {
				t.Fatalf("entries: got %v, want %v", gotPaths, want)
			}
			for i := range gotPaths {
				if gotPaths[i] != want[i] {
					t.Errorf("entry[%d]: got %q, want %q", i, gotPaths[i], want[i])
				}
			}
		})
	}
}
