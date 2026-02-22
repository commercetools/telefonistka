package gh

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"

	cfg "github.com/commercetools/telefonistka/configuration"
	"github.com/go-test/deep"
	"github.com/google/go-github/v62/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
)

func generatePromotionPlanMetadataTestHelper(t *testing.T, config *cfg.Config, expectedPromotion map[string]promotionInstance, mockedHTTPClient *http.Client) {
	t.Helper()
	v3Client := github.NewClient(mockedHTTPClient)
	labelName := "fast-promotion"

	ghPrClientDetails := Context{
		RepoRef: RepoRef{
			Owner:        "AnOwner",
			Repo:         "Arepo",
		},
		PRRef: PRRef{
			PrNumber:     120,
			Ref:          "Abranch",
		},
		Repositories: v3Client.Repositories,
		PullRequests: v3Client.PullRequests,
		PrLogger: slog.Default().With(
			"repo", "AnOwner/Arepo",
			"prNumber", 120,
		),
		Labels: []*github.Label{
			{Name: &labelName},
		},
		Config: config,
	}

	promotionPlan, err := generatePromotionPlan(t.Context(), ghPrClientDetails, "main")
	if err != nil {
		t.Fatalf("Failed to generate promotion plan: err=%s", err)
	}

	// Just check the metadata, this can ignore issues with promotion logic itself
	// Like if a whole element is missing from the generated promotion plan.
	for k, v := range expectedPromotion {
		if diff := deep.Equal(v.Metadata, promotionPlan[k].Metadata); diff != nil {
			t.Error(diff)
		}
	}
}

func generatePromotionPlanTestHelper(t *testing.T, config *cfg.Config, mockedHTTPClient *http.Client, expectedPromotions ...map[string]promotionInstance) {
	t.Helper()
	v3Client := github.NewClient(mockedHTTPClient)
	labelName := "fast-promotion"

	ghPrClientDetails := Context{
		RepoRef: RepoRef{
			Owner:        "AnOwner",
			Repo:         "Arepo",
		},
		PRRef: PRRef{
			PrNumber:     120,
			Ref:          "Abranch",
		},
		Repositories: v3Client.Repositories,
		PullRequests: v3Client.PullRequests,
		PrLogger: slog.Default().With(
			"repo", "AnOwner/Arepo",
			"prNumber", 120,
		),
		Labels: []*github.Label{
			{Name: &labelName},
		},
		Config: config,
	}

	promotionPlan, err := generatePromotionPlan(t.Context(), ghPrClientDetails, "main")
	if err != nil {
		t.Fatalf("Failed to generate promotion plan: err=%s", err)
	}

	expectedPromotionMatched := false
	diffs := []string{}
	for _, expectedPromotion := range expectedPromotions {
		if diff := deep.Equal(expectedPromotion, promotionPlan); diff != nil {
			diffs = append(diffs, diff...)
			continue
		}
		expectedPromotionMatched = true
		break
	}
	if !expectedPromotionMatched {
		if len(diffs) == 0 {
			t.Fatal("expected promotion plan did not match any provided expectations")
		}
		for _, diff := range diffs {
			t.Logf("diff: %s", diff)
		}
		t.Fatalf("expected promotion plan did not match any provided expectations out of %d candidates", len(expectedPromotions))
	}
}

func newPromotionTestHTTPClient(t *testing.T, filenames []string, extraOptions ...mock.MockBackendOption) *http.Client {
	t.Helper()

	commitFiles := make([]*github.CommitFile, 0, len(filenames))
	for _, filename := range filenames {
		name := filename // avoid pointer reuse
		commitFiles = append(commitFiles, &github.CommitFile{Filename: &name})
	}

	options := []mock.MockBackendOption{
		mock.WithRequestMatch(
			mock.GetReposPullsFilesByOwnerByRepoByPullNumber,
			commitFiles,
		),
	}
	options = append(options, extraOptions...)
	// This default handler can be overridden by extraOptions
	options = append(options,
		mock.WithRequestMatchHandler(
			mock.GetReposContentsByOwnerByRepoByPath,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mock.WriteError(
					w,
					http.StatusNotFound,
					"no *optional* in-component telefonistka config file",
				)
			}),
		),
	)

	return mock.NewMockedHTTPClient(options...)
}

func TestGeneratePromotionConditionalPlan(t *testing.T) {
	t.Parallel()
	config := &cfg.Config{
		PromotionPaths: []cfg.PromotionPath{
			{
				SourcePath: "prod/us-east-4/",
				Conditions: cfg.Condition{
					PrHasLabels: []string{
						"non-existing-label", // Fake label not used in the PR struct
					},
				},
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetPaths: []string{
							"prod/not-selected-1/",
							"prod/not-selected-2/",
						},
					},
				},
			},
			{
				SourcePath: "prod/us-east-4/",
				Conditions: cfg.Condition{
					PrHasLabels: []string{
						"fast-promotion", // This label is used in the PR struct
					},
				},
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetPaths: []string{
							"prod/eu-west-1/",
							"prod/eu-east-1/",
						},
					},
				},
			},
			{
				SourcePath: "prod/us-east-4/",
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetPaths: []string{
							"prod/not-selected-3/", // Just a catch-all that shouldn't be used
							"prod/not-selected-4/",
						},
					},
				},
			},
		},
	}

	expectedPromotion := map[string]promotionInstance{
		"prod/us-east-4/>prod/eu-east-1/|prod/eu-west-1/": {
			ComputedSyncPaths: map[string]string{
				"prod/eu-east-1/componentA": "prod/us-east-4/componentA",
				"prod/eu-west-1/componentA": "prod/us-east-4/componentA",
			},
		},
	}
	mockedHTTPClient := newPromotionTestHTTPClient(t, []string{
		"prod/us-east-4/componentA/file.yaml",
		"prod/us-east-4/componentA/file2.yaml",
		"prod/us-east-4/componentA/aSubDir/file3.yaml",
		".ci-config/random-file.json",
	})
	generatePromotionPlanTestHelper(t, config, mockedHTTPClient, expectedPromotion)
}

func TestAggregatePromotionPlan(t *testing.T) {
	// This one tests two identical components that match the same source regex should only generate a single promotion
	// This is relevant for PRs that where generated by a multi target promotion plan.
	// It should only aggregate components that match the same SourcePath regex and targets , this is why dev/us-east-4 and dev/us-east-5 are combined
	// And lab/us-east-5 should not
	t.Parallel()
	config := &cfg.Config{
		PromotionPaths: []cfg.PromotionPath{
			{
				SourcePath: "dev/[^/]*/",
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetPaths: []string{
							"prod/eu-west-1/",
							"prod/eu-east-1/",
						},
					},
				},
			},
			{
				SourcePath: "lab/[^/]*/",
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetPaths: []string{
							"prod/us-west-1/",
							"prod/us-east-1/",
						},
					},
				},
			},
		},
	}

	expectedPromotions := []map[string]promotionInstance{
		{
			"dev/[^/]*/>prod/eu-east-1/|prod/eu-west-1/": {
				ComputedSyncPaths: map[string]string{
					"prod/eu-east-1/componentA": "dev/us-east-5/componentA",
					"prod/eu-west-1/componentA": "dev/us-east-5/componentA",
				},
			},
			"lab/[^/]*/>prod/us-east-1/|prod/us-west-1/": {
				ComputedSyncPaths: map[string]string{
					"prod/us-east-1/componentA": "lab/us-east-5/componentA",
					"prod/us-west-1/componentA": "lab/us-east-5/componentA",
				},
			},
		},
		{
			"dev/[^/]*/>prod/eu-east-1/|prod/eu-west-1/": {
				ComputedSyncPaths: map[string]string{
					"prod/eu-east-1/componentA": "dev/us-east-4/componentA",
					"prod/eu-west-1/componentA": "dev/us-east-4/componentA",
				},
			},
			"lab/[^/]*/>prod/us-east-1/|prod/us-west-1/": {
				ComputedSyncPaths: map[string]string{
					"prod/us-east-1/componentA": "lab/us-east-5/componentA",
					"prod/us-west-1/componentA": "lab/us-east-5/componentA",
				},
			},
		},
	}

	mockedHTTPClient := newPromotionTestHTTPClient(t, []string{
		"dev/us-east-4/componentA/file.yaml",
		"dev/us-east-5/componentA/file.yaml",
		"lab/us-east-5/componentA/file.yaml",
	})
	generatePromotionPlanTestHelper(t, config, mockedHTTPClient, expectedPromotions...)
}

func TestGenerateSourceRegexPromotionPlan(t *testing.T) {
	t.Parallel()
	config := &cfg.Config{
		PromotionPaths: []cfg.PromotionPath{
			{
				SourcePath: "prod/[^/]*/",
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetPaths: []string{
							"prod/eu-west-1/",
							"prod/eu-east-1/",
						},
					},
				},
			},
		},
	}
	expectedPromotion := map[string]promotionInstance{
		"prod/[^/]*/>prod/eu-east-1/|prod/eu-west-1/": {
			ComputedSyncPaths: map[string]string{
				"prod/eu-east-1/componentA": "prod/us-east-4/componentA",
				"prod/eu-west-1/componentA": "prod/us-east-4/componentA",
			},
		},
	}

	mockedHTTPClient := newPromotionTestHTTPClient(t, []string{
		"prod/us-east-4/componentA/file.yaml",
		"prod/us-east-4/componentA/file2.yaml",
		"prod/us-east-4/componentA/aSubDir/file3.yaml",
		".ci-config/random-file.json",
	})
	generatePromotionPlanTestHelper(t, config, mockedHTTPClient, expectedPromotion)
}

func TestGeneratePromotionPlan(t *testing.T) {
	t.Parallel()
	config := &cfg.Config{
		PromotionPaths: []cfg.PromotionPath{
			{
				SourcePath: "prod/us-east-4/",
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetPaths: []string{
							"prod/eu-west-1/",
							"prod/eu-east-1/",
						},
					},
				},
			},
		},
	}
	expectedPromotion := map[string]promotionInstance{
		"prod/us-east-4/>prod/eu-east-1/|prod/eu-west-1/": {
			ComputedSyncPaths: map[string]string{
				"prod/eu-east-1/componentA": "prod/us-east-4/componentA",
				"prod/eu-west-1/componentA": "prod/us-east-4/componentA",
			},
		},
	}
	mockedHTTPClient := newPromotionTestHTTPClient(t, []string{
		"prod/us-east-4/componentA/file.yaml",
		"prod/us-east-4/componentA/file2.yaml",
		"prod/us-east-4/componentA/aSubDir/file3.yaml",
		".ci-config/random-file.json",
	})
	generatePromotionPlanTestHelper(t, config, mockedHTTPClient, expectedPromotion)
}

func TestGeneratePromotionPlanBlockList(t *testing.T) {
	t.Parallel()
	config := &cfg.Config{
		PromotionPaths: []cfg.PromotionPath{
			{
				SourcePath: "prod/us-east-4/",
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetPaths: []string{
							"prod/eu-west-1/",
							"prod/eu-east-1/",
						},
					},
				},
			},
		},
	}

	expectedPromotion := map[string]promotionInstance{
		"prod/us-east-4/>prod/eu-east-1/|prod/eu-west-1/": {
			ComputedSyncPaths: map[string]string{
				"prod/eu-east-1/componentA": "prod/us-east-4/componentA",
			},
		},
	}

	mockedHTTPClient := newPromotionTestHTTPClient(t, []string{
		"prod/us-east-4/componentA/file.yaml",
		".ci-config/random-file.json",
	}, mock.WithRequestMatch(
		mock.GetReposContentsByOwnerByRepoByPath,
		github.RepositoryContent{
			Content: github.String("promotionTargetBlockList: [\"prod/eu-west-.*\"]"),
		},
	))
	generatePromotionPlanTestHelper(t, config, mockedHTTPClient, expectedPromotion)
}

func TestGeneratePromotionPlanAllowList(t *testing.T) {
	t.Parallel()
	config := &cfg.Config{
		PromotionPaths: []cfg.PromotionPath{
			{
				SourcePath: "prod/us-east-4/",
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetPaths: []string{
							"prod/eu-west-1/",
							"prod/eu-east-1/",
						},
					},
				},
			},
		},
	}

	expectedPromotion := map[string]promotionInstance{
		"prod/us-east-4/>prod/eu-east-1/|prod/eu-west-1/": {
			ComputedSyncPaths: map[string]string{
				"prod/eu-west-1/componentA": "prod/us-east-4/componentA",
			},
		},
	}
	mockedHTTPClient := newPromotionTestHTTPClient(t, []string{
		"prod/us-east-4/componentA/file.yaml",
		".ci-config/random-file.json",
	}, mock.WithRequestMatch(
		mock.GetReposContentsByOwnerByRepoByPath,
		github.RepositoryContent{
			Content: github.String("promotionTargetAllowList: [\"prod/eu-(west|foo|bar).*\"]"),
		},
	))
	generatePromotionPlanTestHelper(t, config, mockedHTTPClient, expectedPromotion)
}

func TestGeneratePromotionPlanTwoComponents(t *testing.T) {
	t.Parallel()
	config := &cfg.Config{
		PromotionPaths: []cfg.PromotionPath{
			{
				SourcePath: "prod/us-east-4/",
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetPaths: []string{
							"prod/eu-west-1/",
							"prod/eu-east-1/",
						},
					},
				},
			},
		},
	}
	expectedPromotion := map[string]promotionInstance{
		"prod/us-east-4/>prod/eu-east-1/|prod/eu-west-1/": {
			ComputedSyncPaths: map[string]string{
				"prod/eu-east-1/componentA": "prod/us-east-4/componentA",
				"prod/eu-west-1/componentA": "prod/us-east-4/componentA",
				"prod/eu-east-1/componentB": "prod/us-east-4/componentB",
				"prod/eu-west-1/componentB": "prod/us-east-4/componentB",
			},
		},
	}
	mockedHTTPClient := newPromotionTestHTTPClient(t, []string{
		"prod/us-east-4/componentA/file.yaml",
		"prod/us-east-4/componentB/file.yaml",
	})
	generatePromotionPlanTestHelper(t, config, mockedHTTPClient, expectedPromotion)
}

func TestGenerateNestedSourceRegexPromotionPlan(t *testing.T) {
	t.Parallel()
	config := &cfg.Config{
		PromotionPaths: []cfg.PromotionPath{
			{
				SourcePath:              "prod/us-east-4/",
				ComponentPathExtraDepth: 2,
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetPaths: []string{
							"prod/eu-west-1/",
						},
					},
				},
			},
		},
	}
	expectedPromotion := map[string]promotionInstance{
		"prod/us-east-4/>prod/eu-west-1/": {
			ComputedSyncPaths: map[string]string{
				"prod/eu-west-1/teamA/namespaceB/componentA": "prod/us-east-4/teamA/namespaceB/componentA",
			},
		},
	}

	mockedHTTPClient := newPromotionTestHTTPClient(t, []string{
		"prod/us-east-4/teamA/namespaceB/componentA/file.yaml",
		"prod/us-east-4/teamA/namespaceB/componentA/aSubDir/file3.yaml",
	})
	generatePromotionPlanTestHelper(t, config, mockedHTTPClient, expectedPromotion)
}

func TestGeneratePromotionPlanWithPagination(t *testing.T) {
	t.Parallel()
	config := &cfg.Config{
		PromotionPaths: []cfg.PromotionPath{
			{
				SourcePath: "prod/us-east-4/",
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetPaths: []string{
							"prod/eu-west-1/",
							"prod/eu-east-1/",
						},
					},
				},
			},
		},
	}
	expectedPromotion := map[string]promotionInstance{
		"prod/us-east-4/>prod/eu-east-1/|prod/eu-west-1/": {
			ComputedSyncPaths: map[string]string{
				"prod/eu-east-1/componentA": "prod/us-east-4/componentA",
				"prod/eu-west-1/componentA": "prod/us-east-4/componentA",
			},
		},
	}
	// Note the "relevant" files are in the second page, to ensure pagination is working
	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatchPages(
			mock.GetReposPullsFilesByOwnerByRepoByPullNumber,
			[]github.CommitFile{
				{Filename: github.String(".ci-config/random-file.json")},
				{Filename: github.String(".ci-config/random-file2.json")},
			},
			[]github.CommitFile{
				{Filename: github.String("prod/us-east-4/componentA/file.yaml")},
				{Filename: github.String("prod/us-east-4/componentA/file2.yaml")},
			},
		),
		mock.WithRequestMatchHandler(
			mock.GetReposContentsByOwnerByRepoByPath,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mock.WriteError(
					w,
					http.StatusNotFound,
					"no *optional* in-component telefonistka config file",
				)
			}),
		),
	)
	generatePromotionPlanTestHelper(t, config, mockedHTTPClient, expectedPromotion)
}

// TestGeneratePromotionMetadataWithOutDesc tests the case where the target description is set
func TestGeneratePromotionMetadataWithDesc(t *testing.T) {
	t.Parallel()
	config := &cfg.Config{
		PromotionPaths: []cfg.PromotionPath{
			{
				SourcePath: "prod/us-east-4/",
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetDescription: "foobar2", // This is tested config key
						TargetPaths: []string{
							"prod/eu-west-1/",
							"prod/eu-east-1/",
						},
					},
				},
			},
		},
	}
	expectedPromotion := map[string]promotionInstance{
		"prod/us-east-4/>prod/eu-east-1/|prod/eu-west-1/": {
			ComputedSyncPaths: map[string]string{
				"prod/eu-east-1/componentA": "prod/us-east-4/componentA",
				"prod/eu-west-1/componentA": "prod/us-east-4/componentA",
			},
			Metadata: promotionMeta{
				SourcePath:                     "prod/us-east-4/",
				TargetDescription:              "foobar2", // This is tested config key
				TargetPaths:                    []string{"prod/eu-east-1/", "prod/eu-west-1/"},
				PerComponentSkippedTargetPaths: map[string][]string{},
				ComponentNames:                 []string{"componentA"},
			},
		},
	}
	mockedHTTPClient := newPromotionTestHTTPClient(t, []string{
		"prod/us-east-4/componentA/file.yaml",
		"prod/us-east-4/componentA/file2.yaml",
		"prod/us-east-4/componentA/aSubDir/file3.yaml",
		".ci-config/random-file.json",
	})
	generatePromotionPlanMetadataTestHelper(t, config, expectedPromotion, mockedHTTPClient)
}

// This test is similar to the previous one, but the TargetDescription is not set in the config
func TestGeneratePromotionMetadataWithOutDesc(t *testing.T) {
	t.Parallel()
	config := &cfg.Config{
		PromotionPaths: []cfg.PromotionPath{
			{
				SourcePath: "prod/us-east-4/",
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetPaths: []string{
							"prod/eu-west-1/",
							"prod/eu-east-1/",
						},
					},
				},
			},
		},
	}
	expectedPromotion := map[string]promotionInstance{
		"prod/us-east-4/>prod/eu-east-1/|prod/eu-west-1/": {
			ComputedSyncPaths: map[string]string{
				"prod/eu-east-1/componentA": "prod/us-east-4/componentA",
				"prod/eu-west-1/componentA": "prod/us-east-4/componentA",
			},
			Metadata: promotionMeta{
				SourcePath:                     "prod/us-east-4/",
				TargetDescription:              "prod/eu-east-1/ prod/eu-west-1/", // This is tested config key
				TargetPaths:                    []string{"prod/eu-east-1/", "prod/eu-west-1/"},
				PerComponentSkippedTargetPaths: map[string][]string{},
				ComponentNames:                 []string{"componentA"},
			},
		},
	}
	mockedHTTPClient := newPromotionTestHTTPClient(t, []string{
		"prod/us-east-4/componentA/file.yaml",
		"prod/us-east-4/componentA/file2.yaml",
		"prod/us-east-4/componentA/aSubDir/file3.yaml",
		".ci-config/random-file.json",
	})
	generatePromotionPlanMetadataTestHelper(t, config, expectedPromotion, mockedHTTPClient)
}

func TestAutoMerge(t *testing.T) {
	t.Parallel()
	config := &cfg.Config{
		PromotionPaths: []cfg.PromotionPath{
			{
				SourcePath: "prod/us-east-4/",
				Conditions: cfg.Condition{
					AutoMerge: true,
				},
				PromotionPrs: []cfg.PromotionPr{
					{
						TargetPaths: []string{
							"prod/eu-west-1/",
							"prod/eu-east-1/",
						},
					},
				},
			},
		},
	}
	expectedPromotion := map[string]promotionInstance{
		"prod/us-east-4/>prod/eu-east-1/|prod/eu-west-1/": {
			ComputedSyncPaths: map[string]string{
				"prod/eu-east-1/componentA": "prod/us-east-4/componentA",
				"prod/eu-west-1/componentA": "prod/us-east-4/componentA",
			},
			Metadata: promotionMeta{
				SourcePath:                     "prod/us-east-4/",
				TargetDescription:              "prod/eu-east-1/ prod/eu-west-1/",
				TargetPaths:                    []string{"prod/eu-east-1/", "prod/eu-west-1/"},
				PerComponentSkippedTargetPaths: map[string][]string{},
				ComponentNames:                 []string{"componentA"},
				AutoMerge:                      true,
			},
		},
	}
	mockedHTTPClient := newPromotionTestHTTPClient(t, []string{
		"prod/us-east-4/componentA/file.yaml",
		"prod/us-east-4/componentA/file2.yaml",
		"prod/us-east-4/componentA/aSubDir/file3.yaml",
		".ci-config/random-file.json",
	})
	generatePromotionPlanMetadataTestHelper(t, config, expectedPromotion, mockedHTTPClient)
}

func TestGetComponentConfig(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		content   string
		apiErr    error
		respCode  int
		wantErr   bool
		wantBlock []string
		wantAllow []string
	}{
		"valid config": {
			content:   "promotionTargetBlockList:\n- \"prod/.*\"\npromotionTargetAllowList:\n- \"staging/.*\"\n",
			respCode:  200,
			wantBlock: []string{"prod/.*"},
			wantAllow: []string{"staging/.*"},
		},
		"file not found (404) returns empty config": {
			apiErr:   errors.New("not found"),
			respCode: 404,
		},
		"API error (non-404)": {
			apiErr:   errors.New("server error"),
			respCode: 500,
			wantErr:  true,
		},
		"invalid YAML": {
			content:  ":::invalid",
			respCode: 200,
			wantErr:  true,
		},
		"empty file returns empty config": {
			content:  "",
			respCode: 200,
		},
		"disableArgoCDDiff flag": {
			content:  "disableArgoCDDiff: true\n",
			respCode: 200,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var gotPath string

			repos := &mockRepoService{
				getContentsFn: func(_ context.Context, _, _, path string, _ *github.RepositoryContentGetOptions) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error) {
					gotPath = path
					if tc.apiErr != nil {
						return nil, nil, ghResp(tc.respCode), tc.apiErr
					}
					return &github.RepositoryContent{
						Content:  github.String(tc.content),
						Encoding: github.String(""),
					}, nil, ghResp(tc.respCode), nil
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

			conf, err := getComponentConfig(t.Context(), c, "env/dev/myapp", "main")
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if conf == nil {
				t.Fatal("config is nil")
			}
			if gotPath != "env/dev/myapp/telefonistka.yaml" {
				t.Errorf("path: got %q, want %q", gotPath, "env/dev/myapp/telefonistka.yaml")
			}
			if diff := deep.Equal(conf.PromotionTargetBlockList, tc.wantBlock); diff != nil {
				t.Errorf("BlockList: %v", diff)
			}
			if diff := deep.Equal(conf.PromotionTargetAllowList, tc.wantAllow); diff != nil {
				t.Errorf("AllowList: %v", diff)
			}
			if tc.content == "disableArgoCDDiff: true\n" && !conf.DisableArgoCDDiff {
				t.Error("expected DisableArgoCDDiff to be true")
			}
		})
	}
}
