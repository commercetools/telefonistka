package configuration

import (
	"os"
	"reflect"
	"testing"
)

func TestParseConfigFromYamlEdgeCases(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		input   string
		wantErr bool
	}{
		"empty string": {
			input:   "",
			wantErr: false,
		},
		"malformed yaml": {
			input:   "invalid: [yaml",
			wantErr: true,
		},
		"unknown fields": {
			input:   "unknownKey: value",
			wantErr: false,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseConfigFromYaml(tc.input)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestConfigurationParse(t *testing.T) {
	t.Parallel()

	configurationFileContent, _ := os.ReadFile("testdata/testConfigurationParsing.yaml")

	config, err := ParseConfigFromYaml(string(configurationFileContent))
	if err != nil {
		t.Fatalf("config parsing failed: err=%s", err)
	}

	if config.PromotionPaths == nil {
		t.Fatalf("config is missing PromotionPaths, %v", config.PromotionPaths)
	}

	expectedConfig := &Config{
		PromotionPaths: []PromotionPath{
			{
				SourcePath: "workspace/",
				Conditions: Condition{
					PrHasLabels: []string{
						"some-label",
					},
					AutoMerge: true,
				},
				PromotionPrs: []PromotionPr{
					{
						TargetPaths: []string{
							"env/staging/us-east4/c1/",
						},
					},
					{
						TargetPaths: []string{
							"env/staging/europe-west4/c1/",
						},
					},
				},
			},
			{
				SourcePath: "env/staging/us-east4/c1/",
				Conditions: Condition{
					AutoMerge: false,
				},
				PromotionPrs: []PromotionPr{
					{
						TargetPaths: []string{
							"env/prod/us-central1/c2/",
						},
					},
				},
			},
			{
				SourcePath: "env/prod/us-central1/c2/",
				Conditions: Condition{
					AutoMerge: false,
				},
				PromotionPrs: []PromotionPr{
					{
						TargetPaths: []string{
							"env/prod/us-west1/c2/",
							"env/prod/us-central1/c3/",
						},
					},
				},
			},
		},
	}

	if got, want := config, expectedConfig; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
