package githubapi

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"

	cfg "github.com/commercetools/telefonistka/internal/pkg/configuration"
	prom "github.com/commercetools/telefonistka/internal/pkg/prometheus"
	"github.com/google/go-github/v62/github"
	yaml "gopkg.in/yaml.v2"
)

type PromotionInstance struct {
	Metadata          PromotionInstanceMetaData `deep:"-"` // Unit tests ignore Metadata currently
	ComputedSyncPaths map[string]string         // key is target, value is source
}

type PromotionInstanceMetaData struct {
	SourcePath                     string
	TargetPaths                    []string
	TargetDescription              string
	PerComponentSkippedTargetPaths map[string][]string // ComponentName is the key,
	ComponentNames                 []string
	AutoMerge                      bool
}

func containMatchingRegex(patterns []string, str string) bool {
	for _, pattern := range patterns {
		doesElementMatchPattern, err := regexp.MatchString(pattern, str)
		if err != nil {
			slog.Error("failed to match regex", "pattern", pattern, "str", str, "err", err)
			return false
		}
		if doesElementMatchPattern {
			return true
		}
	}
	return false
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

func DetectDrift(ctx context.Context, ghPrClientDetails Context) error {
	ghPrClientDetails.PrLogger.Debug("Checking for Drift")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	diffOutputMap := make(map[string]string)

	promotions, err := GeneratePromotionPlan(ctx, ghPrClientDetails, ghPrClientDetails.Ref)
	if err != nil {
		return err
	}

	for _, promotion := range promotions {
		ghPrClientDetails.PrLogger.Debug("Checking drift for source", "source", promotion.Metadata.SourcePath)
		for trgt, src := range promotion.ComputedSyncPaths {
			hasDiff, diffOutput, _ := CompareRepoDirectories(ctx, ghPrClientDetails, src, trgt, ghPrClientDetails.DefaultBranch)
			if hasDiff {
				mapKey := fmt.Sprintf("`%s` ↔️  `%s`", src, trgt)
				diffOutputMap[mapKey] = diffOutput
				ghPrClientDetails.PrLogger.Debug("Found diff between source and target", "source", src, "target", trgt)
			}
		}
	}
	if len(diffOutputMap) != 0 {
		templateOutput, err := executeTemplate("driftMsg", defaultTemplatesFullPath("drift-pr-comment.gotmpl"), diffOutputMap)
		if err != nil {
			return err
		}

		err = commentPR(ctx, ghPrClientDetails, templateOutput)
		if err != nil {
			return err
		}
	} else {
		ghPrClientDetails.PrLogger.Info("No drift found")
	}

	return nil
}

func getComponentConfig(ctx context.Context, ghPrClientDetails Context, componentPath string, branch string) (*cfg.ComponentConfig, error) {
	componentConfig := &cfg.ComponentConfig{}
	rGetContentOps := &github.RepositoryContentGetOptions{Ref: branch}
	componentConfigFileContent, _, resp, err := ghPrClientDetails.GhClientPair.v3Client.Repositories.GetContents(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, componentPath+"/telefonistka.yaml", rGetContentOps)
	prom.InstrumentGhCall(resp)
	if (err != nil) && (resp.StatusCode != 404) { // The file is optional
		ghPrClientDetails.PrLogger.Error("could not get file list from GH API", "err", err, "resp", resp)
		return nil, err
	} else if resp.StatusCode == 404 {
		ghPrClientDetails.PrLogger.Debug("No in-component config in path", "path", componentPath)
		return &cfg.ComponentConfig{}, nil
	}
	componentConfigFileContentString, _ := componentConfigFileContent.GetContent()
	err = yaml.Unmarshal([]byte(componentConfigFileContentString), componentConfig)
	if err != nil {
		ghPrClientDetails.PrLogger.Error("Failed to parse configuration", "err", err) // TODO comment this error to PR
		return nil, err
	}
	return componentConfig, nil
}

// This function generates a list of "components" that where changed in the PR and are relevant for promotion)
func generateListOfRelevantComponents(ctx context.Context, ghPrClientDetails Context) (relevantComponents map[relevantComponent]struct{}, err error) {
	relevantComponents = make(map[relevantComponent]struct{})

	// Get the list of files in the PR, with pagination
	opts := &github.ListOptions{}
	prFiles := []*github.CommitFile{}

	for {
		perPagePrFiles, resp, err := ghPrClientDetails.GhClientPair.v3Client.PullRequests.ListFiles(ctx, ghPrClientDetails.Owner, ghPrClientDetails.Repo, ghPrClientDetails.PrNumber, opts)
		prom.InstrumentGhCall(resp)
		if err != nil {
			ghPrClientDetails.PrLogger.Error("could not get file list from GH API", "err", err, "status_code", resp.Response.Status)
			return nil, err
		}
		prFiles = append(prFiles, perPagePrFiles...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	for _, changedFile := range prFiles {
		for _, promotionPathConfig := range ghPrClientDetails.Config.PromotionPaths {
			if match, _ := regexp.MatchString("^"+promotionPathConfig.SourcePath+".*", *changedFile.Filename); match {
				// "components" here are the sub directories of the SourcePath
				// but with promotionPathConfig.ComponentPathExtraDepth we can grab multiple levels of subdirectories,
				// to support cases where components are nested deeper(e.g. [SourcePath]/owningTeam/namespace/component1)
				componentPathRegexSubSstrings := []string{}
				for i := 0; i <= promotionPathConfig.ComponentPathExtraDepth; i++ {
					componentPathRegexSubSstrings = append(componentPathRegexSubSstrings, "[^/]*")
				}
				componentPathRegexSubString := strings.Join(componentPathRegexSubSstrings, "/")
				getComponentRegexString := regexp.MustCompile("^" + promotionPathConfig.SourcePath + "(" + componentPathRegexSubString + ")/.*")
				componentName := getComponentRegexString.ReplaceAllString(*changedFile.Filename, "${1}")

				getSourcePathRegexString := regexp.MustCompile("^(" + promotionPathConfig.SourcePath + ")" + componentName + "/.*")
				compiledSourcePath := getSourcePathRegexString.ReplaceAllString(*changedFile.Filename, "${1}")
				relevantComponentsElement := relevantComponent{
					SourcePath:    compiledSourcePath,
					ComponentName: componentName,
					AutoMerge:     promotionPathConfig.Conditions.AutoMerge,
				}
				relevantComponents[relevantComponentsElement] = struct{}{}
				break // a file can only be a single "source dir"
			}
		}
	}
	return relevantComponents, nil
}

type relevantComponent struct {
	SourcePath    string
	ComponentName string
	AutoMerge     bool
}

func generateListOfChangedComponentPaths(ctx context.Context, ghPrClientDetails Context) (changedComponentPaths []string, err error) {
	// If the PR has a list of promoted paths in the PR Telefonistika metadata(=is a promotion PR), we use that
	if len(ghPrClientDetails.PrMetadata.PromotedPaths) > 0 {
		changedComponentPaths = ghPrClientDetails.PrMetadata.PromotedPaths
		return changedComponentPaths, nil
	}

	// If not we will use in-repo config to generate it, and turns the map with struct keys into a list of strings
	relevantComponents, err := generateListOfRelevantComponents(ctx, ghPrClientDetails)
	if err != nil {
		return nil, err
	}
	for component := range relevantComponents {
		changedComponentPaths = append(changedComponentPaths, component.SourcePath+component.ComponentName)
	}
	return changedComponentPaths, nil
}

// This function generates a promotion plan based on the list of relevant components that where "touched" and the in-repo telefonitka  configuration
func generatePlanBasedOnChangeddComponent(ctx context.Context, ghPrClientDetails Context, relevantComponents map[relevantComponent]struct{}, configBranch string) (promotions map[string]PromotionInstance, err error) {
	promotions = make(map[string]PromotionInstance)
	for componentToPromote := range relevantComponents {
		componentConfig, err := getComponentConfig(ctx, ghPrClientDetails, componentToPromote.SourcePath+componentToPromote.ComponentName, configBranch)
		if err != nil {
			ghPrClientDetails.PrLogger.Error("Failed to get in component configuration, skipping component", "err", err, "component", componentToPromote.SourcePath+componentToPromote.ComponentName)
		}

		for _, configPromotionPath := range ghPrClientDetails.Config.PromotionPaths {
			if match, _ := regexp.MatchString(configPromotionPath.SourcePath, componentToPromote.SourcePath); match {
				// This section checks if a PromotionPath has a condition and skips it if needed
				if configPromotionPath.Conditions.PrHasLabels != nil {
					thisPrHasTheRightLabel := false
					for _, l := range ghPrClientDetails.Labels {
						if contains(configPromotionPath.Conditions.PrHasLabels, *l.Name) {
							thisPrHasTheRightLabel = true
							break
						}
					}
					if !thisPrHasTheRightLabel {
						continue
					}
				}

				for _, ppr := range configPromotionPath.PromotionPrs {
					sort.Strings(ppr.TargetPaths)

					mapKey := configPromotionPath.SourcePath + ">" + strings.Join(ppr.TargetPaths, "|") // This key is used to aggregate the PR based on source and target combination
					if entry, ok := promotions[mapKey]; !ok {
						ghPrClientDetails.PrLogger.Debug("Adding key", "key", mapKey)
						if ppr.TargetDescription == "" {
							ppr.TargetDescription = strings.Join(ppr.TargetPaths, " ")
						}
						promotions[mapKey] = PromotionInstance{
							Metadata: PromotionInstanceMetaData{
								TargetPaths:                    ppr.TargetPaths,
								TargetDescription:              ppr.TargetDescription,
								SourcePath:                     componentToPromote.SourcePath,
								ComponentNames:                 []string{componentToPromote.ComponentName},
								PerComponentSkippedTargetPaths: map[string][]string{},
								AutoMerge:                      componentToPromote.AutoMerge,
							},
							ComputedSyncPaths: map[string]string{},
						}
					} else if !contains(entry.Metadata.ComponentNames, componentToPromote.ComponentName) {
						entry.Metadata.ComponentNames = append(entry.Metadata.ComponentNames, componentToPromote.ComponentName)
						promotions[mapKey] = entry
					}

					for _, indevidualPath := range ppr.TargetPaths {
						if componentConfig != nil {
							// BlockList supersedes Allowlist, if something matched there the entry is ignored regardless of allowlist
							if componentConfig.PromotionTargetBlockList != nil {
								if containMatchingRegex(componentConfig.PromotionTargetBlockList, indevidualPath) {
									promotions[mapKey].Metadata.PerComponentSkippedTargetPaths[componentToPromote.ComponentName] = append(promotions[mapKey].Metadata.PerComponentSkippedTargetPaths[componentToPromote.ComponentName], indevidualPath)
									continue
								}
							}
							if componentConfig.PromotionTargetAllowList != nil {
								if !containMatchingRegex(componentConfig.PromotionTargetAllowList, indevidualPath) {
									promotions[mapKey].Metadata.PerComponentSkippedTargetPaths[componentToPromote.ComponentName] = append(promotions[mapKey].Metadata.PerComponentSkippedTargetPaths[componentToPromote.ComponentName], indevidualPath)
									continue
								}
							}
						}
						promotions[mapKey].ComputedSyncPaths[indevidualPath+componentToPromote.ComponentName] = componentToPromote.SourcePath + componentToPromote.ComponentName
					}
				}
				break
			}
		}
	}
	return promotions, nil
}

func GeneratePromotionPlan(ctx context.Context, ghPrClientDetails Context, configBranch string) (map[string]PromotionInstance, error) {
	ghPrClientDetails.PrLogger.Debug("Generating promotion plan plan")
	// TODO refactor tests to use the two functions below instead of this one
	relevantComponents, err := generateListOfRelevantComponents(ctx, ghPrClientDetails)
	if err != nil {
		return nil, err
	}
	promotions, err := generatePlanBasedOnChangeddComponent(ctx, ghPrClientDetails, relevantComponents, configBranch)
	return promotions, err
}
