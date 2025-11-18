package githubapi

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
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

func hasAnyRequiredLabel(required []string, labels []*github.Label) bool {
	if required == nil {
		return true
	}
	for _, label := range labels {
		if slices.Contains(required, *label.Name) {
			return true
		}
	}
	return false
}

func shouldSkipTarget(componentConfig *cfg.ComponentConfig, componentName, target string, metadata *PromotionInstanceMetaData) bool {
	if metadata.PerComponentSkippedTargetPaths == nil {
		metadata.PerComponentSkippedTargetPaths = map[string][]string{}
	}

	if componentConfig == nil {
		return false
	}

	if blockList := componentConfig.PromotionTargetBlockList; blockList != nil {
		if containMatchingRegex(blockList, target) {
			metadata.PerComponentSkippedTargetPaths[componentName] = append(metadata.PerComponentSkippedTargetPaths[componentName], target)
			return true
		}
	}

	if allowList := componentConfig.PromotionTargetAllowList; allowList != nil {
		if !containMatchingRegex(allowList, target) {
			metadata.PerComponentSkippedTargetPaths[componentName] = append(metadata.PerComponentSkippedTargetPaths[componentName], target)
			return true
		}
	}

	return false
}

func componentFromFile(promotionPath cfg.PromotionPath, filename string) (relevantComponent, bool) {
	match, _ := regexp.MatchString("^"+promotionPath.SourcePath+".*", filename)
	if !match {
		return relevantComponent{}, false
	}

	componentPathRegexSubstrings := make([]string, promotionPath.ComponentPathExtraDepth+1)
	for i := range componentPathRegexSubstrings {
		componentPathRegexSubstrings[i] = "[^/]*"
	}
	componentPathRegexSubString := strings.Join(componentPathRegexSubstrings, "/")
	componentRegex := regexp.MustCompile("^" + promotionPath.SourcePath + "(" + componentPathRegexSubString + ")/.*")
	componentName := componentRegex.ReplaceAllString(filename, "${1}")

	sourceRegex := regexp.MustCompile("^(" + promotionPath.SourcePath + ")" + componentName + "/.*")
	sourcePath := sourceRegex.ReplaceAllString(filename, "${1}")

	component := relevantComponent{
		SourcePath:    sourcePath,
		ComponentName: componentName,
		AutoMerge:     promotionPath.Conditions.AutoMerge,
	}

	return component, true
}

func newPromotionInstance(component relevantComponent, ppr cfg.PromotionPr) PromotionInstance {
	targetDescription := ppr.TargetDescription
	if targetDescription == "" {
		targetDescription = strings.Join(ppr.TargetPaths, " ")
	}

	return PromotionInstance{
		Metadata: PromotionInstanceMetaData{
			TargetPaths:                    ppr.TargetPaths,
			TargetDescription:              targetDescription,
			SourcePath:                     component.SourcePath,
			ComponentNames:                 []string{component.ComponentName},
			PerComponentSkippedTargetPaths: map[string][]string{},
			AutoMerge:                      component.AutoMerge,
		},
		ComputedSyncPaths: map[string]string{},
	}
}

func updatePromotionInstance(instance PromotionInstance, component relevantComponent, componentConfig *cfg.ComponentConfig, targetPaths []string) PromotionInstance {
	if instance.ComputedSyncPaths == nil {
		instance.ComputedSyncPaths = map[string]string{}
	}

	if !slices.Contains(instance.Metadata.ComponentNames, component.ComponentName) {
		instance.Metadata.ComponentNames = append(instance.Metadata.ComponentNames, component.ComponentName)
	}

	for _, target := range targetPaths {
		if shouldSkipTarget(componentConfig, component.ComponentName, target, &instance.Metadata) {
			continue
		}
		instance.ComputedSyncPaths[target+component.ComponentName] = component.SourcePath + component.ComponentName
	}

	return instance
}

func DetectDrift(ctx context.Context, c Context) error {
	c.PrLogger.Debug("Checking for Drift")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	diffOutputMap := make(map[string]string)

	promotions, err := GeneratePromotionPlan(ctx, c, c.Ref)
	if err != nil {
		return err
	}

	for _, promotion := range promotions {
		c.PrLogger.Debug("Checking drift for source", "source", promotion.Metadata.SourcePath)
		for trgt, src := range promotion.ComputedSyncPaths {
			hasDiff, diffOutput, _ := CompareRepoDirectories(ctx, c, src, trgt, c.DefaultBranch)
			if hasDiff {
				mapKey := fmt.Sprintf("`%s` ↔️  `%s`", src, trgt)
				diffOutputMap[mapKey] = diffOutput
				c.PrLogger.Debug("Found diff between source and target", "source", src, "target", trgt)
			}
		}
	}
	if len(diffOutputMap) != 0 {
		templateOutput, err := executeTemplate("driftMsg", defaultTemplatesFullPath("drift-pr-comment.gotmpl"), diffOutputMap)
		if err != nil {
			return err
		}

		err = commentPR(ctx, c, templateOutput)
		if err != nil {
			return err
		}
	} else {
		c.PrLogger.Info("No drift found")
	}

	return nil
}

func getComponentConfig(ctx context.Context, c Context, componentPath string, branch string) (*cfg.ComponentConfig, error) {
	componentConfig := &cfg.ComponentConfig{}
	rGetContentOps := &github.RepositoryContentGetOptions{Ref: branch}
	componentConfigFileContent, _, resp, err := c.GhClientPair.v3Client.Repositories.GetContents(ctx, c.Owner, c.Repo, componentPath+"/telefonistka.yaml", rGetContentOps)
	prom.InstrumentGhCall(resp)
	if resp != nil && resp.StatusCode == 404 { // The file is optional
		c.PrLogger.Debug("No in-component config in path", "path", componentPath)
		return &cfg.ComponentConfig{}, nil
	}
	if err != nil {
		c.PrLogger.Error("could not get file list from GH API", "err", err, "resp", resp)
		return nil, err
	}
	componentConfigFileContentString, _ := componentConfigFileContent.GetContent()
	err = yaml.Unmarshal([]byte(componentConfigFileContentString), componentConfig)
	if err != nil {
		c.PrLogger.Error("Failed to parse configuration", "err", err) // TODO comment this error to PR
		return nil, err
	}
	return componentConfig, nil
}

// This function generates a list of "components" that where changed in the PR and are relevant for promotion)
func generateListOfRelevantComponents(ctx context.Context, c Context) (relevantComponents map[relevantComponent]struct{}, err error) {
	relevantComponents = make(map[relevantComponent]struct{})

	// Get the list of files in the PR, with pagination
	opts := &github.ListOptions{}
	prFiles := []*github.CommitFile{}

	for {
		perPagePrFiles, resp, err := c.GhClientPair.v3Client.PullRequests.ListFiles(ctx, c.Owner, c.Repo, c.PrNumber, opts)
		prom.InstrumentGhCall(resp)
		if err != nil {
			c.PrLogger.Error("could not get file list from GH API", "err", err, "status_code", resp.Response.Status)
			return nil, err
		}
		prFiles = append(prFiles, perPagePrFiles...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	for _, changedFile := range prFiles {
		if changedFile.Filename == nil {
			continue
		}

		filename := *changedFile.Filename
		for _, promotionPathConfig := range c.Config.PromotionPaths {
			relevantComponent, ok := componentFromFile(promotionPathConfig, filename)
			if !ok {
				continue
			}
			relevantComponents[relevantComponent] = struct{}{}
			break // a file can only be a single "source dir"
		}
	}
	return relevantComponents, nil
}

type relevantComponent struct {
	SourcePath    string
	ComponentName string
	AutoMerge     bool
}

func generateListOfChangedComponentPaths(ctx context.Context, c Context) (changedComponentPaths []string, err error) {
	// If the PR has a list of promoted paths in the PR Telefonistika metadata(=is a promotion PR), we use that
	if len(c.PrMetadata.PromotedPaths) > 0 {
		changedComponentPaths = c.PrMetadata.PromotedPaths
		return changedComponentPaths, nil
	}

	// If not we will use in-repo config to generate it, and turns the map with struct keys into a list of strings
	relevantComponents, err := generateListOfRelevantComponents(ctx, c)
	if err != nil {
		return nil, err
	}
	for component := range relevantComponents {
		changedComponentPaths = append(changedComponentPaths, component.SourcePath+component.ComponentName)
	}
	return changedComponentPaths, nil
}

// This function generates a promotion plan based on the list of relevant components that where "touched" and the in-repo telefonitka  configuration
func generatePlanBasedOnChangeddComponent(ctx context.Context, c Context, relevantComponents map[relevantComponent]struct{}, configBranch string) (promotions map[string]PromotionInstance, err error) {
	promotions = make(map[string]PromotionInstance)
	for componentToPromote := range relevantComponents {
		componentConfig, err := getComponentConfig(ctx, c, componentToPromote.SourcePath+componentToPromote.ComponentName, configBranch)
		if err != nil {
			c.PrLogger.Error("Failed to get in component configuration, skipping component", "err", err, "component", componentToPromote.SourcePath+componentToPromote.ComponentName)
		}

		for _, configPromotionPath := range c.Config.PromotionPaths {
			match, _ := regexp.MatchString(configPromotionPath.SourcePath, componentToPromote.SourcePath)
			if !match {
				continue
			}

			requiredLabels := configPromotionPath.Conditions.PrHasLabels
			if requiredLabels != nil && !hasAnyRequiredLabel(requiredLabels, c.Labels) {
				continue
			}

			for _, ppr := range configPromotionPath.PromotionPrs {
				sort.Strings(ppr.TargetPaths)

				mapKey := configPromotionPath.SourcePath + ">" + strings.Join(ppr.TargetPaths, "|") // This key is used to aggregate the PR based on source and target combination
				instance, found := promotions[mapKey]
				if !found {
					c.PrLogger.Debug("Adding key", "key", mapKey)
					instance = newPromotionInstance(componentToPromote, ppr)
				}

				instance = updatePromotionInstance(instance, componentToPromote, componentConfig, ppr.TargetPaths)
				promotions[mapKey] = instance
			}
			break
		}
	}
	return promotions, nil
}

func GeneratePromotionPlan(ctx context.Context, c Context, configBranch string) (map[string]PromotionInstance, error) {
	c.PrLogger.Debug("Generating promotion plan plan")
	// TODO refactor tests to use the two functions below instead of this one
	relevantComponents, err := generateListOfRelevantComponents(ctx, c)
	if err != nil {
		return nil, err
	}
	promotions, err := generatePlanBasedOnChangeddComponent(ctx, c, relevantComponents, configBranch)
	return promotions, err
}
