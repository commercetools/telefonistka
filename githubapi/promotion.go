package githubapi

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	cfg "github.com/commercetools/telefonistka/configuration"
	prom "github.com/commercetools/telefonistka/prometheus"
	"github.com/google/go-github/v62/github"
	yaml "gopkg.in/yaml.v2"
)

type promotionInstance struct {
	Metadata          promotionMeta `deep:"-"` // Unit tests ignore Metadata currently
	ComputedSyncPaths map[string]string         // key is target, value is source
}

type promotionMeta struct {
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

func shouldSkipTarget(componentConfig *cfg.ComponentConfig, componentName, target string, metadata *promotionMeta) bool {
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

func matchSourcePrefix(pattern, candidate string) (string, bool) {
	re, err := regexp.Compile("^" + pattern)
	if err != nil {
		slog.Error("invalid source path pattern", "pattern", pattern, "err", err)
		return "", false
	}
	matched := re.FindString(candidate)
	if matched == "" {
		return "", false
	}
	return matched, true
}

func componentFromFile(promotionPath cfg.PromotionPath, filename string) (relevantComponent, bool) {
	matchedPrefix, ok := matchSourcePrefix(promotionPath.SourcePath, filename)
	if !ok {
		return relevantComponent{}, false
	}

	remainder := strings.TrimPrefix(filename, matchedPrefix)
	remainder = strings.TrimPrefix(remainder, "/")
	parts := strings.Split(remainder, "/")

	requiredParts := promotionPath.ComponentPathExtraDepth + 1
	if len(parts) <= requiredParts {
		return relevantComponent{}, false
	}

	componentName := strings.Join(parts[:requiredParts], "/")

	component := relevantComponent{
		SourcePath:    matchedPrefix,
		ComponentName: componentName,
		AutoMerge:     promotionPath.Conditions.AutoMerge,
	}

	return component, true
}

func normalizedTargetPaths(targetPaths []string) []string {
	clone := slices.Clone(targetPaths)
	slices.Sort(clone)
	return clone
}

func promotionMapKey(source string, targets []string) string {
	return source + ">" + strings.Join(targets, "|")
}

func newpromotionInstance(component relevantComponent, targetPaths []string, description string) promotionInstance {
	desc := description
	if desc == "" {
		desc = strings.Join(targetPaths, " ")
	}

	return promotionInstance{
		Metadata: promotionMeta{
			TargetPaths:                    targetPaths,
			TargetDescription:              desc,
			SourcePath:                     component.SourcePath,
			ComponentNames:                 []string{component.ComponentName},
			PerComponentSkippedTargetPaths: map[string][]string{},
			AutoMerge:                      component.AutoMerge,
		},
		ComputedSyncPaths: map[string]string{},
	}
}

func updatepromotionInstance(instance promotionInstance, component relevantComponent, componentConfig *cfg.ComponentConfig, targetPaths []string) promotionInstance {
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

func applyPromotionPath(promotions map[string]promotionInstance, component relevantComponent, componentConfig *cfg.ComponentConfig, path cfg.PromotionPath, labels []*github.Label, logger *slog.Logger) bool {
	if _, ok := matchSourcePrefix(path.SourcePath, component.SourcePath); !ok {
		return false
	}

	if !hasAnyRequiredLabel(path.Conditions.PrHasLabels, labels) {
		return false
	}

	for _, ppr := range path.PromotionPrs {
		targets := normalizedTargetPaths(ppr.TargetPaths)
		key := promotionMapKey(path.SourcePath, targets)

		instance, found := promotions[key]
		if !found {
			logger.Debug("Adding key", "key", key)
			instance = newpromotionInstance(component, targets, ppr.TargetDescription)
		}

		instance = updatepromotionInstance(instance, component, componentConfig, targets)
		promotions[key] = instance
	}

	return true
}

func detectDrift(ctx context.Context, c Context) error {
	c.PrLogger.Debug("Checking for Drift")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	diffOutputMap := make(map[string]string)

	promotions, err := generatePromotionPlan(ctx, c, c.Ref)
	if err != nil {
		return err
	}

	for _, promotion := range promotions {
		c.PrLogger.Debug("Checking drift for source", "source", promotion.Metadata.SourcePath)
		for trgt, src := range promotion.ComputedSyncPaths {
			hasDiff, diffOutput, _ := compareRepoDirectories(ctx, c, src, trgt, c.DefaultBranch)
			if hasDiff {
				mapKey := fmt.Sprintf("`%s` ↔️  `%s`", src, trgt)
				diffOutputMap[mapKey] = diffOutput
				c.PrLogger.Debug("Found diff between source and target", "source", src, "target", trgt)
			}
		}
	}
	if len(diffOutputMap) != 0 {
		templateOutput, err := executeTemplate("driftMsg", "drift-pr-comment.gotmpl", diffOutputMap)
		if err != nil {
			return err
		}

		err = c.commentOnPr(ctx, templateOutput)
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
	componentConfigFileContent, _, resp, err := c.Repositories.GetContents(ctx, c.Owner, c.Repo, componentPath+"/telefonistka.yaml", rGetContentOps)
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

// generateListOfRelevantComponents returns the set of components that were changed in the PR and are relevant for promotion.
func generateListOfRelevantComponents(ctx context.Context, c Context) (relevantComponents map[relevantComponent]struct{}, err error) {
	relevantComponents = make(map[relevantComponent]struct{})

	// Get the list of files in the PR, with pagination
	opts := &github.ListOptions{}
	prFiles := []*github.CommitFile{}

	for {
		perPagePrFiles, resp, err := c.PullRequests.ListFiles(ctx, c.Owner, c.Repo, c.PrNumber, opts)
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
	// If the PR has a list of promoted paths in the PR Telefonistka metadata (= is a promotion PR), we use that
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

// generatePlanBasedOnChangedComponent builds a promotion plan from the relevant components that were changed and the in-repo telefonistka configuration.
func generatePlanBasedOnChangedComponent(ctx context.Context, c Context, relevantComponents map[relevantComponent]struct{}, configBranch string) (promotions map[string]promotionInstance, err error) {
	promotions = make(map[string]promotionInstance)
	for component := range relevantComponents {
		componentConfig, err := getComponentConfig(ctx, c, component.SourcePath+component.ComponentName, configBranch)
		if err != nil {
			c.PrLogger.Error("Failed to get in component configuration, skipping component", "err", err, "component", component.SourcePath+component.ComponentName)
		}

		for _, path := range c.Config.PromotionPaths {
			if applyPromotionPath(promotions, component, componentConfig, path, c.Labels, c.PrLogger) {
				break
			}
		}
	}
	return promotions, nil
}

func generatePromotionPlan(ctx context.Context, c Context, configBranch string) (map[string]promotionInstance, error) {
	c.PrLogger.Debug("Generating promotion plan")
	// TODO refactor tests to use the two functions below instead of this one
	relevantComponents, err := generateListOfRelevantComponents(ctx, c)
	if err != nil {
		return nil, err
	}
	promotions, err := generatePlanBasedOnChangedComponent(ctx, c, relevantComponents, configBranch)
	return promotions, err
}
