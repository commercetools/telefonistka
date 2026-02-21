package githubapi

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
)

func generatePromotionPrBody(ctx context.Context, c Context, components string, promotion promotionInstance, originalPrAuthor string) string {
	// newPrMetadata will be serialized and persisted in the PR body for use when the PR is merged
	var newPrMetadata prMetadata
	var newPrBody string

	newPrMetadata.OriginalPrAuthor = originalPrAuthor

	if c.PrMetadata.PreviousPromotionMetadata != nil {
		newPrMetadata.PreviousPromotionMetadata = c.PrMetadata.PreviousPromotionMetadata
	} else {
		newPrMetadata.PreviousPromotionMetadata = make(map[int]promotionInstanceMetaData)
	}

	newPrMetadata.PreviousPromotionMetadata[c.PrNumber] = promotionInstanceMetaData{
		TargetPaths: promotion.Metadata.TargetPaths,
		SourcePath:  promotion.Metadata.SourcePath,
	}

	newPrMetadata.PromotedPaths = slices.Collect(maps.Keys(promotion.ComputedSyncPaths))

	promotionSkipPaths := getPromotionSkipPaths(promotion)

	newPrBody = fmt.Sprintf("Promotion path(%s):\n\n", components)

	keys := slices.Sorted(maps.Keys(newPrMetadata.PreviousPromotionMetadata))

	newPrBody = prBody(keys, newPrMetadata, newPrBody, promotionSkipPaths)

	prMetadataString, _ := newPrMetadata.serialize() // json.Marshal on a known struct; safe to ignore

	newPrBody = newPrBody + "\n<!--|Telefonistka data, do not delete|" + prMetadataString + "|-->"

	return newPrBody
}

// getPromotionSkipPaths returns a map of paths that are marked as skipped for this promotion
// when we have multiple components, we are going to use the component that has the fewest skip paths
func getPromotionSkipPaths(promotion promotionInstance) map[string]bool {
	perComponentSkippedTargetPaths := promotion.Metadata.PerComponentSkippedTargetPaths
	promotionSkipPaths := map[string]bool{}

	if len(perComponentSkippedTargetPaths) == 0 {
		return promotionSkipPaths
	}

	// if any promoted component is not in the perComponentSkippedTargetPaths
	// then that means we have a component that is promoted to all paths,
	// therefore, we return an empty promotionSkipPaths map to signify that
	// there are no paths that are skipped for this promotion
	for _, component := range promotion.Metadata.ComponentNames {
		if _, ok := perComponentSkippedTargetPaths[component]; !ok {
			return promotionSkipPaths
		}
	}

	// if we have one or more components then we are just going to
	// use the component that has the fewest skipPaths when
	// generating the promotion prBody. This way the promotion
	// body will error on the side of informing the user
	// of more promotion paths, rather than leaving some out.
	skipCounts := map[string]int{}
	for component, paths := range perComponentSkippedTargetPaths {
		skipCounts[component] = len(paths)
	}

	skipPaths := slices.Collect(maps.Keys(skipCounts))
	slices.SortFunc(skipPaths, func(a, b string) int {
		return cmp.Compare(skipCounts[a], skipCounts[b])
	})

	componentWithFewestSkippedPaths := skipPaths[0]
	for _, p := range perComponentSkippedTargetPaths[componentWithFewestSkippedPaths] {
		promotionSkipPaths[p] = true
	}

	return promotionSkipPaths
}

func prBody(keys []int, newPrMetadata prMetadata, newPrBody string, promotionSkipPaths map[string]bool) string {
	const mkTab = "&nbsp;&nbsp;&nbsp;&nbsp;"
	sp := ""
	tp := ""

	for i, k := range keys {
		sp = newPrMetadata.PreviousPromotionMetadata[k].SourcePath
		x := filterSkipPaths(newPrMetadata.PreviousPromotionMetadata[k].TargetPaths, promotionSkipPaths)
		// sort the paths so that we have a predictable order for tests and better readability for users
		slices.Sort(x)
		tp = strings.Join(x, fmt.Sprintf("`  \n%s`", strings.Repeat(mkTab, i+1)))
		newPrBody = newPrBody + fmt.Sprintf("%s↘️  #%d  `%s` ➡️  \n%s`%s`  \n", strings.Repeat(mkTab, i), k, sp, strings.Repeat(mkTab, i+1), tp)
	}

	return newPrBody
}

// filterSkipPaths filters out the paths that are marked as skipped
func filterSkipPaths(targetPaths []string, promotionSkipPaths map[string]bool) []string {
	var paths []string
	for _, p := range targetPaths {
		if !promotionSkipPaths[p] {
			paths = append(paths, p)
		}
	}
	return paths
}
