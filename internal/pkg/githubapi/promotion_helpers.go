package githubapi

import (
	"regexp"
	"strings"
)

// Hilfsfunktion: true, wenn der Dateiname auf ein Ignore-Pattern matcht
func IsIgnoredFile(filename string, ignoreFiles []string) bool {
	for _, pattern := range ignoreFiles {
		matched, err := regexp.MatchString(pattern, filename)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// Hilfsfunktion: entfernt Zeilen, die auf ein Ignore-Pattern matchen
func FilterLinesByRegex(content string, regexList []string) string {
	lines := strings.Split(content, "\n")
	var filtered []string
	var regexps []*regexp.Regexp
	for _, expr := range regexList {
		re, err := regexp.Compile(expr)
		if err == nil {
			regexps = append(regexps, re)
		}
	}
	for _, line := range lines {
		ignore := false
		for _, re := range regexps {
			if re.MatchString(line) {
				ignore = true
				break
			}
		}
		if !ignore {
			filtered = append(filtered, line)
		}
	}
	return strings.Join(filtered, "\n")
}

// PromotionInstance und PromotionInstanceMetaData Typen exportieren
// (Kopiert aus promotion.go)
type PromotionInstance struct {
	Metadata          PromotionInstanceMetaData `deep:"-"`
	ComputedSyncPaths map[string]string
}

type PromotionInstanceMetaData struct {
	SourcePath                     string
	TargetPaths                    []string
	TargetDescription              string
	PerComponentSkippedTargetPaths map[string][]string
	ComponentNames                 []string
	AutoMerge                      bool
}
