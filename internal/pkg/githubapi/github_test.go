package githubapi

import (
	"bytes"
	"testing"
)

func TestGenerateSafePromotionBranchName(t *testing.T) {
	t.Parallel()
	prNumber := 11
	originBranch := "originBranch"
	targetPaths := []string{"targetPath1", "targetPath2"}
	result := generateSafePromotionBranchName(prNumber, originBranch, targetPaths)
	expectedResult := "promotions/11-originBranch-676f02019f18"
	if result != expectedResult {
		t.Errorf("Expected %s, got %s", expectedResult, result)
	}
}

// TestGenerateSafePromotionBranchNameLongBranchName tests the case where the original  branch name is longer than 250 characters
func TestGenerateSafePromotionBranchNameLongBranchName(t *testing.T) {
	t.Parallel()
	prNumber := 11

	originBranch := string(bytes.Repeat([]byte("originBranch"), 100))
	targetPaths := []string{"targetPath1", "targetPath2"}
	result := generateSafePromotionBranchName(prNumber, originBranch, targetPaths)
	if len(result) > 250 {
		t.Errorf("Expected branch name to be less than 250 characters, got %d", len(result))
	}
}

// TestGenerateSafePromotionBranchNameLongTargets tests the case where the target paths are longer than 250 characters
func TestGenerateSafePromotionBranchNameLongTargets(t *testing.T) {
	t.Parallel()
	prNumber := 11
	originBranch := "originBranch"
	targetPaths := []string{
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/1",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/2",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/3",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/4",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/5",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/6",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/7",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/8",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/9",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/10",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/11",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/12",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/13",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/14",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/15",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/16",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/17",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/18",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/19",
		"loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong/target/path/20",
	}
	result := generateSafePromotionBranchName(prNumber, originBranch, targetPaths)
	if len(result) > 250 {
		t.Errorf("Expected branch name to be less than 250 characters, got %d", len(result))
	}
}

// Testing a case when a checkbox is marked
func TestAnalyzeCommentUpdateCheckBoxChecked(t *testing.T) {
	t.Parallel()
	newBody := `This is a comment
foobar
- [x] <!-- check-slug-1 --> Description of checkbox
foobar`

	oldBody := `This is a comment
foobar
- [ ] <!-- check-slug-1 --> Description of checkbox
foobar`
	checkboxPattern := `(?m)^\s*-\s*\[(.)\]\s*<!-- check-slug-1 -->.*$`

	wasCheckedBefore, isCheckedNow := analyzeCommentUpdateCheckBox(newBody, oldBody, checkboxPattern)
	if !isCheckedNow {
		t.Error("Expected isCheckedNow to be true")
	}
	if wasCheckedBefore {
		t.Errorf("Expected wasCheckedBeforeto be false, actaully got %t", wasCheckedBefore)
	}
}

// Testing a case when a checkbox is unmarked
func TestAnalyzeCommentUpdateCheckBoxUnChecked(t *testing.T) {
	t.Parallel()
	newBody := `This is a comment
foobar
- [ ] <!-- check-slug-1 --> Description of checkbox
foobar`

	oldBody := `This is a comment
foobar
- [x] <!-- check-slug-1 --> Description of checkbox
foobar`
	checkboxPattern := `(?m)^\s*-\s*\[(.)\]\s*<!-- check-slug-1 -->.*$`

	wasCheckedBefore, isCheckedNow := analyzeCommentUpdateCheckBox(newBody, oldBody, checkboxPattern)
	if isCheckedNow {
		t.Error("Expected isCheckedNow to be false")
	}
	if !wasCheckedBefore {
		t.Error("Expected wasCheckedBeforeto be true")
	}
}

// Testing a case when a checkbox isn't in the comment body
func TestAnalyzeCommentUpdateCheckBoxNonRelevent(t *testing.T) {
	t.Parallel()
	newBody := `This is a comment
foobar
foobar`

	oldBody := `This is a comment
foobar2
foobar2`
	checkboxPattern := `(?m)^\s*-\s*\[(.)\]\s*<!-- check-slug-1 -->.*$`

	wasCheckedBefore, isCheckedNow := analyzeCommentUpdateCheckBox(newBody, oldBody, checkboxPattern)
	if isCheckedNow {
		t.Error("Expected isCheckedNow to be false")
	}
	if wasCheckedBefore {
		t.Error("Expected wasCheckedBeforeto be false")
	}
}

func TestIsSyncFromBranchAllowedForThisPathTrue(t *testing.T) {
	t.Parallel()
	allowedPathRegex := `^workspace/.*$`
	path := "workspace/app3"
	result := isSyncFromBranchAllowedForThisPath(allowedPathRegex, path)
	if !result {
		t.Error("Expected result to be true")
	}
}

func TestIsSyncFromBranchAllowedForThisPathFalse(t *testing.T) {
	t.Parallel()
	allowedPathRegex := `^workspace/.*$`
	path := "clusters/prod/aws/eu-east-1/app3"
	result := isSyncFromBranchAllowedForThisPath(allowedPathRegex, path)
	if result {
		t.Error("Expected result to be false")
	}
}
