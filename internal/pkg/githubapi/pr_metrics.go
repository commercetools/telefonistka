package githubapi

import (
	"context"
	"time"

	"github.com/google/go-github/v62/github"
	lru "github.com/hashicorp/golang-lru/v2"
	log "github.com/sirupsen/logrus"
	prom "github.com/wayfair-incubator/telefonistka/internal/pkg/prometheus"
)

const (
	minutesToDfineStale = 20
)

func getRepoPrMetrics(ctx context.Context, ghClient GhClientPair, repo *github.Repository) (prWithStakeChecks int, openPRs int, openPromotionPrs int, err error) {
	log.Debugf("Checking repo %s", repo.GetName())
	ghOwner := repo.GetOwner().GetLogin()
	prListOpts := &github.PullRequestListOptions{
		State: "open",
	}
	prs := []*github.PullRequest{}

	// paginate through PRs, there might be lot of them.
	for {
		perPagePrs, resp, err := ghClient.v3Client.PullRequests.List(ctx, ghOwner, repo.GetName(), prListOpts)
		_ = prom.InstrumentGhCall(resp)
		if err != nil {
			log.Errorf("error getting PRs for %s/%s: %v", ghOwner, repo.GetName(), err)
		}
		prs = append(prs, perPagePrs...)
		if resp.NextPage == 0 {
			break
		}
		prListOpts.Page = resp.NextPage
	}

	for _, pr := range prs {
		if DoesPrHasLabel(pr.Labels, "promotion") {
			openPromotionPrs++
		}
		log.Debugf("Checking PR %d", pr.GetNumber())
		commitStatuses, resp, err := ghClient.v3Client.Repositories.GetCombinedStatus(ctx, ghOwner, repo.GetName(), pr.GetHead().GetSHA(), nil)
		_ = prom.InstrumentGhCall(resp)
		if err != nil {
			log.Errorf("error getting statuses for %s/%s/%d: %v", ghOwner, repo.GetName(), pr.GetNumber(), err)
			continue
		}
		for _, status := range commitStatuses.Statuses {
			if *status.Context == "telefonistka" &&
				*status.State == "pending" &&
				status.UpdatedAt.GetTime().Before(time.Now().Add(-time.Minute*minutesToDfineStale)) {
				log.Debugf("Adding status %s-%v-%s !!!", *status.Context, status.UpdatedAt.GetTime(), *status.State)
				prWithStakeChecks++
			} else {
				log.Debugf("Ignoring status %s-%v-%s", *status.Context, status.UpdatedAt.GetTime(), *status.State)
			}
		}
	}
	openPRs = len(prs)

	return
}

// GetPrMetrics counts the number of pending checks that are older than 20 minutes
func GetPrMetrics(mainGhClientCache *lru.Cache[string, GhClientPair]) {
	ctx := context.Background() // TODO!!!!

	for _, ghOwner := range mainGhClientCache.Keys() {
		log.Debugf("Checking gh Owner %s", ghOwner)
		ghClient, _ := mainGhClientCache.Get(ghOwner)
		repos, resp, err := ghClient.v3Client.Apps.ListRepos(ctx, nil)
		_ = prom.InstrumentGhCall(resp)
		if err != nil {
			log.Errorf("error getting repos for %s: %v", ghOwner, err)
			continue
		}
		for _, repo := range repos.Repositories {
			stalePendingChecks, openPrs, promotionPrs, _ := getRepoPrMetrics(ctx, ghClient, repo)
			prom.PublishPrMetrics(openPrs, promotionPrs, stalePendingChecks, repo.GetFullName())
		}
	}
}
