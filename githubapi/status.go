package githubapi

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	prom "github.com/commercetools/telefonistka/prometheus"
	"github.com/google/go-github/v62/github"
)

func setCommitStatus(_ context.Context, c Context, state string) {
	// TODO change all these values
	tcontext := "telefonistka"
	avatarURL := "https://avatars.githubusercontent.com/u/1616153?s=64"
	description := "Telefonistka GitOps Bot"
	tmplFile := os.Getenv("CUSTOM_COMMIT_STATUS_URL_TEMPLATE_PATH")

	targetURL := commitStatusTargetURL(time.Now(), tmplFile)

	commitStatus := &github.RepoStatus{
		TargetURL:   &targetURL,
		Description: &description,
		State:       &state,
		Context:     &tcontext,
		AvatarURL:   &avatarURL,
	}
	c.PrLogger.Debug("Setting commit status", "commit", c.PrSHA, "status", state)

	// use a separate context to avoid event processing timeout to cause
	// failures in updating the commit status
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_, resp, err := c.Repositories.CreateStatus(ctx, c.Owner, c.Repo, c.PrSHA, commitStatus)
	prom.InstrumentGhCall(resp)
	repoSlug := c.Owner + "/" + c.Repo
	prom.IncCommitStatusUpdateCounter(repoSlug, state)
	if err != nil {
		c.PrLogger.Error("Failed to set commit status", "err", err, "resp", resp)
	}
}

func (p *Context) toggleCommitStatus(ctx context.Context, context string, user string) error {
	var r error
	listOpts := &github.ListOptions{}

	initialStatuses, resp, err := p.Repositories.ListStatuses(ctx, p.Owner, p.Repo, p.Ref, listOpts)
	prom.InstrumentGhCall(resp)
	if err != nil {
		p.PrLogger.Error("Failed to fetch  existing statuses for commit", "commit", p.Ref, "err", err)
		r = err
	}

	for _, commitStatus := range initialStatuses {
		if commitStatus.GetContext() == context {
			if commitStatus.GetState() != "success" {
				p.PrLogger.Info("User toggled state to success", "user", user, "context", context, "state", commitStatus.GetState())
				commitStatus.State = github.String("success")
				_, resp, err := p.Repositories.CreateStatus(ctx, p.Owner, p.Repo, p.PrSHA, commitStatus)
				prom.InstrumentGhCall(resp)
				if err != nil {
					p.PrLogger.Error("Failed to create context", "context", context, "err", err)
					r = err
				}
			} else {
				p.PrLogger.Info("User toggled state to failure", "user", user, "context", context, "state", commitStatus.GetState())
				commitStatus.State = github.String("failure")
				_, resp, err := p.Repositories.CreateStatus(ctx, p.Owner, p.Repo, p.PrSHA, commitStatus)
				prom.InstrumentGhCall(resp)
				if err != nil {
					p.PrLogger.Error("Failed to create context", "context", context, "err", err)
					r = err
				}
			}
			break
		}
	}

	return r
}

// commitStatusTargetURL generates a target URL based on an optional
// template file specified by the environment variable CUSTOM_COMMIT_STATUS_URL_TEMPLATE_PATH.
// If the template file is not found or an error occurs during template execution,
// it returns a default URL.
// passed parameter commitTime can be used in the template as .CommitTime
func commitStatusTargetURL(commitTime time.Time, tmplFile string) string {
	const targetURL string = "https://github.com/commercetools/telefonistka"

	tmplName := filepath.Base(tmplFile)

	// dynamic parameters to be used in the template
	p := struct {
		CommitTime time.Time
	}{
		CommitTime: commitTime,
	}
	var buf bytes.Buffer
	tmpl, err := template.New(tmplName).ParseFiles(tmplFile)
	if err != nil {
		slog.Debug("Failed to render target URL template", "err", err)
		return targetURL
	}
	if err := tmpl.ExecuteTemplate(&buf, tmplName, p); err != nil {
		slog.Debug("Failed to render target URL template", "err", err)
		return targetURL
	}
	// trim any leading/trailing whitespace
	renderedURL := strings.TrimSpace(buf.String())
	return renderedURL
}
