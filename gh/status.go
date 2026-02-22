package gh

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"text/template"
	"time"

	prom "github.com/commercetools/telefonistka/prometheus"
	"github.com/google/go-github/v62/github"
)

func setCommitStatus(_ context.Context, c Context, state string, commitStatusURLTmpl *template.Template) {
	tcontext := "telefonistka"
	avatarURL := "https://avatars.githubusercontent.com/u/1616153?s=64"
	description := "Telefonistka GitOps Bot"

	targetURL := commitStatusTargetURL(time.Now(), commitStatusURLTmpl)

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
	initialStatuses, resp, err := p.Repositories.ListStatuses(ctx, p.Owner, p.Repo, p.Ref, &github.ListOptions{})
	prom.InstrumentGhCall(resp)
	if err != nil {
		p.PrLogger.Error("Failed to fetch existing statuses for commit", "commit", p.Ref, "err", err)
		return err
	}

	for _, commitStatus := range initialStatuses {
		if commitStatus.GetContext() != context {
			continue
		}

		newState := "success"
		if commitStatus.GetState() == "success" {
			newState = "failure"
		}
		p.PrLogger.Info("User toggled state", "user", user, "context", context, "from", commitStatus.GetState(), "to", newState)
		commitStatus.State = github.String(newState)

		_, resp, err := p.Repositories.CreateStatus(ctx, p.Owner, p.Repo, p.PrSHA, commitStatus)
		prom.InstrumentGhCall(resp)
		if err != nil {
			p.PrLogger.Error("Failed to create context", "context", context, "err", err)
			return err
		}
		break
	}

	return nil
}

// commitStatusTargetURL renders a target URL from a pre-compiled template.
// If tmpl is nil (no custom template configured), it returns the default URL.
func commitStatusTargetURL(commitTime time.Time, tmpl *template.Template) string {
	const defaultURL = "https://github.com/commercetools/telefonistka"

	if tmpl == nil {
		return defaultURL
	}

	p := struct {
		CommitTime time.Time
	}{
		CommitTime: commitTime,
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		slog.Debug("Failed to render target URL template", "err", err)
		return defaultURL
	}
	return strings.TrimSpace(buf.String())
}
