package githubapi

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"text/template"

	cfg "github.com/commercetools/telefonistka/configuration"
	"github.com/commercetools/telefonistka/templates"
	prom "github.com/commercetools/telefonistka/prometheus"
	"github.com/google/go-github/v62/github"
)

func templatesFS() fs.FS {
	if p := os.Getenv("TEMPLATES_PATH"); p != "" {
		return os.DirFS(p)
	}
	return templates.FS
}

func executeTemplate(templateName string, templateFile string, data any) (string, error) {
	var buf bytes.Buffer
	tmpl, err := template.New(templateName).ParseFS(templatesFS(), templateFile)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}
	if err := tmpl.ExecuteTemplate(&buf, templateName, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}
	return buf.String(), nil
}

func executeTemplateFile(templateName string, templateFile string, data any) (string, error) {
	var buf bytes.Buffer
	tmpl, err := template.New(templateName).ParseFiles(templateFile)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}
	if err := tmpl.ExecuteTemplate(&buf, templateName, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}
	return buf.String(), nil
}

func GetInRepoConfig(ctx context.Context, c Context) (*cfg.Config, error) {
	inRepoConfigFileContentString, err := GetFileContent(ctx, c, c.DefaultBranch, "telefonistka.yaml")
	if err != nil {
		c.PrLogger.Error("Could not get in-repo configuration", "err", err)
		inRepoConfigFileContentString = ""
	}
	conf, err := cfg.ParseConfigFromYaml(inRepoConfigFileContentString)
	if err != nil {
		c.PrLogger.Error("Failed to parse configuration", "err", err)
	}
	return conf, err
}

func GetFileContent(ctx context.Context, c Context, branch string, filePath string) (string, error) {
	rGetContentOps := github.RepositoryContentGetOptions{Ref: branch}
	fileContent, _, resp, err := c.GhClientPair.v3Client.Repositories.GetContents(ctx, c.Owner, c.Repo, filePath, &rGetContentOps)
	if err != nil {
		c.PrLogger.Error("Fail to get file", "err", err, "resp", resp)
		if resp == nil {
			return "", err
		}
		prom.InstrumentGhCall(resp)
		return "", err
	} else {
		prom.InstrumentGhCall(resp)
	}
	fileContentString, err := fileContent.GetContent()
	if err != nil {
		c.PrLogger.Error("Fail to serlize file", "err", err)
		return "", err
	}
	return fileContentString, nil
}
