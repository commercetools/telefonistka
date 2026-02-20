package githubapi

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"text/template"

	cfg "github.com/commercetools/telefonistka/configuration"
	prom "github.com/commercetools/telefonistka/prometheus"
	"github.com/google/go-github/v62/github"
)

func executeTemplate(fsys fs.FS, templateName string, templateFile string, data any) (string, error) {
	var buf bytes.Buffer
	tmpl, err := template.New(templateName).ParseFS(fsys, templateFile)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}
	if err := tmpl.ExecuteTemplate(&buf, templateName, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}
	return buf.String(), nil
}

func getInRepoConfig(ctx context.Context, c Context) (*cfg.Config, error) {
	inRepoConfigFileContentString, err := getFileContent(ctx, c, c.DefaultBranch, "telefonistka.yaml")
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

func getFileContent(ctx context.Context, c Context, branch string, filePath string) (string, error) {
	rGetContentOps := github.RepositoryContentGetOptions{Ref: branch}
	fileContent, _, resp, err := c.Repositories.GetContents(ctx, c.Owner, c.Repo, filePath, &rGetContentOps)
	if resp != nil {
		prom.InstrumentGhCall(resp)
	}
	if err != nil {
		c.PrLogger.Error("Fail to get file", "err", err, "resp", resp)
		return "", err
	}
	fileContentString, err := fileContent.GetContent()
	if err != nil {
		c.PrLogger.Error("Failed to serialize file", "err", err)
		return "", err
	}
	return fileContentString, nil
}
