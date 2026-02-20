package githubapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v62/github"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getCrucialEnv(key string) (string, error) {
	if value, ok := os.LookupEnv(key); ok {
		return value, nil
	}
	return "", fmt.Errorf("required environment variable %s is not set", key)
}

type GhClientPair struct {
	v3Client *github.Client
	v4Client *githubv4.Client
}

func getAppInstallationId(githubAppPrivateKeyPath string, githubAppId int64, githubRestAltURL string, ctx context.Context, owner string) (int64, error) {
	atr, err := ghinstallation.NewAppsTransportKeyFromFile(http.DefaultTransport, githubAppId, githubAppPrivateKeyPath)
	if err != nil {
		return 0, fmt.Errorf("loading app private key: %w", err)
	}
	tempClient := github.NewClient(
		&http.Client{
			Transport: atr,
			Timeout:   time.Second * 30,
		})

	if githubRestAltURL != "" {
		tempClient, err = tempClient.WithEnterpriseURLs(githubRestAltURL, githubRestAltURL)
		if err != nil {
			return 0, fmt.Errorf("configuring enterprise URL: %w", err)
		}
	}

	installations, _, err := tempClient.Apps.ListInstallations(ctx, &github.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("listing installations: %w", err)
	}

	var installID int64
	for _, i := range installations {
		if *i.Account.Login == owner {
			installID = i.GetID()
			slog.Info("Installation ID for GitHub Application", "github_app_id", githubAppId, "install_id", installID)
			return installID, nil
		}
	}

	return 0, err
}

func createGithubAppRestClient(githubAppPrivateKeyPath string, githubAppId int64, githubAppInstallationId int64, githubRestAltURL string, ctx context.Context) (*github.Client, error) {
	itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, githubAppId, githubAppInstallationId, githubAppPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading installation key: %w", err)
	}

	if githubRestAltURL != "" {
		itr.BaseURL = githubRestAltURL
		client, err := github.NewClient(&http.Client{Transport: itr}).WithEnterpriseURLs(githubRestAltURL, githubRestAltURL)
		if err != nil {
			return nil, fmt.Errorf("configuring enterprise REST URL: %w", err)
		}
		return client, nil
	}
	return github.NewClient(&http.Client{Transport: itr}), nil
}

func createGithubRestClient(githubOauthToken string, githubRestAltURL string, ctx context.Context) *github.Client {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: githubOauthToken},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)
	if githubRestAltURL != "" {
		client, _ = client.WithEnterpriseURLs(githubRestAltURL, githubRestAltURL)
	}

	return client
}

func createGithubAppGraphQlClient(githubAppPrivateKeyPath string, githubAppId int64, githubAppInstallationId int64, githubGraphqlAltURL string, githubRestAltURL string, ctx context.Context) (*githubv4.Client, error) {
	itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, githubAppId, githubAppInstallationId, githubAppPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading installation key: %w", err)
	}

	if githubGraphqlAltURL != "" {
		itr.BaseURL = githubRestAltURL
		return githubv4.NewEnterpriseClient(githubGraphqlAltURL, &http.Client{Transport: itr}), nil
	}
	return githubv4.NewClient(&http.Client{Transport: itr}), nil
}

func createGithubGraphQlClient(githubOauthToken string, githubGraphqlAltURL string) *githubv4.Client {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: githubOauthToken},
	)
	httpClient := oauth2.NewClient(context.Background(), ts)
	var client *githubv4.Client
	if githubGraphqlAltURL != "" {
		client = githubv4.NewEnterpriseClient(githubGraphqlAltURL, httpClient)
	} else {
		client = githubv4.NewClient(httpClient)
	}
	return client
}

func createGhAppClientPair(ctx context.Context, githubAppId int64, owner string, ghAppPKeyPathEnvVarName string) (GhClientPair, error) {
	var githubRestAltURL string
	var githubGraphqlAltURL string
	githubAppPrivateKeyPath, err := getCrucialEnv(ghAppPKeyPathEnvVarName)
	if err != nil {
		return GhClientPair{}, err
	}
	githubHost := getEnv("GITHUB_HOST", "")
	if githubHost != "" {
		githubRestAltURL = fmt.Sprintf("https://%s/api/v3", githubHost)
		githubGraphqlAltURL = fmt.Sprintf("https://%s/api/graphql", githubHost)
		slog.Info("Github REST API endpoint is configured", "url", githubRestAltURL)
		slog.Info("Github graphql API endpoint is configured", "url", githubGraphqlAltURL)
	} else {
		slog.Debug("Using public Github API endpoint")
	}

	githubAppInstallationId, err := getAppInstallationId(githubAppPrivateKeyPath, githubAppId, githubRestAltURL, ctx, owner)
	if err != nil {
		return GhClientPair{}, fmt.Errorf("getting app installation ID for owner %s: %w", owner, err)
	}

	v3, err := createGithubAppRestClient(githubAppPrivateKeyPath, githubAppId, githubAppInstallationId, githubRestAltURL, ctx)
	if err != nil {
		return GhClientPair{}, fmt.Errorf("creating REST client: %w", err)
	}
	v4, err := createGithubAppGraphQlClient(githubAppPrivateKeyPath, githubAppId, githubAppInstallationId, githubGraphqlAltURL, githubRestAltURL, ctx)
	if err != nil {
		return GhClientPair{}, fmt.Errorf("creating GraphQL client: %w", err)
	}

	return GhClientPair{v3Client: v3, v4Client: v4}, nil
}

func createGhTokenClientPair(ctx context.Context, ghOauthToken string) GhClientPair {
	var githubRestAltURL string
	var githubGraphqlAltURL string
	githubHost := getEnv("GITHUB_HOST", "")
	if githubHost != "" {
		githubRestAltURL = fmt.Sprintf("https://%s/api/v3", githubHost)
		githubGraphqlAltURL = fmt.Sprintf("https://%s/api/graphql", githubHost)
		slog.Info("Github REST API endpoint is configured", "url", githubRestAltURL)
		slog.Info("Github graphql API endpoint is configured", "url", githubGraphqlAltURL)
	} else {
		slog.Debug("Using public Github API endpoint")
	}

	return GhClientPair{
		v3Client: createGithubRestClient(ghOauthToken, githubRestAltURL, ctx),
		v4Client: createGithubGraphQlClient(ghOauthToken, githubGraphqlAltURL),
	}
}

func (gcp *GhClientPair) GetAndCache(ghClientCache *lru.Cache[string, GhClientPair], ghAppIdEnvVarName string, ghAppPKeyPathEnvVarName string, ghOauthTokenEnvVarName string, repoOwner string, ctx context.Context) error {
	githubAppId := getEnv(ghAppIdEnvVarName, "")
	var keyExist bool
	if githubAppId != "" {
		*gcp, keyExist = ghClientCache.Get(repoOwner)
		if keyExist {
			slog.Debug("Found cached client for owner", "owner", repoOwner)
			return nil
		}
		slog.Info("Did not find cached client for owner, creating one", "owner", repoOwner, "github_app_id_env", ghAppIdEnvVarName, "github_app_key_env", ghAppPKeyPathEnvVarName)
		githubAppIdint, err := strconv.ParseInt(githubAppId, 10, 64)
		if err != nil {
			return fmt.Errorf("parsing %s value %q as int64: %w", ghAppIdEnvVarName, githubAppId, err)
		}
		pair, err := createGhAppClientPair(ctx, githubAppIdint, repoOwner, ghAppPKeyPathEnvVarName)
		if err != nil {
			return fmt.Errorf("creating app client pair: %w", err)
		}
		*gcp = pair
		ghClientCache.Add(repoOwner, *gcp)
		return nil
	}
	*gcp, keyExist = ghClientCache.Get("global")
	if keyExist {
		slog.Debug("Found global cached client")
		return nil
	}
	slog.Info("Did not find global cached client, creating one with env var", "env", ghOauthTokenEnvVarName)
	ghOauthToken, err := getCrucialEnv(ghOauthTokenEnvVarName)
	if err != nil {
		return err
	}

	*gcp = createGhTokenClientPair(ctx, ghOauthToken)
	ghClientCache.Add("global", *gcp)
	return nil
}
