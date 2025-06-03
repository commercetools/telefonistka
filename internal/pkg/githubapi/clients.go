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

func getCrucialEnv(key string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	slog.Error("environment variable is required", "key", key)
	os.Exit(3)
	return ""
}

type GhClientPair struct {
	v3Client *github.Client
	v4Client *githubv4.Client
}

func getAppInstallationId(githubAppPrivateKeyPath string, githubAppId int64, githubRestAltURL string, ctx context.Context, owner string) (int64, error) {
	atr, err := ghinstallation.NewAppsTransportKeyFromFile(http.DefaultTransport, githubAppId, githubAppPrivateKeyPath)
	if err != nil {
		panic(err)
	}
	tempClient := github.NewClient(
		&http.Client{
			Transport: atr,
			Timeout:   time.Second * 30,
		})

	if githubRestAltURL != "" {
		tempClient, err = tempClient.WithEnterpriseURLs(githubRestAltURL, githubRestAltURL)
		if err != nil {
			slog.Error("failed to create git client for app", "err", err)
			os.Exit(1)
		}
	}

	installations, _, err := tempClient.Apps.ListInstallations(ctx, &github.ListOptions{})
	if err != nil {
		slog.Error("failed to list installations", "err", err)
		os.Exit(1)
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

func createGithubAppRestClient(githubAppPrivateKeyPath string, githubAppId int64, githubAppInstallationId int64, githubRestAltURL string, ctx context.Context) *github.Client {
	itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, githubAppId, githubAppInstallationId, githubAppPrivateKeyPath)
	if err != nil {
		slog.Error("NewKeyFromFile", "err", err)
		os.Exit(1)
	}
	var client *github.Client

	if githubRestAltURL != "" {
		itr.BaseURL = githubRestAltURL
		client, _ = github.NewClient(&http.Client{Transport: itr}).WithEnterpriseURLs(githubRestAltURL, githubRestAltURL)
	} else {
		client = github.NewClient(&http.Client{Transport: itr})
	}
	return client
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

func createGithubAppGraphQlClient(githubAppPrivateKeyPath string, githubAppId int64, githubAppInstallationId int64, githubGraphqlAltURL string, githubRestAltURL string, ctx context.Context) *githubv4.Client {
	itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, githubAppId, githubAppInstallationId, githubAppPrivateKeyPath)
	if err != nil {
		slog.Error("NewKeyFromFile", "err", err)
		os.Exit(1)
	}
	var client *githubv4.Client

	if githubGraphqlAltURL != "" {
		itr.BaseURL = githubRestAltURL
		client = githubv4.NewEnterpriseClient(githubGraphqlAltURL, &http.Client{Transport: itr})
	} else {
		client = githubv4.NewClient(&http.Client{Transport: itr})
	}
	return client
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

func createGhAppClientPair(ctx context.Context, githubAppId int64, owner string, ghAppPKeyPathEnvVarName string) GhClientPair {
	var githubRestAltURL string
	var githubGraphqlAltURL string
	githubAppPrivateKeyPath := getCrucialEnv(ghAppPKeyPathEnvVarName)
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
		slog.Error("Couldn't find installation for app ID and repo owner", "github_app_id", githubAppId, "owner", owner)
	}

	return GhClientPair{
		v3Client: createGithubAppRestClient(githubAppPrivateKeyPath, githubAppId, githubAppInstallationId, githubRestAltURL, ctx),
		v4Client: createGithubAppGraphQlClient(githubAppPrivateKeyPath, githubAppId, githubAppInstallationId, githubGraphqlAltURL, githubRestAltURL, ctx),
	}
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

func (gcp *GhClientPair) GetAndCache(ghClientCache *lru.Cache[string, GhClientPair], ghAppIdEnvVarName string, ghAppPKeyPathEnvVarName string, ghOauthTokenEnvVarName string, repoOwner string, ctx context.Context) {
	githubAppId := getEnv(ghAppIdEnvVarName, "")
	var keyExist bool
	if githubAppId != "" {
		*gcp, keyExist = ghClientCache.Get(repoOwner)
		if keyExist {
			slog.Debug("Found cached client for owner", "owner", repoOwner)
		} else {
			slog.Info("Did not found cached client for owner, creating one", "owner", repoOwner, "github_app_id_env", ghAppIdEnvVarName, "github_app_key_env", ghAppPKeyPathEnvVarName)
			githubAppIdint, err := strconv.ParseInt(githubAppId, 10, 64)
			if err != nil {
				slog.Error("GITHUB_APP_ID value could not converted to int64", "err", err)
				os.Exit(1)
			}
			*gcp = createGhAppClientPair(ctx, githubAppIdint, repoOwner, ghAppPKeyPathEnvVarName)
			ghClientCache.Add(repoOwner, *gcp)
		}
	} else {
		*gcp, keyExist = ghClientCache.Get("global")
		if keyExist {
			slog.Debug("Found global cached client")
		} else {
			slog.Info("Did not found global cached client, creating one with env var", "env", ghOauthTokenEnvVarName)
			ghOauthToken := getCrucialEnv(ghOauthTokenEnvVarName)

			*gcp = createGhTokenClientPair(ctx, ghOauthToken)
			ghClientCache.Add("global", *gcp)
		}
	}
}
