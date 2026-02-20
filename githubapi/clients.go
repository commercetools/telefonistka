package githubapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v62/github"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

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

func createGhAppClientPair(ctx context.Context, appID int64, keyPath string, endpoints GithubEndpoints, owner string) (GhClientPair, error) {
	if endpoints.RestURL != "" {
		slog.Info("Github REST API endpoint is configured", "url", endpoints.RestURL)
		slog.Info("Github graphql API endpoint is configured", "url", endpoints.GraphqlURL)
	} else {
		slog.Debug("Using public Github API endpoint")
	}

	githubAppInstallationId, err := getAppInstallationId(keyPath, appID, endpoints.RestURL, ctx, owner)
	if err != nil {
		return GhClientPair{}, fmt.Errorf("getting app installation ID for owner %s: %w", owner, err)
	}

	v3, err := createGithubAppRestClient(keyPath, appID, githubAppInstallationId, endpoints.RestURL, ctx)
	if err != nil {
		return GhClientPair{}, fmt.Errorf("creating REST client: %w", err)
	}
	v4, err := createGithubAppGraphQlClient(keyPath, appID, githubAppInstallationId, endpoints.GraphqlURL, endpoints.RestURL, ctx)
	if err != nil {
		return GhClientPair{}, fmt.Errorf("creating GraphQL client: %w", err)
	}

	return GhClientPair{v3Client: v3, v4Client: v4}, nil
}

func createGhTokenClientPair(ctx context.Context, oauthToken string, endpoints GithubEndpoints) GhClientPair {
	if endpoints.RestURL != "" {
		slog.Info("Github REST API endpoint is configured", "url", endpoints.RestURL)
		slog.Info("Github graphql API endpoint is configured", "url", endpoints.GraphqlURL)
	} else {
		slog.Debug("Using public Github API endpoint")
	}

	return GhClientPair{
		v3Client: createGithubRestClient(oauthToken, endpoints.RestURL, ctx),
		v4Client: createGithubGraphQlClient(oauthToken, endpoints.GraphqlURL),
	}
}

// GetOrCreateClient retrieves a cached client pair or creates one.
// App-auth clients are cached per owner; token-auth clients are cached globally.
func GetOrCreateClient(ctx context.Context, cache *lru.Cache[string, GhClientPair], creds ClientConfig, endpoints GithubEndpoints, owner string) (GhClientPair, error) {
	key := owner
	if creds.AppID == 0 {
		key = "global"
	}
	if pair, ok := cache.Get(key); ok {
		slog.Debug("Found cached client", "key", key)
		return pair, nil
	}

	slog.Info("Creating new GitHub client", "key", key, "app_auth", creds.AppID != 0)

	var pair GhClientPair
	if creds.AppID != 0 {
		var err error
		pair, err = createGhAppClientPair(ctx, creds.AppID, creds.AppKeyPath, endpoints, owner)
		if err != nil {
			return GhClientPair{}, fmt.Errorf("creating app client pair: %w", err)
		}
	} else {
		if creds.OAuthToken == "" {
			return GhClientPair{}, fmt.Errorf("neither AppID nor OAuthToken set in ClientConfig")
		}
		pair = createGhTokenClientPair(ctx, creds.OAuthToken, endpoints)
	}

	cache.Add(key, pair)
	return pair, nil
}
