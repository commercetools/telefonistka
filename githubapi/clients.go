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

type GhClient struct {
	v3Client *github.Client
	v4Client *githubv4.Client
}

func getAppInstallationId(ctx context.Context, keyPath string, appID int64, restURL string, owner string) (int64, error) {
	atr, err := ghinstallation.NewAppsTransportKeyFromFile(http.DefaultTransport, appID, keyPath)
	if err != nil {
		return 0, fmt.Errorf("loading app private key: %w", err)
	}
	tempClient := github.NewClient(
		&http.Client{
			Transport: atr,
			Timeout:   time.Second * 30,
		})

	if restURL != "" {
		tempClient, err = tempClient.WithEnterpriseURLs(restURL, restURL)
		if err != nil {
			return 0, fmt.Errorf("configuring enterprise URL: %w", err)
		}
	}

	installations, _, err := tempClient.Apps.ListInstallations(ctx, &github.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("listing installations: %w", err)
	}

	for _, i := range installations {
		if i.GetAccount().GetLogin() == owner {
			id := i.GetID()
			slog.Info("Installation ID for GitHub Application", "github_app_id", appID, "install_id", id)
			return id, nil
		}
	}

	return 0, fmt.Errorf("no installation found for owner %s", owner)
}

// newAppClientPair creates a REST+GraphQL client pair using GitHub App auth.
// A single ghinstallation transport is shared by both clients.
func newAppClientPair(ctx context.Context, appID int64, keyPath string, endpoints GithubEndpoints, owner string) (GhClient, error) {
	installID, err := getAppInstallationId(ctx, keyPath, appID, endpoints.RestURL, owner)
	if err != nil {
		return GhClient{}, fmt.Errorf("getting app installation ID for owner %s: %w", owner, err)
	}

	itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, appID, installID, keyPath)
	if err != nil {
		return GhClient{}, fmt.Errorf("loading installation key: %w", err)
	}
	if endpoints.RestURL != "" {
		itr.BaseURL = endpoints.RestURL
	}

	httpClient := &http.Client{Transport: itr}

	v3 := github.NewClient(httpClient)
	if endpoints.RestURL != "" {
		v3, err = v3.WithEnterpriseURLs(endpoints.RestURL, endpoints.RestURL)
		if err != nil {
			return GhClient{}, fmt.Errorf("configuring enterprise REST URL: %w", err)
		}
	}

	var v4 *githubv4.Client
	if endpoints.GraphqlURL != "" {
		v4 = githubv4.NewEnterpriseClient(endpoints.GraphqlURL, httpClient)
	} else {
		v4 = githubv4.NewClient(httpClient)
	}

	return GhClient{v3Client: v3, v4Client: v4}, nil
}

// newTokenClientPair creates a REST+GraphQL client pair using an OAuth token.
func newTokenClientPair(ctx context.Context, token string, endpoints GithubEndpoints) GhClient {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	httpClient := oauth2.NewClient(ctx, ts)

	v3 := github.NewClient(httpClient)
	if endpoints.RestURL != "" {
		v3, _ = v3.WithEnterpriseURLs(endpoints.RestURL, endpoints.RestURL)
	}

	var v4 *githubv4.Client
	if endpoints.GraphqlURL != "" {
		v4 = githubv4.NewEnterpriseClient(endpoints.GraphqlURL, httpClient)
	} else {
		v4 = githubv4.NewClient(httpClient)
	}

	return GhClient{v3Client: v3, v4Client: v4}
}

// GetOrCreateClient retrieves a cached client pair or creates one.
// App-auth clients are cached per owner; token-auth clients are cached globally.
func GetOrCreateClient(ctx context.Context, cache *lru.Cache[string, GhClient], creds ClientConfig, endpoints GithubEndpoints, owner string) (GhClient, error) {
	key := owner
	if creds.AppID == 0 {
		key = "global"
	}
	if pair, ok := cache.Get(key); ok {
		slog.Debug("Found cached client", "key", key)
		return pair, nil
	}

	slog.Info("Creating new GitHub client", "key", key, "app_auth", creds.AppID != 0)

	if creds.AppID != 0 {
		pair, err := newAppClientPair(ctx, creds.AppID, creds.AppKeyPath, endpoints, owner)
		if err != nil {
			return GhClient{}, err
		}
		cache.Add(key, pair)
		return pair, nil
	}

	if creds.OAuthToken == "" {
		return GhClient{}, fmt.Errorf("neither AppID nor OAuthToken set in ClientConfig")
	}
	pair := newTokenClientPair(ctx, creds.OAuthToken, endpoints)
	cache.Add(key, pair)
	return pair, nil
}
