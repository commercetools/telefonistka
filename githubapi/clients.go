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

// GhClient holds the REST and GraphQL clients for a single GitHub identity.
type GhClient struct {
	v3Client *github.Client
	v4Client *githubv4.Client
}

// GhClients bundles the main and approver GitHub clients for one repo owner.
// The approver is a separate identity so that auto-approvals don't come from
// the same user that opened the PR.
type GhClients struct {
	Main     GhClient
	Approver GhClient
}

// setServices populates all GitHub service fields on a Context.
func (gc GhClients) setServices(c *Context) {
	c.Repositories = gc.Main.v3Client.Repositories
	c.PullRequests = gc.Main.v3Client.PullRequests
	c.Issues = gc.Main.v3Client.Issues
	c.Git = gc.Main.v3Client.Git
	c.GraphQL = gc.Main.v4Client
	c.ApproverPRs = gc.Approver.v3Client.PullRequests
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

// newAppClient creates a REST+GraphQL client using GitHub App auth.
// A single ghinstallation transport is shared by both clients.
func newAppClient(ctx context.Context, appID int64, keyPath string, endpoints GithubEndpoints, owner string) (GhClient, error) {
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

// newTokenClient creates a REST+GraphQL client using an OAuth token.
func newTokenClient(ctx context.Context, token string, endpoints GithubEndpoints) GhClient {
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

// newClient creates a GhClient from credentials, dispatching to app or token auth.
func newClient(ctx context.Context, creds ClientConfig, endpoints GithubEndpoints, owner string) (GhClient, error) {
	if creds.AppID != 0 {
		return newAppClient(ctx, creds.AppID, creds.AppKeyPath, endpoints, owner)
	}
	if creds.OAuthToken == "" {
		return GhClient{}, fmt.Errorf("neither AppID nor OAuthToken set in ClientConfig")
	}
	return newTokenClient(ctx, creds.OAuthToken, endpoints), nil
}

// getOrCreateClients retrieves cached clients or creates both main and approver
// for the given owner. The cache key is the owner for app-auth, "global" for token-auth.
func getOrCreateClients(ctx context.Context, cache *lru.Cache[string, GhClients], mainCreds, approverCreds ClientConfig, endpoints GithubEndpoints, owner string) (GhClients, error) {
	key := owner
	if mainCreds.AppID == 0 {
		key = "global"
	}
	if clients, ok := cache.Get(key); ok {
		slog.Debug("Found cached clients", "key", key)
		return clients, nil
	}

	slog.Info("Creating new GitHub clients", "key", key, "app_auth", mainCreds.AppID != 0)

	main, err := newClient(ctx, mainCreds, endpoints, owner)
	if err != nil {
		return GhClients{}, fmt.Errorf("creating main client: %w", err)
	}
	approver, err := newClient(ctx, approverCreds, endpoints, owner)
	if err != nil {
		return GhClients{}, fmt.Errorf("creating approver client: %w", err)
	}

	clients := GhClients{Main: main, Approver: approver}
	cache.Add(key, clients)
	return clients, nil
}
