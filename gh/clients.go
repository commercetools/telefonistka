package gh

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

// Client holds the REST and GraphQL clients for a single GitHub identity.
type Client struct {
	v3Client *github.Client
	v4Client *githubv4.Client
}

// Clients bundles the main and approver GitHub clients for one repo owner.
// The approver is a separate identity so that auto-approvals don't come from
// the same user that opened the PR.
type Clients struct {
	Main     Client
	Approver Client
}

// setServices populates all GitHub service fields on a Context.
func (gc Clients) setServices(c *Context) {
	c.Repositories = gc.Main.v3Client.Repositories
	c.PullRequests = gc.Main.v3Client.PullRequests
	c.Issues = gc.Main.v3Client.Issues
	c.Git = gc.Main.v3Client.Git
	c.GraphQL = gc.Main.v4Client
	c.ApproverPRs = gc.Approver.v3Client.PullRequests
}

// ClientProvider creates and caches GitHub clients for repo owners.
// Credentials and endpoints are immutable; the cache is populated lazily.
type ClientProvider struct {
	cache         *lru.Cache[string, Clients]
	mainCreds     ClientConfig
	approverCreds ClientConfig
	endpoints     Endpoints
}

// NewClientProvider creates a ClientProvider with an LRU cache of the given size.
func NewClientProvider(size int, mainCreds, approverCreds ClientConfig, endpoints Endpoints) *ClientProvider {
	cache, _ := lru.New[string, Clients](size) // size is always a positive literal
	return &ClientProvider{
		cache:         cache,
		mainCreds:     mainCreds,
		approverCreds: approverCreds,
		endpoints:     endpoints,
	}
}

// ForOwner returns cached clients for the owner, creating them on a cache miss.
// App-auth clients are cached per owner; token-auth clients are cached globally.
func (cp *ClientProvider) ForOwner(ctx context.Context, owner string) (Clients, error) {
	key := owner
	if cp.mainCreds.AppID == 0 {
		key = "global"
	}
	if clients, ok := cp.cache.Get(key); ok {
		slog.Debug("Found cached clients", "key", key)
		return clients, nil
	}

	slog.Info("Creating new GitHub clients", "key", key, "app_auth", cp.mainCreds.AppID != 0)

	main, err := newClient(ctx, cp.mainCreds, cp.endpoints, owner)
	if err != nil {
		return Clients{}, fmt.Errorf("creating main client: %w", err)
	}
	approver, err := newClient(ctx, cp.approverCreds, cp.endpoints, owner)
	if err != nil {
		return Clients{}, fmt.Errorf("creating approver client: %w", err)
	}

	clients := Clients{Main: main, Approver: approver}
	cp.cache.Add(key, clients)
	return clients, nil
}

// IsAppAuth reports whether the provider is configured with GitHub App
// credentials. Some API endpoints (e.g. Apps.ListRepos) require
// installation tokens and are unavailable under personal access tokens.
func (cp *ClientProvider) IsAppAuth() bool {
	return cp.mainCreds.AppID != 0
}

// CachedOwners returns the keys currently in the cache, for use by the
// metrics loop.
func (cp *ClientProvider) CachedOwners() []string {
	return cp.cache.Keys()
}

// CachedClients returns the cached Clients for the given key, if present.
func (cp *ClientProvider) CachedClients(key string) (Clients, bool) {
	return cp.cache.Get(key)
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

	return 0, fmt.Errorf("%w: %s", ErrNoInstallation, owner)
}

// newAppClient creates a REST+GraphQL client using GitHub App auth.
// A single ghinstallation transport is shared by both clients.
func newAppClient(ctx context.Context, appID int64, keyPath string, endpoints Endpoints, owner string) (Client, error) {
	installID, err := getAppInstallationId(ctx, keyPath, appID, endpoints.RestURL, owner)
	if err != nil {
		return Client{}, fmt.Errorf("getting app installation ID for owner %s: %w", owner, err)
	}

	itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, appID, installID, keyPath)
	if err != nil {
		return Client{}, fmt.Errorf("loading installation key: %w", err)
	}
	if endpoints.RestURL != "" {
		itr.BaseURL = endpoints.RestURL
	}

	httpClient := &http.Client{Transport: itr}

	v3 := github.NewClient(httpClient)
	if endpoints.RestURL != "" {
		v3, err = v3.WithEnterpriseURLs(endpoints.RestURL, endpoints.RestURL)
		if err != nil {
			return Client{}, fmt.Errorf("configuring enterprise REST URL: %w", err)
		}
	}

	var v4 *githubv4.Client
	if endpoints.GraphqlURL != "" {
		v4 = githubv4.NewEnterpriseClient(endpoints.GraphqlURL, httpClient)
	} else {
		v4 = githubv4.NewClient(httpClient)
	}

	return Client{v3Client: v3, v4Client: v4}, nil
}

// newTokenClient creates a REST+GraphQL client using an OAuth token.
func newTokenClient(ctx context.Context, token string, endpoints Endpoints) (Client, error) {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	httpClient := oauth2.NewClient(ctx, ts)

	v3 := github.NewClient(httpClient)
	if endpoints.RestURL != "" {
		var err error
		v3, err = v3.WithEnterpriseURLs(endpoints.RestURL, endpoints.RestURL)
		if err != nil {
			return Client{}, fmt.Errorf("configuring enterprise URL: %w", err)
		}
	}

	var v4 *githubv4.Client
	if endpoints.GraphqlURL != "" {
		v4 = githubv4.NewEnterpriseClient(endpoints.GraphqlURL, httpClient)
	} else {
		v4 = githubv4.NewClient(httpClient)
	}

	return Client{v3Client: v3, v4Client: v4}, nil
}

// newClient creates a Client from credentials, dispatching to app or token auth.
func newClient(ctx context.Context, creds ClientConfig, endpoints Endpoints, owner string) (Client, error) {
	if creds.AppID != 0 {
		return newAppClient(ctx, creds.AppID, creds.AppKeyPath, endpoints, owner)
	}
	if creds.OAuthToken == "" {
		return Client{}, fmt.Errorf("%w", ErrNoCredentials)
	}
	return newTokenClient(ctx, creds.OAuthToken, endpoints)
}
