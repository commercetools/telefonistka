# Changes: main..internal

## User-facing changes

### Logging overhaul

- Replaced `logrus` with `log/slog` throughout the entire codebase. Log output is now structured JSON by default.
- New environment variable `LOG_FORMAT`: set to `text` for human-readable output, defaults to `json`.
- JSON log keys renamed to `timestamp`, `severity`, `message` (from slog's `time`, `level`, `msg`).

### ArgoCD v3 API

- Upgraded the ArgoCD Go module from `argoproj/argo-cd/v2` to `argoproj/argo-cd/v3`. Deployments must now target an ArgoCD v3-compatible server.

### Container image changes

- Dockerfile no longer performs a multi-stage Go build. The binary is built in CI workflows and copied into the image. This makes both the `scratch` and `alpine` images smaller and faster to build.
- The binary path inside the container changed from `/usr/local/bin/telefonistka` to `/telefonistka/bin/telefonistka`. Custom health probes or exec commands referencing the old path must be updated.
- The working directory changed from `/srv` to `/telefonistka`.
- Templates are now embedded in the binary via `embed.FS` (new `templates` package exports `FS`). The `scratch` image no longer copies a `templates/` directory. The `TEMPLATES_PATH` env var still works as an override but is no longer required.
- CA certificates are embedded at compile time via `golang.org/x/crypto/x509roots/fallback`, so the `scratch` image no longer copies `/etc/ssl/certs/` from Alpine.
- Build includes `-trimpath` flag, so log source locations use module-relative paths instead of absolute build-machine paths.

### Removed CLI commands

- The `bump-version-overwrite`, `bump-version-regex`, and `bump-version-yaml` subcommands have been removed. The `yq` library dependency (`mikefarah/yq`) was dropped along with them.

### Bug fixes

- **Split diff comments rendered all components**: when a diff comment exceeded GitHub's size limit and was split into per-component comments, every split comment incorrectly showed all components instead of just one.
- **Empty diff blocks on promotion PRs**: when ArgoCD's `StateDiff` flagged a resource as modified but `dyff` found zero semantic differences, a header-only diff block was rendered. These are now suppressed.
- **Blame URL missing scheme on GHES**: when `GITHUB_HOST` was set (GitHub Enterprise), the blame URL was constructed without `https://`, producing broken links.
- **Swallowed error in ApplicationSet template rendering**: a template rendering failure was logged but not returned, causing downstream code to operate on a zero-valued application object.
- **PR title truncation**: promotion PR titles are now truncated to 250 characters (with overflow prepended to the body) to avoid GitHub API rejection.
- **Goroutine leak in diff fan-out**: diff goroutines could leak when the parent context was cancelled before the goroutine finished. Now uses a bounded fan-out with proper cancellation propagation.

### ArgoCD client initialization

- ArgoCD gRPC clients (`App`, `Setting`, `AppSet`) are now created once at startup rather than per-request. The `Project` client has been removed entirely -- the diff pipeline no longer requires it. Connection parameters are read from the existing `ARGOCD_SERVER_ADDR`, `ARGOCD_TOKEN`, `ARGOCD_PLAINTEXT`, and `ARGOCD_INSECURE` env vars (no new configuration required).

### Temporary app cleanup

- Temporary ArgoCD applications created for new-component diffs are now cleaned up with `defer` and a 30-second timeout, preventing leaked app objects when the diff goroutine is cancelled or panics.

### Webhook handling

- Webhook proxy forwarding errors are now logged (previously silently ignored).
- Payload validation (`github.ValidatePayload`) is now handled by the `webhook` package at the HTTP layer; event parsing (`github.ParseWebHook`) happens in `gh.HandleEvent`. Previously both were in the same function.

### HANDLE_SELF_COMMENT behavior

- The `HANDLE_SELF_COMMENT` env var is now read once at startup (previously per-request). Accepted value is strictly `"true"` (previously used `strconv.ParseBool` which accepted `1`, `t`, `TRUE`, etc.).

### Eliminated redundant API call

- `GetDefaultBranch()` no longer makes an API call to fetch the repo's default branch. It is now always populated from the webhook event payload, removing one GitHub API call per request.

### Documentation updates

- `README.md`: the "Local Testing" section (mirrord/ngrok instructions) was replaced with an "Integration Tests" section describing the kind + ArgoCD + GitHub e2e test setup.
- `docs/installation.md`: the "Images" section was simplified. Template and certificate embedding is reflected. The two-flavour (scratch + alpine) description was updated.

## Internal improvements

### Package restructure

- Flattened the `internal/pkg/` tree into top-level packages: `argocd`, `gh` (was `githubapi`), `configuration`, `prometheus`, `mocks`, `templates`, `webhook`.
- Moved `main.go` into `cmd/telefonistka/`. The `cmd/telefonistka/` package changed from `package telefonistka` with an exported `Execute()` to `package main` with an unexported `execute()`. The root package is now `package telefonistka` with a `doc.go`.
- Extracted the HTTP handler wiring from `gh` into a new `webhook` package to separate transport concerns from domain logic. The `webhook` package handles payload validation and health checks; `gh.HandleEvent` handles event parsing and dispatch.
- The `webhook.Config` struct has a `Sync bool` field that runs event handling synchronously (instead of spawning a goroutine) for deterministic in-process testing.
- New `templates` package (`templates/templates.go`) exports `embed.FS` for `.gotmpl` files.
- `CODEOWNERS` moved from repo root to `.github/CODEOWNERS`.
- `configuration/` test data directory renamed from `tests/` to `testdata/` (Go convention).
- The monolithic `github.go` (1432 lines) was split into focused files within `gh/`:
  - `handler.go` -- event dispatch and per-type handlers
  - `handler_dispatch_test.go` -- dispatch tests
  - `handler_test.go` -- integration handler tests
  - `clients.go` -- GitHub client construction and caching
  - `context.go` -- `Context` type, `Endpoints`, `RepoRef`, `PRRef`, service interfaces
  - `promotion.go` -- promotion plan generation and PR creation
  - `drift_detection.go` -- drift detection between environments
  - `gittree.go` -- Git tree operations (creating tree entries, commits, branches)
  - `pr.go` -- PR operations (create, merge, approve, comment)
  - `prbody.go` -- PR body template rendering
  - `status.go` -- commit status operations
  - `argocd_diff.go` -- ArgoCD diff commenting and markdown generation
  - `github.go` -- `ReciveEventFile` removal, utility functions
  - `github_graphql.go` -- GraphQL queries
  - `webhook_proxy.go` -- webhook forwarding to downstream endpoints
  - `errors.go` -- domain error sentinels
  - `mock_test.go` -- mock implementations of service interfaces for testing

### Go version

- Upgraded from Go 1.24.6 to Go 1.26.

### Dependency cleanup

- Dropped `golang.org/x/exp` as a direct dependency (replaced by stdlib `maps`, `slices`).
- Dropped `sirupsen/logrus` as a direct dependency (remains as indirect transitive dependency of ArgoCD v3).
- Dropped `mikefarah/yq/v4` (removed along with bump-version commands).
- Dropped the vendored `internal/pkg/argocd/diff` package (a copy of Go's internal diff library).
- Dropped `internal/pkg/testutils` package (`Quiet()` for logrus replaced by `TestMain` with slog discard handlers).
- Removed `cyphar/filepath-securejoin` replace directive from `go.mod` (ArgoCD v2 workaround no longer needed).
- `golang.org/x/tools` moved from direct to indirect dependency.
- `k8s.io/apiextensions-apiserver` promoted from indirect to direct dependency.
- Upgraded mock generator to `go.uber.org/mock` v0.6.0. Generated mock files are checked in; `go generate` is no longer run in CI. New `MockApplicationSetServiceClient` mock added.
- Added `golang.org/x/crypto/x509roots/fallback` for embedded CA certs.
- Several direct dependencies were downgraded as part of the ArgoCD v3 transition (ArgoCD v3 pins older versions of some shared transitive deps): `docker/docker` v28 to v25, `bradleyfalzon/ghinstallation` v2.16 to v2.14, `gonvenience/ytbx` v1.4.7 to v1.4.4, `homeport/dyff` v1.10.2 to v1.9.4, `migueleliasweb/go-github-mock` v1.3 to v1.1, `nao1215/markdown` v0.8 to v0.7, `stretchr/testify` v1.11 to v1.10, `spf13/cobra` v1.10 to v1.9, `google.golang.org/grpc` v1.76 to v1.71, k8s libraries from v0.33/v0.35 to v0.32, `sigs.k8s.io/kind` v0.30 to v0.27.

### Symbol renames and stutter removal

- `githubapi` package renamed to `gh`. All exported symbols updated:
  - `GithubEndpoints` to `Endpoints`
  - `NewGithubEndpoints` to `NewEndpoints`
  - `GhClient` to `Client`
  - `GhClients` to `Clients`
  - `MainGhMetricsLoop` to `MetricsLoop` (signature also changed: accepts `*ClientProvider` instead of LRU cache)
- `GhPrClientDetails` renamed to `Context` in the `gh` package.
- `argocd` package stutter removal:
  - `ArgoCDClients` to `Clients`
  - `NewArgoCDClients` to `NewClients`
  - `SetArgoCDAppRevision` to `SetAppRevision`
  - `GenerateDiffOfChangedComponents` to `DiffComponents`
- `DiffResult` field renames: `ArgoCdAppName` to `AppName`, `ArgoCdAppURL` to `AppURL`.
- `DiffResult` removed fields: `HasDiff` (callers check `len(DiffElements) > 0`).
- `DiffResult` new fields: `HealthStatus`, `SyncStatus`, `AutoSyncEnabled`.
- `DiffElement` removed fields: `ObjectGroup` (unused).
- `ReciveWebhook` renamed to `ReceiveWebhook` (typo fix).
- `ReciveEventFile` removed (replaced by inline logic calling `gh.HandleEvent` directly).
- `GhClientPair` renamed to `Client`, consolidated 6 client constructors into 2.
- Unexported package-internal symbols across `gh` and `argocd`.

### Error handling

- Replaced `os.Exit` and `panic` calls in library code with proper error returns. `os.Exit` is now confined to `cmd/`.
- Added domain error sentinels in dedicated `errors.go` files:
  - `argocd.ErrAppNotFound`, `argocd.ErrAppSetNotFound`
  - `gh.ErrNoInstallation`, `gh.ErrNoCredentials`
- Errors from tree-walking functions, promotion plan generation, and component config loading are now propagated instead of silently swallowed.
- Error messages across both packages normalized to lowercase wrapping style with `fmt.Errorf("%w")`.

### Decoupling and testability

- `HandleEvent` decoupled from `*http.Request`: accepts `(context, config, eventType, headers, payload)` enabling in-process testing without HTTP.
- Introduced `ClientProvider` to encapsulate GitHub client creation and caching, replacing scattered LRU cache plumbing.
- `EventConfig` struct bundles all handler dependencies (clients, ArgoCD, templates FS, commit status template), replacing environment variable reads at call sites.
- Environment variable reads pushed to `cmd/`; library packages accept resolved values only. Specific env vars moved: `ARGOCD_SERVER_ADDR`, `ARGOCD_TOKEN`, `ARGOCD_PLAINTEXT`, `ARGOCD_INSECURE`, `GITHUB_HOST`, `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY_PATH`, `GITHUB_OAUTH_TOKEN`, `APPROVER_GITHUB_*`, `TEMPLATES_PATH`, `CUSTOM_COMMIT_STATUS_URL_TEMPLATE_PATH`, `HANDLE_SELF_COMMENT`.
- The `argocd` package no longer reads any env vars; it accepts a `ClientOptions` struct.
- Pre-compiled static regexes and commit-status URL templates at startup instead of per-request.
- New `Endpoints` type and `NewEndpoints(host)` constructor derive GitHub REST/GraphQL URLs from hostname, replacing per-function `GITHUB_HOST` env var reads.
- Service interfaces introduced in `gh/context.go` (`repoService`, `pullRequestService`, `issueService`, `gitService`, `graphQLClient`) enabling mock injection for unit testing without a real GitHub API.
- `alexliesenfeld/health` library moved from `cmd/` to `webhook/` package.

### ArgoCD package split

- Split the monolithic `argocd.go` (663 lines) into focused files: `client.go`, `diff.go`, `discovery.go`, `revision.go`, `tempapp.go`, `errors.go`.
- The diff pipeline was completely rewritten. The old approach used `generateArgocdAppDiff` which required a `*argoappv1.AppProject` (fetched via the now-removed Project client), called into copied upstream logic, and used a vendored Go diff library. The new approach uses `GetManifests`, indexes by `kube.ResourceKey`, builds live-vs-target pairs, and diffs with ArgoCD's `StateDiff` directly.
- Introduced `DiffConfig` struct with `UseSHALabel` and `CreateTempApps` fields, replacing individual boolean parameters.
- Diff errors are aggregated with `errors.Join`.
- Request-scoped `*slog.Logger` threaded through all per-request functions.

### Debug logging

- Added structured debug logging at entry and decision points in both `argocd` and `gh` packages.
- `Context` implements `slog.LogValuer` for clean structured log output.

### Test coverage

- Added integration tests using `httptest` for the `gh` handler (PR, push, comment events) in `handler_test.go` and `handler_dispatch_test.go`.
- Added webhook proxy tests (`webhook_proxy_test.go`).
- Added `gittree_test.go` with tests for deletion tree entry generation, including recursive directory, symlink, and 404 handling.
- Added `status_test.go` with tests for commit status toggling.
- Added `pr_test.go` with tests for `createPrObject`, `commentOnPr`, `approvePr`, `mergePr`, and `splitTitleAt250`.
- Added `mock_test.go` providing lightweight mock implementations of all service interfaces.
- Added `github_graphql_test.go` with tests for GraphQL-based file tree fetching and PR metadata queries.
- Added ArgoCD integration tests with a fake gRPC server (`argocd_fake_test.go`) supporting per-app responses, delete tracking, and AppSet listing.
- Added end-to-end integration tests (`github_event_test.go`) covering ~20 scenarios: `TestAutoMergeNoDiffPromotion`, `TestChangedPRArgoCDDiff`, `TestChangedPRDriftDetection`, `TestCheckboxBranchSync`, `TestComponentBlockList`, `TestDisableArgoCDDiff`, `TestDryRunMode`, `TestHelm`, `TestLabelConditionalPromotion`, `TestMergedPRArgoCDRevisionSync`, `TestMultiplePromotionTargets`, `TestNonEmptyDiff`, `TestPromotionPRCreated`, `TestRetriggerComment`, `TestSHALabelAppDiscovery`, `TestShowPlanLabel`, `TestStaleCommentMinimization`, `TestTempAppCreation`, `TestToggleCommitStatus`.
- Added kind + ArgoCD + GitHub e2e tests (`telefonistka_test.go`, `helpers_test.go`): `TestTelefonistka` and `TestHelm` spin up a real cluster, install Argo CD via Helm, create a temp GitHub repo, start an in-process Telefonistka server, and forward webhooks. Gated behind `INTEGRATE=1`.
- Added `cmd/telefonistka/root_test.go` with tests for `replaceAttr` (slog key replacement) and `getEnv` helper.
- Expanded `configuration/config_test.go` with edge cases: empty string, malformed YAML, unknown fields.
- Expanded `prometheus/prometheus_test.go` with additional metric instrumentation tests.
- Each new test package has a `testmain_test.go` that suppresses slog output via discard handler.
- Test `slog` output is routed through `t.Log` with timestamps stripped.
- Integration test ArgoCD image updated from v2.11.13 to v3.0.3 in `testdata/TestTelefonistka/argo.values.yaml`.

### CI/CD

- Build workflows now compile the binary in the workflow and pass it to Docker, instead of building inside the Dockerfile. Build command: `CGO_ENABLED=0 go build -trimpath -ldflags '-extldflags "-static"' -o telefonistka ./cmd/telefonistka`.
- `CGO_ENABLED=0` moved from job-level env to inline on the build command.
- Added `-trimpath` flag so log source locations use module-relative paths.
- Static linking flags (`-ldflags '-extldflags "-static"'`) explicitly set.
- Removed manual Go module caching (now relies on `actions/setup-go` built-in caching).
- `go generate` removed from all CI workflows (mocks are checked in).
- Lint workflow no longer runs `make get-deps`.
- Updated `golangci-lint` from v1.64.7 to v2.9.0, action from `v6` to `v9`.
- `.golangci.yml` migrated to v2 format: deprecated `tenv` replaced by `usetesting`, formatters moved to dedicated section, `paralleltest` linter enabled.
- Lint fixes applied: `strings.ReplaceAll`, `resp.StatusCode` instead of `resp.Response.StatusCode`, `if/else` chains to `switch` for type checks, `ns.Name` instead of `ns.ObjectMeta.Name`, bare channel receive instead of `select`.
- Test timeout explicitly set to 30s in CI (`go test -v -timeout 30s ./...`).
- Dependabot cadence changed to monthly.
- Added `permissions: contents: read` block to the lint workflow.
- Removed stale workflow comments (cosign TODOs, buildx workaround links, commented-out push triggers, option descriptions in lint action).
- Removed the `renovate` lint job (renovate.json was deleted).
- `renovate.json` removed.

### Removed files

- `Makefile` (replaced by direct `go` commands).
- `CHANGELOG.md` (empty/stale).
- `mirrord.json` (development tooling).
- `renovate.json` (no longer using Renovate).
- `internal/pkg/` directory tree (migrated to top-level packages).
- `internal/pkg/testutils/` package (`Quiet()` for logrus, replaced by `TestMain` discard handlers).
- `main.go` at repo root (replaced by `cmd/telefonistka/main.go`).
- Bump-version CLI commands (`cmd/telefonistka/bump-version-{overwrite,regex,yaml}.go`) and their tests.
- Vendored Go diff library (`internal/pkg/argocd/diff/` with all testdata).
