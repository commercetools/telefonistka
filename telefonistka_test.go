package main

import (
	"crypto/rand"
	"net"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"helm.sh/helm/v3/pkg/chartutil"
	corev1 "k8s.io/api/core/v1"
)

// TestTelefonistka spins up a full integration environment. It requires that
// INTEGRATE=1 is set in the environment.
//
// * Creates a cluster running in Docker
// * Installs Argo CD
// * Creates a Github repository
// * Creates initial commits setting the state of main branch
// * Adds a tracked demo application to Argo CD
// * Creates a pull request with a change to the demo application
// * Starts an up-to-date version of Telefonistka server, connecting it to Argo CD and Github
// * Forwards webhook requests from the Github repository to Telefonistka
//
// Note that it is currently interactive meaning it will run until receiving an
// interrupt signal, or it times out but in this case it will not gracefully
// cleanup resources. Otherwise it will clean up everything that it has created.
//
// Each invocation starts a fresh isolated setup. It is (should be) possible to
// run multiple invocations at the same time.
//
// As of now, a suggested invocation might be
//
//	INTEGRATE=1 GITHUB_TOKEN=$(gh auth token) go test -run Telefonistka -v -timeout=30m
//
// When printing logging information, details about a saved kubeconfig copy,
// and Argo CD login details are shown. They can be used to connect to the
// cluster or to login to the Argo CD web UI.
func TestTelefonistka(t *testing.T) {
	t.Parallel()
	if enabled, _ := strconv.ParseBool(os.Getenv("INTEGRATE")); !enabled {
		t.Skip("This is an interactive test; set INTEGRATE explicitly to run it")
	}

	// Make test interactive by waiting for explicit interrupt before
	// finishing. This allows setting things up so that caller can interact
	// with resources before they're all cleaned up.
	ctx, cancel := signal.NotifyContext(t.Context(), os.Interrupt)
	defer cancel()
	defer waitFor(ctx)

	var (
		argoNamespace                 = "argocd"
		argoLocalPort                 = "8083"
		argoContainerPort             = "8080"
		argoServer                    = "argocd-server"
		argoForwardPorts              = []string{strings.Join([]string{argoLocalPort, argoContainerPort}, ":")}
		argoForwardAddr               = []string{"127.0.0.1"}
		argoServerAddr                = net.JoinHostPort("localhost", argoLocalPort)
		argoUsername                  = "admin"
		argoInitialPasswordSecretName = "argocd-initial-admin-secret" //nolint:gosec // not a password
		argoInitialPasswordSecretKey  = "password"
	)

	var (
		// TODO make sure this aligns with what is configured when starting the
		// server. For now it is hardcoded.
		forwardTarget = "http://localhost:8080/webhook"
		webhookSecret = rand.Text()
	)

	cluster := newCluster(t)
	clientset := newClientset(t, cluster.Config)
	gh := newGithubClient(t)
	repository := createRepository(t, gh)
	conn := newArgoGRPCConnection(t, cluster.Config, argoServerAddr)

	createNamespace(t, clientset.CoreV1().Namespaces(), argoNamespace)

	// Alternatively install without Helm.
	//
	// installYamlFile := getFile(t, "https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml")
	// applyResource(t, cl.Config, argoNamespace, installYamlFile)

	vals := readValuesFile(t, "argo.values.yaml")
	releaseExternalChart(t, cluster.TemporaryConfigFile, argoNamespace, "https://argoproj.github.io/argo-helm", "argo-cd", vals)

	waitForReady(t, clientset.CoreV1().RESTClient(), argoNamespace, "Pod", "app.kubernetes.io/name="+argoServer, "", func(o any) {
		switch o := o.(type) {
		case *corev1.Pod:
			portForward(t, cluster.Config, argoNamespace, o.Name, argoForwardAddr, argoForwardPorts)
		}
	})

	// Template a demo application, setting it to track the created repository.
	var data struct{ RepoURL string }
	data.RepoURL = repository.GetHTMLURL()
	templated := readTemplate(t, "additional.yaml", data)
	applyResource(t, cluster.Config, argoNamespace, templated)

	// At this point we have an initial connection to use, so let's get the
	// default password, and login so we get a token we can use.
	adminPassword := getDecodedSecret(t, clientset.CoreV1(), argoNamespace, argoInitialPasswordSecretName, argoInitialPasswordSecretKey)
	token := newArgoToken(t, conn, argoUsername, adminPassword.String())
	t.Logf("You can log into Argo CD on %q using %q and %q as the password", "https://"+argoServerAddr, argoUsername, adminPassword)

	startTelefonistka(t, token, argoServerAddr, webhookSecret)

	// There is no good way to wait for execution and start of server; TODO: as
	// mentioned above, refactor entrypoint such that it will be just as easy
	// to spin up an isolated instance in code
	time.Sleep(5 * time.Second)

	wsURL := createRepoHook(t, gh, repository, webhookSecret)

	// dst, src
	forwardData(t, ctx, forwardTarget, wsURL)

	//  Setup initial state of repository based on testdata.
	first := createCommit(t, gh, repository, "heads/main", "Initial", os.DirFS(path.Join("testdata", t.Name(), "start")))
	updateRef(t, gh, repository, "heads/main", first.GetSHA())

	// Create a PR with some changes based on testdata.
	branch := createBranch(t, gh, repository, first, "upgrade")
	createCommit(t, gh, repository, "heads/upgrade", "Upgrade application", os.DirFS(path.Join("testdata", t.Name(), "pr")))

	var n TestPR
	n.Title = "Upgrade to vX.X.X"
	n.Ref = branch.GetRef()
	n.Base = "main"
	n.Body = "This upgrades to the bleeding edge."

	createPR(t, gh, repository, &n)
}

func TestHelm(t *testing.T) {
	// Make test interactive by waiting for explicit interrupt before
	// finishing. This allows setting things up so that caller can interact
	// with resources before they're all cleaned up.
	ctx, cancel := contextWithGracePeriod(t.Context(), 10*time.Second)
	defer cancel()

	ctx, cancel = signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()
	defer waitFor(ctx)

	var (
		argoNamespace                 = "argocd"
		argoLocalPort                 = "8083"
		argoContainerPort             = "8080"
		argoServer                    = "argocd-server"
		argoForwardPorts              = []string{strings.Join([]string{argoLocalPort, argoContainerPort}, ":")}
		argoForwardAddr               = []string{"127.0.0.1"}
		argoServerAddr                = net.JoinHostPort("localhost", argoLocalPort)
		argoUsername                  = "admin"
		argoInitialPasswordSecretName = "argocd-initial-admin-secret" //nolint:gosec // not a password
		argoInitialPasswordSecretKey  = "password"
	)

	var (
		// TODO make sure this aligns with what is configured when starting the
		// server. For now it is hardcoded.
		forwardTarget = "http://localhost:8080/webhook"
		webhookSecret = rand.Text()
	)

	cluster := newCluster(t)
	clientset := newClientset(t, cluster.Config)
	gh := newGithubClient(t)
	repository := createRepository(t, gh)
	conn := newArgoGRPCConnection(t, cluster.Config, argoServerAddr)

	createNamespace(t, clientset.CoreV1().Namespaces(), argoNamespace)

	// Alternatively install without Helm.
	//
	// installYamlFile := getFile(t, "https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml")
	// applyResource(t, cl.Config, argoNamespace, installYamlFile)

	loadLocalImage(t, newDockerClient(t), cluster.Provider, "gcr.io/ct-services/argo-cd-helmfile:v0.5.0") // sha256:ed34582d67cab4fbba9057134858043b64852ba8ace0cc7b45ac995f8d47337c

	vals := readValuesFile(t, "argo.values.yaml")
	releaseExternalChart(t, cluster.TemporaryConfigFile, argoNamespace, "https://argoproj.github.io/argo-helm", "argo-cd", vals)

	waitForReady(t, clientset.CoreV1().RESTClient(), argoNamespace, "Pod", "app.kubernetes.io/name="+argoServer, "", func(o any) {
		switch o := o.(type) {
		case *corev1.Pod:
			portForward(t, cluster.Config, argoNamespace, o.Name, argoForwardAddr, argoForwardPorts)
		}
	})

	createNamespace(t, clientset.CoreV1().Namespaces(), "cert-manager")
	releaseExternalChart(t, cluster.TemporaryConfigFile, "cert-manager", "https://charts.jetstack.io", "cert-manager", chartutil.Values{
		"installCRDs":                    "true",
		"crds.enabled":                   "true",
		"prometheus.enabled":             "false",
		"startupapicheck.enabled":        "false",
		"global.crds.enabled":            "true",
		"global.prometheus.enabled":      "false",
		"global.startupapicheck.enabled": "false",
	})

	// Template a demo application, setting it to track the created repository.
	var data struct{ RepoURL string }
	data.RepoURL = repository.GetHTMLURL()
	templated := readTemplate(t, "additional.yaml", data)
	applyResource(t, cluster.Config, argoNamespace, templated)

	// At this point we have an initial connection to use, so let's get the
	// default password, and login so we get a token we can use.
	adminPassword := getDecodedSecret(t, clientset.CoreV1(), argoNamespace, argoInitialPasswordSecretName, argoInitialPasswordSecretKey)
	token := newArgoToken(t, conn, argoUsername, adminPassword.String())
	t.Logf("You can log into Argo CD on %q using %q and %q as the password", "https://"+argoServerAddr, argoUsername, adminPassword)

	startTelefonistka(t, token, argoServerAddr, webhookSecret)

	// There is no good way to wait for execution and start of server; TODO: as
	// mentioned above, refactor entrypoint such that it will be just as easy
	// to spin up an isolated instance in code
	time.Sleep(5 * time.Second)

	wsURL := createRepoHook(t, gh, repository, webhookSecret)

	// dst, src
	forwardData(t, ctx, forwardTarget, wsURL)

	//  Setup initial state of repository based on testdata.
	first := createCommit(t, gh, repository, "heads/main", "Initial", os.DirFS(path.Join("testdata", t.Name(), "start")))
	updateRef(t, gh, repository, "heads/main", first.GetSHA())

	// Create a PR with some changes based on testdata.
	branch := createBranch(t, gh, repository, first, "upgrade")
	createCommit(t, gh, repository, "heads/upgrade", "Upgrade application", os.DirFS(path.Join("testdata", t.Name(), "pr")))

	var n TestPR
	n.Title = "Upgrade to vX.X.X"
	n.Ref = branch.GetRef()
	n.Base = "main"
	n.Body = "This upgrades to the bleeding edge."

	createPR(t, gh, repository, &n)
}
