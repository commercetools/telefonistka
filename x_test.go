package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"text/template"
	"time"

	"github.com/argoproj/argo-cd/v2/pkg/apiclient/session"
	dockerclient "github.com/docker/docker/client"
	"github.com/google/go-github/v62/github"
	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"
)

func execTemplate(t *testing.T, tpl *bytes.Buffer, data any) *bytes.Buffer {
	t.Helper()
	tm, err := template.New("").Parse(tpl.String())
	checkErr(t, err)
	buf := bytes.NewBuffer(nil)
	checkErr(t, tm.Execute(buf, data))
	return buf
}

func readTemplate(t *testing.T, filepath string, data any) *bytes.Buffer {
	t.Helper()
	f := getTestdata(t, filepath)
	return execTemplate(t, f, data)
}

func updateRef(t *testing.T, c *github.Client, repo *github.Repository, ref, sha string) *github.Reference {
	t.Helper()
	var force bool
	var new github.Reference
	new.Ref = github.String(ref)
	new.Object = &github.GitObject{SHA: github.String(sha)}
	r, _, err := c.Git.UpdateRef(t.Context(), repo.GetOwner().GetLogin(), repo.GetName(), &new, force)
	checkErr(t, err)
	t.Logf("Updated %s to %s", ref, sha)
	return r
}

func createPR(t *testing.T, c *github.Client, repo *github.Repository, new *github.NewPullRequest) *github.PullRequest {
	t.Helper()
	pr, _, err := c.PullRequests.Create(t.Context(), repo.GetOwner().GetLogin(), repo.GetName(), new)
	checkErr(t, err)
	t.Logf("Created PR %+v", pr.GetHTMLURL())
	return pr
}

//nolint:unused
func createBlob(t *testing.T, c *github.GitService, repo *github.Repository, b *github.Blob) *github.Blob {
	t.Helper()
	bl, _, err := c.CreateBlob(t.Context(), repo.GetOwner().GetLogin(), repo.GetName(), b)
	checkErr(t, err)
	return bl
}

func entriesFromFS(t *testing.T, fsys fs.FS) []*github.TreeEntry {
	t.Helper()
	var entries []*github.TreeEntry
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		t.Helper()
		checkErr(t, err)
		if d.IsDir() {
			return nil
		}
		var e github.TreeEntry
		e.Path = github.String(path)
		e.Mode = github.String("100644")
		e.Type = github.String("blob")
		e.Content = github.String(direntryContent(t, fsys, path).String())
		entries = append(entries, &e)
		return nil
	})
	checkErr(t, err)
	return entries
}

func direntryContent(t *testing.T, fsys fs.FS, path string) *bytes.Buffer {
	t.Helper()
	b, err := fs.ReadFile(fsys, path)
	checkErr(t, err)
	return bytes.NewBuffer(b)
}

func createCommit(t *testing.T, s *github.Client, repo *github.Repository, parentRef, msg string, fsys fs.FS) *github.Commit {
	t.Helper()
	p := getCommit(t, s, repo, parentRef)
	entries := entriesFromFS(t, fsys)
	tr := createTree(t, s.Git, repo, p.GetTree().GetSHA(), entries...)
	var new github.Commit
	new.Message = github.String(msg)
	new.Tree = tr
	new.Parents = []*github.Commit{{SHA: p.SHA}}
	co, _, err := s.Git.CreateCommit(t.Context(), repo.GetOwner().GetLogin(), repo.GetName(), &new, nil) // TODO default read running users signing details and sign
	checkErr(t, err)
	t.Logf("Created commit %s", co.GetSHA())
	updateRef(t, s, repo, parentRef, co.GetSHA())
	return co
}

func createBranch(t *testing.T, s *github.Client, repo *github.Repository, target *github.Commit, name string) *github.Reference {
	t.Helper()
	var b github.Reference
	b.Ref = github.String("refs/heads/" + name)
	b.Object = &github.GitObject{SHA: target.SHA}
	r, _, err := s.Git.CreateRef(t.Context(), repo.GetOwner().GetLogin(), repo.GetName(), &b)
	checkErr(t, err)
	t.Logf("Created branch %s", name)
	return r
}

func getCommit(t *testing.T, s *github.Client, repo *github.Repository, sha string) *github.Commit {
	t.Helper()
	rc, _, err := s.Repositories.GetCommit(t.Context(), repo.GetOwner().GetLogin(), repo.GetName(), sha, nil)
	checkErr(t, err)

	// For some reason the returned object is not a github.Commit and the
	// included commit object does not have the SHA set
	c := rc.GetCommit()
	if c.SHA == nil {
		c.SHA = rc.SHA
	}
	return c
}

//nolint:unused
func getRef(t *testing.T, c *github.GitService, repo *github.Repository, ref string) *github.Reference {
	t.Helper()
	r, _, err := c.GetRef(t.Context(), repo.GetOwner().GetLogin(), repo.GetName(), ref)
	checkErr(t, err)
	return r
}

func createTree(t *testing.T, c *github.GitService, repo *github.Repository, baseTree string, entries ...*github.TreeEntry) *github.Tree {
	t.Helper()
	tr, _, err := c.CreateTree(t.Context(), repo.GetOwner().GetLogin(), repo.GetName(), baseTree, entries)
	checkErr(t, err)
	return tr
}

func readFile(t *testing.T, path string) *bytes.Buffer {
	t.Helper()
	b, err := os.ReadFile(path)
	checkErr(t, err)
	return bytes.NewBuffer(b)
}

//nolint:unused
func newDockerClient(t *testing.T) *dockerclient.Client {
	t.Helper()
	c, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	checkErr(t, err)
	return c
}

// loadLocalImage loads an image from the host into the cluster.
//
//nolint:unused
func loadLocalImage(t *testing.T, c *dockerclient.Client, p *cluster.Provider, cluster string, images ...string) {
	t.Helper()
	archive, err := c.ImageSave(t.Context(), images)
	checkErr(t, err)

	nodes, err := p.ListNodes(cluster)
	checkErr(t, err)
	for n := range slices.Values(nodes) {
		t.Logf("Loading %s into %s", images, n)
		checkErr(t, nodeutils.LoadImageArchive(n, archive))
	}
}

func helmLogFunc(t *testing.T) func(format string, values ...interface{}) {
	t.Helper()
	return func(format string, v ...interface{}) {
		t.Helper()
		t.Logf(format, v...)
	}
}

func releaseExternalChart(t *testing.T, externalKubeconfigName, namespace, repo, name string, vals chartutil.Values) {
	t.Helper()
	settings := cli.New()

	cf := genericclioptions.NewConfigFlags(true)
	cf.KubeConfig = &externalKubeconfigName
	cf.Namespace = &namespace
	helmconf := &action.Configuration{}

	// This is the namespace where Helm will store release history for rollback.
	helmReleasesNamespace := "default"

	checkErr(t, helmconf.Init(cf, helmReleasesNamespace, "", helmLogFunc(t)))
	helminstall := action.NewInstall(helmconf)

	helminstall.RepoURL = repo
	// sadly the helm downloader does not allow customising the logger :(
	// see https://github.com/helm/helm/blob/980d8ac1939e39138101364400756af2bdee1da5/pkg/action/install.go#L765
	chrt_path, err := helminstall.LocateChart(name, settings)
	checkErr(t, err)

	chart, err := loader.Load(chrt_path)
	checkErr(t, err)

	helminstall.ReleaseName = name
	helminstall.Namespace = namespace
	release, err := helminstall.Run(chart, vals)
	checkErr(t, err)
	t.Logf("released %s in %s namespace", release.Name, release.Namespace)
}

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
	var wg sync.WaitGroup
	wg.Add(1)
	defer func() {
		defer wg.Done()
		<-ctx.Done()
	}()

	cl := newCluster(t)

	client, err := kubernetes.NewForConfig(cl.Config)
	checkErr(t, err)

	argoNamespace := "argocd"
	argoLocalPort := "8083"     // local, TODO: allow dynamic allocation using port 0
	argoContainerPort := "8080" // TODO: constant?
	argoServer := "argocd-server"
	ports := []string{strings.Join([]string{argoLocalPort, argoContainerPort}, ":")}
	addresses := []string{"127.0.0.1"} // TODO: does it need to be IP?
	serverAddr := net.JoinHostPort("localhost", argoLocalPort)

	createNamespace(t, client.CoreV1().Namespaces(), argoNamespace)

	// Alternatively install without Helm.
	//
	// installYamlFile := getFile(t, "https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml")
	// applyResource(t, cl.Config, argoNamespace, installYamlFile) // TODO: install with external helm chart using SDK

	vals, err := chartutil.ReadValues(getTestdata(t, "argo.values.yaml").Bytes())
	checkErr(t, err)
	releaseExternalChart(t, cl.TemporaryConfigFile, argoNamespace, "https://argoproj.github.io/argo-helm", "argo-cd", vals)

	waitForReady(t, client.CoreV1().RESTClient(), argoNamespace, "Pod", "app.kubernetes.io/name="+argoServer, "", func(o any) {
		switch o := o.(type) {
		case *corev1.Pod:
			portForward(t, cl.Config, argoNamespace, o.Name, addresses, ports)
		}
	})

	gh := createGithubClient(t)
	repo := createGithubRepo(t, gh)

	// Template a demo application, setting it to track the created repository.
	var data struct{ RepoURL string }
	data.RepoURL = repo.GetHTMLURL()
	templated := readTemplate(t, "additional.yaml", data)
	applyResource(t, cl.Config, argoNamespace, templated)

	// TODO: pull out into a custom Argo CD client since the upstream SDK is a
	// massive pain to work with to instantiate. We'll probably only need some
	// basics anyway.
	tlsConf, err := rest.TLSConfigFor(cl.Config)
	checkErr(t, err)
	tlsConf.InsecureSkipVerify = true
	tlsCreds := credentials.NewTLS(tlsConf)
	endpointCreds := jwtCredentials{}
	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(&endpointCreds))
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(tlsCreds))
	conn, err := grpc.NewClient(serverAddr, dialOpts...)
	checkErr(t, err)
	t.Cleanup(func() {
		checkErr(t, conn.Close())
	})

	// At this point we have an initial connection to use, so let's get the
	// default password, and login so we get a token we can use.
	argoAdmin := "admin"
	argoInitialPasswordSecretName, argoInitialPasswordSecretKey := "argocd-initial-admin-secret", "password" //nolint:gosec // not a password
	adminPassword := getDecodedSecret(t, client.CoreV1(), argoNamespace, argoInitialPasswordSecretName, argoInitialPasswordSecretKey)
	sessc := session.NewSessionServiceClient(conn)
	createRequest := session.SessionCreateRequest{
		Username: argoAdmin,
		Password: adminPassword.String(),
	}
	t.Logf("You can log into Argo CD on %q using %q and %q as the password", "https://"+serverAddr, createRequest.Username, createRequest.Password)
	createResponse, err := sessc.Create(t.Context(), &createRequest)
	if err != nil {
		t.Fatalf("Failed to create a JWT token, try setting GRPC_ENFORCE_ALPN_ENABLED=false (https://github.com/grpc/grpc-go/issues/434): %v", err)
	}

	webhookSecret := rand.Text()

	startTelefonistka(t, createResponse.GetToken(), serverAddr, webhookSecret)

	// There is no good way to wait for execution and start of server; TODO: as
	// mentioned above, refactor entrypoint such that it will be just as easy
	// to spin up an isolated instance in code
	time.Sleep(5 * time.Second)

	wsURL := createRepoHook(t, gh, repo, webhookSecret)

	// TODO make sure this aligns with what is configured when starting the server. For now it is hardcoded.
	fwd := "http://localhost:8080/webhook"

	// dst, src
	forwardData(t, ctx, fwd, wsURL)

	//  Setup initial state of repository based on testdata.
	first := createCommit(t, gh, repo, "heads/main", "Initial", os.DirFS(path.Join("testdata", t.Name(), "start")))
	updateRef(t, gh, repo, "heads/main", first.GetSHA())

	// Create a PR with some changes based on testdata.
	branch := createBranch(t, gh, repo, first, "upgrade")
	createCommit(t, gh, repo, "heads/upgrade", "Upgrade application", os.DirFS(path.Join("testdata", t.Name(), "pr")))

	var n github.NewPullRequest
	n.Title = github.String("Upgrade to vX.X.X")
	n.Head = branch.Ref
	n.Base = github.String("main")
	n.Body = github.String("This upgrades to the bleeding edge.")

	createPR(t, gh, repo, &n)
}

//nolint:unused
func getFile(t *testing.T, url string) *bytes.Buffer {
	t.Helper()
	//nolint:noctx,gosec // let us leave http.Get for now; this is a test
	installRes, err := http.Get(url)
	checkErr(t, err)
	f := copyData(t, installRes.Body)
	checkErr(t, installRes.Body.Close())
	return f
}

//nolint:unused
func copyData(t *testing.T, src io.Reader) *bytes.Buffer {
	t.Helper()
	dst := bytes.NewBuffer(nil)
	_, err := io.Copy(dst, src)
	if !errors.Is(err, io.EOF) {
		checkErr(t, err)
	}
	return dst
}

type jwtCredentials struct {
	Token string
}

func (c jwtCredentials) RequireTransportSecurity() bool {
	return false
}

func (c jwtCredentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		"token": c.Token,
	}, nil
}

func getTestdata(t *testing.T, filepath string) *bytes.Buffer {
	t.Helper()
	return readFile(t, path.Join("testdata", t.Name(), filepath))
}

//nolint:thelper // want to get the line where the error occurs here
func startTelefonistka(t *testing.T, token, argoServerAddr, webhookSecret string) {
	// TODO: refactor so that it is easy to instead instantiate the server in
	// code.
	// cmd := exec.CommandContext(t.Context(), "go", "run", ".", "server")
	// NOTE: testing air to get live reloading
	cmd := exec.CommandContext(t.Context(), "go", "run", "github.com/air-verse/air@latest", "--build.cmd", "go build", "--build.bin", "./telefonistka server")
	cmd.Env = append(os.Environ(),
		"GITHUB_WEBHOOK_SECRET="+webhookSecret,

		// TODO: read in top-level test
		"GITHUB_OAUTH_TOKEN="+os.Getenv("GITHUB_TOKEN"),
		"APPROVER_GITHUB_OAUTH_TOKEN="+os.Getenv("GITHUB_TOKEN"),

		"LOG_LEVEL=debug",
		"ARGOCD_SERVER_ADDR="+argoServerAddr,
		"ARGOCD_TOKEN="+token,
		"ARGOCD_INSECURE=true",

		"HANDLE_SELF_COMMENT=true",
	)

	// Make sure we get output from the executed command above.
	//
	// TODO: properly wrap and forward to t.Log
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		stderr, err := cmd.StderrPipe()
		checkErr(t, err)
		wg.Add(1)
		go func() {
			defer wg.Done()
			io.Copy(os.Stderr, stderr) //nolint:errcheck
		}()
		checkErr(t, cmd.Start())
	}()

	t.Cleanup(func() {
		wg.Wait()
	})
}

//nolint:thelper // want to get the line where the error occurs here
func forwardData(t *testing.T, ctx context.Context, fwd, wsURL string) {
	var wg sync.WaitGroup

	header := http.Header{}
	header.Set("Authorization", os.Getenv("GITHUB_TOKEN")) // TODO: pull out to top-level

	c, dialRes, err := websocket.DefaultDialer.Dial(wsURL, header)
	checkErr(t, err)
	checkErr(t, dialRes.Body.Close())

	// Make sure we appropriately close the connection when we are done.
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			t.Logf("Closing forwarding connection")
		case <-t.Context().Done():
			t.Logf("Closing forwarding connection")
		}
		checkErr(t, c.Close())
	}()

	// Start forwarding. Should errors cause the test to fail or just log and
	// continue? Probably better to continue until the connection is closed.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			v := struct {
				Header http.Header
				Body   []byte
			}{}
			if err := c.ReadJSON(&v); websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure) {
				return
			} else if err != nil {
				checkErr(t, err)
			}
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, fwd, bytes.NewReader(v.Body))
			for k := range v.Header {
				req.Header.Set(k, v.Header.Get(k))
			}
			req.Header = v.Header

			// TODO: figure out how to handle properly
			tres, err := http.DefaultClient.Do(req)
			if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
				t.Logf("Forwarder fatal: forward request: %v", err)
				return
			}
			checkErr(t, err)

			// TODO: not sure we should log here as it is better to refactor
			// Telefonistka to do this on its own when debug logging is
			// enabled.
			d, err := httputil.DumpResponse(tres, true)
			checkErr(t, err)
			t.Logf("Telefonistka response %s", d)

			body, err := io.ReadAll(tres.Body)
			checkErr(t, err)
			checkErr(t, tres.Body.Close())

			// The connection expects a response and if it does not get it, it
			// will bail.
			res := struct {
				Status int
				Header http.Header
				Body   []byte
			}{
				tres.StatusCode,
				tres.Header,
				body,
			}
			if err := c.WriteJSON(res); err != nil {
				t.Logf("Forwarding write error: %v", err)
				return
			}
		}
	}()

	t.Cleanup(func() {
		wg.Wait()
		t.Logf("Forwarding done")
	})
}

func createGithubClient(t *testing.T) *github.Client {
	t.Helper()
	return github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN"))
}

//nolint:thelper // want to get the line where the error occurs here
func createGithubRepo(t *testing.T, c *github.Client) *github.Repository {
	name := "telefonistka-" + rand.Text()
	var x github.Repository
	x.Name = github.String(name)
	x.Description = github.String(fmt.Sprintf("I'm a Telefonistka test repository generated at %s", time.Now().Format(time.RFC3339)))

	// It seems the Github API does not allow creating the first commit in an
	// empty repository in any way, so this is needed to get a first commit to
	// use as parents for following ones created through the API.
	x.AutoInit = github.Bool(true)

	// An empty owner means create for owner identified by the credential used
	// in the client.
	owner := ""

	r, _, err := c.Repositories.Create(t.Context(), owner, &x)
	checkErr(t, err)
	t.Cleanup(func() {
		_, err := c.Repositories.Delete(context.Background(),
			r.GetOwner().GetLogin(), r.GetName())
		checkErr(t, err)
	})
	t.Logf("Created repository %s", r.GetHTMLURL())
	return r
}

//nolint:thelper // want to get the line where the error occurs here
func createRepoHook(t *testing.T, c *github.Client, r *github.Repository, webhookSecret string) (ws string) {
	var x github.Hook
	x.Name = github.String("cli") // Must be "cli" to get websocket; it has special treatment :(
	x.Events = []string{"*"}      // TODO possibly configurable
	x.Active = github.Bool(true)  // TODO: could add it deactivated and activate just after listener started
	x.Config = &github.HookConfig{}
	x.Config.ContentType = github.String("json")
	x.Config.Secret = github.String(webhookSecret)

	// Need to make our own request because the "ws_url" field is not available
	// on github.Hook.
	var h struct {
		ID    int64  `json:"id"`
		WSURL string `json:"ws_url"`
	}
	url := fmt.Sprintf("/repos/%s/%s/hooks", r.GetOwner().GetLogin(), r.GetName())
	req, err := c.NewRequest(http.MethodPost, url, &x)
	checkErr(t, err)
	m := map[string]any{}
	_, err = c.Do(t.Context(), req, &m)
	checkErr(t, err)
	h.ID = int64(m["id"].(float64))
	h.WSURL = m["ws_url"].(string)

	t.Cleanup(func() {
		_, err := c.Repositories.DeleteHook(context.Background(), r.GetOwner().GetLogin(), r.GetName(), h.ID)
		if err != nil {
			t.Logf("Failed to delete repository: %v", err)
		}
		t.Logf("Hook %q deleted", h.ID)
	})
	return h.WSURL
}

func getDecodedSecret(t *testing.T, c typedcorev1.CoreV1Interface, namespace, name, key string) *bytes.Buffer {
	t.Helper()
	var opts metav1.GetOptions
	s, err := c.Secrets(namespace).Get(t.Context(), name, opts)
	checkErr(t, err)
	data, ok := s.Data[key]
	if !ok {
		t.Logf("Secret data %q %s/%s not found", key, namespace, name)
	}

	return bytes.NewBuffer(data)
}

func createNamespace(t *testing.T, c typedcorev1.NamespaceInterface, name string) {
	t.Helper()
	var ns corev1.Namespace
	ns.ObjectMeta.Name = name
	_, err := c.Create(t.Context(), &ns, metav1.CreateOptions{})
	checkErr(t, err)
}

type Cluster struct {
	Name                string
	TemporaryConfigFile string
	*rest.Config
	*cluster.Provider
}

// newCluster creates a new cluster through kind running in Docker.
//
// When the provider creates the cluster it will take an option to a
// kubeconfig. The default is to modify the default kubeconfig file and insert
// the connection details. When the cluster is deleted it will remove only the
// deleted cluster from the file and leave rest untouched.
//
// Given that we might want to use it and not provide a separate config,
// although it could be good to have a separate file for debugging.
//
// Note: we encountered a very dumb error where kind does not run because
// Docker is not running. There is no error output it just doesn't run, but
// test execution continues and then fails after timing out.
//
//nolint:thelper // want to get the line where the error occurs here
func newCluster(t *testing.T) *Cluster {
	clusterName := strings.ToLower(rand.Text())

	logger := testLogger{t}
	t.Logf("clusterName: %s", clusterName)

	kubeconfigName := clusterName + ".kubeconfig"
	t.Logf("Using temporary kubeconfig %q", kubeconfigName)

	clusterWaitDuration := 30 * time.Second
	t.Logf("Waiting on cluster for %s", clusterWaitDuration)

	var providerOpts []cluster.ProviderOption

	// make configurable, see https://github.com/kubernetes-sigs/kind/blob/v0.27.0/pkg/internal/runtime/runtime.go
	providerOpts = append(providerOpts, cluster.ProviderWithDocker())
	providerOpts = append(providerOpts, cluster.ProviderWithLogger(logger))

	provider := cluster.NewProvider(providerOpts...)

	var createOpts []cluster.CreateOption
	createOpts = append(createOpts, cluster.CreateWithRetain(false)) // may want to make configurable

	// This will export (write out to filename) the external kubeconfig
	// i.e. same as running provider.KubeConfig with internal false.
	//
	// We want to pass it to avoid touching host default kubeconfig
	// ($HOME/.kube/config) etc.
	createOpts = append(createOpts, cluster.CreateWithKubeconfigPath(kubeconfigName))

	// added to allow controller to create all the things, like service
	// accounts, before we go ahead and start connecting to do stuff.
	//
	// we might be able to improve this some other way in the future, but
	// seems to work for now. some backoff strategy seems to be performed
	// and waiting for 30s will continue after 15s if all is green.
	//
	// see https://github.com/kubernetes/kubernetes/issues/66689
	//
	// Importantly note that this will shell out to kubectl! *sigh*
	createOpts = append(createOpts, cluster.CreateWithWaitForReady(clusterWaitDuration))

	checkErr(t, provider.Create(clusterName, createOpts...))

	t.Cleanup(func() {
		checkErr(t, provider.Delete(clusterName, kubeconfigName))
		checkErr(t, os.Remove(kubeconfigName))
	})

	clientConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfigName)
	checkErr(t, err)

	cl := Cluster{}
	cl.Name = clusterName
	cl.TemporaryConfigFile = kubeconfigName
	cl.Config = clientConfig
	cl.Provider = provider
	return &cl
}

func checkErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
}

//nolint:thelper // want to get the line where the error occurs here
func portForward(t *testing.T, clientConfig *rest.Config, namespace, podName string, addresses, ports []string) {
	stopChannel := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func(ctx context.Context) {
		defer wg.Done()
		//nolint:gosimple // TBD how to handle this
		select {
		case <-ctx.Done():
		}
		t.Log("Stopping portforward")
		close(stopChannel)
	}(t.Context())

	client, err := kubernetes.NewForConfig(clientConfig)
	checkErr(t, err)

	const podResource, subResource = "pods", "portforward"

	req := client.CoreV1().RESTClient().Post().
		Resource(podResource).
		Namespace(namespace).
		Name(podName).
		SubResource(subResource)

	transport, upgrader, err := spdy.RoundTripperFor(clientConfig)
	checkErr(t, err)

	readyChannel := make(chan struct{})
	httpClient := http.Client{Transport: transport}
	method := http.MethodPost

	dialer := spdy.NewDialer(upgrader, &httpClient, method, req.URL())

	fw, err := portforward.NewOnAddresses(dialer, addresses, ports,
		stopChannel, readyChannel, ioLogger{t}, ioLogger{t})
	checkErr(t, err)

	wg.Add(1)
	go func() {
		defer wg.Done()
		checkErr(t, fw.ForwardPorts())
	}()

	t.Cleanup(func() {
		wg.Wait()
		t.Logf("Port forwarding done")
	})
	<-readyChannel
}

//nolint:thelper // want to get the line where the error occurs here
func waitForReady(t *testing.T, client rest.Interface, namespace, res, labelSelector, selector string, callback func(any)) {
	// TODO: pull this out and figure out if all defaults are registered somewhere in the SDK already
	s := runtime.NewScheme()
	checkErr(t, appsv1.AddToScheme(s))
	checkErr(t, corev1.AddToScheme(s))

	// TODO: see if we can pull some of this out, it is not clear which
	// rest.Interface is needed, depending on which resource is targeted.
	//
	// The first pass tried to make this able to target pods, deployments and
	// services, but was not able to figure out how to parse things right and
	// get the right clients out from the SDK so that the watcher worked.
	//
	// It does what is needed for now.
	dc := discovery.NewDiscoveryClient(client)
	gr, err := restmapper.GetAPIGroupResources(dc)
	checkErr(t, err)
	mapper := restmapper.NewDiscoveryRESTMapper(gr)
	mapping, err := mapper.RESTMapping(schema.ParseGroupKind(res))
	checkErr(t, err)
	obj, err := s.New(mapping.GroupVersionKind)
	checkErr(t, err)

	_, err = fields.ParseSelector(selector)
	checkErr(t, err)

	// TODO: see if maybe https://pkg.go.dev/k8s.io/client-go@v0.32.0/informers
	// is better suited or if there is another package in the SDK to use.
	watchlist := cache.NewFilteredListWatchFromClient(client, mapping.Resource.Resource,
		namespace, func(o *metav1.ListOptions) {
			o.FieldSelector = selector
			o.LabelSelector = labelSelector
		})

	stop := make(chan struct{})

	// TODO: make configurable which type we are listening for. Might want to
	// wait for creates or deletes too.
	eventHandler := cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, new any) {
			// TODO: make the check configurable
			if isReady(new) {
				callback(new)
				t.Logf("Resource matching selector %q and labels %q is ready", selector, labelSelector)
				close(stop)
			}
		},
	}

	var informerOptions cache.InformerOptions
	informerOptions.ListerWatcher = watchlist
	informerOptions.ObjectType = obj
	informerOptions.Handler = eventHandler
	_, controller := cache.NewInformerWithOptions(informerOptions)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t.Logf("Waiting for %q with labels %q and selector %q to be ready in %q", res, labelSelector, selector, namespace)
		controller.Run(stop)
	}()

	wg.Wait()
	t.Log("Done waiting for ready")
}

func isReady(o any) bool {
	switch o := o.(type) {
	case *appsv1.Deployment:
		for c := range slices.Values(o.Status.Conditions) {
			if c.Type == appsv1.DeploymentAvailable && c.Status == corev1.ConditionTrue {
				return true
			}
		}
	case *corev1.Pod:
		for c := range slices.Values(o.Status.Conditions) {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				return true
			}
		}
	}
	return false
}

//nolint:thelper // want to get the line where the error occurs here
func applyResource(t *testing.T, config *rest.Config, ns string, r io.Reader) {
	// 2. Prepare a REST mapper to find resource GVR
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	checkErr(t, err)

	dc := memory.NewMemCacheClient(discoveryClient)
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(dc)

	// 3. Create a dynamic client
	dynamicClient, err := dynamic.NewForConfig(config)
	checkErr(t, err)

	// 4. Read and unmarshal the YAML file
	yamlFile, err := io.ReadAll(r)
	checkErr(t, err)

	for y := range slices.Values(bytes.Split(yamlFile, []byte("---"))) {
		var obj map[string]interface{}
		checkErr(t, yaml.Unmarshal(y, &obj))

		// 5. Convert unstructured data into object
		u := &unstructured.Unstructured{Object: obj}

		gvk := u.GroupVersionKind()
		m, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		checkErr(t, err)

		// 7. Obtain namespace and resource interface
		var dr dynamic.ResourceInterface
		switch m.Scope.Name() {
		case meta.RESTScopeNameRoot:
			dr = dynamicClient.Resource(m.Resource)
		case meta.RESTScopeNameNamespace:
			if ns == "" {
				ns = metav1.NamespaceDefault
			}
			if uns := u.GetNamespace(); uns != "" {
				ns = uns
			}
			dr = dynamicClient.Resource(m.Resource).Namespace(ns)
		default:
			t.Fatal("Unknown scope")
		}

		_, err = dr.Apply(t.Context(), u.GetName(), u, metav1.ApplyOptions{FieldManager: "x"})
		if k8serrors.IsNotFound(err) {
			_, err = dr.Create(t.Context(), u, metav1.CreateOptions{FieldManager: "x"})
			checkErr(t, err)
		}
		t.Logf("Resource %q applied successfully", u.GetName())
	}
}
