package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/argoproj/argo-cd/v2/pkg/apiclient/session"
	"github.com/google/go-github/v62/github"
	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
)

// TestTelefonistka spins up a full integration environment. It requires that
// INTEGRATE=1 is set in the environment.
//
// 1. Creates a cluster running in Docker
// 2. Installs Argo CD
// 3. Creates a Github repository
// 4. Starts an up-to-date version of Telefonistka server, connecting it to Argo CD and Github
// 5. Forwards webhook requests from the Github repository to Telefonistka
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
//
//nolint:paralleltest // let us skip running this in parallel for now since it requires a human
func TestTelefonistka(t *testing.T) {
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
	createNamespace(t, client.CoreV1().Namespaces(), argoNamespace)

	// TODO: install using helm SDK
	//nolint:noctx // let us leave http.Get for now; this is a test
	installRes, err := http.Get("https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml")
	checkErr(t, err)
	installYamlFile, err := os.CreateTemp(t.TempDir(), "")
	checkErr(t, err)
	t.Cleanup(func() {
		checkErr(t, os.Remove(installYamlFile.Name()))
	})
	io.Copy(installYamlFile, installRes.Body) //nolint:errcheck
	checkErr(t, installRes.Body.Close())

	applyResource(t, cl.Config, argoNamespace, installYamlFile.Name()) // TODO: install with external helm chart using SDK

	waitForReady(t, client.CoreV1().RESTClient(), argoNamespace, "Pod", "app.kubernetes.io/name="+argoServer, "", func(o any) {
		switch o := o.(type) {
		case *corev1.Pod:
			ports := []string{strings.Join([]string{argoLocalPort, argoContainerPort}, ":")}
			addresses := []string{"127.0.0.1"} // TODO: does it need to be IP?

			portForward(t, cl.Config, argoNamespace, o.Name, addresses, ports)
		}
	})
	serverAddr := net.JoinHostPort("localhost", argoLocalPort)

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
	//
	// TODO: use the token to setup separate identity and get a token for that
	// instead.
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
	checkErr(t, err)

	// TODO: pull out GH setup so that we can run Telefonistka in the
	// background and do some Github interactions directly on the created repo
	// here, using the Github client, in order to simulate things happening.
	//
	// Right now user will have to manually push things to the created
	// repository.
	testTelefonistkaClient(t, createResponse.GetToken(), serverAddr)
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

//nolint:thelper // want to get the line where the error occurs here
func testTelefonistkaClient(t *testing.T, token, argoServerAddr string) {
	// TODO: pull some of these configurable things so that they can be chosen
	// in the top-level test.
	webhookSecret := rand.Text()

	// TODO: refactor so that it is easy to instead instantiate the server in
	// code.
	cmd := exec.CommandContext(t.Context(), "go", "run", ".", "server")
	cmd.Env = append(os.Environ(),
		"GITHUB_WEBHOOK_SECRET="+webhookSecret,

		// TODO: read in top-level test
		"GITHUB_OAUTH_TOKEN="+os.Getenv("GITHUB_TOKEN"),
		"APPROVER_GITHUB_OAUTH_TOKEN="+os.Getenv("GITHUB_TOKEN"),

		"LOG_LEVEL=debug",
		"ARGOCD_SERVER_ADDR="+argoServerAddr,
		"ARGOCD_TOKEN="+token,
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

	gh := createGithubClient(t)
	repo := createGithubRepo(t, gh)

	// There is no way to wait for execution and start of server; TODO: as
	// mentioned above, refactor entrypoint such that it will be just as easy
	// to spin up an isolated instance in code
	time.Sleep(5 * time.Second)

	wsURL := createRepoHook(t, gh, repo, webhookSecret)

	// TODO make sure this aligns with what is configured when starting the server. For now it is hardcoded.
	fwd := "http://localhost:8080/webhook"

	// dst, src
	forwardData(t, fwd, wsURL)

	t.Cleanup(func() {
		wg.Wait()
	})
}

//nolint:thelper // want to get the line where the error occurs here
func forwardData(t *testing.T, fwd, wsURL string) {
	var wg sync.WaitGroup
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	header := http.Header{}
	header.Set("Authorization", os.Getenv("GITHUB_TOKEN")) // TODO: pull out to top-level

	c, dialRes, err := websocket.DefaultDialer.Dial(wsURL, header)
	checkErr(t, err)
	checkErr(t, dialRes.Body.Close())

	// Make sure we appropriately close the connection when we are done.
	wg.Add(1)
	defer func() {
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
			if err := c.ReadJSON(&v); err != nil {
				// TODO: figure out how to properly handle errors here.
				if websocket.IsCloseError(err, websocket.CloseAbnormalClosure) {
					t.Logf("Websocket error: %v", err)
					time.Sleep(5 * time.Second)
					continue
				} else if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
					return
				}
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
	name := rand.Text()
	var x github.Repository
	x.Name = github.String(name)
	x.Description = github.String(fmt.Sprintf("I'm a Telefonistka test repository generated at %s", time.Now().Format(time.RFC3339)))

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
	t.Logf("Created repository %q (gh repo clone %s/%s)",
		name, r.GetOwner().GetLogin(), name)
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
		t.Fatalf("Unexpected error %q", err)
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
func applyResource(t *testing.T, config *rest.Config, ns, filePath string) {
	// 2. Prepare a REST mapper to find resource GVR
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	checkErr(t, err)

	dc := memory.NewMemCacheClient(discoveryClient)
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(dc)

	// 3. Create a dynamic client
	dynamicClient, err := dynamic.NewForConfig(config)
	checkErr(t, err)

	// 4. Read and unmarshal the YAML file
	yamlFile, err := os.ReadFile(filePath)
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
