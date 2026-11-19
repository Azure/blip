// Package cli implements the blip command.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
)

// Env is the command's environment. Tests replace Connect with fakes.
type Env struct {
	In      io.Reader
	Out     io.Writer
	Err     io.Writer
	Connect func(KubeFlags) (*Clients, error)
	// ProgressDelay holds progress lines back so fast operations stay
	// quiet.
	ProgressDelay time.Duration
	// NamespaceFile, NameFile and Hostname find the blip the command runs
	// in. The guest writes its Blip name to NameFile so names longer than a
	// hostname (64 bytes) still work; Hostname is the fallback for older
	// guests. Without NamespaceFile the command is never inside a blip.
	NamespaceFile string
	NameFile      string
	Hostname      func() (string, error)
	// Args is the raw command line. Commands use it to notice flags that
	// pflag parsed after a positional argument, where the user meant them
	// for the command instead.
	Args []string
}

// KubeFlags are the kubeconfig flags.
type KubeFlags struct {
	Kubeconfig string
	Context    string
	Namespace  string
}

// Clients are the API clients a command uses.
type Clients struct {
	Kube      client.WithWatch
	Stream    streamAPI
	Namespace string
	// REST reaches aggregated APIs. Its base path is empty, so AbsPath
	// addresses /apis/stream.blip.dev/... directly.
	REST rest.Interface
}

// ExitError makes the process exit with Code without printing anything.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// Scheme has the core and blip types.
var Scheme = runtime.NewScheme()

func init() {
	_ = clientgoscheme.AddToScheme(Scheme)
	_ = v1alpha1.AddToScheme(Scheme)
}

// DefaultEnv uses the process's stdio and kubeconfig.
func DefaultEnv() *Env {
	return &Env{In: os.Stdin, Out: os.Stdout, Err: os.Stderr, Connect: connect, ProgressDelay: time.Second,
		NamespaceFile: "/run/blip/namespace", NameFile: "/run/blip/name", Hostname: os.Hostname}
}

func connect(f KubeFlags) (*Clients, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = f.Kubeconfig
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: f.Context})
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, err
	}
	// One `blip run` issues a burst of gets, creates, watches and an exec.
	// client-go's default 5 QPS throttles the CLI itself, making fast
	// sandboxes feel slow; the gateway and controller already disable it.
	cfg.QPS, cfg.Burst = 50, 100
	ns := f.Namespace
	if ns == "" {
		if ns, _, err = cc.Namespace(); err != nil {
			return nil, err
		}
	}
	kube, err := client.NewWithWatch(cfg, client.Options{Scheme: Scheme})
	if err != nil {
		return nil, err
	}
	// A generated client's REST client prefixes its group version (/api/v1
	// for core), and the discovery client adds a request timeout. Build an
	// unversioned client with an empty base path so AbsPath reaches the
	// aggregated stream API unchanged.
	streamConfig := *cfg
	streamConfig.APIPath = ""
	streamConfig.GroupVersion = nil
	streamConfig.NegotiatedSerializer = clientgoscheme.Codecs.WithoutConversion()
	restClient, err := rest.UnversionedRESTClientFor(&streamConfig)
	if err != nil {
		return nil, err
	}
	return &Clients{
		Kube:      kube,
		Stream:    &streamClient{rest: restClient},
		Namespace: ns,
		REST:      restClient,
	}, nil
}

type app struct {
	env   *Env
	args  []string
	flags KubeFlags
	c     *Clients
	// self is the blip the command runs in, if any. prefix scopes the
	// names of an owned self ("<owner>.").
	self   *v1alpha1.Blip
	owner  string
	prefix string

	// signalGrace overrides the default grace for tests. signalGraceMax
	// overrides the hard cap.
	signalGrace    time.Duration
	signalGraceMax time.Duration
}

func (a *app) clients() (*Clients, error) {
	if a.c == nil {
		c, err := a.env.Connect(a.flags)
		if err != nil {
			return nil, err
		}
		a.c = c
		if err := a.findSelf(context.Background()); err != nil {
			return nil, err
		}
	}
	return a.c, nil
}

func (a *app) findSelf(ctx context.Context) error {
	if a.env.NamespaceFile == "" {
		return nil
	}
	ns, err := os.ReadFile(a.env.NamespaceFile)
	if err != nil || strings.TrimSpace(string(ns)) != a.c.Namespace {
		return nil
	}
	name := ""
	if a.env.NameFile != "" {
		if data, err := os.ReadFile(a.env.NameFile); err == nil {
			name = strings.TrimSpace(string(data))
		}
	}
	if name == "" {
		if a.env.Hostname == nil {
			return nil
		}
		if name, err = a.env.Hostname(); err != nil {
			return nil
		}
	}
	var b v1alpha1.Blip
	err = a.c.Kube.Get(ctx, client.ObjectKey{Namespace: a.c.Namespace, Name: name}, &b)
	switch {
	case apierrors.IsNotFound(err):
		return nil
	case apierrors.IsForbidden(err):
		return fmt.Errorf("cannot read blip %q to find out where this command runs: %w", name, err)
	case err != nil:
		return err
	}
	a.self = &b
	if o := b.Labels[v1alpha1.LabelOwner]; o != "" {
		a.owner, a.prefix = o, v1alpha1.OwnerPrefix(o)
	}
	return nil
}

// scope connects and maps the names a user typed to the names of objects
// in the caller's owner scope.
func (a *app) scope(names ...*string) error {
	if _, err := a.clients(); err != nil {
		return err
	}
	for _, n := range names {
		*n = a.full(*n)
	}
	return nil
}

func (a *app) full(name string) string {
	if a.owner == "" || name == "" || v1alpha1.OwnedBy(name, a.owner) {
		return name
	}
	return a.prefix + name
}

// resolveState prefers the caller's workspace, then a literal shared source.
// Only NotFound triggers fallback: authorization and transport failures must
// not silently select another source.
func (a *app) resolveState(ctx context.Context, name string) (*v1alpha1.BlipState, error) {
	if err := a.validateStateName(name); err != nil {
		return nil, err
	}
	c, err := a.clients()
	if err != nil {
		return nil, err
	}
	full := a.full(name)
	st, err := get(ctx, c, full, &v1alpha1.BlipState{})
	if apierrors.IsNotFound(err) && full != name {
		st, err = get(ctx, c, name, &v1alpha1.BlipState{})
	}
	if err != nil {
		return nil, notFound("state", name, c.Namespace, err)
	}
	return st, nil
}

// short is how a scoped name is shown.
func (a *app) short(name string) string {
	return strings.TrimPrefix(name, a.prefix)
}

func (a *app) label(o client.Object) {
	if a.owner != "" {
		o.SetLabels(map[string]string{v1alpha1.LabelOwner: a.owner})
	}
}

func (a *app) progress(format string, args ...any) {
	fmt.Fprintf(a.env.Err, format+"\n", args...)
}

// NewCommand returns the root command.
func NewCommand(env *Env) *cobra.Command {
	a := &app{env: env, args: env.Args}
	root := &cobra.Command{
		Use:         "blip",
		Annotations: map[string]string{cobra.CommandDisplayNameAnnotation: "kubectl blip"},
		Short:       "Run fast VM sandboxes with durable state on Kubernetes",
		Long: `Run fast VM sandboxes with durable state on Kubernetes.

These commands cover what kubectl cannot do: starting one-shot blips, following
their output and stdin through the stream API, gathering results, mounts, and
importing container images as shared bases. Use kubectl for everything else:
  kubectl get blips,blipstates
  kubectl apply -f state.yaml  # advanced state fields
  kubectl delete blip NAME`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetIn(env.In)
	root.SetOut(env.Out)
	root.SetErr(env.Err)
	pf := root.PersistentFlags()
	pf.StringVar(&a.flags.Kubeconfig, "kubeconfig", "", "path to the kubeconfig file")
	pf.StringVar(&a.flags.Context, "context", "", "kubeconfig context to use")
	pf.StringVarP(&a.flags.Namespace, "namespace", "n", "", "namespace (default from kubeconfig)")
	root.AddCommand(
		a.runCommand(), a.gatherCommand(), a.logsCommand(), a.sendCommand(),
		a.stopCommand(), a.mountCommand(), a.pullCommand(),
	)
	return root
}

// Main runs the command line and returns the process exit code.
func Main(ctx context.Context, env *Env, args []string) int {
	env.Args = args
	cmd := NewCommand(env)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		return exit.Code
	}
	fmt.Fprintf(env.Err, "error: %v\n", err)
	return 1
}
