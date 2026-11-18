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
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/session"
)

// Env is the command's environment. Tests replace Connect with fakes.
type Env struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
	// Terminal enables raw mode, resize and signal forwarding when In is a
	// terminal.
	Terminal bool
	Connect  func(KubeFlags) (*Clients, error)
	// ProgressDelay holds progress lines back so fast operations stay
	// quiet.
	ProgressDelay time.Duration
	// NamespaceFile and Hostname find the blip the command runs in: the
	// Blip named by the hostname in the guest metadata's namespace.
	// Without NamespaceFile the command is never inside a blip.
	NamespaceFile string
	Hostname      func() (string, error)
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
	Sessions  *session.Client
	Namespace string
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
	return &Env{In: os.Stdin, Out: os.Stdout, Err: os.Stderr, Terminal: true, Connect: connect, ProgressDelay: time.Second,
		NamespaceFile: "/run/blip/namespace", Hostname: os.Hostname}
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
	sessions, err := session.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Clients{Kube: kube, Sessions: sessions, Namespace: ns}, nil
}

type app struct {
	env   *Env
	flags KubeFlags
	c     *Clients
	// self is the blip the command runs in, if any. prefix scopes the
	// names of an owned self ("<owner>.").
	self   *v1alpha1.Blip
	owner  string
	prefix string
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
	if a.env.NamespaceFile == "" || a.env.Hostname == nil {
		return nil
	}
	ns, err := os.ReadFile(a.env.NamespaceFile)
	if err != nil || strings.TrimSpace(string(ns)) != a.c.Namespace {
		return nil
	}
	host, err := a.env.Hostname()
	if err != nil {
		return nil
	}
	var b v1alpha1.Blip
	err = a.c.Kube.Get(ctx, client.ObjectKey{Namespace: a.c.Namespace, Name: host}, &b)
	if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) {
		return nil
	}
	if err != nil {
		return err
	}
	a.self = &b
	if o := b.Labels[ownerLabel]; o != "" {
		a.owner, a.prefix = o, o+"."
	}
	return nil
}

// ownerLabel names the owner of an SSH sandbox and the blips it creates.
const ownerLabel = "blip.dev/owner"

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
	if a.prefix == "" || name == "" || strings.HasPrefix(name, a.prefix) {
		return name
	}
	return a.prefix + name
}

// short is how a scoped name is shown.
func (a *app) short(name string) string {
	return strings.TrimPrefix(name, a.prefix)
}

func (a *app) label(o client.Object) {
	if a.owner != "" {
		o.SetLabels(map[string]string{ownerLabel: a.owner})
	}
}

func (a *app) progress(format string, args ...any) {
	fmt.Fprintf(a.env.Err, format+"\n", args...)
}

// NewCommand returns the root command.
func NewCommand(env *Env) *cobra.Command {
	a := &app{env: env}
	root := &cobra.Command{
		Use:         "blip",
		Annotations: map[string]string{cobra.CommandDisplayNameAnnotation: "kubectl blip"},
		Short:       "Run fast VM sandboxes with durable state on Kubernetes",
		Long: `Run fast VM sandboxes with durable state on Kubernetes.

These commands cover what kubectl cannot do: sessions inside a blip,
mounts on a running blip, waits that report its result, collecting files
and commits from a blip's state, and creating states without YAML. Use
kubectl for everything else:
  kubectl get blips,blipstates
  kubectl apply -f state.yaml  # advanced state fields
  kubectl patch blip NAME --type=merge -p '{"spec":{"stop":true}}'
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
		a.createCommand(), a.runCommand(), a.collectCommand(), a.execCommand(), a.attachCommand(),
		a.sessionsCommand(), a.mountCommand(), a.unmountCommand(), a.waitCommand(),
	)
	return root
}

// Main runs the command line and returns the process exit code.
func Main(ctx context.Context, env *Env, args []string) int {
	cmd := NewCommand(env)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(ctx)
	if err == nil || errors.Is(err, errDetached) {
		return 0
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		return exit.Code
	}
	fmt.Fprintf(env.Err, "error: %v\n", err)
	return 1
}
