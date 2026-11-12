// Package cmd implements the kubectl-blip commands.
package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"k8s.io/apimachinery/pkg/util/duration"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/kubectlblip/local"
	"github.com/example/blip/internal/kubectlblip/session"
)

// Version is set at build time with -ldflags -X.
var Version = "dev"

// ExitError carries the exit status of a remote command.
type ExitError struct{ Code int }

func (e ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// kubeFlags are the kubeconfig flags shared by all commands.
type kubeFlags struct {
	kubeconfig, context, namespace string
}

func (f *kubeFlags) add(c *cobra.Command) {
	p := c.PersistentFlags()
	p.StringVar(&f.kubeconfig, "kubeconfig", "", "path to the kubeconfig file")
	p.StringVar(&f.context, "context", "", "kubeconfig context to use")
	p.StringVarP(&f.namespace, "namespace", "n", "", "namespace (default: from the kubeconfig context)")
}

// args returns the flags that are set, as command-line arguments.
func (f *kubeFlags) args() []string {
	var a []string
	for _, kv := range [][2]string{{"--kubeconfig", f.kubeconfig}, {"--context", f.context}, {"--namespace", f.namespace}} {
		if kv[1] != "" {
			a = append(a, kv[0], kv[1])
		}
	}
	return a
}

type env struct {
	flags  kubeFlags
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func (e *env) logf(f string, a ...any) { fmt.Fprintf(e.stderr, f+"\n", a...) }

// kube resolves the client, REST config and namespace.
func (e *env) kube() (*session.Client, *rest.Config, string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = e.flags.kubeconfig
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{
		CurrentContext: e.flags.context,
		Context:        clientcmdapi.Context{Namespace: e.flags.namespace},
	})
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, nil, "", err
	}
	ns, _, err := cc.Namespace()
	if err != nil {
		return nil, nil, "", err
	}
	c, err := client.NewWithWatch(cfg, client.Options{Scheme: session.Scheme()})
	if err != nil {
		return nil, nil, "", err
	}
	return &session.Client{C: c, Log: e.logf}, cfg, ns, nil
}

// NewRoot returns the root command.
func NewRoot(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	e := &env{stdin: stdin, stdout: stdout, stderr: stderr}
	root := &cobra.Command{
		Use:   "kubectl-blip",
		Short: "Create and SSH into Blip sessions",
		Long: `kubectl blip manages sessions: Blips created by this plugin (label
blip.example.com/session=true) that boot an SSH-enabled image. It keeps an
SSH key pair, known_hosts and defaults in ~/.blip ($BLIP_HOME).`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	e.flags.add(root)
	root.AddCommand(e.shellCmd(), e.createCmd(), e.listCmd(), e.deleteCmd(), e.proxyCmd(), e.sshConfigCmd(), e.setupCmd(),
		e.deriveCmd(), e.volumesCmd(), e.attachCmd(), e.detachCmd(), versionCmd())
	return root
}

// Main runs the plugin and returns the process exit code.
func Main(args []string) int {
	inGuest()
	root := NewRoot(os.Stdin, os.Stdout, os.Stderr)
	root.SetArgs(args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := root.ExecuteContext(ctx)
	var ee ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		return ee.Code
	default:
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use: "version", Short: "Print the plugin version", Args: cobra.NoArgs,
		Run: func(c *cobra.Command, _ []string) { fmt.Fprintln(c.OutOrStdout(), "kubectl-blip", Version) },
	}
}

// createOpts are the session creation flags.
type createOpts struct {
	volume, image, sku string
	ttl                time.Duration
	timeout            time.Duration
}

func (o *createOpts) addFlags(c *cobra.Command) {
	f := c.Flags()
	f.StringVar(&o.volume, "volume", "", "BlipVol to boot as the root volume")
	f.StringVar(&o.image, "image", "", "image reference to import as the root BlipVol (img-<hash>)")
	f.StringVar(&o.sku, "sku", "", "slot SKU (default \"default\")")
	f.DurationVar(&o.ttl, "ttl", 0, "maximum session lifetime, sets spec.maxTTLSeconds (default 1h)")
	f.DurationVar(&o.timeout, "timeout", 15*time.Minute, "how long to wait for the image and the session")
}

func (e *env) create(ctx context.Context, c *session.Client, ns, name, pub string, o *createOpts) error {
	dir, err := local.DefaultDir()
	if err != nil {
		return err
	}
	cfg, err := dir.LoadConfig()
	if err != nil {
		return err
	}
	opts, err := local.Resolve(local.Options{Volume: o.volume, Image: o.image, SKU: o.sku, TTL: o.ttl}, cfg)
	if err != nil {
		return err
	}
	if _, err := session.BuildBlip(session.Spec{Name: name, Volume: "x", TTL: opts.TTL}); err != nil {
		return err // validate before creating a BlipVol
	}
	vol := opts.Volume
	if opts.Image != "" {
		if vol, err = c.EnsureImageVolume(ctx, ns, opts.Image); err != nil {
			return err
		}
	}
	_, err = c.Create(ctx, session.Spec{
		Namespace: ns, Name: name, Volume: vol, SKU: opts.SKU, TTL: opts.TTL,
		AuthorizedKeys: pub, Owner: c.Whoami(ctx),
	})
	return err
}

func (e *env) createCmd() *cobra.Command {
	o := &createOpts{}
	var waitReady bool
	c := &cobra.Command{
		Use:   "create SESSION",
		Short: "Create a session without connecting",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := session.ValidateName(name); err != nil {
				return err
			}
			pub, err := ensureKey()
			if err != nil {
				return err
			}
			kc, _, ns, err := e.kube()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
			defer cancel()
			if err := e.create(ctx, kc, ns, name, pub, o); err != nil {
				return err
			}
			if !waitReady {
				return nil
			}
			_, _, _, err = kc.WaitReady(ctx, ns, name)
			return err
		},
	}
	o.addFlags(c)
	c.Flags().BoolVar(&waitReady, "wait", false, "wait until the session accepts SSH connections")
	return c
}

func ensureKey() (string, error) {
	dir, err := local.DefaultDir()
	if err != nil {
		return "", err
	}
	return dir.EnsureKey()
}

func (e *env) confirm(question string) bool {
	f, ok := e.stdin.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return false
	}
	fmt.Fprintf(e.stderr, "%s [y/N] ", question)
	line, _ := bufio.NewReader(e.stdin).ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

func (e *env) shellCmd() *cobra.Command {
	o := &createOpts{}
	var recreate bool
	c := &cobra.Command{
		Use:   "shell SESSION [-- COMMAND...]",
		Short: "SSH into a session, creating it if needed",
		Long: `Connect to the session with ssh, using "kubectl blip proxy" as the
ProxyCommand (see ssh-config). A missing session is created (see create). A
finished session is deleted and recreated after confirmation (or with
--recreate).`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, remote := args[0], args[1:]
			if cmd.ArgsLenAtDash() > 1 {
				return fmt.Errorf("unexpected arguments before --: %v", args[1:cmd.ArgsLenAtDash()])
			}
			if err := session.ValidateName(name); err != nil {
				return err
			}
			pub, err := ensureKey()
			if err != nil {
				return err
			}
			kc, _, ns, err := e.kube()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
			defer cancel()
			b, err := kc.Get(ctx, ns, name)
			if err != nil {
				return err
			}
			if b != nil && session.Finished(b) {
				if !session.IsSession(b) {
					return fmt.Errorf("blip %s is %s and is not a session; not recreating it", name, b.Status.Phase)
				}
				if !recreate && !e.confirm(fmt.Sprintf("session %s is %s. Delete and recreate it?", name, b.Status.Phase)) {
					return fmt.Errorf("session %s is %s (%s); use --recreate to replace it", name, b.Status.Phase, b.Status.Message)
				}
				e.logf("deleting blip/%s", name)
				if err := kc.Delete(ctx, b, true); err != nil {
					return err
				}
				b = nil
			}
			if b == nil {
				if err := e.create(ctx, kc, ns, name, pub, o); err != nil {
					return err
				}
			} else if !local.ContainsKey(b.Annotations[api.AnnotationSSHAuthorizedKeys], pub) {
				e.logf("warning: your key (%s) is not in the %s annotation of blip/%s; login will likely fail",
					local.KeyFields(pub), api.AnnotationSSHAuthorizedKeys, name)
			}
			return e.ssh(name, o.timeout, remote)
		},
	}
	o.addFlags(c)
	c.Flags().BoolVarP(&recreate, "recreate", "y", false, "delete and recreate a finished session without asking")
	return c
}

// ssh runs ssh to session name through `kubectl-blip proxy`, with the
// options of ssh-config.
func (e *env) ssh(name string, timeout time.Duration, remote []string) error {
	dir, err := local.DefaultDir()
	if err != nil {
		return err
	}
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh client not found: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	args := append(e.flags.args(), "--timeout", timeout.String())
	cmd := exec.Command(sshBin, session.SSHArgs(session.ProxyCommand(session.ShellQuote(self), args),
		dir.File(local.KeyFile), dir.File(local.KnownHostsFile), session.HostPrefix+name, remote)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = e.stdin, e.stdout, e.stderr
	// ssh handles terminal signals; keep running until it exits.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGQUIT)
	defer signal.Stop(sigs)
	err = cmd.Run()
	var xe *exec.ExitError
	if errors.As(err, &xe) {
		return ExitError{Code: xe.ExitCode()}
	}
	return err
}

func (e *env) listCmd() *cobra.Command {
	var all bool
	c := &cobra.Command{
		Use: "list", Aliases: []string{"ls"}, Short: "List sessions", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			kc, _, ns, err := e.kube()
			if err != nil {
				return err
			}
			if all {
				ns = ""
			}
			items, err := kc.List(cmd.Context(), ns)
			if err != nil {
				return err
			}
			if len(items) == 0 {
				e.logf("no sessions found")
				return nil
			}
			writeTable(e.stdout, items, all, time.Now())
			return nil
		},
	}
	c.Flags().BoolVarP(&all, "all-namespaces", "A", false, "list sessions in all namespaces")
	return c
}

func writeTable(out io.Writer, items []v1alpha1.Blip, all bool, now time.Time) {
	w := tabwriter.NewWriter(out, 0, 4, 3, ' ', 0)
	if all {
		fmt.Fprint(w, "NAMESPACE\t")
	}
	fmt.Fprintln(w, "NAME\tPHASE\tAGE\tDEADLINE\tOWNER")
	for _, b := range items {
		if all {
			fmt.Fprintf(w, "%s\t", b.Namespace)
		}
		phase := string(b.Status.Phase)
		if phase == "" {
			phase = string(v1alpha1.BlipPending)
		}
		deadline := "<none>"
		if d := b.Status.Deadline; d != nil {
			if left := d.Sub(now); left > 0 {
				deadline = "in " + duration.HumanDuration(left)
			} else {
				deadline = duration.HumanDuration(-left) + " ago"
			}
		}
		owner := b.Annotations[api.AnnotationSessionOwner]
		if owner == "" {
			owner = "<unknown>"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", b.Name, phase, duration.HumanDuration(now.Sub(b.CreationTimestamp.Time)), deadline, owner)
	}
	w.Flush()
}

func (e *env) deleteCmd() *cobra.Command {
	var force, wait bool
	c := &cobra.Command{
		Use: "delete SESSION...", Aliases: []string{"rm"}, Short: "Delete sessions", Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, _, ns, err := e.kube()
			if err != nil {
				return err
			}
			var errs []error
			for _, name := range args {
				b, err := kc.Get(cmd.Context(), ns, name)
				switch {
				case err != nil:
					errs = append(errs, err)
				case b == nil:
					errs = append(errs, fmt.Errorf("session %s/%s not found", ns, name))
				case !session.IsSession(b) && !force:
					errs = append(errs, fmt.Errorf("blip %s/%s is not a session (no %s=true label); use --force to delete it", ns, name, api.LabelSession))
				default:
					if err := kc.Delete(cmd.Context(), b, wait); err != nil {
						errs = append(errs, err)
					} else {
						fmt.Fprintf(e.stdout, "blip/%s deleted\n", name)
					}
				}
			}
			return errors.Join(errs...)
		},
	}
	c.Flags().BoolVar(&force, "force", false, "also delete Blips that are not sessions")
	c.Flags().BoolVar(&wait, "wait", false, "wait until the Blips are gone")
	return c
}

func (e *env) proxyCmd() *cobra.Command {
	var timeout time.Duration
	c := &cobra.Command{
		Use:   "proxy HOST",
		Short: "Connect stdin/stdout to a session's SSH port (for ssh ProxyCommand)",
		Long: `Wait for the session, record its host key in ~/.blip/known_hosts under
HOST, and relay stdin/stdout to its sshd. HOST is the session name, optionally
prefixed with "blip-" (see ssh-config). The session must exist.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			name := session.SessionFromHost(host)
			if err := session.ValidateName(name); err != nil {
				return err
			}
			kc, cfg, ns, err := e.kube()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			b, err := kc.Get(ctx, ns, name)
			if err != nil {
				return err
			}
			if b == nil {
				return fmt.Errorf("session %s/%s not found; create it with `kubectl blip create %s`", ns, name, name)
			}
			_, pod, hk, err := kc.WaitReady(ctx, ns, name)
			if err != nil {
				return err
			}
			dir, err := local.DefaultDir()
			if err != nil {
				return err
			}
			if err := dir.UpsertKnownHost(host, hk); err != nil {
				return err
			}
			fw, err := session.PortForward(ctx, cfg, ns, pod, session.SSHPort, e.stderr)
			if err != nil {
				return err
			}
			defer fw.Close()
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", fw.LocalPort))
			if err != nil {
				return err
			}
			cancel()
			return relay(cmd.Context(), conn, e.stdin, e.stdout, fw.Done())
		},
	}
	c.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "how long to wait for the session")
	return c
}

// relay copies in->conn and conn->out until the remote side closes, the
// forward ends or ctx is cancelled.
func relay(ctx context.Context, conn net.Conn, in io.Reader, out io.Writer, fwDone <-chan error) error {
	defer conn.Close()
	done := make(chan error, 2)
	var once sync.Once
	go func() {
		_, err := io.Copy(conn, in)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		if err != nil {
			done <- err
		}
	}()
	go func() {
		_, err := io.Copy(out, conn)
		once.Do(func() { done <- err })
	}()
	select {
	case err := <-done:
		return err
	case err := <-fwDone:
		if err != nil {
			return fmt.Errorf("port-forward: %w", err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *env) sshConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ssh-config",
		Short: "Print an ssh_config stanza for blip-<session> hosts",
		Long: `Print a "Host blip-*" stanza for ~/.ssh/config, so that
"ssh blip-<session>" connects through "kubectl blip proxy". The kubeconfig
flags given to this command (--context, -n, --kubeconfig) are baked into the
ProxyCommand. Host keys are recorded under the name blip-<session>.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := local.DefaultDir()
			if err != nil {
				return err
			}
			if _, err := dir.EnsureKey(); err != nil {
				return err
			}
			fmt.Fprint(e.stdout, session.SSHConfig("kubectl blip", dir.File(local.KeyFile), dir.File(local.KnownHostsFile), e.flags.args()))
			return nil
		},
	}
}

func (e *env) setupCmd() *cobra.Command {
	var nested bool
	c := &cobra.Command{
		Use:   "setup",
		Short: "Create the blip-ssh ServiceAccount, Role and RoleBinding in the namespace",
		Long: `Create or update the blip-ssh ServiceAccount, Role and RoleBinding
of examples/ssh/rbac.yaml (built into the plugin) that SSH images use to read authorized keys
and publish their host key. Needs permission to manage RBAC in the namespace.

With --nested, also create the blip-ssh-nested Role and RoleBinding of
examples/ssh/nested-rbac.yaml so that kubectl blip works inside the
sessions: every guest in the namespace can then derive, create, attach,
detach and delete Blips and BlipVols in the namespace.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			kc, _, ns, err := e.kube()
			if err != nil {
				return err
			}
			return kc.Setup(cmd.Context(), ns, nested, e.stdout)
		},
	}
	c.Flags().BoolVar(&nested, "nested", false, "also let guests run kubectl blip in the namespace")
	return c
}
