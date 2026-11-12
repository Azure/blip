package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/example/blip/internal/api"
	"github.com/example/blip/internal/api/v1alpha1"

	"github.com/example/blip/internal/kubectlblip/guest"
	"github.com/example/blip/internal/kubectlblip/session"
)

// selfIdentity finds the Blip this process runs in; a variable for tests.
var selfIdentity = guest.Self

// guestOps are the in-guest operations; a variable for tests.
var guestOps = struct {
	sync          func()
	findDevice    func(name string) string
	waitDevice    func(ctx context.Context, name string) (string, error)
	mount         func(ctx context.Context, dev, dir string, readOnly bool) error
	unmountDevice func(dev string) ([]string, error)
}{guest.Sync, guest.FindDevice, guest.WaitDevice, guest.Mount, guest.UnmountDevice}

// targetKube returns the client and namespace for volume commands; a
// variable for tests.
var targetKube = func(e *env) (*session.Client, string, error) {
	kc, _, ns, err := e.kube()
	return kc, ns, err
}

// target is the Blip a volume command acts on.
type target struct {
	kc   *session.Client
	ns   string
	name string
	self bool // the Blip this process runs in
}

// target resolves the Blip name, or the Blip this process runs in when name
// is empty. The namespace of that Blip is used unless --namespace is set.
func (e *env) target(name string) (*target, error) {
	kc, ns, err := targetKube(e)
	if err != nil {
		return nil, err
	}
	id, ok, err := selfIdentity()
	if err != nil && name == "" {
		return nil, fmt.Errorf("find the blip this command runs in: %w", err)
	}
	if !ok && name == "" {
		return nil, fmt.Errorf("not running inside a blip: name the blip")
	}
	explicitNS := e.flags.namespace != ""
	t := &target{kc: kc, ns: ns, name: name}
	if ok && id.Namespace != "" && !explicitNS && (name == "" || name == id.Name) {
		t.ns = id.Namespace
	}
	if name == "" {
		t.name = id.Name
	}
	t.self = ok && t.name == id.Name && (id.Namespace == "" || t.ns == id.Namespace)
	return t, nil
}

func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}

func (e *env) deriveCmd() *cobra.Command {
	var vol, name string
	var snap int64
	var waitReady, skipShutdown bool
	var interval time.Duration
	var limit int32
	var timeout time.Duration
	c := &cobra.Command{
		Use:   "derive [SOURCE]",
		Short: "Create a BlipVol from a snapshot of another and print its name",
		Long: `Create a BlipVol whose spec.parent is BlipVol SOURCE and print its name
(default: SOURCE-xxxxx). It is a clone of the newest Ready snapshot of
SOURCE, or of snapshot --snapshot N. While SOURCE is attached to a running
Blip and --snapshot is not set, the controller first captures a new
snapshot of it (WaitingForCapture).

Without SOURCE, --volume names an attachment of the Blip this command runs
in: its BlipVol is the source, and the file systems are synced first.

With --wait, wait until the new BlipVol is Ready. Boot it with
'create --volume', attach it with 'attach', and list its history with
'volumes'.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src := argOr(args, 0)
			if (src == "") == (vol == "") {
				return fmt.Errorf("name a SOURCE blipvol, or --volume ATTACHMENT inside a blip")
			}
			o := session.DeriveOptions{Name: name}
			if cmd.Flags().Changed("snapshot") {
				if snap < 1 {
					return fmt.Errorf("--snapshot must be at least 1")
				}
				o.Snapshot = &snap
			}
			if skipShutdown || interval != 0 || limit != 0 {
				o.Policy = &v1alpha1.SnapshotPolicy{SkipShutdown: skipShutdown, Limit: limit}
				if interval != 0 {
					if interval < api.MinSnapshotInterval*time.Second {
						return fmt.Errorf("--interval must be at least %s", api.MinSnapshotInterval*time.Second)
					}
					o.Policy.Interval = &metav1.Duration{Duration: interval}
				}
			}
			ctx, cancel := withTimeout(cmd.Context(), timeout)
			defer cancel()
			var kc *session.Client
			var ns string
			if src == "" {
				t, err := e.target("")
				if err != nil {
					return err
				}
				if !t.self {
					return fmt.Errorf("--volume only works inside a blip")
				}
				kc, ns = t.kc, t.ns
				if src, err = kc.AttachmentVolume(ctx, ns, t.name, vol); err != nil {
					return err
				}
				guestOps.sync()
			} else {
				var err error
				if kc, ns, err = targetKube(e); err != nil {
					return err
				}
			}
			bv, err := kc.Derive(ctx, ns, src, o)
			if err != nil {
				return err
			}
			if waitReady {
				if _, err := kc.WaitVolume(ctx, ns, bv.Name); err != nil {
					return fmt.Errorf("blipvol %s: %w", bv.Name, err)
				}
			}
			fmt.Fprintln(e.stdout, bv.Name)
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&vol, "volume", "", "inside a blip: derive from this attachment of the blip (e.g. root)")
	f.Int64Var(&snap, "snapshot", 0, "sequence of the source snapshot (default: newest, or a live capture)")
	f.StringVar(&name, "name", "", "name of the new BlipVol (default: SOURCE-xxxxx)")
	f.BoolVar(&waitReady, "wait", false, "wait until the new BlipVol is Ready")
	f.BoolVar(&skipShutdown, "skip-shutdown", false, "snapshotPolicy.skipShutdown of the new BlipVol")
	f.DurationVar(&interval, "interval", 0, "snapshotPolicy.interval of the new BlipVol (at least 5m)")
	f.Int32Var(&limit, "limit", 0, "snapshotPolicy.limit of the new BlipVol (default 24)")
	f.DurationVar(&timeout, "timeout", 15*time.Minute, "how long to wait")
	return c
}

func (e *env) attachCmd() *cobra.Command {
	var to, name, dir string
	var readOnly bool
	var timeout time.Duration
	c := &cobra.Command{
		Use:   "attach BLIPVOL",
		Short: "Attach a BlipVol to a running Blip and print its device",
		Long: `Attach a private writable copy of a BlipVol to a running Blip (default:
the Blip this command runs in) and print its device path in the guest,
/dev/disk/by-id/virtio-NAME. NAME defaults to the BlipVol name.

With --mount DIR, which needs root inside the Blip itself, also wait for the
device and mount it at DIR.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			bv := args[0]
			if name == "" {
				name = bv
				if err := session.ValidateVolumeName(name); err != nil {
					return fmt.Errorf("%w; set --name", err)
				}
			}
			t, err := e.target(to)
			if err != nil {
				return err
			}
			if dir != "" && !t.self {
				return fmt.Errorf("--mount only works inside blip %s itself", t.name)
			}
			ctx, cancel := withTimeout(cmd.Context(), timeout)
			defer cancel()
			vs, err := t.kc.Attach(ctx, t.ns, t.name, name, bv)
			if err != nil {
				return err
			}
			dev := vs.DevicePath
			if dir != "" {
				if dev, err = guestOps.waitDevice(ctx, name); err != nil {
					return err
				}
				if err := guestOps.mount(ctx, dev, dir, readOnly); err != nil {
					return err
				}
				e.logf("mounted %s at %s", dev, dir)
			}
			fmt.Fprintln(e.stdout, dev)
			return nil
		},
	}
	c.Flags().StringVar(&to, "to", "", "Blip to attach to (default: this Blip)")
	c.Flags().StringVar(&name, "name", "", "spec.volumes name, at most 20 characters (default: the BlipVol name)")
	c.Flags().StringVar(&dir, "mount", "", "mount the volume at this directory (inside the Blip only)")
	c.Flags().BoolVar(&readOnly, "read-only", false, "mount read-only")
	c.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "how long to wait for the attachment")
	return c
}

func (e *env) detachCmd() *cobra.Command {
	var from string
	var del bool
	var timeout time.Duration
	c := &cobra.Command{
		Use:   "detach NAME",
		Short: "Detach a volume from a running Blip",
		Long: `Remove volume NAME from a running Blip (default: the Blip this command
runs in) and wait until it is released. Inside the Blip itself, first
unmount every mount of its device. Detach is forced: anything still using
the device gets I/O errors.

With --delete, also delete the BlipVol that was attached and wait until it
is gone, unless something else still holds it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			t, err := e.target(from)
			if err != nil {
				return err
			}
			ctx, cancel := withTimeout(cmd.Context(), timeout)
			defer cancel()
			if t.self {
				if dev := guestOps.findDevice(name); dev != "" {
					mps, err := guestOps.unmountDevice(dev)
					for _, mp := range mps {
						e.logf("unmounted %s", mp)
					}
					if err != nil {
						return err
					}
				}
			}
			bv, err := t.kc.Detach(ctx, t.ns, t.name, name)
			if err != nil {
				return err
			}
			fmt.Fprintf(e.stdout, "volume/%s detached\n", name)
			if del && bv != "" {
				pending, err := t.kc.DeleteVolume(ctx, t.ns, bv)
				if err != nil {
					return err
				}
				if pending != "" {
					fmt.Fprintf(e.stdout, "blipvol/%s deletion pending: %s\n", bv, pending)
				} else {
					fmt.Fprintf(e.stdout, "blipvol/%s deleted\n", bv)
				}
			}
			return nil
		},
	}
	c.Flags().StringVar(&from, "from", "", "Blip to detach from (default: this Blip)")
	c.Flags().BoolVar(&del, "delete", false, "delete the BlipVol after detaching it")
	c.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "how long to wait for the detach")
	return c
}

func argOr(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// inGuest prepares the environment when the plugin runs inside a Blip
// without a kubeconfig: client-go then uses the Blip's service account.
func inGuest() {
	if os.Getenv("KUBECONFIG") == "" {
		guest.InClusterEnv()
	}
}
