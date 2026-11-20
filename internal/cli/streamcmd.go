// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Azure/blip/api/v1alpha1"
)

type logsFlags struct {
	state  string
	offset int64
	raw    bool
	follow bool
}

func (a *app) logsCommand() *cobra.Command {
	f := &logsFlags{}
	cmd := &cobra.Command{
		Use:   "logs NAME [flags]",
		Short: "Print the output of a blip or state",
		Long: `Read a state's trajectory through the aggregated stream API. NAME may be a
Blip, which uses its spec.state, or a BlipState, which uses its own name. With
-f/--follow, keep following until the blip finishes. The trajectory survives the
VM pod, so a finished blip can still be read.

Output records go to stdout. Error records go to stderr. Input records are
shown with a "> " prefix and start/end records as status lines, also on stderr.
--raw prints only stdout bytes.`,
		Example: `  blip logs worker-1
  blip logs worker-1 -f --raw > output
  blip logs --state alice/home --offset 4096
  blip logs -f child-1 & blip send child-1 --text $'hello\n'`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.logs(cmd.Context(), args, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.state, "state", "", "BlipState to read (NAMESPACE/NAME is allowed)")
	fl.Int64Var(&f.offset, "offset", 0, "start at this trajectory record offset")
	fl.BoolVar(&f.raw, "raw", false, "print only stdout bytes")
	fl.BoolVarP(&f.follow, "follow", "f", false, "follow until the blip finishes")
	return cmd
}

func (a *app) logs(ctx context.Context, args []string, f *logsFlags) error {
	if f.offset < 0 {
		return fmt.Errorf("--offset must not be negative: %d", f.offset)
	}
	name := ""
	if len(args) > 0 {
		name = args[0]
	}
	if name == "" && f.state == "" {
		return errors.New("logs needs a blip or state name, or --state")
	}
	if name != "" && f.state != "" {
		return errors.New("logs takes NAME or --state, not both")
	}
	target, err := a.resolveStreamTarget(ctx, name, f.state)
	if err != nil {
		return err
	}
	w := &recordWriter{out: a.env.Out, err: a.env.Err, raw: f.raw}
	var done func(context.Context) bool
	if f.follow {
		done = func(ctx context.Context) bool { return a.streamTargetDone(ctx, target) }
	}
	return a.readStream(ctx, target, f.offset, f.follow, w, done)
}

func (a *app) streamTargetDone(ctx context.Context, target streamTarget) bool {
	if target.blip != "" {
		return a.blipDone(ctx, target.blip)
	}
	c, err := a.clients()
	if err != nil {
		return false
	}
	st, err := get(ctx, c, target.state, &v1alpha1.BlipState{})
	return err == nil && st.Status.Writer == nil && st.Status.Phase != v1alpha1.StateInUse
}

type sendFlags struct {
	text    string
	eof     bool
	textSet bool
}

func (a *app) sendCommand() *cobra.Command {
	f := &sendFlags{}
	cmd := &cobra.Command{
		Use:   "send NAME [--text TEXT | -] [--eof]",
		Short: "Send stdin to a running blip",
		Long: `Write bytes to a blip's stdin through the aggregated stream API. NAME may be
a Blip, which uses its spec.state, or a BlipState. Use --text for a literal
string, or "-" (or no --text) to copy stdin, which sends raw bytes from a pipe.
--eof closes the command's stdin.`,
		Example: `  blip send worker-1 --text $'hello\n'
  printf 'raw\n' | blip send worker-1 -
  blip send worker-1 --eof`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			f.textSet = cmd.Flags().Changed("text")
			return a.send(cmd.Context(), args, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.text, "text", "", "send TEXT instead of reading stdin")
	fl.BoolVar(&f.eof, "eof", false, "close the command's stdin")
	return cmd
}

func (a *app) send(ctx context.Context, args []string, f *sendFlags) error {
	target, err := a.resolveStreamTarget(ctx, args[0], "")
	if err != nil {
		return err
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	stream := c.stream()
	if stream == nil {
		return errors.New("stream API is unavailable")
	}
	var data []byte
	switch {
	case f.textSet && len(args) > 1:
		return errors.New("send takes --text or -, not both")
	case f.textSet:
		data = []byte(f.text)
	case len(args) > 1 && args[1] != "-":
		return fmt.Errorf("invalid input %q: use --text TEXT or - for stdin", args[1])
	case f.eof && len(args) == 1:
		// EOF alone: do not wait for local stdin just to close the remote
		// side.
	default:
		data, err = io.ReadAll(a.env.In)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
	}
	if len(data) > 0 || f.eof {
		// The API writes data and closes stdin in one request when eof is
		// set, so a pipe followed by EOF is atomic from the caller's view.
		if err := stream.Stdin(ctx, target.namespace, target.state, data, f.eof); err != nil {
			return stdinError(target, err)
		}
	}
	return nil
}

func stdinError(target streamTarget, err error) error {
	if apierrors.IsConflict(err) {
		return fmt.Errorf("state %q is not running; stdin is closed", target.state)
	}
	return err
}

type stopFlags struct {
	all bool
}

func (a *app) stopCommand() *cobra.Command {
	f := &stopFlags{}
	cmd := &cobra.Command{
		Use:   "stop NAME... [--all]",
		Short: "Stop running blips",
		Long: `Set spec.stop=true on running blips. A NAME that is a Blip stops that blip.
A NAME that is a BlipState stops the newest running Blip using that state. With
--all, stop every running Blip that matches. With no NAME, --all stops every
running Blip in the namespace.`,
		Example: `  blip stop worker-1
  blip stop alice/home
  blip stop --all alice/home alice/data`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.stop(cmd.Context(), args, f)
		},
	}
	cmd.Flags().BoolVar(&f.all, "all", false, "stop every matching running blip, not only the newest")
	return cmd
}

func (a *app) stop(ctx context.Context, names []string, f *stopFlags) error {
	if len(names) == 0 && !f.all {
		return errors.New("stop needs a blip or state name, or --all")
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	var targets []streamTarget
	if len(names) == 0 {
		var list v1alpha1.BlipList
		if err := c.Kube.List(ctx, &list, client.InNamespace(c.Namespace)); err != nil {
			return err
		}
		for i := range list.Items {
			b := &list.Items[i]
			if runningBlipForStop(b) {
				targets = append(targets, streamTarget{namespace: b.Namespace, state: b.Spec.State, blip: b.Name})
			}
		}
	} else {
		for _, name := range names {
			target, err := a.resolveStreamTarget(ctx, name, "")
			if err != nil {
				return err
			}
			if target.blip != "" {
				targets = append(targets, target)
				continue
			}
			var list v1alpha1.BlipList
			if err := c.Kube.List(ctx, &list, client.InNamespace(target.namespace)); err != nil {
				return err
			}
			var matching []*v1alpha1.Blip
			for i := range list.Items {
				b := &list.Items[i]
				if b.Spec.State == target.state && runningBlipForStop(b) {
					matching = append(matching, b)
				}
			}
			if len(matching) == 0 {
				fmt.Fprintf(a.env.Err, "no running blip for state %s\n", a.short(target.state))
				continue
			}
			sort.Slice(matching, func(i, j int) bool {
				ti, tj := matching[i].CreationTimestamp, matching[j].CreationTimestamp
				if ti.Equal(&tj) {
					return matching[i].Name > matching[j].Name
				}
				return ti.After(tj.Time)
			})
			if !f.all {
				matching = matching[:1]
			}
			for _, b := range matching {
				targets = append(targets, streamTarget{namespace: b.Namespace, state: b.Spec.State, blip: b.Name})
			}
		}
	}
	seen := map[string]bool{}
	for _, target := range targets {
		if seen[target.blip] {
			continue
		}
		seen[target.blip] = true
		if err := a.stopBlip(ctx, c, target.blip); err != nil {
			return err
		}
		fmt.Fprintf(a.env.Out, "blip/%s stopped\n", a.short(target.blip))
	}
	return nil
}

func runningBlipForStop(b *v1alpha1.Blip) bool {
	return b.Status.Phase == v1alpha1.BlipRunning && !b.Spec.Stop && b.DeletionTimestamp == nil
}

func (a *app) stopBlip(ctx context.Context, c *Clients, name string) error {
	b, err := get(ctx, c, name, &v1alpha1.Blip{})
	if err != nil {
		return notFound("blip", name, c.Namespace, err)
	}
	if !runningBlipForStop(b) {
		return fmt.Errorf("blip %q is not running (%s)", a.short(name), describe(b))
	}
	before := b.DeepCopy()
	b.Spec.Stop = true
	if err := c.Kube.Patch(ctx, b, client.MergeFrom(before)); err != nil {
		return fmt.Errorf("stop blip %q: %w", a.short(name), err)
	}
	return nil
}
