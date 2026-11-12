package cmd

import (
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/example/blip/internal/api/v1alpha1"
	"github.com/example/blip/internal/kubectlblip/session"
)

func (e *env) volumesCmd() *cobra.Command {
	var all bool
	c := &cobra.Command{
		Use:     "volumes [BLIPVOL]",
		Aliases: []string{"vols"},
		Short:   "List BlipVols, or show the snapshot history of one",
		Long: `List the BlipVols of the namespace with their phase, current snapshot
sequence, number of snapshots and pins. With BLIPVOL, show its snapshot
history (sequence, reason, state, capture time, writer Blip) and what pins
its snapshots or blocks its deletion: derived BlipVols whose origin it is,
holds, and the snapshots its current attachment started from and is based
on.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, ns, err := targetKube(e)
			if err != nil {
				return err
			}
			name := argOr(args, 0)
			if all && name == "" {
				ns = ""
			}
			vols, err := kc.ListVolumes(cmd.Context(), ns, name)
			if err != nil {
				return err
			}
			if name != "" {
				writeVolumeDetail(e.stdout, vols[0], time.Now())
				return nil
			}
			if len(vols) == 0 {
				e.logf("no blipvols found")
				return nil
			}
			writeVolumeTable(e.stdout, vols, all, time.Now())
			return nil
		},
	}
	c.Flags().BoolVarP(&all, "all-namespaces", "A", false, "list BlipVols in all namespaces")
	return c
}

func volPhase(v *v1alpha1.BlipVol) string {
	if v.DeletionTimestamp != nil {
		return "Deleting"
	}
	if v.Status.Phase == "" {
		return string(v1alpha1.BlipVolPending)
	}
	return string(v.Status.Phase)
}

func orNone(s string) string {
	if s == "" {
		return "<none>"
	}
	return s
}

func writeVolumeTable(out io.Writer, vols []session.VolumeInfo, all bool, now time.Time) {
	w := tabwriter.NewWriter(out, 0, 4, 3, ' ', 0)
	if all {
		fmt.Fprint(w, "NAMESPACE\t")
	}
	fmt.Fprintln(w, "NAME\tPHASE\tCURRENT\tSNAPSHOTS\tPINS\tATTACHED\tPARENT\tAGE")
	for _, vi := range vols {
		v := &vi.Vol
		if all {
			fmt.Fprintf(w, "%s\t", v.Namespace)
		}
		attached := ""
		if cl := v.Status.Claim; cl != nil {
			attached = cl.BlipName
		}
		parent := ""
		if o := v.Status.Origin; o != nil {
			parent = o.Name + "@" + strconv.FormatInt(o.Snapshot, 10)
		} else if p := v.Spec.Parent; p != nil {
			parent = p.Name
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%s\t%s\t%s\n", v.Name, volPhase(v), v.Status.Current, len(v.Status.Snapshots),
			len(vi.Pins), orNone(attached), orNone(parent), duration.HumanDuration(now.Sub(v.CreationTimestamp.Time)))
	}
	w.Flush()
}

func writeVolumeDetail(out io.Writer, vi session.VolumeInfo, now time.Time) {
	v := &vi.Vol
	fmt.Fprintf(out, "Name:       %s\nNamespace:  %s\nPhase:      %s\n", v.Name, v.Namespace, volPhase(v))
	if v.Status.Size != nil {
		fmt.Fprintf(out, "Size:       %s\n", v.Status.Size.String())
	}
	switch {
	case v.Spec.Image != nil:
		fmt.Fprintf(out, "Image:      %s\n", v.Spec.Image.Reference)
	case v.Status.Origin != nil:
		o := v.Status.Origin
		fmt.Fprintf(out, "Parent:     %s/%s snapshot %d\n", o.Namespace, o.Name, o.Snapshot)
	case v.Spec.Parent != nil:
		fmt.Fprintf(out, "Parent:     %s\n", v.Spec.Parent.Name)
	}
	fmt.Fprintf(out, "Current:    %d\nLimit:      %d\n", v.Status.Current, v.SnapshotLimit())
	if d := v.SnapshotInterval(); d > 0 {
		fmt.Fprintf(out, "Interval:   %s\n", d)
	}
	if v.SkipShutdown() {
		fmt.Fprintln(out, "Shutdown:   skipped")
	}
	if cl := v.Status.Claim; cl != nil {
		fmt.Fprintf(out, "Attached:   blip %s (from snapshot %d)\n", cl.BlipName, cl.Snapshot)
	}
	for _, c := range v.Status.Conditions {
		fmt.Fprintf(out, "Condition:  %s=%s %s %s\n", c.Type, c.Status, c.Reason, c.Message)
	}
	fmt.Fprintln(out, "\nSnapshots:")
	w := tabwriter.NewWriter(out, 0, 4, 3, ' ', 0)
	fmt.Fprintln(w, "  SEQ\tREASON\tSTATE\tCAPTURED\tWRITER\tMESSAGE")
	for i := len(v.Status.Snapshots) - 1; i >= 0; i-- {
		s := v.Status.Snapshots[i]
		mark := " "
		if s.Sequence == v.Status.Current {
			mark = "*"
		}
		captured := ""
		if s.CaptureTime != nil {
			captured = duration.HumanDuration(now.Sub(s.CaptureTime.Time)) + " ago"
		}
		writer := ""
		if s.Writer != nil {
			writer = s.Writer.BlipName
		}
		fmt.Fprintf(w, "%s %d\t%s\t%s\t%s\t%s\t%s\n", mark, s.Sequence, s.Reason, s.State, orNone(captured), orNone(writer), s.Message)
	}
	w.Flush()
	if len(vi.Pins) > 0 {
		fmt.Fprintln(out, "\nPins:")
		for _, p := range vi.Pins {
			if p.Snapshot != 0 {
				fmt.Fprintf(out, "  snapshot %d: %s\n", p.Snapshot, p.Why)
			} else {
				fmt.Fprintf(out, "  %s\n", p.Why)
			}
		}
	}
	if v.DeletionTimestamp != nil {
		if b := session.DeletionBlockers(v); b != "" {
			fmt.Fprintf(out, "\nDeletion %s\n", b)
		}
	}
}
