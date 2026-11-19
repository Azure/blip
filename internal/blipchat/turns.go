package blipchat

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// turnSpec describes a turn a producer wants to create.
type turnSpec struct {
	Thread string
	// ThreadUID, when set, pins the turn to one incarnation of Thread. A
	// turn that would be owned by a recreated thread of the same name is
	// rejected instead of being adopted by it.
	ThreadUID  string
	AuthorKind string
	AuthorName string
	Topic      string
	Text       string
	Wake       string
	InReplyTo  int64
	Subjects   []v1.TurnSubject
	Attributes map[string]string
}

func createTurnIn(ctx context.Context, c client.Client, namespace, name string, spec turnSpec) error {
	if spec.Wake == "" {
		spec.Wake = v1.WakeBatch
	}
	if spec.InReplyTo < 0 {
		spec.InReplyTo = 0
	}
	spec.Thread = strings.TrimSpace(spec.Thread)
	meta := metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
		// The owner and thread labels let the in-guest API proxy scope
		// turn reads to one project without trusting self-asserted labels
		// on the caller's Blip.
		Labels: map[string]string{
			v1.LabelThread: v1.ThreadLabel(spec.Thread),
			v1.LabelOwner:  v1.ThreadOwner(namespace, spec.Thread),
		},
	}
	// Own the turn by its thread so deleting the thread deletes its turns
	// rather than leaving them to be adopted by a later thread of the same
	// name. A turn may race its thread; it then stays unowned until the
	// sequencer stamps its thread UID.
	if spec.Thread != "" {
		var thread v1.BlipThread
		err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: spec.Thread}, &thread)
		if spec.ThreadUID != "" && (err != nil || string(thread.UID) != spec.ThreadUID) {
			return errStaleIncarnation
		}
		if err == nil && thread.UID != "" {
			// The label pins the turn to this incarnation for the in-guest
			// proxy, which selects only its own thread UID.
			meta.Labels[v1.LabelThreadUID] = string(thread.UID)
			meta.OwnerReferences = []metav1.OwnerReference{
				*metav1.NewControllerRef(&thread, v1.GroupVersion.WithKind("BlipThread")),
			}
		}
	}
	turn := &v1.BlipTurn{
		ObjectMeta: meta,
		Spec: v1.BlipTurnSpec{
			Thread:     spec.Thread,
			Author:     v1.TurnAuthor{Kind: spec.AuthorKind, Name: spec.AuthorName},
			Topic:      spec.Topic,
			Text:       truncateRunes(spec.Text, 2048),
			Wake:       spec.Wake,
			InReplyTo:  spec.InReplyTo,
			Subjects:   spec.Subjects,
			Attributes: cleanAttributes(spec.Attributes),
		},
	}
	if err := c.Create(ctx, turn); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		// Deterministic names make retries idempotent, but an existing turn
		// is only a retry if it is the same turn. A different producer may
		// have squatted the name before admission reserved it; the owner of
		// the name is still the coordinator, so replace the impostor.
		var existing v1.BlipTurn
		if err := c.Get(ctx, client.ObjectKeyFromObject(turn), &existing); err != nil {
			return err
		}
		if equality.Semantic.DeepEqual(existing.Spec, turn.Spec) {
			return nil
		}
		if existing.Spec.Thread != turn.Spec.Thread || existing.Spec.Author != turn.Spec.Author {
			// A different producer squatted the name before admission
			// reserved it; the owner of the name is the coordinator, so
			// replace the impostor.
			if err := c.Delete(ctx, &existing); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
			return c.Create(ctx, turn)
		}
		// The same producer re-sent a deterministic turn with changed
		// content (for example a report whose fields were cleaned
		// differently). Turns are immutable at admission, so the spec cannot
		// be updated: doing so fails validation and wedges the producer's
		// watcher forever. The already-created turn is authoritative and may
		// already record status.seq/threadUID; keep its content and report
		// success so the reconcile converges.
		return nil
	}
	return nil
}

// cleanAttributes drops fields the API would reject so a malformed report
// never blocks the coordinator.
func cleanAttributes(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	// Sort the keys so an oversized map keeps the same subset on every call.
	// Map iteration order is random, and a different subset makes a
	// deterministic turn name look like a changed spec, which used to make
	// the watcher delete and re-create the turn on every reconcile.
	keys := make([]string, 0, len(in))
	for k := range in {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := make(map[string]string, len(in))
	for _, k := range keys {
		out[truncateRunes(k, 63)] = truncateRunes(in[k], 256)
		if len(out) == 16 {
			break
		}
	}
	return out
}

// turnBelongsToThread reports whether a turn belongs to this incarnation of a
// thread. A thread that is deleted and recreated keeps its name but gets a new
// UID; turns from the old incarnation must not become input of the new one.
// The sequencer stamps status.threadUID; new turns also carry
// blip.dev/thread-uid before they are sequenced. Turns without either are
// legacy turns that predate this field; when they carry a BlipThread owner
// reference, that reference decides.
func turnBelongsToThread(t *v1.BlipTurn, thread *v1.BlipThread) bool {
	if t.Status.ThreadUID != "" {
		return t.Status.ThreadUID == string(thread.UID)
	}
	// New turns carry the incarnation as a label before the sequencer stamps
	// status. A turn labelled for an earlier incarnation must not be adopted
	// by the recreated thread.
	if uid := t.Labels[v1.LabelThreadUID]; uid != "" {
		return uid == string(thread.UID)
	}
	for _, ref := range t.OwnerReferences {
		if ref.Kind == "BlipThread" && ref.Name == thread.Name && ref.APIVersion == v1.GroupVersion.String() {
			return thread.UID == "" || ref.UID == thread.UID
		}
	}
	return true
}

// sortTurns orders turns by sequence, breaking ties by name so equal sequence
// numbers (only possible in damaged data) still render deterministically.
func sortTurns(turns []v1.BlipTurn) {
	sort.SliceStable(turns, func(i, j int) bool {
		if turns[i].Status.Seq != turns[j].Status.Seq {
			return turns[i].Status.Seq < turns[j].Status.Seq
		}
		return turns[i].Name < turns[j].Name
	})
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// reportFields splits a JSON report into attributes and a summary. Anything
// that is not a flat JSON object is plain text.
func reportFields(text string) (map[string]string, string) {
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil || len(m) == 0 {
		return nil, truncateRunes(text, 2048)
	}
	attrs := map[string]string{}
	summary := ""
	for k, v := range m {
		switch value := v.(type) {
		case string:
			if k == "summary" {
				summary = value
			} else {
				attrs[k] = value
			}
		case float64, bool:
			attrs[k] = fmt.Sprint(value)
		default:
			encoded, err := json.Marshal(value)
			if err == nil {
				attrs[k] = string(encoded)
			}
		}
	}
	if summary == "" {
		summary = truncateRunes(text, 2048)
	}
	return attrs, summary
}

// renderTurn renders one turn for the coordinator prompt.
func renderTurn(t *v1.BlipTurn) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#%d %s/%s %s", t.Status.Seq, t.Spec.Author.Kind, t.Spec.Author.Name, t.Spec.Topic)
	if len(t.Spec.Subjects) > 0 {
		names := make([]string, 0, len(t.Spec.Subjects))
		for _, s := range t.Spec.Subjects {
			switch {
			case s.Name != "" && s.Kind != "":
				names = append(names, s.Kind+"/"+s.Name)
			case s.Name != "":
				names = append(names, s.Name)
			default:
				names = append(names, s.URI)
			}
		}
		fmt.Fprintf(&b, " [%s]", strings.Join(names, " "))
	}
	keys := make([]string, 0, len(t.Spec.Attributes))
	for k := range t.Spec.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%q", k, t.Spec.Attributes[k])
	}
	if t.Spec.InReplyTo != 0 {
		fmt.Fprintf(&b, " re=#%d", t.Spec.InReplyTo)
	}
	if t.Spec.Text != "" {
		fmt.Fprintf(&b, " %q", t.Spec.Text)
	}
	return b.String()
}
