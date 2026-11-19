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
	Thread     string
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
			v1.LabelThread: spec.Thread,
			v1.LabelOwner:  v1.ThreadOwner(namespace, spec.Thread),
		},
	}
	// Own the turn by its thread so deleting the thread deletes its turns
	// rather than leaving them to be adopted by a later thread of the same
	// name. A turn may race its thread; it then stays unowned until the
	// sequencer stamps its thread UID.
	if spec.Thread != "" {
		var thread v1.BlipThread
		if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: spec.Thread}, &thread); err == nil &&
			thread.UID != "" {
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
		if err := c.Delete(ctx, &existing); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		return c.Create(ctx, turn)
	}
	return nil
}

// cleanAttributes drops fields the API would reject so a malformed report
// never blocks the coordinator.
func cleanAttributes(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if k == "" {
			continue
		}
		k = truncateRunes(k, 63)
		out[k] = truncateRunes(v, 256)
		if len(out) == 16 {
			break
		}
	}
	return out
}

// turnBelongsToThread reports whether a turn belongs to this incarnation of a
// thread. A thread that is deleted and recreated keeps its name but gets a new
// UID; turns from the old incarnation must not become input of the new one.
// Turns without a recorded thread UID are legacy turns that predate this
// field; when they carry a BlipThread owner reference, that reference decides.
func turnBelongsToThread(t *v1.BlipTurn, thread *v1.BlipThread) bool {
	if t.Status.ThreadUID != "" {
		return t.Status.ThreadUID == string(thread.UID)
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
