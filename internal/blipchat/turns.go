package blipchat

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

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
	turn := &v1.BlipTurn{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
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
	if err := c.Create(ctx, turn); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
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
