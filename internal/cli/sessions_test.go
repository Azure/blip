package cli

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Azure/blip/api/v1alpha1"
)

func TestPodFor(t *testing.T) {
	b := &v1alpha1.Blip{ObjectMeta: metav1.ObjectMeta{Name: "a"}}
	b.Status.Message = "waiting for a VM"
	if _, err := podFor(b); err == nil || !strings.Contains(err.Error(), "not running yet: waiting for a VM") {
		t.Fatalf("err = %v", err)
	}
	b.Status.Phase, b.Status.Pod = v1alpha1.BlipRunning, "pool-abcde"
	if p, err := podFor(b); err != nil || p != "pool-abcde" {
		t.Fatalf("pod=%q err=%v", p, err)
	}
	b.Status.Phase = v1alpha1.BlipSucceeded
	if _, err := podFor(b); err == nil || !strings.Contains(err.Error(), "finished") {
		t.Fatalf("err = %v", err)
	}
}
