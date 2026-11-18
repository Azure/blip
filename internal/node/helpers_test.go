package node

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/image"
	"github.com/Azure/blip/internal/podapi"
	"github.com/Azure/blip/internal/storage"
)

const (
	self     = "n1"
	ns       = "default"
	imageRef = "registry.local/img@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	imageID  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

var testNow = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

func newView() *view {
	v := &view{
		now:         testNow,
		node:        self,
		incarnation: "inc-n1",
		blipNodes:   map[string]*v1alpha1.BlipNode{},
		kubeNodes:   map[string]*corev1.Node{},
		pools:       map[string]*v1alpha1.BlipPool{},
		pods:        map[string]*corev1.Pod{},
		dirs:        map[string]*podDir{},
		volumes:     map[string]storage.Volume{},
		devices:     map[string]uint64{},
		configs:     map[string]*image.Config{},
		busy:        map[string]bool{},
		sealErrs:    map[string]string{},
		stateErrs:   map[string]string{},
		progress:    map[string]*v1alpha1.Transfer{},
		podsGone:    map[string]bool{},
		statesGone:  map[string]bool{},
		blipsGone:   map[string]bool{},
	}
	v.pools[ns+"/default"] = &v1alpha1.BlipPool{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "default"}}
	now := metav1.NewTime(testNow)
	for i, n := range []string{"n1", "n2", "n3"} {
		v.blipNodes[n] = &v1alpha1.BlipNode{
			ObjectMeta: metav1.ObjectMeta{Name: n},
			Status: v1alpha1.BlipNodeStatus{
				Incarnation: "inc-" + n, Heartbeat: &now,
				TLSPublicKey: testPublicKey(n), Endpoint: fmt.Sprintf("192.0.2.%d", i+1),
			},
		}
		v.kubeNodes[n] = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: n, Labels: map[string]string{"blip.dev/enrolled": "true"}},
		}
	}
	return v
}

func testPublicKey(node string) string {
	seed := sha256.Sum256([]byte(node))
	key := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(key)
}

// pkey is the namespace-qualified key of the test namespace's pod name.
func pkey(name string) string { return podKey(ns, name) }

func state(name string) *v1alpha1.BlipState {
	return &v1alpha1.BlipState{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + name)},
		Status:     v1alpha1.BlipStateStatus{SizeBytes: 1 << 30},
	}
}

func holding(node string, commits ...string) v1alpha1.NodeObservation {
	return v1alpha1.NodeObservation{Node: node, Incarnation: "inc-" + node, Commits: commits}
}

func vmPod(name string, blipUID string) *corev1.Pod {
	labels := map[string]string{LabelPool: "default"}
	if blipUID != "" {
		labels[LabelBlipUID] = blipUID
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("poduid-" + name), Labels: labels},
		Spec:       corev1.PodSpec{NodeName: self},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func blip(name string) *v1alpha1.Blip {
	return &v1alpha1.Blip{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("blipuid-" + name)},
		Spec:       v1alpha1.BlipSpec{State: "root"},
		Status:     v1alpha1.BlipStatus{Phase: v1alpha1.BlipRunning, Node: self},
	}
}

func dir(phase string) *podDir {
	return &podDir{observed: &podapi.Observed{Phase: phase}, devs: map[string]uint64{}}
}

func commit(id, stateUID string) storage.Volume {
	return storage.Volume{ID: id, Kind: storage.KindCommit, StateUID: stateUID, SizeBytes: 1 << 30}
}

// readyDev registers a working volume with an active device and its device
// node in the pod directory.
func readyDev(v *view, d *podDir, vol storage.Volume, rdev uint64) {
	vol.Kind = storage.KindWorking
	vol.Device = "/dev/mapper/" + vol.ID
	v.volumes[vol.ID] = vol
	v.devices[vol.ID] = rdev
	d.devs[vol.ID] = rdev
}
