// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/podapi"
)

// A committed workspace does not establish command success. A requested stop
// and a clean pod exit, however, should have the same outcome whether or not
// the node mirrored the runtime's final Exited observation before the pod died.
func TestStoppedPodSucceededAfterCommittedSave(t *testing.T) {
	for _, tt := range []struct {
		name     string
		stop     bool
		podPhase corev1.PodPhase
		exited   bool
		gone     bool
		phase    string
		reason   string
	}{
		{name: "stopped_clean_pod_exit_without_final_observation", stop: true, podPhase: corev1.PodSucceeded, phase: v1.BlipSucceeded, reason: ReasonStopped},
		{name: "stopped_with_final_observation", stop: true, podPhase: corev1.PodSucceeded, exited: true, phase: v1.BlipSucceeded, reason: ReasonStopped},
		{name: "unexpected_clean_pod_exit", podPhase: corev1.PodSucceeded, phase: v1.BlipFailed, reason: ReasonPodLost},
		{name: "unexpected_pod_disappearance", gone: true, phase: v1.BlipFailed, reason: ReasonPodLost},
		{name: "stopped_failed_pod", stop: true, podPhase: corev1.PodFailed, phase: v1.BlipFailed, reason: ReasonRuntimeFailed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.addNodes("n1")
			e.newPool("default", 0, 0)
			b := e.startBlip("b", "n1", e.withImage("reg/img:v1"))
			if tt.stop {
				e.updateBlip("b", func(b *v1.Blip) { b.Spec.Stop = true })
			}
			if tt.exited {
				e.observe(b.Status.Pod, podapi.Observed{Phase: podapi.PhaseExited})
			}
			pod := e.getPod(b.Status.Pod)
			if tt.gone {
				e.must(e.c.Delete(e.ctx, pod))
			} else {
				pod.Status.Phase = tt.podPhase
				pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
					Name: "runtime",
					State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
						FinishedAt: metav1.NewTime(e.now),
					}},
				}}
				e.must(e.c.Status().Update(e.ctx, pod))
			}
			if tt.podPhase == corev1.PodSucceeded && !tt.exited {
				res := e.run(e.blip, ns, "b")
				expectPhase(t, e.getBlip("b"), v1.BlipRunning, "")
				if res.RequeueAfter != exitAnnotationGrace {
					t.Fatalf("exit annotation grace = %s, want %s", res.RequeueAfter, exitAnnotationGrace)
				}
			}
			e.now = e.now.Add(exitAnnotationGrace + time.Second)
			e.run(e.blip, ns, "b")
			if got := e.getBlip("b"); got.Status.Phase != v1.BlipSaving {
				t.Fatalf("before save: %+v", got.Status)
			}
			const commitID = "c2c2c2c2c2c2c2c2"
			e.saveWriter(b.Spec.State, commitID)
			st := e.getState(b.Spec.State)
			if st.Status.Phase != v1.StateReady || st.Status.Committed == nil ||
				st.Status.Committed.ID != commitID || st.Status.Committed.AttachmentID != b.Status.RootAttachmentID {
				t.Fatalf("save did not commit this Blip's attachment: %+v", st.Status)
			}
			for range 3 {
				e.run(e.blip, ns, "b")
			}
			got := e.getBlip("b")
			if got.Status.Phase != tt.phase || got.Status.Reason != tt.reason {
				t.Fatalf("after committed save: phase=%s reason=%s message=%q; want phase=%s reason=%s",
					got.Status.Phase, got.Status.Reason, got.Status.Message, tt.phase, tt.reason)
			}
		})
	}
}
