package controller

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// VMOwnersConfigMap is the parameter table of the blip-vm-owner
// ValidatingAdmissionPolicy (deploy/base/vm-owner-policy.yaml). Keys are
// "sa.<service account>" for every VM service account, with the sorted,
// space-separated names of the pools using it, and "<pod>" with the owner of
// each claimed VM pod ("-" for an unrestricted Blip). "bases" lists the
// ownerless imported states available for shared read-only use and copying.
const VMOwnersConfigMap = "blip-vm-owners"

const (
	ownersSAPrefix = "sa."
	ownersBasesKey = "bases"
	ownerAny       = "-"
)

// blipOwner is the owner a Blip's VM acts for, or "" for an unrestricted
// Blip. An absent pod label is what makes the VM unrestricted; the admission
// table uses ownerAny because it needs a non-empty entry per claimed pod.
func blipOwner(b *v1.Blip) string {
	return b.Labels[v1.LabelOwner]
}

// ownerEntry is the admission table value for a Blip's claimed pod.
func ownerEntry(b *v1.Blip) string {
	if o := blipOwner(b); o != "" {
		return o
	}
	return ownerAny
}

// podServiceAccount is the account whose token pod holds, or "" if it has
// none.
func podServiceAccount(p *corev1.Pod) string {
	// Legacy VMs automounted their token. New VMs disable automount but
	// their API sidecar still authenticates as this pod's service account.
	if a := p.Spec.AutomountServiceAccountToken; a != nil && !*a && !hasAPIProxyToken(p) {
		return ""
	}
	if p.Spec.ServiceAccountName == "" {
		return "default"
	}
	return p.Spec.ServiceAccountName
}

func hasAPIProxyToken(p *corev1.Pod) bool {
	for _, v := range p.Spec.Volumes {
		// Endpoint tokens have other audiences; only api-token authenticates
		// to the Kubernetes API.
		if v.Name != apiTokenVolume || v.Projected == nil || !slices.ContainsFunc(v.Projected.Sources, func(s corev1.VolumeProjection) bool {
			return s.ServiceAccountToken != nil
		}) {
			continue
		}
		for _, c := range p.Spec.InitContainers {
			if c.Name == apiProxyName && slices.ContainsFunc(c.VolumeMounts, func(m corev1.VolumeMount) bool {
				return m.Name == v.Name
			}) {
				return true
			}
		}
	}
	return false
}

// poolsByServiceAccount maps the table key of each pool service account to
// the sorted, space-separated names of its pools. Pools without an account
// give their VMs no token and are not listed.
func poolsByServiceAccount(pools []v1.BlipPool) map[string]string {
	names := map[string][]string{}
	for i := range pools {
		if sa := pools[i].Spec.ServiceAccountName; sa != "" {
			names[ownersSAPrefix+sa] = append(names[ownersSAPrefix+sa], pools[i].Name)
		}
	}
	out := map[string]string{}
	for k, v := range names {
		slices.Sort(v)
		out[k] = strings.Join(v, " ")
	}
	return out
}

// patchVMOwners merge-patches the table in ns; a nil value removes the key.
// A missing table is created.
func patchVMOwners(ctx context.Context, c client.Client, ns string, data map[string]*string) error {
	if len(data) == 0 {
		return nil
	}
	raw, err := json.Marshal(map[string]any{"data": data})
	if err != nil {
		return err
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: VMOwnersConfigMap}}
	err = c.Patch(ctx, cm, client.RawPatch(types.MergePatchType, raw))
	if !apierrors.IsNotFound(err) {
		return err
	}
	cm.Data = map[string]string{}
	for k, v := range data {
		if v != nil {
			cm.Data[k] = *v
		}
	}
	if len(cm.Data) == 0 {
		return nil
	}
	err = c.Create(ctx, cm)
	if apierrors.IsAlreadyExists(err) {
		return c.Patch(ctx, cm, client.RawPatch(types.MergePatchType, raw))
	}
	return err
}

// setVMOwner records the owner of pod before b claims it, so the VM's
// token is restricted from the moment it acts for b.
func setVMOwner(ctx context.Context, c client.Client, p *corev1.Pod, b *v1.Blip) error {
	owner := ownerEntry(b)
	patch := map[string]*string{p.Name: &owner}
	if sa := podServiceAccount(p); sa != "" {
		var pools v1.BlipPoolList
		if err := c.List(ctx, &pools, client.InNamespace(p.Namespace)); err != nil {
			return err
		}
		names := poolsByServiceAccount(pools.Items)[ownersSAPrefix+sa]
		patch[ownersSAPrefix+sa] = &names
	}
	return patchVMOwners(ctx, c, p.Namespace, patch)
}

// restoreVMOwner corrects the entry of a pod after a failed claim: the pod
// may be gone or claimed by another Blip.
func restoreVMOwner(ctx context.Context, c client.Client, live client.Reader, ns, name string) error {
	var owner *string
	p := &corev1.Pod{}
	err := live.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, p)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if err == nil && !isVacant(p) {
		b := &v1.Blip{}
		err := live.Get(ctx, types.NamespacedName{Namespace: ns, Name: p.Annotations[v1.AnnotationBlip]}, b)
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if err == nil && string(b.UID) == p.Labels[v1.LabelBlipUID] {
			o := ownerEntry(b)
			owner = &o
		}
	}
	return patchVMOwners(ctx, c, ns, map[string]*string{name: owner})
}

// syncVMOwners reconciles the table of ns with the cluster: every pool and
// VM pod service account is listed with its pools, claimed pods carry their Blip's owner,
// and entries of deleted pods are removed. A namespace with a pool always
// has the table, empty if no pool names a service account. Vacant pods keep
// any entry: the cache may not show a claim yet, and the claim path
// overwrites the entry before the next claim.
func syncVMOwners(ctx context.Context, c client.Client, ns string) error {
	var pools v1.BlipPoolList
	if err := c.List(ctx, &pools, client.InNamespace(ns)); err != nil {
		return err
	}
	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.InNamespace(ns), client.HasLabels{v1.LabelPool}); err != nil {
		return err
	}
	var blips v1.BlipList
	if err := c.List(ctx, &blips, client.InNamespace(ns)); err != nil {
		return err
	}
	byUID := map[string]*v1.Blip{}
	for i := range blips.Items {
		byUID[string(blips.Items[i].UID)] = &blips.Items[i]
	}

	want := poolsByServiceAccount(pools.Items)
	var states v1.BlipStateList
	if err := c.List(ctx, &states, client.InNamespace(ns)); err != nil {
		return err
	}
	var bases []string
	for i := range states.Items {
		s := &states.Items[i]
		if s.Spec.Image != "" && s.Labels[v1.LabelOwner] == "" && s.DeletionTimestamp == nil {
			bases = append(bases, s.Name)
		}
	}
	if len(bases) > 0 {
		slices.Sort(bases)
		want[ownersBasesKey] = strings.Join(bases, " ")
	}
	exists := map[string]bool{}
	for i := range pods.Items {
		p := &pods.Items[i]
		exists[p.Name] = true
		if sa := podServiceAccount(p); sa != "" {
			if _, ok := want[ownersSAPrefix+sa]; !ok {
				want[ownersSAPrefix+sa] = ""
			}
		}
		if b := byUID[p.Labels[v1.LabelBlipUID]]; !isVacant(p) && b != nil && b.Name == p.Annotations[v1.AnnotationBlip] {
			want[p.Name] = ownerEntry(b)
		}
	}

	cm := &corev1.ConfigMap{}
	err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: VMOwnersConfigMap}, cm)
	if apierrors.IsNotFound(err) && len(pools.Items) > 0 {
		// The blip-write policy binding denies every change when its
		// params are missing, so a namespace with a pool always has a
		// table, even when no pool names a service account and the table
		// is empty.
		err = c.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: VMOwnersConfigMap}})
		if apierrors.IsAlreadyExists(err) {
			// Another writer created it; read it so stale keys are pruned.
			err = c.Get(ctx, types.NamespacedName{Namespace: ns, Name: VMOwnersConfigMap}, cm)
		}
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	patch := map[string]*string{}
	for k, v := range want {
		if old, ok := cm.Data[k]; !ok || old != v {
			patch[k] = &v
		}
	}
	// A service account key is removed only once no pool and no VM pod
	// uses it; pod-bound tokens die with their pod, so no VM token is left
	// unrestricted.
	for k := range cm.Data {
		if _, ok := want[k]; !ok && (strings.HasPrefix(k, ownersSAPrefix) || !exists[k]) {
			patch[k] = nil
		}
	}
	return patchVMOwners(ctx, c, ns, patch)
}
