// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/network"
	"github.com/Azure/blip/internal/podapi"
)

// denyNetwork uses the compiler's canonical revision for default deny, so
// unchanged warm pods and failed policies do not rewrite desired.json.
func denyNetwork() *network.Policy {
	policy, _ := network.Compile(nil, nil, nil)
	return &policy
}

// podNameservers returns the resolvers the controller wrote into the VM pod.
// Reading the pod rather than the live BlipPool keeps claimed VMs consistent
// with the resolv.conf they booted with.
func podNameservers(pod *corev1.Pod) []string {
	for _, c := range pod.Spec.Containers {
		if c.Name != podapi.VMContainer {
			continue
		}
		for _, e := range c.Env {
			if e.Name != podapi.NameserversEnv {
				continue
			}
			var nameservers []string
			for _, value := range strings.Split(e.Value, ",") {
				if value = strings.TrimSpace(value); value != "" {
					nameservers = append(nameservers, value)
				}
			}
			return nameservers
		}
	}
	return nil
}

// networkFor always returns a policy, including on failure. Retaining an old
// grant when a pool disappears or a policy becomes invalid would fail open.
// A pool that omits spec.network denies all egress.
func (v *view) networkFor(pod *corev1.Pod, b *v1alpha1.Blip) (*network.Policy, error) {
	name := b.Spec.Pool
	if name == "" {
		name = "default"
	}
	if pod.Labels[v1alpha1.LabelPool] != name {
		return denyNetwork(), fmt.Errorf("pod pool %q does not match Blip pool %q", pod.Labels[v1alpha1.LabelPool], name)
	}
	pool := v.pools[b.Namespace+"/"+name]
	if pool == nil {
		return denyNetwork(), fmt.Errorf("BlipPool %s/%s not found", b.Namespace, name)
	}
	policySpec := b.Spec.Network
	// The second layer is labelled by the object an operator must edit. A
	// Blip without its own spec.network inherits the root state's policy, so
	// a compile failure there is not a Blip network error.
	blipLayer := "blip network"
	if policySpec == nil {
		root := v.stateByName[b.Namespace+"/"+b.Spec.State]
		if root == nil {
			return denyNetwork(), fmt.Errorf("root BlipState %s/%s not found", b.Namespace, b.Spec.State)
		}
		if root.Spec.Runtime != nil {
			policySpec = root.Spec.Runtime.Network
			if policySpec != nil {
				blipLayer = "state network"
			}
		}
	}
	policy, err := network.CompileNamed(pool.Spec.Network, policySpec, podNameservers(pod), blipLayer)
	if err != nil {
		return denyNetwork(), err
	}
	return &policy, nil
}
