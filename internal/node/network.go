// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package node

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/Azure/blip/api/v1alpha1"
	"github.com/Azure/blip/internal/network"
)

// denyNetwork uses the compiler's canonical revision for default deny, so
// unchanged warm pods and failed policies do not rewrite desired.json.
func denyNetwork() *network.Policy {
	policy, _ := network.Compile("", nil, nil, network.Destinations{})
	return &policy
}

// networkFor always returns a policy, including on failure. Retaining an old
// grant when a pool disappears or a policy becomes invalid would fail open.
// A pool that omits spec.network gets the default policy: public internet
// egress only, with LAN and other non-public ranges denied.
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
	poolPolicy := pool.Spec.Network
	if poolPolicy == nil {
		poolPolicy = network.Default()
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
	policy, err := network.CompileNamed(b.Namespace, poolPolicy, policySpec, v.destinations, blipLayer)
	if err != nil {
		return denyNetwork(), err
	}
	return &policy, nil
}
