package network

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"

	v1alpha1 "github.com/Azure/blip/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metavalidation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Compile resolves selectors without API calls. The pool is always a layer,
// including when nil (deny all); a non-nil Blip policy adds a narrowing layer.
// The returned revision depends only on canonical compiled rules, not object
// ordering or resource versions. Invalid input returns an empty, denying policy.
func Compile(namespace string, pool, blip *v1alpha1.NetworkPolicy, destinations Destinations) (Policy, error) {
	c := compiler{namespace: namespace, destinations: destinations,
		namespaceLabels: make(map[string]labels.Set), serviceSlices: make(map[string][]discoveryv1.EndpointSlice)}
	for _, ns := range destinations.Namespaces {
		c.namespaceLabels[ns.Name] = labels.Set(ns.Labels)
	}
	for _, es := range destinations.EndpointSlices {
		key := es.Namespace + "/" + es.Labels[discoveryv1.LabelServiceName]
		c.serviceSlices[key] = append(c.serviceSlices[key], es)
	}
	poolRules, err := c.layer(pool)
	if err != nil {
		return Policy{}, fmt.Errorf("pool network: %w", err)
	}
	policy := Policy{Layers: [][]Rule{poolRules}}
	if blip != nil {
		blipRules, err := c.layer(blip)
		if err != nil {
			return Policy{}, fmt.Errorf("blip network: %w", err)
		}
		policy.Layers = append(policy.Layers, blipRules)
	}
	data, err := json.Marshal(policy.Layers)
	if err != nil {
		return Policy{}, fmt.Errorf("encode network policy: %w", err)
	}
	digest := sha256.Sum256(data)
	policy.Revision = hex.EncodeToString(digest[:])
	return policy, nil
}

type compiler struct {
	namespace       string
	destinations    Destinations
	namespaceLabels map[string]labels.Set
	serviceSlices   map[string][]discoveryv1.EndpointSlice
}

func (c *compiler) layer(policy *v1alpha1.NetworkPolicy) ([]Rule, error) {
	rules := []Rule{}
	if policy == nil {
		return rules, nil
	}
	for i, egress := range policy.Egress {
		ports, err := compilePorts(egress.Ports)
		if err != nil {
			return nil, fmt.Errorf("egress[%d]: %w", i, err)
		}
		peers := []Rule{}
		if len(egress.To) == 0 {
			peers = append(peers, Rule{CIDR: "0.0.0.0/0"})
		}
		for j, peer := range egress.To {
			resolved, err := c.peer(peer)
			if err != nil {
				return nil, fmt.Errorf("egress[%d].to[%d]: %w", i, j, err)
			}
			peers = append(peers, resolved...)
		}
		for _, peer := range peers {
			for _, port := range ports {
				rule := peer
				rule.Protocol, rule.Port, rule.EndPort = port.Protocol, port.Port, port.EndPort
				rules = append(rules, rule)
			}
		}
	}
	// JSON is also the wire representation; using it as a key keeps ordering and
	// deduplication consistent for exceptions, protocols, ports, and ranges.
	byKey := make(map[string]Rule, len(rules))
	keys := make([]string, 0, len(rules))
	for _, rule := range rules {
		data, _ := json.Marshal(rule)
		key := string(data)
		if _, ok := byKey[key]; !ok {
			byKey[key] = rule
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	rules = make([]Rule, 0, len(keys))
	for _, key := range keys {
		rules = append(rules, byKey[key])
	}
	return rules, nil
}

func compilePorts(ports []v1alpha1.NetworkPort) ([]Rule, error) {
	if len(ports) == 0 {
		return []Rule{{}}, nil
	}
	rules := make([]Rule, 0, len(ports))
	for i, port := range ports {
		protocol := port.Protocol
		if protocol == "" {
			protocol = corev1.ProtocolTCP
		}
		if protocol != corev1.ProtocolTCP && protocol != corev1.ProtocolUDP {
			return nil, fmt.Errorf("ports[%d]: protocol must be TCP or UDP", i)
		}
		if port.Port < 1 || port.Port > 65535 {
			return nil, fmt.Errorf("ports[%d]: port must be between 1 and 65535", i)
		}
		rule := Rule{Protocol: string(protocol), Port: port.Port}
		if port.EndPort != nil {
			if *port.EndPort < port.Port || *port.EndPort > 65535 {
				return nil, fmt.Errorf("ports[%d]: endPort must be between port and 65535", i)
			}
			if *port.EndPort != port.Port {
				rule.EndPort = *port.EndPort
			}
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (c *compiler) peer(peer v1alpha1.NetworkPeer) ([]Rule, error) {
	hasSelectors := peer.PodSelector != nil || peer.NamespaceSelector != nil || peer.ServiceSelector != nil
	if peer.IPBlock != nil {
		if hasSelectors {
			return nil, fmt.Errorf("ipBlock cannot be combined with selectors")
		}
		prefix, err := ipv4Prefix(peer.IPBlock.CIDR)
		if err != nil {
			return nil, err
		}
		rule := Rule{CIDR: prefix.String()}
		for _, except := range peer.IPBlock.Except {
			excluded, err := ipv4Prefix(except)
			if err != nil {
				return nil, err
			}
			if excluded.Bits() <= prefix.Bits() || !prefix.Contains(excluded.Addr()) {
				return nil, fmt.Errorf("exception %q must be strictly inside %q", except, peer.IPBlock.CIDR)
			}
			rule.Except = append(rule.Except, excluded.String())
		}
		slices.Sort(rule.Except)
		rule.Except = slices.Compact(rule.Except)
		return []Rule{rule}, nil
	}
	if !hasSelectors {
		return nil, fmt.Errorf("peer must select an IP block, pods, namespaces, or services")
	}
	if peer.PodSelector != nil && peer.ServiceSelector != nil {
		return nil, fmt.Errorf("podSelector and serviceSelector cannot be combined")
	}
	namespaces, err := selector(peer.NamespaceSelector)
	if err != nil {
		return nil, fmt.Errorf("namespaceSelector: %w", err)
	}
	inNamespace := func(namespace string) bool {
		if peer.NamespaceSelector == nil {
			return namespace == c.namespace
		}
		nsLabels, exists := c.namespaceLabels[namespace]
		return exists && namespaces.Matches(nsLabels)
	}
	if peer.ServiceSelector != nil {
		services, err := selector(peer.ServiceSelector)
		if err != nil {
			return nil, fmt.Errorf("serviceSelector: %w", err)
		}
		return c.services(services, inNamespace)
	}
	pods, err := selector(peer.PodSelector)
	if err != nil {
		return nil, fmt.Errorf("podSelector: %w", err)
	}
	var rules []Rule
	for _, pod := range c.destinations.Pods {
		// Finished and deleting pods can retain historical PodIPs after those
		// addresses are reassigned to unrelated, unselected pods.
		if pod.Spec.HostNetwork || pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		if !inNamespace(pod.Namespace) || !pods.Matches(labels.Set(pod.Labels)) {
			continue
		}
		ips := pod.Status.PodIPs
		if len(ips) == 0 && pod.Status.PodIP != "" {
			ips = []corev1.PodIP{{IP: pod.Status.PodIP}}
		}
		for _, ip := range ips {
			rules, err = appendAddress(rules, ip.IP)
			if err != nil {
				return nil, fmt.Errorf("pod %s/%s: %w", pod.Namespace, pod.Name, err)
			}
		}
	}
	return rules, nil
}

func (c *compiler) services(selected labels.Selector, inNamespace func(string) bool) ([]Rule, error) {
	var rules []Rule
	for _, service := range c.destinations.Services {
		if !inNamespace(service.Namespace) || !selected.Matches(labels.Set(service.Labels)) || service.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		var addresses []string
		if service.Spec.ClusterIP == corev1.ClusterIPNone {
			for _, es := range c.serviceSlices[service.Namespace+"/"+service.Name] {
				if es.AddressType == discoveryv1.AddressTypeIPv4 {
					for _, endpoint := range es.Endpoints {
						addresses = append(addresses, endpoint.Addresses...)
					}
				}
			}
		} else {
			addresses = service.Spec.ClusterIPs
			if len(addresses) == 0 && service.Spec.ClusterIP != "" {
				addresses = []string{service.Spec.ClusterIP}
			}
		}
		for _, address := range addresses {
			var err error
			rules, err = appendAddress(rules, address)
			if err != nil {
				return nil, fmt.Errorf("service %s/%s: %w", service.Namespace, service.Name, err)
			}
		}
	}
	return rules, nil
}

func selector(value *metav1.LabelSelector) (labels.Selector, error) {
	if value == nil {
		return labels.Everything(), nil
	}
	if errs := metavalidation.ValidateLabelSelector(value, metavalidation.LabelSelectorValidationOptions{}, field.NewPath("selector")); len(errs) != 0 {
		return nil, errs.ToAggregate()
	}
	return metav1.LabelSelectorAsSelector(value)
}

func ipv4Prefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%q is not a valid IPv4 CIDR", value)
	}
	return prefix.Masked(), nil
}

func appendAddress(rules []Rule, value string) ([]Rule, error) {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return nil, fmt.Errorf("%q is not a valid IP address", value)
	}
	if ip.Is4() {
		rules = append(rules, Rule{CIDR: netip.PrefixFrom(ip, 32).String()})
	}
	return rules, nil
}
