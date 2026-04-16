package vm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"math/rand"
	"slices"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	kubevirtv1 "kubevirt.io/api/core/v1"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ErrQuotaExceeded is returned when a user has reached their per-user blip limit.
var ErrQuotaExceeded = fmt.Errorf("per-user blip quota exceeded")

var (
	errNoVMsAvailable      = errors.New("no unclaimed ready blips available")
	errAllocationFailed    = errors.New("failed to claim a blip after retries")
	errSessionNotFound     = errors.New("blip does not exist")
	errSessionAuthMismatch = errors.New("auth fingerprint does not match the session owner")
	errSessionVMNotReady   = errors.New("blip for session is not ready")
)

const (
	indexVMPool      = ".metadata.labels.blip.io/pool"
	indexVMSessionID = ".metadata.annotations.blip.io/session-id"
	indexVMUser      = ".metadata.annotations.blip.io/user"
)

type ClaimResult struct {
	Name     string
	PodIP    string
	NodeName string
}

// Client provides access to KubeVirt VirtualMachine resources for the SSH gateway.
type Client struct {
	cache     crcache.Cache
	writer    client.Client
	namespace string
}

// Writer returns the underlying Kubernetes client used for write operations.
// This allows other components (e.g. the ghactions VMAnnotator) to reuse the
// same client rather than creating a separate one.
func (c *Client) Writer() client.Client { return c.writer }

// Cache returns the underlying informer cache. This allows other components
// to watch additional resource types (e.g. Secrets) without creating a
// separate cache.
func (c *Client) Cache() crcache.Cache { return c.cache }

// New creates a Client backed by an in-cluster informer cache scoped to the given namespace.
func New(ctx context.Context, namespace string) (*Client, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	s, err := newScheme()
	if err != nil {
		return nil, err
	}
	mapper := newStaticRESTMapper()

	writer, err := client.New(cfg, client.Options{Scheme: s, Mapper: mapper})
	if err != nil {
		return nil, fmt.Errorf("controller-runtime client: %w", err)
	}

	informerCache, err := crcache.New(cfg, crcache.Options{
		Scheme: s,
		Mapper: mapper,
		DefaultNamespaces: map[string]crcache.Config{
			namespace: {},
		},
		DefaultTransform: crcache.TransformStripManagedFields(),
	})
	if err != nil {
		return nil, fmt.Errorf("create informer cache: %w", err)
	}

	if err := informerCache.IndexField(ctx, &kubevirtv1.VirtualMachine{}, indexVMPool, func(obj client.Object) []string {
		pool := obj.GetLabels()["blip.io/pool"]
		if pool == "" {
			return nil
		}
		return []string{pool}
	}); err != nil {
		return nil, fmt.Errorf("index VMs by pool: %w", err)
	}

	if err := informerCache.IndexField(ctx, &kubevirtv1.VirtualMachine{}, indexVMSessionID, func(obj client.Object) []string {
		sid := obj.GetAnnotations()["blip.io/session-id"]
		if sid == "" {
			return nil
		}
		return []string{sid}
	}); err != nil {
		return nil, fmt.Errorf("index VMs by session-id: %w", err)
	}

	if err := informerCache.IndexField(ctx, &kubevirtv1.VirtualMachine{}, indexVMUser, func(obj client.Object) []string {
		user := obj.GetAnnotations()["blip.io/user"]
		if user == "" {
			return nil
		}
		if obj.GetAnnotations()["blip.io/session-id"] == "" {
			return nil
		}
		return []string{user}
	}); err != nil {
		return nil, fmt.Errorf("index VMs by user: %w", err)
	}

	go func() {
		if err := informerCache.Start(ctx); err != nil {
			slog.Error("informer cache stopped", "error", err)
		}
	}()

	if !informerCache.WaitForCacheSync(ctx) {
		return nil, fmt.Errorf("informer cache sync failed")
	}

	slog.Info("informer cache synced")

	return &Client{cache: informerCache, writer: writer, namespace: namespace}, nil
}

// Claim allocates an unclaimed, ready VM from the given pool for the session.
func (c *Client) Claim(ctx context.Context, poolName, sessionID, gatewayPodName string, maxDuration int, userIdentity string, maxBlips int) (*ClaimResult, error) {
	if userIdentity != "" && maxBlips > 0 {
		count, err := c.countActiveBlips(ctx, userIdentity)
		if err != nil {
			return nil, fmt.Errorf("check user quota: %w", err)
		}
		if count >= maxBlips {
			slog.Warn("user quota exceeded",
				"user", userIdentity,
				"active_blips", count,
				"limit", maxBlips,
			)
			return nil, fmt.Errorf("%w: %d/%d blips in use", ErrQuotaExceeded, count, maxBlips)
		}
	}

	for range 10 { // bounded retries
		allocs, err := c.listAllocations(ctx, poolName)
		if err != nil {
			return nil, fmt.Errorf("list VMs: %w", err)
		}

		var candidates []allocation
		for _, a := range allocs {
			if _, claimed := a.Annotations["blip.io/session-id"]; claimed {
				continue
			}
			if a.Annotations["blip.io/host-key"] == "" {
				continue
			}
			if a.Annotations["blip.io/client-key"] == "" {
				continue
			}
			inst, err := c.getInstance(ctx, a.Name)
			if err != nil || !inst.Ready {
				continue
			}
			candidates = append(candidates, a)
		}

		if len(candidates) == 0 {
			return nil, errNoVMsAvailable
		}

		slices.SortFunc(candidates, func(a, b allocation) int {
			return a.raw.GetCreationTimestamp().Time.Compare(b.raw.GetCreationTimestamp().Time)
		})
		chosen := candidates[weightedOldestIndex(len(candidates))]
		setClaimAnnotations(&chosen, sessionID, gatewayPodName, maxDuration, userIdentity)

		err = c.updateAllocation(ctx, &chosen)
		if k8serrors.IsConflict(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("update VM: %w", err)
		}

		inst, err := c.getInstance(ctx, chosen.Name)
		if err != nil {
			return nil, fmt.Errorf("get VMI after claim: %w", err)
		}

		return &ClaimResult{
			Name:     chosen.Name,
			PodIP:    inst.PodIP,
			NodeName: inst.NodeName,
		}, nil
	}

	return nil, errAllocationFailed
}

// Reconnect verifies the auth fingerprint and returns connection details for a previously claimed VM.
func (c *Client) Reconnect(ctx context.Context, sessionID, authFingerprint, gatewayPodName string, maxDuration int) (*ClaimResult, error) {
	allocs, err := c.listAllocationsBySession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("list VMs: %w", err)
	}

	for _, a := range allocs {
		storedFingerprint := a.Annotations["blip.io/auth-fingerprint"]
		if storedFingerprint == "" || storedFingerprint != authFingerprint {
			return nil, errSessionAuthMismatch
		}

		inst, err := c.getInstance(ctx, a.Name)
		if err != nil {
			return nil, fmt.Errorf("get VMI for reconnect: %w", err)
		}
		if !inst.Ready {
			return nil, errSessionVMNotReady
		}

		a.Annotations["blip.io/claimed-by"] = gatewayPodName
		if err := c.updateAllocation(ctx, &a); err != nil {
			return nil, fmt.Errorf("update VM on reconnect: %w", err)
		}

		return &ClaimResult{
			Name:     a.Name,
			PodIP:    inst.PodIP,
			NodeName: inst.NodeName,
		}, nil
	}

	return nil, errSessionNotFound
}

// StoreAuthFingerprint records the auth fingerprint on the VM for reconnect verification.
func (c *Client) StoreAuthFingerprint(ctx context.Context, sessionID, fingerprint string) error {
	allocs, err := c.listAllocationsBySessionDirect(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("list VMs: %w", err)
	}
	for _, a := range allocs {
		a.Annotations["blip.io/auth-fingerprint"] = fingerprint
		return c.updateAllocation(ctx, &a)
	}
	return fmt.Errorf("blip with session ID %s not found", sessionID)
}

// GetHostKey reads the host-key annotation from the VM via a direct API call.
func (c *Client) GetHostKey(ctx context.Context, vmName string) (string, error) {
	var vm kubevirtv1.VirtualMachine
	if err := c.writer.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: vmName}, &vm); err != nil {
		return "", fmt.Errorf("get VM %s: %w", vmName, err)
	}
	key := vm.Annotations["blip.io/host-key"]
	if key == "" {
		return "", fmt.Errorf("blip %s has no blip.io/host-key annotation", vmName)
	}
	return key, nil
}

// ResolveRootIdentity returns the root user identity and auth fingerprint for
// a VM identified by SSH client key fingerprint (e.g. "SHA256:..."). It
// iterates claimed VMs and parses each blip.io/client-key annotation to find a
// match. The returned auth fingerprint is the original user's SSH key
// fingerprint stored in blip.io/auth-fingerprint, enabling nested blips to be
// retained and reconnected to directly by the original user.
func (c *Client) ResolveRootIdentity(ctx context.Context, fingerprint string) (string, string, error) {
	var list kubevirtv1.VirtualMachineList
	if err := c.cache.List(ctx, &list,
		client.InNamespace(c.namespace),
	); err != nil {
		return "", "", fmt.Errorf("list VMs for client-key lookup: %w", err)
	}

	for _, vm := range list.Items {
		ann := vm.Annotations
		clientKeyRaw := ann["blip.io/client-key"]
		if clientKeyRaw == "" {
			continue
		}
		// Only search claimed VMs (those with a session).
		if ann["blip.io/session-id"] == "" {
			continue
		}

		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(clientKeyRaw))
		if err != nil {
			continue
		}
		if ssh.FingerprintSHA256(pub) == fingerprint {
			user := ann["blip.io/user"]
			if user == "" {
				return "", "", fmt.Errorf("blip %s has no blip.io/user annotation", vm.Name)
			}
			authFP := ann["blip.io/auth-fingerprint"]
			return user, authFP, nil
		}
	}
	return "", "", fmt.Errorf("no blip found with client-key fingerprint %s", fingerprint)
}

// MaxLifespan is the absolute maximum lifespan for a blip from its original claim time.
const MaxLifespan = 12 * time.Hour

// ReleaseVM marks the VM for immediate deallocation by setting the release annotation.
func (c *Client) ReleaseVM(ctx context.Context, sessionID string) error {
	allocs, err := c.listAllocationsBySession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("list VMs: %w", err)
	}
	for _, a := range allocs {
		a.Annotations["blip.io/release"] = "true"
		if err := c.updateAllocation(ctx, &a); err != nil {
			return fmt.Errorf("release VM %s: %w", a.Name, err)
		}
		return nil
	}
	return fmt.Errorf("blip with session ID %s not found", sessionID)
}

// IsEphemeral reports whether the VM for sessionID is marked as ephemeral.
func (c *Client) IsEphemeral(ctx context.Context, sessionID string) (bool, error) {
	allocs, err := c.listAllocationsBySession(ctx, sessionID)
	if err != nil {
		return false, fmt.Errorf("list VMs: %w", err)
	}
	for _, a := range allocs {
		return a.Annotations["blip.io/ephemeral"] == "true", nil
	}
	return false, fmt.Errorf("blip with session ID %s not found", sessionID)
}

// SessionStatus describes the current lifecycle state of a session's VM.
type SessionStatus struct {
	Ephemeral    bool
	RemainingTTL time.Duration
}

// GetSessionStatus returns the ephemeral flag and remaining TTL for the given session.
func (c *Client) GetSessionStatus(ctx context.Context, sessionID string) (SessionStatus, error) {
	allocs, err := c.listAllocationsBySession(ctx, sessionID)
	if err != nil {
		return SessionStatus{}, fmt.Errorf("list VMs: %w", err)
	}
	for _, a := range allocs {
		ephemeral := a.Annotations["blip.io/ephemeral"] == "true"

		var remaining time.Duration
		claimedAtStr := a.Annotations["blip.io/claimed-at"]
		maxDurStr := a.Annotations["blip.io/max-duration"]
		if claimedAtStr != "" && maxDurStr != "" {
			if claimedAt, err := time.Parse(time.RFC3339, claimedAtStr); err == nil {
				if maxDurSec, err := strconv.Atoi(maxDurStr); err == nil && maxDurSec > 0 {
					remaining = time.Until(claimedAt.Add(time.Duration(maxDurSec) * time.Second))
					if remaining < 0 {
						remaining = 0
					}
				}
			}
		}

		return SessionStatus{Ephemeral: ephemeral, RemainingTTL: remaining}, nil
	}
	return SessionStatus{}, fmt.Errorf("blip with session ID %s not found", sessionID)
}

// Retain marks the VM as non-ephemeral, optionally updating TTL (capped by MaxLifespan).
func (c *Client) Retain(ctx context.Context, sessionID string, newTTLSeconds int) (string, error) {
	allocs, err := c.listAllocationsBySession(ctx, sessionID)
	if err != nil {
		return "", fmt.Errorf("list VMs: %w", err)
	}
	for _, a := range allocs {
		a.Annotations["blip.io/ephemeral"] = "false"

		if newTTLSeconds > 0 {
			claimedAtStr, ok := a.Annotations["blip.io/claimed-at"]
			if !ok {
				return "", fmt.Errorf("blip %s missing claimed-at annotation", a.Name)
			}
			claimedAt, err := time.Parse(time.RFC3339, claimedAtStr)
			if err != nil {
				return "", fmt.Errorf("parse claimed-at: %w", err)
			}

			// Cap the new TTL so that claimed-at + total does not exceed MaxLifespan.
			maxAllowedSeconds := int(MaxLifespan.Seconds())
			elapsed := int(time.Since(claimedAt).Seconds())
			remainingBudget := maxAllowedSeconds - elapsed
			if remainingBudget < 0 {
				remainingBudget = 0
			}
			if newTTLSeconds > remainingBudget {
				newTTLSeconds = remainingBudget
			}

			// Store as total seconds from claimed-at (not from now) so that
			// GetSessionStatus can compute remaining TTL correctly:
			//   remaining = claimed-at + max-duration - now
			a.Annotations["blip.io/max-duration"] = strconv.Itoa(elapsed + newTTLSeconds)
		}

		if err := c.updateAllocation(ctx, &a); err != nil {
			return "", fmt.Errorf("retain VM %s: %w", a.Name, err)
		}
		return a.Annotations["blip.io/session-id"], nil
	}
	return "", fmt.Errorf("blip with session ID %s not found", sessionID)
}

// GetSessionIDByVMName returns the session ID annotation for the named VM,
// or "" if the VM is not claimed.
func (c *Client) GetSessionIDByVMName(ctx context.Context, vmName string) string {
	var vm kubevirtv1.VirtualMachine
	if err := c.cache.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: vmName}, &vm); err != nil {
		return ""
	}
	return vm.Annotations["blip.io/session-id"]
}

// RegisterKeys sets the host-key and client-key annotations on the named VM.
// This is the readiness signal: once set, the gateway considers the VM
// eligible for allocation. Registration is one-shot: if keys are already
// set, the call is rejected to prevent session hijacking.
func (c *Client) RegisterKeys(ctx context.Context, vmName, hostKey, clientKey string) error {
	var vm kubevirtv1.VirtualMachine
	if err := c.writer.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: vmName}, &vm); err != nil {
		return fmt.Errorf("get VM %s: %w", vmName, err)
	}
	if vm.Annotations == nil {
		vm.Annotations = make(map[string]string)
	}
	// Reject if keys are already registered to prevent re-registration attacks.
	if vm.Annotations["blip.io/host-key"] != "" || vm.Annotations["blip.io/client-key"] != "" {
		return fmt.Errorf("keys already registered for VM %s", vmName)
	}
	vm.Annotations["blip.io/host-key"] = hostKey
	vm.Annotations["blip.io/client-key"] = clientKey
	return c.writer.Update(ctx, &vm)
}

// ResolveVMNameByIP looks up the VM name for the given pod IP address by
// searching VirtualMachineInstances. Falls back to a direct API call if the
// informer cache doesn't have a match (handles the race where a VMI boots
// before the cache has synced its entry). Returns "" if no match is found.
func (c *Client) ResolveVMNameByIP(ctx context.Context, podIP string) string {
	// Try the informer cache first (fast path).
	if name := c.resolveVMNameByIPFromCache(ctx, podIP); name != "" {
		return name
	}

	// Fallback: direct API call to handle informer cache lag at VM boot.
	var list kubevirtv1.VirtualMachineInstanceList
	if err := c.writer.List(ctx, &list, client.InNamespace(c.namespace)); err != nil {
		slog.Debug("ResolveVMNameByIP direct API fallback failed", "error", err)
		return ""
	}
	for _, vmi := range list.Items {
		for _, iface := range vmi.Status.Interfaces {
			if iface.IP == podIP {
				return vmi.Name
			}
		}
	}
	return ""
}

func (c *Client) resolveVMNameByIPFromCache(ctx context.Context, podIP string) string {
	var list kubevirtv1.VirtualMachineInstanceList
	if err := c.cache.List(ctx, &list, client.InNamespace(c.namespace)); err != nil {
		return ""
	}
	for _, vmi := range list.Items {
		for _, iface := range vmi.Status.Interfaces {
			if iface.IP == podIP {
				return vmi.Name
			}
		}
	}
	return ""
}

// GetNodeLabel returns the value of the given label on the named node.
func (c *Client) GetNodeLabel(ctx context.Context, nodeName, label string) string {
	if nodeName == "" {
		return ""
	}
	var node corev1.Node
	if err := c.cache.Get(ctx, client.ObjectKey{Name: nodeName}, &node); err != nil {
		return ""
	}
	return node.Labels[label]
}

type allocation struct {
	Name            string
	ResourceVersion string
	Labels          map[string]string
	Annotations     map[string]string
	raw             client.Object
}

type allocationInstance struct {
	Name     string
	PodIP    string
	NodeName string
	Ready    bool
}

func (c *Client) listVMs(ctx context.Context, matchingFields client.MatchingFields) ([]allocation, error) {
	var list kubevirtv1.VirtualMachineList
	if err := c.cache.List(ctx, &list,
		client.InNamespace(c.namespace),
		matchingFields,
	); err != nil {
		return nil, fmt.Errorf("list VMs: %w", err)
	}
	allocs := make([]allocation, 0, len(list.Items))
	for i := range list.Items {
		allocs = append(allocs, allocationFromObject(&list.Items[i]))
	}
	return allocs, nil
}

func (c *Client) listAllocations(ctx context.Context, poolName string) ([]allocation, error) {
	return c.listVMs(ctx, client.MatchingFields{indexVMPool: poolName})
}

func (c *Client) listAllocationsBySession(ctx context.Context, sessionID string) ([]allocation, error) {
	return c.listVMs(ctx, client.MatchingFields{indexVMSessionID: sessionID})
}

// listAllocationsBySessionDirect fetches VMs via a direct API call, bypassing the informer cache.
func (c *Client) listAllocationsBySessionDirect(ctx context.Context, sessionID string) ([]allocation, error) {
	var list kubevirtv1.VirtualMachineList
	if err := c.writer.List(ctx, &list, client.InNamespace(c.namespace)); err != nil {
		return nil, fmt.Errorf("list VMs (direct): %w", err)
	}
	var allocs []allocation
	for i := range list.Items {
		if list.Items[i].Annotations["blip.io/session-id"] == sessionID {
			allocs = append(allocs, allocationFromObject(&list.Items[i]))
		}
	}
	return allocs, nil
}

func (c *Client) getInstance(ctx context.Context, name string) (*allocationInstance, error) {
	key := client.ObjectKey{Namespace: c.namespace, Name: name}
	var vmi kubevirtv1.VirtualMachineInstance
	if err := c.cache.Get(ctx, key, &vmi); err != nil {
		return nil, fmt.Errorf("get instance %s: %w", name, err)
	}
	return vmiInstance(&vmi)
}

func (c *Client) updateAllocation(ctx context.Context, a *allocation) error {
	a.raw.SetAnnotations(a.Annotations)
	return c.writer.Update(ctx, a.raw)
}

func (c *Client) countActiveBlips(ctx context.Context, userIdentity string) (int, error) {
	var list kubevirtv1.VirtualMachineList
	if err := c.cache.List(ctx, &list,
		client.InNamespace(c.namespace),
		client.MatchingFields{indexVMUser: userIdentity},
	); err != nil {
		return 0, fmt.Errorf("list VMs by user: %w", err)
	}
	return len(list.Items), nil
}

// weightedOldestIndex returns a random index biased toward older (lower-index) candidates.
func weightedOldestIndex(n int) int {
	const lambda = 3.0
	u := rand.Float64()
	idx := int(math.Floor(-math.Log1p(-u*(1-math.Exp(-lambda))) / lambda * float64(n)))
	return min(idx, n-1)
}

func setClaimAnnotations(a *allocation, sessionID, gatewayPodName string, maxDuration int, userIdentity string) {
	if a.Annotations == nil {
		a.Annotations = make(map[string]string)
	}
	a.Annotations["blip.io/session-id"] = sessionID
	a.Annotations["blip.io/claimed-at"] = time.Now().Format(time.RFC3339)
	a.Annotations["blip.io/claimed-by"] = gatewayPodName
	a.Annotations["blip.io/max-duration"] = strconv.Itoa(maxDuration)
	a.Annotations["blip.io/ephemeral"] = "true"
	if userIdentity != "" {
		a.Annotations["blip.io/user"] = userIdentity
	}
}

func allocationFromObject(obj client.Object) allocation {
	return allocation{
		Name:            obj.GetName(),
		ResourceVersion: obj.GetResourceVersion(),
		Labels:          obj.GetLabels(),
		Annotations:     maps.Clone(obj.GetAnnotations()),
		raw:             obj,
	}
}

func vmiInstance(vmi *kubevirtv1.VirtualMachineInstance) (*allocationInstance, error) {
	inst := &allocationInstance{Name: vmi.Name, NodeName: vmi.Status.NodeName}

	for _, cond := range vmi.Status.Conditions {
		if cond.Type == kubevirtv1.VirtualMachineInstanceReady && cond.Status == corev1.ConditionTrue {
			inst.Ready = true
			break
		}
	}

	if len(vmi.Status.Interfaces) > 0 {
		inst.PodIP = vmi.Status.Interfaces[0].IP
	}

	if inst.PodIP == "" {
		return nil, fmt.Errorf("blip %s has no IP address in status.interfaces", inst.Name)
	}
	return inst, nil
}

func newScheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("register core/v1: %w", err)
	}
	if err := kubevirtv1.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("register kubevirt/v1: %w", err)
	}
	return s, nil
}

func newStaticRESTMapper() meta.RESTMapper {
	return restmapper.NewDiscoveryRESTMapper([]*restmapper.APIGroupResources{
		{
			Group: metav1.APIGroup{
				Name: "",
				Versions: []metav1.GroupVersionForDiscovery{
					{GroupVersion: "v1", Version: "v1"},
				},
			},
			VersionedResources: map[string][]metav1.APIResource{
				"v1": {
					{Name: "pods", Namespaced: true, Kind: "Pod"},
					{Name: "nodes", Namespaced: false, Kind: "Node"},
				},
			},
		},
		{
			Group: metav1.APIGroup{
				Name: kubevirtv1.VirtualMachineGroupVersionKind.Group,
				Versions: []metav1.GroupVersionForDiscovery{
					{GroupVersion: kubevirtv1.SchemeGroupVersion.String(), Version: kubevirtv1.SchemeGroupVersion.Version},
				},
			},
			VersionedResources: map[string][]metav1.APIResource{
				kubevirtv1.SchemeGroupVersion.Version: {
					{Name: "virtualmachines", Namespaced: true, Kind: "VirtualMachine", Group: kubevirtv1.SchemeGroupVersion.Group, Version: kubevirtv1.SchemeGroupVersion.Version},
					{Name: "virtualmachineinstances", Namespaced: true, Kind: "VirtualMachineInstance", Group: kubevirtv1.SchemeGroupVersion.Group, Version: kubevirtv1.SchemeGroupVersion.Version},
				},
			},
		},
	})
}
