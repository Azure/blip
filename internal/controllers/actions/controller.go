// Package actions implements a controller-runtime based GitHub Actions runner
// backend. It replaces the previous goroutine-based polling design with two
// stateless components that derive all state from Kubernetes VM annotations:
//
//  1. A periodic runnable that polls the GitHub API for queued workflow jobs
//     and allocates VMs as self-hosted runners. Already-allocated jobs are
//     detected by the existence of a VM with session-id "actions-<jobID>".
//
//  2. A reconciler on VirtualMachine resources that monitors active runner VMs
//     and releases them when the associated GitHub job completes.
//
// All state lives in VM annotations — no in-memory maps or long-running
// goroutines beyond the controller-runtime reconcile loop are required.
package actions

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ghactions "github.com/project-unbounded/blip/internal/gateway/actions"
)

const (
	// runnerMaxTTL is the maximum TTL for runner VMs (30 minutes).
	runnerMaxTTL = 1800

	// pollInterval is how often the job poller checks for queued jobs.
	pollInterval = 10 * time.Second

	// jobCheckInterval is how often the reconciler requeues to re-check
	// job completion status.
	jobCheckInterval = 15 * time.Second

	// runnerRepoAnnotation stores the repo (owner/repo) for a runner VM,
	// enabling the reconciler to check job status without external state.
	runnerRepoAnnotation = "blip.io/runner-repo"

	// runnerJobIDAnnotation stores the GitHub job ID for a runner VM.
	runnerJobIDAnnotation = "blip.io/runner-job-id"
)

// Config holds the configuration for the actions runner controller.
type Config struct {
	Namespace     string
	PoolName      string
	PodName       string
	PATSecretName string
	Repos         []string
	RunnerLabels  []string
}

// PATHolder is a thread-safe container for the PAT provider. It is populated
// by the actionsRunnable after the cache has synced, and read by the
// completion controller and runner config controller during reconciliation.
// It implements the Token() method so it can be passed directly to consumers
// that need a GitHub PAT.
type PATHolder struct {
	mu  sync.RWMutex
	pat *ghactions.PATProvider
}

func (h *PATHolder) set(p *ghactions.PATProvider) {
	h.mu.Lock()
	h.pat = p
	h.mu.Unlock()
}

func (h *PATHolder) get() *ghactions.PATProvider {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.pat
}

// Token returns the current GitHub PAT. Returns an error if the PAT
// provider has not been initialised yet or if the underlying Secret has
// no token.
func (h *PATHolder) Token() (string, error) {
	p := h.get()
	if p == nil {
		return "", fmt.Errorf("PAT provider not yet initialised")
	}
	return p.Token()
}

// Add registers the actions runner controller and job poller with the given
// controller-runtime manager. The PAT provider is created lazily when the
// manager starts (after the informer cache has synced).
func Add(mgr ctrl.Manager, cfg Config) (*PATHolder, error) {
	holder := &PATHolder{}

	// Register the completion controller (reconciles runner VMs).
	c := &completionController{
		Client: mgr.GetClient(),
		pat:    holder,
	}
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("actions-completion").
		For(&kubevirtv1.VirtualMachine{}).
		WithEventFilter(predicate.Or(
			predicate.AnnotationChangedPredicate{},
			predicate.GenerationChangedPredicate{},
		)).
		Complete(c); err != nil {
		return nil, fmt.Errorf("register actions-completion controller: %w", err)
	}

	// Register the combined runnable that initialises the PAT provider
	// (requires a synced cache) and then runs the periodic job poller.
	if err := mgr.Add(&actionsRunnable{
		mgr:    mgr,
		cfg:    cfg,
		holder: holder,
	}); err != nil {
		return nil, fmt.Errorf("register actions runnable: %w", err)
	}

	return holder, nil
}

// ---------------------------------------------------------------------------
// Completion controller — reconciles VMs with actions-* session IDs
// ---------------------------------------------------------------------------

// completionController reconciles VMs that are allocated as GitHub Actions
// runners. For each such VM, it checks the GitHub job status and releases the
// VM when the job completes.
type completionController struct {
	Client client.Client
	pat    *PATHolder
}

func (c *completionController) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var vm kubevirtv1.VirtualMachine
	if err := c.Client.Get(ctx, req.NamespacedName, &vm); err != nil {
		if k8serrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("get VM: %w", err)
	}

	ann := vm.GetAnnotations()

	// Only handle VMs that are actions runners.
	sessionID := ann["blip.io/session-id"]
	if !strings.HasPrefix(sessionID, "actions-") {
		return reconcile.Result{}, nil
	}

	// Already released — nothing to do (deallocation controller handles deletion).
	if ann["blip.io/release"] == "true" {
		return reconcile.Result{}, nil
	}

	repo := ann[runnerRepoAnnotation]
	jobIDStr := ann[runnerJobIDAnnotation]
	if repo == "" || jobIDStr == "" {
		// VM is still being provisioned (annotations not yet set), requeue.
		return reconcile.Result{RequeueAfter: jobCheckInterval}, nil
	}

	jobID, err := strconv.ParseInt(jobIDStr, 10, 64)
	if err != nil {
		slog.Error("invalid runner-job-id annotation",
			"vm", vm.Name,
			"value", jobIDStr,
		)
		return reconcile.Result{}, nil
	}

	pat := c.pat.get()
	if pat == nil {
		// PAT provider not yet initialised, requeue.
		return reconcile.Result{RequeueAfter: jobCheckInterval}, nil
	}

	token, err := pat.Token()
	if err != nil {
		slog.Debug("failed to get PAT for job status check",
			"vm", vm.Name,
			"error", err,
		)
		return reconcile.Result{RequeueAfter: jobCheckInterval}, nil
	}

	status, err := ghactions.GetJobStatus(ctx, token, repo, jobID)
	if err != nil {
		slog.Debug("failed to check job status",
			"vm", vm.Name,
			"repo", repo,
			"job_id", jobID,
			"error", err,
		)
		return reconcile.Result{RequeueAfter: jobCheckInterval}, nil
	}

	if status == "completed" {
		slog.Info("job completed, releasing runner VM",
			"repo", repo,
			"job_id", jobID,
			"vm", vm.Name,
		)

		base := vm.DeepCopy()
		if vm.Annotations == nil {
			vm.Annotations = make(map[string]string)
		}
		vm.Annotations["blip.io/release"] = "true"
		if err := c.Client.Patch(ctx, &vm, client.MergeFrom(base)); err != nil {
			if k8serrors.IsNotFound(err) {
				return reconcile.Result{}, nil
			}
			return reconcile.Result{}, fmt.Errorf("release VM %s: %w", vm.Name, err)
		}
		return reconcile.Result{}, nil
	}

	// Job still running — requeue to check again.
	return reconcile.Result{RequeueAfter: jobCheckInterval}, nil
}

// ---------------------------------------------------------------------------
// Actions runnable — initialises PAT provider + runs the job poller
// ---------------------------------------------------------------------------

// actionsRunnable is a controller-runtime Runnable that creates the PAT
// provider (which requires a synced cache), then polls GitHub for queued jobs.
type actionsRunnable struct {
	mgr    ctrl.Manager
	cfg    Config
	holder *PATHolder
}

// NeedLeaderElection returns true so the poller only runs on the leader.
func (r *actionsRunnable) NeedLeaderElection() bool {
	return true
}

func (r *actionsRunnable) Start(ctx context.Context) error {
	// Create the PAT provider now that the cache is synced.
	pat, err := ghactions.NewPATProvider(ctx, r.mgr.GetCache(), r.cfg.Namespace, r.cfg.PATSecretName)
	if err != nil {
		return fmt.Errorf("create PAT provider: %w", err)
	}
	r.holder.set(pat)

	slog.Info("actions job poller started",
		"repos", r.cfg.Repos,
		"labels", r.cfg.RunnerLabels,
	)

	poller := &jobPoller{
		client: r.mgr.GetClient(),
		cfg:    r.cfg,
		pat:    pat,
	}

	for {
		for _, repo := range r.cfg.Repos {
			poller.pollRepo(ctx, repo)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(pollInterval):
		}
	}
}

// ---------------------------------------------------------------------------
// Job poller — stateless GitHub job discovery and VM allocation
// ---------------------------------------------------------------------------

// jobPoller polls GitHub for queued workflow jobs and allocates VMs.
type jobPoller struct {
	client client.Client
	cfg    Config
	pat    *ghactions.PATProvider
}

func (p *jobPoller) pollRepo(ctx context.Context, repo string) {
	token, err := p.pat.Token()
	if err != nil {
		slog.Error("failed to get PAT", "repo", repo, "error", err)
		return
	}

	jobs, err := ghactions.ListQueuedJobs(ctx, repo, token)
	if err != nil {
		slog.Error("poll queued jobs failed", "repo", repo, "error", err)
		return
	}

	for _, job := range jobs {
		// Only handle jobs whose labels match our configured runner labels.
		if !labelsMatch(job.Labels, p.cfg.RunnerLabels) {
			continue
		}

		sessionID := fmt.Sprintf("actions-%d", job.ID)

		// Check if a VM is already allocated for this job by looking up
		// the session-id in the Kubernetes API. This replaces the old
		// in-memory allocated map.
		if p.vmExistsForSession(ctx, sessionID) {
			continue
		}

		p.allocateAndProvision(ctx, repo, job, sessionID, token)
	}
}

// vmExistsForSession checks whether any VM in the namespace already has the
// given session-id annotation.
func (p *jobPoller) vmExistsForSession(ctx context.Context, sessionID string) bool {
	var list kubevirtv1.VirtualMachineList
	if err := p.client.List(ctx, &list,
		client.InNamespace(p.cfg.Namespace),
	); err != nil {
		slog.Error("failed to list VMs for session check", "error", err)
		return true // safe default: assume exists to avoid double-allocation
	}
	for _, vm := range list.Items {
		if vm.Annotations["blip.io/session-id"] == sessionID {
			return true
		}
	}
	return false
}

func (p *jobPoller) allocateAndProvision(ctx context.Context, repo string, job ghactions.WorkflowJob, sessionID, token string) {
	// Claim a VM from the pool.
	vmName, err := p.claimVM(ctx, sessionID, repo)
	if err != nil {
		slog.Error("failed to allocate runner VM",
			"repo", repo,
			"job_id", job.ID,
			"error", err,
		)
		return
	}
	slog.Info("allocated runner VM",
		"repo", repo,
		"job_id", job.ID,
		"vm", vmName,
	)

	// Write repo and job-id annotations to the VM. The runner-config
	// controller will detect these annotations, create a JIT config via
	// the GitHub API, and deliver it to the VM over SSH — ensuring no
	// sensitive values are stored in the VM object.
	if err := p.patchVMAnnotations(ctx, vmName, map[string]string{
		runnerRepoAnnotation:  repo,
		runnerJobIDAnnotation: strconv.FormatInt(job.ID, 10),
	}); err != nil {
		slog.Error("failed to set annotations on runner VM",
			"vm", vmName,
			"job_id", job.ID,
			"error", err,
		)
		p.releaseVM(ctx, vmName)
		return
	}

	slog.Info("runner VM annotated, awaiting SSH provisioning",
		"repo", repo,
		"job_id", job.ID,
		"vm", vmName,
	)
}

// claimVM finds an unclaimed, ready VM from the pool and claims it for the
// given session. Uses optimistic concurrency with retries on conflict.
func (p *jobPoller) claimVM(ctx context.Context, sessionID, repo string) (string, error) {
	for range 10 {
		var list kubevirtv1.VirtualMachineList
		if err := p.client.List(ctx, &list, client.InNamespace(p.cfg.Namespace)); err != nil {
			return "", fmt.Errorf("list VMs: %w", err)
		}

		var candidates []kubevirtv1.VirtualMachine
		for _, vm := range list.Items {
			if vm.Labels["blip.io/pool"] != p.cfg.PoolName {
				continue
			}
			if _, claimed := vm.Annotations["blip.io/session-id"]; claimed {
				continue
			}
			if vm.Annotations["blip.io/host-key"] == "" || vm.Annotations["blip.io/client-key"] == "" {
				continue
			}
			// Check if the VMI is ready.
			var vmi kubevirtv1.VirtualMachineInstance
			if err := p.client.Get(ctx, client.ObjectKey{
				Namespace: p.cfg.Namespace,
				Name:      vm.Name,
			}, &vmi); err != nil {
				continue
			}
			ready := false
			for _, cond := range vmi.Status.Conditions {
				if cond.Type == kubevirtv1.VirtualMachineInstanceReady && string(cond.Status) == "True" {
					ready = true
					break
				}
			}
			if !ready {
				continue
			}
			candidates = append(candidates, vm)
		}

		if len(candidates) == 0 {
			return "", fmt.Errorf("no unclaimed ready VMs available")
		}

		// Pick the oldest candidate.
		chosen := candidates[0]
		for _, c := range candidates[1:] {
			if c.CreationTimestamp.Before(&chosen.CreationTimestamp) {
				chosen = c
			}
		}

		if chosen.Annotations == nil {
			chosen.Annotations = make(map[string]string)
		}
		chosen.Annotations["blip.io/session-id"] = sessionID
		chosen.Annotations["blip.io/claimed-at"] = time.Now().Format(time.RFC3339)
		chosen.Annotations["blip.io/claimed-by"] = p.cfg.PodName
		chosen.Annotations["blip.io/max-duration"] = strconv.Itoa(runnerMaxTTL)
		chosen.Annotations["blip.io/ephemeral"] = "true"
		chosen.Annotations["blip.io/user"] = fmt.Sprintf("actions:%s", repo)

		if err := p.client.Update(ctx, &chosen); err != nil {
			if k8serrors.IsConflict(err) {
				continue
			}
			return "", fmt.Errorf("claim VM %s: %w", chosen.Name, err)
		}

		return chosen.Name, nil
	}

	return "", fmt.Errorf("failed to claim a VM after retries")
}

func (p *jobPoller) releaseVM(ctx context.Context, vmName string) {
	var vm kubevirtv1.VirtualMachine
	if err := p.client.Get(ctx, client.ObjectKey{
		Namespace: p.cfg.Namespace,
		Name:      vmName,
	}, &vm); err != nil {
		slog.Error("failed to get VM for release", "vm", vmName, "error", err)
		return
	}

	base := vm.DeepCopy()
	if vm.Annotations == nil {
		vm.Annotations = make(map[string]string)
	}
	vm.Annotations["blip.io/release"] = "true"
	if err := p.client.Patch(ctx, &vm, client.MergeFrom(base)); err != nil {
		slog.Error("failed to release VM", "vm", vmName, "error", err)
	}
}

func (p *jobPoller) patchVMAnnotations(ctx context.Context, vmName string, annotations map[string]string) error {
	var vm kubevirtv1.VirtualMachine
	if err := p.client.Get(ctx, client.ObjectKey{
		Namespace: p.cfg.Namespace,
		Name:      vmName,
	}, &vm); err != nil {
		return fmt.Errorf("get VM %s: %w", vmName, err)
	}

	base := vm.DeepCopy()
	if vm.Annotations == nil {
		vm.Annotations = make(map[string]string)
	}
	for k, v := range annotations {
		vm.Annotations[k] = v
	}
	return p.client.Patch(ctx, &vm, client.MergeFrom(base))
}

// labelsMatch returns true if all of our configured runner labels appear in the
// job's label set. GitHub Actions jobs specify the labels they require (e.g.
// ["self-hosted", "blip"]); we only handle jobs that match our labels exactly.
func labelsMatch(jobLabels, runnerLabels []string) bool {
	set := make(map[string]struct{}, len(jobLabels))
	for _, l := range jobLabels {
		set[l] = struct{}{}
	}
	for _, rl := range runnerLabels {
		if _, ok := set[rl]; !ok {
			return false
		}
	}
	return true
}
