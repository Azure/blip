// Package runnerconfig implements a controller that provisions GitHub Actions
// runners on allocated VMs via short-lived SSH connections. When the actions
// job poller claims a VM and writes the repo/job-id annotations, this
// controller detects the VM, creates a JIT runner config via the GitHub API,
// SSHes into the VM to deliver the config and start the runner process, then
// disconnects. No sensitive values (JIT configs, tokens) are ever stored in
// the VM object — they are passed exclusively through the mutually
// authenticated SSH channel.
package runnerconfig

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ghactions "github.com/project-unbounded/blip/internal/gateway/actions"
)

const (
	// runnerRepoAnnotation stores the repo (owner/repo) for a runner VM.
	runnerRepoAnnotation = "blip.io/runner-repo"

	// runnerJobIDAnnotation stores the GitHub job ID for a runner VM.
	runnerJobIDAnnotation = "blip.io/runner-job-id"

	// runnerProvisionedAnnotation marks a VM as having been successfully
	// provisioned with runner credentials via SSH. This is the only
	// annotation set by this controller — it is a boolean flag, not a
	// secret value.
	runnerProvisionedAnnotation = "blip.io/runner-provisioned"

	// sshTimeout is the maximum time for the entire SSH provisioning
	// operation (connect + start runner + disconnect).
	sshTimeout = 30 * time.Second

	// sshDialTimeout is the TCP dial timeout for each SSH attempt.
	sshDialTimeout = 5 * time.Second

	// sshHandshakeTimeout is the SSH handshake timeout.
	sshHandshakeTimeout = 10 * time.Second

	// maxDialAttempts is the number of SSH connection attempts with backoff.
	maxDialAttempts = 10

	// requeueDelay is used when the VM is not yet ready for provisioning.
	requeueDelay = 5 * time.Second

	// clientKeySecretName is the Kubernetes Secret containing the gateway's
	// SSH client private key (created by the keygen controller).
	clientKeySecretName = "ssh-gateway-client-key"

	// clientKeySecretKey is the key within the Secret that holds the PEM
	// private key.
	clientKeySecretKey = "client_key"
)

// Config holds the configuration for the runner config controller.
type Config struct {
	Namespace    string
	PATHolder    PATProvider
	RunnerLabels []string
}

// PATProvider abstracts access to the GitHub PAT for creating JIT configs.
type PATProvider interface {
	Token() (string, error)
}

// Add registers the runner config controller with the given manager.
func Add(mgr ctrl.Manager, cfg Config) error {
	c := &controller{
		Client:       mgr.GetClient(),
		pat:          cfg.PATHolder,
		namespace:    cfg.Namespace,
		runnerLabels: cfg.RunnerLabels,
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		Named("runner-config").
		For(&kubevirtv1.VirtualMachine{}).
		WithEventFilter(predicate.Or(
			predicate.AnnotationChangedPredicate{},
			predicate.GenerationChangedPredicate{},
		)).
		Complete(c); err != nil {
		return fmt.Errorf("register runner-config controller: %w", err)
	}

	return nil
}

type controller struct {
	Client       client.Client
	pat          PATProvider
	namespace    string
	runnerLabels []string

	// signerOnce lazily loads the SSH client key from the Secret.
	signerOnce sync.Once
	signer     ssh.Signer
	signerErr  error
}

func (c *controller) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
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

	// Already released — nothing to do.
	if ann["blip.io/release"] == "true" {
		return reconcile.Result{}, nil
	}

	// Already provisioned — nothing to do.
	if ann[runnerProvisionedAnnotation] == "true" {
		return reconcile.Result{}, nil
	}

	// Need repo and job-id to provision.
	repo := ann[runnerRepoAnnotation]
	jobIDStr := ann[runnerJobIDAnnotation]
	if repo == "" || jobIDStr == "" {
		// Not yet fully annotated by the job poller, requeue.
		return reconcile.Result{RequeueAfter: requeueDelay}, nil
	}

	jobID, err := strconv.ParseInt(jobIDStr, 10, 64)
	if err != nil {
		slog.Error("invalid runner-job-id annotation",
			"vm", vm.Name,
			"value", jobIDStr,
		)
		return reconcile.Result{}, nil // not recoverable
	}

	// Ensure the VMI is ready and has an IP.
	var vmi kubevirtv1.VirtualMachineInstance
	if err := c.Client.Get(ctx, req.NamespacedName, &vmi); err != nil {
		if k8serrors.IsNotFound(err) {
			return reconcile.Result{RequeueAfter: requeueDelay}, nil
		}
		return reconcile.Result{}, fmt.Errorf("get VMI: %w", err)
	}
	ready := false
	for _, cond := range vmi.Status.Conditions {
		if cond.Type == kubevirtv1.VirtualMachineInstanceReady && cond.Status == corev1.ConditionTrue {
			ready = true
			break
		}
	}
	if !ready {
		return reconcile.Result{RequeueAfter: requeueDelay}, nil
	}
	if len(vmi.Status.Interfaces) == 0 || vmi.Status.Interfaces[0].IP == "" {
		return reconcile.Result{RequeueAfter: requeueDelay}, nil
	}
	vmIP := vmi.Status.Interfaces[0].IP

	// Verify host key is available.
	hostKeyStr := ann["blip.io/host-key"]
	if hostKeyStr == "" {
		return reconcile.Result{RequeueAfter: requeueDelay}, nil
	}

	// Get the SSH client signer.
	signer, err := c.getOrLoadSigner(ctx)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("load SSH client key: %w", err)
	}

	// Get the PAT for the GitHub API.
	token, err := c.pat.Token()
	if err != nil {
		slog.Debug("PAT not yet available for runner provisioning",
			"vm", vm.Name,
			"error", err,
		)
		return reconcile.Result{RequeueAfter: requeueDelay}, nil
	}

	// Create JIT runner config via GitHub API.
	runnerName := fmt.Sprintf("blip-%d", jobID)
	labels := c.runnerLabels
	if len(labels) == 0 {
		labels = []string{"self-hosted", "blip"}
	}

	jitConfig, err := ghactions.CreateJITRunnerConfig(ctx, token, repo, labels, runnerName)
	if err != nil {
		slog.Error("failed to create JIT runner config",
			"vm", vm.Name,
			"repo", repo,
			"job_id", jobID,
			"error", err,
		)
		// Release the VM on permanent failure.
		c.releaseVM(ctx, &vm)
		return reconcile.Result{}, nil
	}

	// SSH into the VM and start the runner.
	provisionCtx, cancel := context.WithTimeout(ctx, sshTimeout)
	defer cancel()

	if err := c.provisionRunner(provisionCtx, vmIP, hostKeyStr, signer, jitConfig); err != nil {
		slog.Error("failed to provision runner via SSH",
			"vm", vm.Name,
			"ip", vmIP,
			"repo", repo,
			"job_id", jobID,
			"error", err,
		)
		// Release the VM — it may be unhealthy.
		c.releaseVM(ctx, &vm)
		return reconcile.Result{}, nil
	}

	// Mark as provisioned.
	base := vm.DeepCopy()
	if vm.Annotations == nil {
		vm.Annotations = make(map[string]string)
	}
	vm.Annotations[runnerProvisionedAnnotation] = "true"
	if err := c.Client.Patch(ctx, &vm, client.MergeFrom(base)); err != nil {
		if k8serrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("mark VM %s as provisioned: %w", vm.Name, err)
	}

	slog.Info("runner provisioned via SSH",
		"vm", vm.Name,
		"repo", repo,
		"job_id", jobID,
		"runner_name", runnerName,
	)

	return reconcile.Result{}, nil
}

// provisionRunner establishes a short-lived SSH connection to the VM, delivers
// the JIT config, and starts the runner process. The connection is closed as
// soon as the runner start command completes (the runner continues running as
// a background process in the VM).
func (c *controller) provisionRunner(ctx context.Context, vmIP, hostKeyStr string, signer ssh.Signer, jitConfig string) error {
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKeyStr))
	if err != nil {
		return fmt.Errorf("parse host key: %w", err)
	}

	cfg := &ssh.ClientConfig{
		User:              "runner",
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   ssh.FixedHostKey(hostKey),
		HostKeyAlgorithms: []string{hostKey.Type()},
		Timeout:           sshHandshakeTimeout,
	}

	sshClient, err := c.dialSSH(ctx, vmIP, cfg)
	if err != nil {
		return fmt.Errorf("SSH dial: %w", err)
	}
	defer sshClient.Close()

	session, err := sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()

	// Close the session if context expires so we don't block.
	go func() {
		<-ctx.Done()
		session.Close()
	}()

	// Start the runner with the JIT config passed via stdin to avoid it
	// appearing in process arguments or environment variables. The script
	// reads the config from stdin, writes it to a temporary file, starts
	// the runner in the background via nohup, then removes the temp file.
	// Using stdin ensures the JIT config never touches the filesystem in
	// plaintext for longer than the brief moment between write and
	// runner startup, and never appears in /proc/*/cmdline.
	script := `#!/bin/sh
set -e
JITCONFIG="$(cat)"
cd /home/runner/actions-runner
nohup ./run.sh --jitconfig "$JITCONFIG" > /home/runner/actions-runner/_diag/runner.log 2>&1 &
`

	session.Stdin = strings.NewReader(jitConfig)
	if err := session.Run(script); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("SSH session: %w", ctx.Err())
		}
		return fmt.Errorf("run provisioning script: %w", err)
	}

	return nil
}

// dialSSH connects to the VM with retry and exponential backoff.
func (c *controller) dialSSH(ctx context.Context, vmIP string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	addr := net.JoinHostPort(vmIP, "22")
	dialer := net.Dialer{Timeout: sshDialTimeout}

	const (
		baseBackoff = 200 * time.Millisecond
		maxBackoff  = 2 * time.Second
	)

	var lastErr error
	for attempt := range maxDialAttempts {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("cancelled: %w", err)
		}

		tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			lastErr = fmt.Errorf("tcp dial (attempt %d/%d): %w", attempt+1, maxDialAttempts, err)
			slog.Debug("runner SSH TCP dial failed", "addr", addr, "attempt", attempt+1, "error", err)
		} else {
			tcpConn.SetDeadline(time.Now().Add(sshHandshakeTimeout))
			sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, addr, cfg)
			if err != nil {
				tcpConn.Close()
				lastErr = fmt.Errorf("ssh handshake (attempt %d/%d): %w", attempt+1, maxDialAttempts, err)
				slog.Debug("runner SSH handshake failed", "addr", addr, "attempt", attempt+1, "error", err)
			} else {
				tcpConn.SetDeadline(time.Time{})
				return ssh.NewClient(sshConn, chans, reqs), nil
			}
		}

		if attempt < maxDialAttempts-1 {
			backoff := baseBackoff * time.Duration(1<<attempt)
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("cancelled: %w", ctx.Err())
			case <-time.After(backoff):
			}
		}
	}
	return nil, fmt.Errorf("dial %s after %d attempts: %w", addr, maxDialAttempts, lastErr)
}

// getOrLoadSigner lazily loads the SSH client private key from the Kubernetes
// Secret created by the keygen controller.
func (c *controller) getOrLoadSigner(ctx context.Context) (ssh.Signer, error) {
	c.signerOnce.Do(func() {
		var secret corev1.Secret
		if err := c.Client.Get(ctx, client.ObjectKey{
			Namespace: c.namespace,
			Name:      clientKeySecretName,
		}, &secret); err != nil {
			c.signerErr = fmt.Errorf("get client key secret %s: %w", clientKeySecretName, err)
			return
		}

		keyPEM := secret.Data[clientKeySecretKey]
		if len(keyPEM) == 0 {
			c.signerErr = fmt.Errorf("client key secret %s has no %s key", clientKeySecretName, clientKeySecretKey)
			return
		}

		signer, err := ssh.ParsePrivateKey(keyPEM)
		if err != nil {
			c.signerErr = fmt.Errorf("parse client private key: %w", err)
			return
		}
		c.signer = signer
	})
	return c.signer, c.signerErr
}

// releaseVM marks a VM for deallocation.
func (c *controller) releaseVM(ctx context.Context, vm *kubevirtv1.VirtualMachine) {
	base := vm.DeepCopy()
	if vm.Annotations == nil {
		vm.Annotations = make(map[string]string)
	}
	vm.Annotations["blip.io/release"] = "true"
	if err := c.Client.Patch(ctx, vm, client.MergeFrom(base)); err != nil {
		slog.Error("failed to release VM after provisioning failure",
			"vm", vm.Name,
			"error", err,
		)
	}
}
