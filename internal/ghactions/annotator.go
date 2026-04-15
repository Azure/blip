package ghactions

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubevirtv1 "kubevirt.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RunnerConfig holds the GitHub Actions runner configuration to be stored
// on a VM as annotations so the cloud-init script can start the runner agent.
type RunnerConfig struct {
	// Token is the registration token (legacy App-based flow).
	Token string
	// JITConfig is the base64-encoded JIT runner config (scale set flow).
	JITConfig string
	RepoURL   string
	Labels    []string
}

// Annotations used for runner configuration.
const (
	AnnotationRunnerToken     = "blip.io/runner-token"
	AnnotationRunnerURL       = "blip.io/runner-url"
	AnnotationRunnerLabels    = "blip.io/runner-labels"
	AnnotationRunnerJITConfig = "blip.io/runner-jitconfig"
)

// VMAnnotator patches runner configuration annotations on VMs.
type VMAnnotator struct {
	writer    client.Client
	namespace string
}

var _ RunnerConfigStore = (*VMAnnotator)(nil)

// NewVMAnnotator creates a VMAnnotator using the provided Kubernetes client.
func NewVMAnnotator(writer client.Client, namespace string) *VMAnnotator {
	return &VMAnnotator{writer: writer, namespace: namespace}
}

// StoreRunnerConfig patches the named VM with runner configuration annotations.
// If JITConfig is set, the JIT config annotation is written (scale set flow).
// Otherwise, the token/URL/labels annotations are written (legacy flow).
func (a *VMAnnotator) StoreRunnerConfig(ctx context.Context, vmName string, cfg RunnerConfig) error {
	annotations := make(map[string]string)

	if cfg.JITConfig != "" {
		// Scale set flow: only the JIT config is needed. The VM will
		// use run.sh --jitconfig instead of config.sh.
		annotations[AnnotationRunnerJITConfig] = cfg.JITConfig
	} else {
		// Legacy App-based flow.
		annotations[AnnotationRunnerToken] = cfg.Token
		annotations[AnnotationRunnerURL] = cfg.RepoURL
		annotations[AnnotationRunnerLabels] = strings.Join(cfg.Labels, ",")
	}

	patch := map[string]any{
		"metadata": map[string]any{
			"annotations": annotations,
		},
	}
	patchData, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}

	vm := &kubevirtv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      vmName,
			Namespace: a.namespace,
		},
	}
	if err := a.writer.Patch(ctx, vm, client.RawPatch(
		types.MergePatchType,
		patchData,
	)); err != nil {
		return fmt.Errorf("patch VM %s: %w", vmName, err)
	}

	return nil
}
