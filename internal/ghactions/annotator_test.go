package ghactions

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubevirtv1 "kubevirt.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const testNamespace = "test-ns"

var testScheme = func() *runtime.Scheme {
	s := runtime.NewScheme()
	if err := kubevirtv1.AddToScheme(s); err != nil {
		panic(err)
	}
	return s
}()

func newFakeClient(t *testing.T, fns interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(objs...).
		WithInterceptorFuncs(fns).
		Build()
}

func makeTestVM(name string) *kubevirtv1.VirtualMachine {
	return &kubevirtv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       testNamespace,
			ResourceVersion: "1",
		},
	}
}

func TestVMAnnotator_StoreRunnerConfig(t *testing.T) {
	vm := makeTestVM("vm-1")
	fc := newFakeClient(t, interceptor.Funcs{}, vm)
	a := NewVMAnnotator(fc, testNamespace)

	err := a.StoreRunnerConfig(context.Background(), "vm-1", RunnerConfig{
		Token:   "AABBC123",
		RepoURL: "https://github.com/org/repo",
		Labels:  []string{"self-hosted", "blip"},
	})
	require.NoError(t, err)

	var got kubevirtv1.VirtualMachine
	require.NoError(t, fc.Get(context.Background(), client.ObjectKey{
		Namespace: testNamespace,
		Name:      "vm-1",
	}, &got))

	assert.Equal(t, "AABBC123", got.Annotations[AnnotationRunnerToken])
	assert.Equal(t, "https://github.com/org/repo", got.Annotations[AnnotationRunnerURL])
	assert.Equal(t, "self-hosted,blip", got.Annotations[AnnotationRunnerLabels])
}

func TestVMAnnotator_StoreRunnerConfig_PreservesExistingAnnotations(t *testing.T) {
	vm := makeTestVM("vm-1")
	vm.Annotations = map[string]string{
		"blip.io/session-id": "blip-000000000000002a",
		"blip.io/pool":       "default",
	}
	fc := newFakeClient(t, interceptor.Funcs{}, vm)
	a := NewVMAnnotator(fc, testNamespace)

	err := a.StoreRunnerConfig(context.Background(), "vm-1", RunnerConfig{
		Token:   "tok",
		RepoURL: "https://github.com/o/r",
		Labels:  []string{"blip"},
	})
	require.NoError(t, err)

	var got kubevirtv1.VirtualMachine
	require.NoError(t, fc.Get(context.Background(), client.ObjectKey{
		Namespace: testNamespace,
		Name:      "vm-1",
	}, &got))

	assert.Equal(t, "tok", got.Annotations[AnnotationRunnerToken])
	assert.Equal(t, "https://github.com/o/r", got.Annotations[AnnotationRunnerURL])
	assert.Equal(t, "blip", got.Annotations[AnnotationRunnerLabels])

	assert.Equal(t, "blip-000000000000002a", got.Annotations["blip.io/session-id"])
	assert.Equal(t, "default", got.Annotations["blip.io/pool"])
}

func TestVMAnnotator_StoreRunnerConfig_VMNotFound(t *testing.T) {
	fc := newFakeClient(t, interceptor.Funcs{})
	a := NewVMAnnotator(fc, testNamespace)

	err := a.StoreRunnerConfig(context.Background(), "nonexistent", RunnerConfig{
		Token: "tok",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "patch VM nonexistent")
}

func TestVMAnnotator_StoreRunnerConfig_PatchFailure(t *testing.T) {
	vm := makeTestVM("vm-1")
	fc := newFakeClient(t, interceptor.Funcs{
		Patch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
			return fmt.Errorf("api unavailable")
		},
	}, vm)
	a := NewVMAnnotator(fc, testNamespace)

	err := a.StoreRunnerConfig(context.Background(), "vm-1", RunnerConfig{
		Token:   "tok",
		RepoURL: "https://github.com/o/r",
		Labels:  []string{"blip"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "patch VM vm-1")
}

func TestVMAnnotator_StoreRunnerConfig_EmptyLabels(t *testing.T) {
	vm := makeTestVM("vm-1")
	fc := newFakeClient(t, interceptor.Funcs{}, vm)
	a := NewVMAnnotator(fc, testNamespace)

	err := a.StoreRunnerConfig(context.Background(), "vm-1", RunnerConfig{
		Token:   "tok",
		RepoURL: "https://github.com/o/r",
		Labels:  nil,
	})
	require.NoError(t, err)

	var got kubevirtv1.VirtualMachine
	require.NoError(t, fc.Get(context.Background(), client.ObjectKey{
		Namespace: testNamespace,
		Name:      "vm-1",
	}, &got))

	assert.Equal(t, "tok", got.Annotations[AnnotationRunnerToken])
	assert.Equal(t, "", got.Annotations[AnnotationRunnerLabels])
}
