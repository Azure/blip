package diskkey

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const ns = "blip-system"

func getKey(t *testing.T, c client.Client) []byte {
	t.Helper()
	sec := &corev1.Secret{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: SecretName}, sec); err != nil {
		t.Fatal(err)
	}
	return sec.Data[DataKey]
}

func TestEnsureCreatesOnce(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().Build()
	if err := Ensure(ctx, c, ns); err != nil {
		t.Fatal(err)
	}
	first := getKey(t, c)
	if len(first) != Size {
		t.Fatalf("key is %d bytes", len(first))
	}
	if err := Ensure(ctx, c, ns); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(getKey(t, c), first) {
		t.Fatal("Ensure replaced an existing key")
	}
	got, err := Load(ctx, c, ns)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatal("Load returned a different key")
	}
}

func TestLoadWaitsForSecret(t *testing.T) {
	pollInterval = 10 * time.Millisecond
	ctx := context.Background()
	c := fake.NewClientBuilder().Build()
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = Ensure(ctx, c, ns)
	}()
	key, err := Load(ctx, c, ns)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != Size {
		t.Fatalf("key is %d bytes", len(key))
	}
}

func TestLoadCanceled(t *testing.T) {
	pollInterval = 10 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := Load(ctx, fake.NewClientBuilder().Build(), ns)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRejectsBadLength(t *testing.T) {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: SecretName, Namespace: ns},
		Data:       map[string][]byte{DataKey: []byte("short")},
	}
	c := fake.NewClientBuilder().WithObjects(sec).Build()
	if _, err := Load(context.Background(), c, ns); err == nil {
		t.Fatal("expected error for short key")
	}
}
