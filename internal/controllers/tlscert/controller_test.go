package tlscert

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newFakeClient() client.Client {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	return fake.NewClientBuilder().WithScheme(s).Build()
}

func TestGenerateSelfSignedCert(t *testing.T) {
	keyPEM, certPEM, err := generateSelfSignedCert("gateway.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify key parses.
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatal("expected EC PRIVATE KEY PEM block")
	}

	// Verify cert parses.
	block, _ = pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("expected CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if cert.Subject.CommonName != "gateway.example.com" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "gateway.example.com")
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "gateway.example.com" {
		t.Errorf("DNSNames = %v, want [gateway.example.com]", cert.DNSNames)
	}
	if cert.NotAfter.Before(time.Now().Add(23 * time.Hour)) {
		t.Error("cert expires too soon")
	}
}

func TestReconcile_InitialCreation(t *testing.T) {
	cl := newFakeClient()

	// Pre-create the kube-public namespace so the fake client can create
	// resources in it.
	_ = cl.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: PublicNamespace},
	})

	r := &certRotator{
		cl:               cl,
		namespace:        "blip",
		gatewayHostname:  "gw.test.io",
		rotationInterval: time.Hour,
	}

	ctx := context.Background()
	if err := r.reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Verify Secret was created.
	var secret corev1.Secret
	if err := cl.Get(ctx, client.ObjectKey{Namespace: "blip", Name: SecretName}, &secret); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if _, ok := secret.Data[keyDataKey]; !ok {
		t.Error("secret missing tls.key")
	}

	// Verify ConfigMap was created.
	var cm corev1.ConfigMap
	if err := cl.Get(ctx, client.ObjectKey{Namespace: PublicNamespace, Name: ConfigMapName}, &cm); err != nil {
		t.Fatalf("get configmap: %v", err)
	}
	if cm.Data[hostnameKey] != "gw.test.io" {
		t.Errorf("hostname = %q, want %q", cm.Data[hostnameKey], "gw.test.io")
	}
	if cm.Data[activeCertKey] == "" {
		t.Error("active cert is empty")
	}
	if _, ok := cm.Data[previousCertKey]; ok {
		t.Error("previous cert should not exist on first creation")
	}
}

func TestReconcile_Rotation(t *testing.T) {
	cl := newFakeClient()
	_ = cl.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: PublicNamespace},
	})

	r := &certRotator{
		cl:               cl,
		namespace:        "blip",
		gatewayHostname:  "gw.test.io",
		rotationInterval: time.Hour,
	}

	ctx := context.Background()
	if err := r.reconcile(ctx); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}

	// Get the first active cert.
	var cm corev1.ConfigMap
	_ = cl.Get(ctx, client.ObjectKey{Namespace: PublicNamespace, Name: ConfigMapName}, &cm)
	firstCert := cm.Data[activeCertKey]

	// Second rotation.
	if err := r.reconcile(ctx); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}

	_ = cl.Get(ctx, client.ObjectKey{Namespace: PublicNamespace, Name: ConfigMapName}, &cm)
	if cm.Data[previousCertKey] != firstCert {
		t.Error("previous cert should be the old active cert")
	}
	if cm.Data[activeCertKey] == firstCert {
		t.Error("active cert should have changed after rotation")
	}
}

func TestReconcile_HostnameChange(t *testing.T) {
	cl := newFakeClient()
	_ = cl.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: PublicNamespace},
	})

	r := &certRotator{
		cl:               cl,
		namespace:        "blip",
		gatewayHostname:  "old.host.io",
		rotationInterval: time.Hour,
	}

	ctx := context.Background()
	if err := r.reconcile(ctx); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}

	// Change hostname.
	r.gatewayHostname = "new.host.io"
	if err := r.reconcile(ctx); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}

	var cm corev1.ConfigMap
	_ = cl.Get(ctx, client.ObjectKey{Namespace: PublicNamespace, Name: ConfigMapName}, &cm)

	if cm.Data[hostnameKey] != "new.host.io" {
		t.Errorf("hostname = %q, want %q", cm.Data[hostnameKey], "new.host.io")
	}
	// Previous cert should be discarded on hostname change.
	if _, ok := cm.Data[previousCertKey]; ok {
		t.Error("previous cert should be discarded on hostname change")
	}

	// Verify the active cert has the new hostname.
	block, _ := pem.Decode([]byte(cm.Data[activeCertKey]))
	cert, _ := x509.ParseCertificate(block.Bytes)
	if cert.Subject.CommonName != "new.host.io" {
		t.Errorf("cert CN = %q, want %q", cert.Subject.CommonName, "new.host.io")
	}
}
