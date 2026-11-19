package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"

	v1 "github.com/Azure/blip/api/v1alpha1"
)

// waitForEvent returns the next recorder event, failing when none was
// published.
func waitForEvent(t *testing.T, recorder *record.FakeRecorder) string {
	t.Helper()
	select {
	case event := <-recorder.Events:
		return event
	default:
		t.Fatal("no Event was published")
		return ""
	}
}

func TestPoolInvalidEndpointEmitsEvent(t *testing.T) {
	e := newEnv(t)
	e.newPool("default", 1, 0)
	e.updatePool("default", func(p *v1.BlipPool) {
		p.Spec.Endpoints = []v1.PoolEndpoint{{Name: "whoami", URL: "http://whoami.example.com"}}
	})
	recorder := record.NewFakeRecorder(10)
	e.pool.Recorder = recorder

	if _, err := e.pool.Reconcile(e.ctx, req(ns, "default")); err == nil {
		t.Fatal("invalid pool reconciled without an error")
	}
	event := waitForEvent(t, recorder)
	if !strings.Contains(event, corev1.EventTypeWarning+" InvalidEndpoints") {
		t.Errorf("event = %q, want a Warning InvalidEndpoints event", event)
	}
	if n := len(e.pods()); n != 0 {
		t.Errorf("%d pods created for an invalid pool", n)
	}
}

func TestPoolEndpointCAValidation(t *testing.T) {
	badCA := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-ca"},
		Data:       map[string]string{"ca.crt": "not a certificate"},
	}
	validCA := testCAPEM(t)

	t.Run("unparseable ca.crt emits an event", func(t *testing.T) {
		e := newEnv(t)
		e.newPool("default", 1, 0)
		e.create(badCA)
		e.updatePool("default", func(p *v1.BlipPool) {
			p.Spec.Endpoints = []v1.PoolEndpoint{{Name: "whoami", URL: "https://whoami.example.com", CAConfigMap: "bad-ca"}}
		})
		recorder := record.NewFakeRecorder(10)
		e.pool.Recorder = recorder

		_, err := e.pool.Reconcile(e.ctx, req(ns, "default"))
		if err == nil || !strings.Contains(err.Error(), "no parseable ca.crt") {
			t.Fatalf("reconcile error %v, want a ca.crt parse error", err)
		}
		event := waitForEvent(t, recorder)
		if !strings.Contains(event, corev1.EventTypeWarning+" InvalidEndpointCA") {
			t.Errorf("event = %q, want a Warning InvalidEndpointCA event", event)
		}
		if n := len(e.pods()); n != 0 {
			t.Errorf("%d pods created for an invalid pool", n)
		}
	})

	t.Run("missing ConfigMap emits an event", func(t *testing.T) {
		e := newEnv(t)
		e.newPool("default", 1, 0)
		e.updatePool("default", func(p *v1.BlipPool) {
			p.Spec.Endpoints = []v1.PoolEndpoint{{Name: "whoami", URL: "https://whoami.example.com", CAConfigMap: "absent"}}
		})
		recorder := record.NewFakeRecorder(10)
		e.pool.Recorder = recorder

		_, err := e.pool.Reconcile(e.ctx, req(ns, "default"))
		if err == nil || !strings.Contains(err.Error(), `caConfigMap "absent"`) {
			t.Fatalf("reconcile error %v, want a missing ConfigMap error", err)
		}
		event := waitForEvent(t, recorder)
		if !strings.Contains(event, corev1.EventTypeWarning+" InvalidEndpointCA") {
			t.Errorf("event = %q, want a Warning InvalidEndpointCA event", event)
		}
	})

	t.Run("valid CA is accepted", func(t *testing.T) {
		e := newEnv(t)
		e.create(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "good-ca"},
			Data:       map[string]string{"ca.crt": validCA},
		})
		pool := &v1.BlipPool{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: ns},
			Spec: v1.BlipPoolSpec{
				Endpoints: []v1.PoolEndpoint{{Name: "whoami", URL: "https://whoami.example.com", CAConfigMap: "good-ca"}},
			},
		}
		if err := validateEndpointCAs(e.ctx, e.c, pool); err != nil {
			t.Fatalf("valid CA rejected: %v", err)
		}
	})
}

func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
