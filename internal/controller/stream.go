// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	// StreamServiceName is the Service the aggregated stream API is served
	// from. Node agents listen on StreamPort.
	StreamServiceName = "blip-stream"
	// StreamPort is the aggregated API port.
	StreamPort = 7891
	// StreamTLSSecret holds the serving certificate and its CA.
	StreamTLSSecret = "blip-stream-tls"
	// StreamAPIService is the APIService object name.
	StreamAPIService = "v1alpha1.stream.blip.dev"
	// StreamGroup is the aggregated API group.
	StreamGroup = "stream.blip.dev"
	// StreamVersion is the aggregated API version.
	StreamVersion = "v1alpha1"
	// IdentityAPIService is the identity APIService object name.
	IdentityAPIService = "v1alpha1.identity.blip.dev"
	// IdentityGroup is the aggregated identity API group.
	IdentityGroup = "identity.blip.dev"
	// IdentityVersion is the aggregated identity API version.
	IdentityVersion = "v1alpha1"
)

// streamTLS keeps the serving certificate, its Secret, and the APIServices in
// sync. It runs on the leader only.
type streamTLS struct {
	client    client.Client
	namespace string
	now       func() time.Time
}

func (r *streamTLS) NeedLeaderElection() bool { return true }

func (r *streamTLS) Start(ctx context.Context) error {
	r.ensure(ctx)
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.ensure(ctx)
		}
	}
}

func (r *streamTLS) ensure(ctx context.Context) {
	if err := r.ensureSecret(ctx); err != nil && ctx.Err() == nil {
		ctrl.Log.Error(err, "stream TLS")
		return
	}
	if err := r.ensureAPIService(ctx, StreamAPIService, StreamGroup, StreamVersion); err != nil && ctx.Err() == nil {
		ctrl.Log.Error(err, "stream APIService")
	}
	if err := r.ensureAPIService(ctx, IdentityAPIService, IdentityGroup, IdentityVersion); err != nil && ctx.Err() == nil {
		ctrl.Log.Error(err, "identity APIService")
	}
}

func (r *streamTLS) ensureSecret(ctx context.Context) error {
	name := client.ObjectKey{Namespace: r.namespace, Name: StreamTLSSecret}
	var sec corev1.Secret
	err := r.client.Get(ctx, name, &sec)
	notFound := apierrors.IsNotFound(err)
	if err == nil && validServingCert(sec.Data["tls.crt"], r.namespace, r.now().Add(30*24*time.Hour)) {
		return nil
	}
	if err != nil && !notFound {
		return err
	}
	data, err := generateServingCert(r.namespace, r.now())
	if err != nil {
		return err
	}
	if notFound {
		sec = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: r.namespace, Name: StreamTLSSecret},
			Type:       corev1.SecretTypeTLS,
			Data:       data,
		}
		return r.client.Create(ctx, &sec)
	}
	sec.Data = data
	return r.client.Update(ctx, &sec)
}

func (r *streamTLS) ensureAPIService(ctx context.Context, name, group, version string) error {
	var sec corev1.Secret
	if err := r.client.Get(ctx, client.ObjectKey{Namespace: r.namespace, Name: StreamTLSSecret}, &sec); err != nil {
		return err
	}
	api := &unstructured.Unstructured{Object: map[string]any{}}
	api.SetGroupVersionKind(schema.GroupVersionKind{Group: "apiregistration.k8s.io", Version: "v1", Kind: "APIService"})
	api.SetName(name)
	spec := map[string]any{
		"group":                group,
		"version":              version,
		"groupPriorityMinimum": int64(100),
		"versionPriority":      int64(100),
		"service": map[string]any{
			"name":      StreamServiceName,
			"namespace": r.namespace,
			"port":      int64(StreamPort),
		},
		"caBundle":              base64.StdEncoding.EncodeToString(sec.Data["ca.crt"]),
		"insecureSkipTLSVerify": false,
	}
	var cur unstructured.Unstructured
	cur.SetGroupVersionKind(schema.GroupVersionKind{Group: "apiregistration.k8s.io", Version: "v1", Kind: "APIService"})
	err := r.client.Get(ctx, client.ObjectKey{Name: name}, &cur)
	if apierrors.IsNotFound(err) {
		if err := unstructured.SetNestedMap(api.Object, spec, "spec"); err != nil {
			return err
		}
		return r.client.Create(ctx, api)
	}
	if err != nil {
		return err
	}
	if err := unstructured.SetNestedMap(cur.Object, spec, "spec"); err != nil {
		return err
	}
	return r.client.Update(ctx, &cur)
}

// validServingCert reports whether the PEM chain is a currently valid serving
// certificate for the service DNS names.
func validServingCert(pemData []byte, namespace string, until time.Time) bool {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	if cert.NotAfter.Before(until) {
		return false
	}
	for _, name := range cert.DNSNames {
		if name == StreamServiceName+"."+namespace+".svc" {
			return true
		}
	}
	return false
}

func generateServingCert(namespace string, now time.Time) (map[string][]byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(now, 1),
		Subject:               pkix.Name{CommonName: "blip-stream-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	dns := []string{
		StreamServiceName,
		StreamServiceName + "." + namespace,
		StreamServiceName + "." + namespace + ".svc",
		StreamServiceName + "." + namespace + ".svc.cluster.local",
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(now, 2),
		Subject:      pkix.Name{CommonName: dns[3]},
		DNSNames:     dns,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return map[string][]byte{"tls.crt": pemCert, "tls.key": keyPEM, "ca.crt": caPEM}, nil
}

func serial(now time.Time, n int64) *big.Int {
	return new(big.Int).SetInt64(now.Unix()*10 + n)
}

// addStreamTLS installs the certificate manager.
func addStreamTLS(mgr manager.Manager, namespace string, now func() time.Time) error {
	return mgr.Add(&streamTLS{client: mgr.GetClient(), namespace: namespace, now: now})
}
