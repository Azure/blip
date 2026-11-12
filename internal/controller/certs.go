package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/example/blip/internal/api"
)

// Secret and ConfigMap keys.
const (
	keyCACert  = "ca.crt"
	keyCAKey   = "ca.key"
	keyTLSCert = "tls.crt"
	keyTLSKey  = "tls.key"
	keyPSK     = "key"
)

// servingNames are the DNS names of the controller Service.
func servingNames(service, ns string, extra []string) []string {
	n := []string{service, service + "." + ns, service + "." + ns + ".svc", service + "." + ns + ".svc.cluster.local"}
	return append(n, extra...)
}

// ensureCerts loads or creates the CA and serving certificate in Secret blip-ca,
// publishes the CA in ConfigMap blip-ca and returns the serving certificate.
func ensureCerts(ctx context.Context, c client.Client, ns string, names []string) (tls.Certificate, []byte, error) {
	for range 5 {
		cert, caPEM, err := ensureCertsOnce(ctx, c, ns, names)
		if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) {
			continue
		}
		if err != nil {
			return cert, nil, err
		}
		if err := publishCA(ctx, c, ns, caPEM); err != nil {
			return cert, nil, err
		}
		return cert, caPEM, nil
	}
	return tls.Certificate{}, nil, fmt.Errorf("certificate secret keeps changing")
}

func ensureCertsOnce(ctx context.Context, c client.Client, ns string, names []string) (tls.Certificate, []byte, error) {
	var s corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: api.CASecret}, &s)
	exists := err == nil
	if err != nil && !apierrors.IsNotFound(err) {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	caCert, caKey, caOK := parseCA(s.Data[keyCACert], s.Data[keyCAKey], now)
	if caOK {
		if cert, err := tls.X509KeyPair(s.Data[keyTLSCert], s.Data[keyTLSKey]); err == nil && servingValid(cert, caCert, names, now) {
			return cert, s.Data[keyCACert], nil
		}
	} else {
		var err error
		caCert, caKey, err = newCA(now)
		if err != nil {
			return tls.Certificate{}, nil, err
		}
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM, keyPEM, err := newServing(caCert, caKey, names, now)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	s.Data = map[string][]byte{
		keyCACert:  caPEM,
		keyCAKey:   pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER}),
		keyTLSCert: certPEM,
		keyTLSKey:  keyPEM,
	}
	s.Type = corev1.SecretTypeOpaque
	if exists {
		err = c.Update(ctx, &s)
	} else {
		s.ObjectMeta = metav1.ObjectMeta{Namespace: ns, Name: api.CASecret}
		err = c.Create(ctx, &s)
	}
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	return cert, caPEM, err
}

func parseCA(certPEM, keyPEM []byte, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, bool) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, false
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, false
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil || now.Add(90*24*time.Hour).After(cert.NotAfter) {
		return nil, nil, false
	}
	return cert, key, true
}

func servingValid(cert tls.Certificate, ca *x509.Certificate, names []string, now time.Time) bool {
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || now.Add(30*24*time.Hour).After(leaf.NotAfter) || leaf.CheckSignatureFrom(ca) != nil {
		return false
	}
	for _, n := range names {
		if !slices.Contains(leaf.DNSNames, n) {
			return false
		}
	}
	return true
}

func newCA(now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "blip-controller-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

func newServing(ca *x509.Certificate, caKey *ecdsa.PrivateKey, names []string, now time.Time) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func publishCA(ctx context.Context, c client.Client, ns string, caPEM []byte) error {
	var cm corev1.ConfigMap
	err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: api.CAConfigMap}, &cm)
	if apierrors.IsNotFound(err) {
		cm = corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: api.CAConfigMap}, Data: map[string]string{keyCACert: string(caPEM)}}
		return c.Create(ctx, &cm)
	}
	if err != nil {
		return err
	}
	if cm.Data[keyCACert] == string(caPEM) {
		return nil
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[keyCACert] = string(caPEM)
	return c.Update(ctx, &cm)
}

// ensureClusterKey loads or creates the 32-byte NVMe cluster key (design 7.3).
func ensureClusterKey(ctx context.Context, c client.Client, ns string) ([]byte, error) {
	for range 3 {
		var s corev1.Secret
		err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: api.NVMePSKSecret}, &s)
		if err == nil {
			if k := s.Data[keyPSK]; len(k) == 32 {
				return k, nil
			}
			return nil, fmt.Errorf("secret %s/%s: key %q must be 32 bytes", ns, api.NVMePSKSecret, keyPSK)
		}
		if !apierrors.IsNotFound(err) {
			return nil, err
		}
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		s = corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: api.NVMePSKSecret}, Data: map[string][]byte{keyPSK: k}}
		if err := c.Create(ctx, &s); err == nil {
			return k, nil
		} else if !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("could not load secret %s", api.NVMePSKSecret)
}
