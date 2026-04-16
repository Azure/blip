// Package tlscert manages a self-signed TLS certificate for the SSH gateway
// hostname. The private key is stored in a Secret in the blip namespace, and
// the public certificate (along with the previous certificate for trust
// continuity) is published in a ConfigMap in the kube-public namespace.
//
// Certificates are automatically rotated every hour or when the gateway
// hostname changes.
package tlscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// SecretName is the name of the Secret holding the TLS private key.
	SecretName = "gateway-tls-key"
	// ConfigMapName is the name of the ConfigMap holding the active and
	// previous TLS certificates.
	ConfigMapName = "gateway-tls-certs"
	// PublicNamespace is the namespace for the public ConfigMap.
	PublicNamespace = "kube-public"

	// certValidity is how long each generated certificate is valid for.
	// This is deliberately longer than the rotation interval so that
	// both the active and previous certs are valid simultaneously.
	certValidity = 24 * time.Hour

	// rotationInterval is how often we rotate to a fresh certificate.
	rotationInterval = 1 * time.Hour

	// retryInterval is the delay before retrying after a failed rotation.
	retryInterval = 30 * time.Second

	// Secret data keys.
	keyDataKey  = "tls.key"
	certDataKey = "tls.crt"

	// ConfigMap data keys.
	activeCertKey   = "active.crt"
	previousCertKey = "previous.crt"
	hostnameKey     = "hostname"
)

// Add registers the TLS certificate manager with the controller manager.
// The runnable blocks until the context is cancelled, periodically rotating
// the certificate.
func Add(mgr ctrl.Manager, namespace, gatewayHostname string) error {
	return mgr.Add(&certRotator{
		cl:               mgr.GetClient(),
		namespace:        namespace,
		gatewayHostname:  gatewayHostname,
		rotationInterval: rotationInterval,
	})
}

type certRotator struct {
	cl               client.Client
	namespace        string
	gatewayHostname  string
	rotationInterval time.Duration
}

func (r *certRotator) Start(ctx context.Context) error {
	slog.Info("tls cert rotator starting", "hostname", r.gatewayHostname)

	// Run an initial rotation immediately. On failure, fall through to the
	// ticker loop which will retry at retryInterval.
	if err := r.reconcile(ctx); err != nil {
		slog.Error("initial tls cert rotation failed, will retry", "error", err)
	}

	ticker := time.NewTicker(r.rotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.reconcile(ctx); err != nil {
				slog.Error("tls cert rotation failed, retrying shortly", "error", err)
				// Reset the ticker to a short retry interval. On success
				// the next reconcile will reset it back to rotationInterval.
				ticker.Reset(retryInterval)
			} else {
				ticker.Reset(r.rotationInterval)
			}
		}
	}
}

// reconcile ensures a valid TLS certificate exists. It rotates when:
//   - No certificate exists yet (first run)
//   - The hostname stored in the ConfigMap doesn't match the current hostname
//   - The rotation interval has elapsed (ticker fired)
func (r *certRotator) reconcile(ctx context.Context) error {
	// Check current state of the ConfigMap.
	var existingCM corev1.ConfigMap
	cmExists := false
	err := r.cl.Get(ctx, client.ObjectKey{Namespace: PublicNamespace, Name: ConfigMapName}, &existingCM)
	if err == nil {
		cmExists = true
	} else if !k8serrors.IsNotFound(err) {
		return fmt.Errorf("get configmap %s/%s: %w", PublicNamespace, ConfigMapName, err)
	}

	hostnameChanged := cmExists && existingCM.Data[hostnameKey] != r.gatewayHostname

	// Generate new key pair and certificate.
	keyPEM, certPEM, err := generateSelfSignedCert(r.gatewayHostname)
	if err != nil {
		return fmt.Errorf("generate self-signed cert: %w", err)
	}

	// Write private key and certificate to Secret in blip namespace.
	// Both are written atomically so the gateway always sees a matching pair.
	if err := r.writeSecret(ctx, keyPEM, certPEM); err != nil {
		return err
	}

	// Build ConfigMap data: new cert becomes active, old active becomes previous.
	previousCert := ""
	if cmExists {
		if hostnameChanged {
			// Hostname changed: don't carry over old cert from different hostname.
			slog.Info("gateway hostname changed, discarding previous cert",
				"old", existingCM.Data[hostnameKey],
				"new", r.gatewayHostname)
		} else {
			previousCert = existingCM.Data[activeCertKey]
		}
	}

	cmData := map[string]string{
		activeCertKey: string(certPEM),
		hostnameKey:   r.gatewayHostname,
	}
	if previousCert != "" {
		cmData[previousCertKey] = previousCert
	}

	if err := r.writeConfigMap(ctx, &existingCM, cmExists, cmData); err != nil {
		return err
	}

	slog.Info("tls cert rotated", "hostname", r.gatewayHostname, "hostname_changed", hostnameChanged)
	return nil
}

func (r *certRotator) writeSecret(ctx context.Context, keyPEM, certPEM []byte) error {
	data := map[string][]byte{keyDataKey: keyPEM, certDataKey: certPEM}
	var existing corev1.Secret
	err := r.cl.Get(ctx, client.ObjectKey{Namespace: r.namespace, Name: SecretName}, &existing)
	if k8serrors.IsNotFound(err) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: r.namespace,
				Name:      SecretName,
			},
			Data: data,
		}
		if err := r.cl.Create(ctx, secret); err != nil {
			if k8serrors.IsAlreadyExists(err) {
				// Lost the race; fetch and update.
				if err := r.cl.Get(ctx, client.ObjectKey{Namespace: r.namespace, Name: SecretName}, &existing); err != nil {
					return fmt.Errorf("get secret after race: %w", err)
				}
				existing.Data = data
				return r.cl.Update(ctx, &existing)
			}
			return fmt.Errorf("create secret %s: %w", SecretName, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get secret %s: %w", SecretName, err)
	}

	existing.Data = data
	if err := r.cl.Update(ctx, &existing); err != nil {
		return fmt.Errorf("update secret %s: %w", SecretName, err)
	}
	return nil
}

func (r *certRotator) writeConfigMap(ctx context.Context, existing *corev1.ConfigMap, exists bool, data map[string]string) error {
	if !exists {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: PublicNamespace,
				Name:      ConfigMapName,
			},
			Data: data,
		}
		if err := r.cl.Create(ctx, cm); err != nil {
			if k8serrors.IsAlreadyExists(err) {
				// Lost race; fetch and update.
				if err := r.cl.Get(ctx, client.ObjectKey{Namespace: PublicNamespace, Name: ConfigMapName}, existing); err != nil {
					return fmt.Errorf("get configmap after race: %w", err)
				}
				existing.Data = data
				return r.cl.Update(ctx, existing)
			}
			return fmt.Errorf("create configmap %s/%s: %w", PublicNamespace, ConfigMapName, err)
		}
		return nil
	}

	// Update using the existing object which already has the correct ResourceVersion.
	existing.Data = data
	if err := r.cl.Update(ctx, existing); err != nil {
		return fmt.Errorf("update configmap %s/%s: %w", PublicNamespace, ConfigMapName, err)
	}
	return nil
}

// generateSelfSignedCert creates an ECDSA P-256 private key and a self-signed
// X.509 certificate for the given hostname. Returns PEM-encoded key and cert.
func generateSelfSignedCert(hostname string) (keyPEM, certPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ecdsa key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		DNSNames:              []string{hostname},
		NotBefore:             now.Add(-5 * time.Minute), // small clock-skew tolerance
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return keyPEM, certPEM, nil
}
