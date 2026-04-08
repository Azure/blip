package keygen

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/ssh"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

func Add(mgr ctrl.Manager, ns string) error {
	return mgr.Add(&initSecretsRunnable{
		cl:        mgr.GetClient(),
		namespace: ns,
	})
}

type initSecretsRunnable struct {
	cl        client.Client
	namespace string
}

func (r initSecretsRunnable) Start(ctx context.Context) error {
	slog.Info("initializing gateway keys")
	if err := ensureHostKey(ctx, r.cl, r.namespace); err != nil {
		return fmt.Errorf("ensure gateway host key: %w", err)
	}
	slog.Info("gateway host key initialized")

	if err := ensureClientKey(ctx, r.cl, r.namespace); err != nil {
		return fmt.Errorf("ensure gateway client key: %w", err)
	}
	slog.Info("gateway client key initialized")

	<-ctx.Done()
	return nil
}

func ensureSecret(ctx context.Context, cl client.Client, namespace, name string, data map[string][]byte) error {
	var existing corev1.Secret
	err := cl.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &existing)
	if err == nil {
		slog.Info("secret already exists, skipping", "secret", name)
		return nil
	}
	if !k8serrors.IsNotFound(err) {
		return fmt.Errorf("check secret %s: %w", name, err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Data: data,
	}
	if err := cl.Create(ctx, secret); err != nil {
		if k8serrors.IsAlreadyExists(err) {
			slog.Info("secret created concurrently, skipping", "secret", name)
			return nil
		}
		return fmt.Errorf("create secret %s: %w", name, err)
	}
	slog.Info("created secret", "secret", name)
	return nil
}

func ensureConfigMap(ctx context.Context, cl client.Client, namespace, name string, data map[string]string) error {
	var existing corev1.ConfigMap
	err := cl.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &existing)
	if err == nil {
		slog.Info("configmap already exists, skipping", "configmap", name)
		return nil
	}
	if !k8serrors.IsNotFound(err) {
		return fmt.Errorf("check configmap %s: %w", name, err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Data: data,
	}
	if err := cl.Create(ctx, cm); err != nil {
		if k8serrors.IsAlreadyExists(err) {
			slog.Info("configmap created concurrently, skipping", "configmap", name)
			return nil
		}
		return fmt.Errorf("create configmap %s: %w", name, err)
	}
	slog.Info("created configmap", "configmap", name)
	return nil
}

// ensureHostKey generates a stable Ed25519 host key for the SSH gateway.
// All replicas share this key so users see a consistent host fingerprint.
// The private key is stored in a Secret and the public key in a ConfigMap
// so VMs can pin the gateway identity for known_hosts.
func ensureHostKey(ctx context.Context, cl client.Client, namespace string) error {
	var privPEM []byte

	// Check if the Secret already exists; if so, derive the public key from it.
	var existing corev1.Secret
	err := cl.Get(ctx, client.ObjectKey{Namespace: namespace, Name: "ssh-host-key"}, &existing)
	if err == nil {
		privPEM = existing.Data["host_key"]
	} else if !k8serrors.IsNotFound(err) {
		return fmt.Errorf("check host key secret: %w", err)
	}

	// Generate a new key pair only if no Secret exists.
	if len(privPEM) == 0 {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate host key: %w", err)
		}
		pemBlock, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			return fmt.Errorf("marshal host key: %w", err)
		}
		privPEM = pem.EncodeToMemory(pemBlock)

		if err := ensureSecret(ctx, cl, namespace, "ssh-host-key", map[string][]byte{
			"host_key": privPEM,
		}); err != nil {
			return err
		}
	}

	// Derive the public key from the private key for the ConfigMap.
	signer, err := ssh.ParsePrivateKey(privPEM)
	if err != nil {
		return fmt.Errorf("parse host key for pubkey derivation: %w", err)
	}
	authorizedKey := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	return ensureConfigMap(ctx, cl, namespace, "ssh-gateway-host-pubkey", map[string]string{
		"host_key.pub": authorizedKey,
	})
}

// ensureClientKey generates a stable Ed25519 client key pair for the SSH
// gateway to use when connecting to VMs. The private key is stored in a
// Secret (mounted by the gateway pods) and the public key is stored in a
// ConfigMap so VMs can load it into their authorized_keys.
func ensureClientKey(ctx context.Context, cl client.Client, namespace string) error {
	var privPEM []byte

	// Check if the Secret already exists; if so, derive the public key from it.
	var existing corev1.Secret
	err := cl.Get(ctx, client.ObjectKey{Namespace: namespace, Name: "ssh-gateway-client-key"}, &existing)
	if err == nil {
		privPEM = existing.Data["client_key"]
	} else if !k8serrors.IsNotFound(err) {
		return fmt.Errorf("check client key secret: %w", err)
	}

	// Generate a new key pair only if no Secret exists.
	if len(privPEM) == 0 {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate client key: %w", err)
		}
		pemBlock, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			return fmt.Errorf("marshal client key: %w", err)
		}
		privPEM = pem.EncodeToMemory(pemBlock)

		if err := ensureSecret(ctx, cl, namespace, "ssh-gateway-client-key", map[string][]byte{
			"client_key": privPEM,
		}); err != nil {
			return err
		}
	}

	// Derive the public key from the private key for the ConfigMap.
	signer, err := ssh.ParsePrivateKey(privPEM)
	if err != nil {
		return fmt.Errorf("parse client key for pubkey derivation: %w", err)
	}
	authorizedKey := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	return ensureConfigMap(ctx, cl, namespace, "ssh-gateway-client-pubkey", map[string]string{
		"client_key.pub": authorizedKey,
	})
}
