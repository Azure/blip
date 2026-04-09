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
	return ensureKeyPair(ctx, cl, namespace, "ssh-host-key", "host_key", "ssh-gateway-host-pubkey", "host_key.pub", "host key")
}

// ensureClientKey generates a stable Ed25519 client key pair for the SSH
// gateway to use when connecting to VMs. The private key is stored in a
// Secret (mounted by the gateway pods) and the public key is stored in a
// ConfigMap so VMs can load it into their authorized_keys.
func ensureClientKey(ctx context.Context, cl client.Client, namespace string) error {
	return ensureKeyPair(ctx, cl, namespace, "ssh-gateway-client-key", "client_key", "ssh-gateway-client-pubkey", "client_key.pub", "client key")
}

// ensureKeyPair generates and stores an Ed25519 key pair as a Secret (private)
// and ConfigMap (public authorized_keys format). If the Secret already exists,
// the public key is derived from it without regeneration.
func ensureKeyPair(ctx context.Context, cl client.Client, namespace, secretName, secretKey, cmName, cmKey, label string) error {
	var privPEM []byte

	var existing corev1.Secret
	err := cl.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, &existing)
	if err == nil {
		privPEM = existing.Data[secretKey]
	} else if !k8serrors.IsNotFound(err) {
		return fmt.Errorf("check %s secret: %w", label, err)
	}

	if len(privPEM) == 0 {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate %s: %w", label, err)
		}
		pemBlock, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			return fmt.Errorf("marshal %s: %w", label, err)
		}
		privPEM = pem.EncodeToMemory(pemBlock)

		if err := ensureSecret(ctx, cl, namespace, secretName, map[string][]byte{
			secretKey: privPEM,
		}); err != nil {
			return err
		}
	}

	signer, err := ssh.ParsePrivateKey(privPEM)
	if err != nil {
		return fmt.Errorf("parse %s for pubkey derivation: %w", label, err)
	}
	authorizedKey := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	return ensureConfigMap(ctx, cl, namespace, cmName, map[string]string{
		cmKey: authorizedKey,
	})
}
