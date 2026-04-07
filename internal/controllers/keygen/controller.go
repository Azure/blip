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

	"github.com/project-unbounded/blip/internal/sshca"
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
	slog.Info("initializing SSH CA")
	if err := ensureCA(ctx, r.cl, r.namespace); err != nil {
		return fmt.Errorf("ensure SSH CA: %w", err)
	}
	slog.Info("SSH CA initialized")

	slog.Info("initializing gateway host key")
	if err := ensureHostKey(ctx, r.cl, r.namespace); err != nil {
		return fmt.Errorf("ensure gateway host key: %w", err)
	}
	slog.Info("gateway host key initialized")

	<-ctx.Done()
	return nil
}

// ensureCA creates the SSH CA keypair Secret and a ConfigMap with the public key.
func ensureCA(ctx context.Context, cl client.Client, namespace string) error {
	caPrivPEM, caPub, err := sshca.GenerateCAKeypair()
	if err != nil {
		return fmt.Errorf("generate SSH CA keypair: %w", err)
	}

	if err := ensureSecret(ctx, cl, namespace, "ssh-ca-keypair", map[string][]byte{
		"ca": caPrivPEM,
	}); err != nil {
		return err
	}

	// Resolve the public key from the persisted secret so we always
	// publish the original CA even if this controller restarted and
	// generated a new random keypair above.
	caPubResolved, err := resolvePublicKey(ctx, cl, namespace, "ssh-ca-keypair", "ca", caPub)
	if err != nil {
		return fmt.Errorf("resolve CA public key: %w", err)
	}

	if err := ensureConfigMap(ctx, cl, namespace, "ssh-ca-pubkey", map[string]string{
		"ca.pub": caPubResolved + "\n",
	}); err != nil {
		return err
	}

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

func resolvePublicKey(ctx context.Context, cl client.Client, namespace, secretName, dataKey, fallback string) (string, error) {
	var s corev1.Secret
	if err := cl.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, &s); err != nil {
		if k8serrors.IsNotFound(err) {
			return fallback, nil
		}
		return "", fmt.Errorf("get secret %s: %w", secretName, err)
	}
	privBytes, ok := s.Data[dataKey]
	if !ok {
		return fallback, nil
	}

	signer, err := sshca.ParseCAPrivateKey(privBytes)
	if err != nil {
		return "", fmt.Errorf("parse private key from %s/%s: %w", secretName, dataKey, err)
	}

	pub := sshca.MarshalPublicKey(signer.PublicKey())
	return pub, nil
}

// ensureHostKey generates a stable Ed25519 host key for the SSH gateway.
// All replicas share this key so users see a consistent host fingerprint.
func ensureHostKey(ctx context.Context, cl client.Client, namespace string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate host key: %w", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return fmt.Errorf("marshal host key: %w", err)
	}

	return ensureSecret(ctx, cl, namespace, "ssh-host-key", map[string][]byte{
		"host_key": pem.EncodeToMemory(pemBlock),
	})
}
