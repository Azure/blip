package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// HostKeySecret holds the gateway's SSH host key.
	HostKeySecret = "blip-ssh-host-key"
	// UserCASecret holds the CA key that signs short-lived SSH user
	// certificates. It must be shared by all gateway replicas.
	UserCASecret = "blip-ssh-user-ca"
)

// LoadHostKey reads the host key from the Secret, creating it with a new
// ed25519 key if it does not exist. Concurrent replicas agree on one key.
func LoadHostKey(ctx context.Context, cs kubernetes.Interface, namespace string) (ssh.Signer, error) {
	return loadOrCreateSigner(ctx, cs, namespace, HostKeySecret)
}

// LoadUserCA reads the SSH user certificate CA key from the Secret, creating
// it with a new ed25519 key if it does not exist.
func LoadUserCA(ctx context.Context, cs kubernetes.Interface, namespace string) (ssh.Signer, error) {
	return loadOrCreateSigner(ctx, cs, namespace, UserCASecret)
}

func loadOrCreateSigner(ctx context.Context, cs kubernetes.Interface, namespace, name string) (ssh.Signer, error) {
	secrets := cs.CoreV1().Secrets(namespace)
	sec, err := secrets.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		sec, err = newKeySecret(namespace, name)
		if err == nil {
			_, err = secrets.Create(ctx, sec, metav1.CreateOptions{})
		}
		if apierrors.IsAlreadyExists(err) {
			sec, err = secrets.Get(ctx, name, metav1.GetOptions{})
		}
	}
	if err != nil {
		return nil, fmt.Errorf("key secret %s/%s: %w", namespace, name, err)
	}
	signer, err := ssh.ParsePrivateKey(sec.Data[corev1.SSHAuthPrivateKey])
	if err != nil {
		return nil, fmt.Errorf("key secret %s/%s: %w", namespace, name, err)
	}
	return signer, nil
}

func newKeySecret(namespace, name string) (*corev1.Secret, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, name)
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Type:       corev1.SecretTypeSSHAuth,
		Data:       map[string][]byte{corev1.SSHAuthPrivateKey: pem.EncodeToMemory(block)},
	}, nil
}
