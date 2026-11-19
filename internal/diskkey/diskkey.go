// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package diskkey manages the cluster disk key: one dm-crypt key shared by
// every node, because volumes move between nodes as ciphertext.
package diskkey

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// SecretName is the Secret holding the disk key. Losing it makes every
	// volume on every node unreadable.
	SecretName = "blip-disk-key"
	// DataKey is the Secret data key holding the raw key bytes.
	DataKey = "key"
	// Size is the key length: aes-xts-plain64 with a 512-bit key.
	Size = 64
)

var pollInterval = 3 * time.Second

// Ensure creates the disk key Secret if it does not exist. An existing
// Secret is never changed.
func Ensure(ctx context.Context, c client.Client, namespace string) error {
	key := make([]byte, Size)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	immutable := true
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: SecretName, Namespace: namespace},
		Type:       corev1.SecretTypeOpaque,
		Immutable:  &immutable,
		Data:       map[string][]byte{DataKey: key},
	}
	if err := c.Create(ctx, sec); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create secret %s/%s: %w", namespace, SecretName, err)
	}
	return nil
}

// Load waits until the disk key Secret exists and returns the key.
func Load(ctx context.Context, c client.Reader, namespace string) ([]byte, error) {
	logged := false
	for {
		sec := &corev1.Secret{}
		err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: SecretName}, sec)
		if err == nil {
			key := sec.Data[DataKey]
			if len(key) != Size {
				return nil, fmt.Errorf("secret %s/%s: key is %d bytes, want %d", namespace, SecretName, len(key), Size)
			}
			return key, nil
		}
		if !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("get secret %s/%s: %w", namespace, SecretName, err)
		}
		if !logged {
			slog.Info("waiting for disk key secret", "namespace", namespace, "name", SecretName)
			logged = true
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}
