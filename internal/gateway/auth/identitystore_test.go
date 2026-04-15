package auth

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func newFakeIdentityStore(t *testing.T, ttl time.Duration, objects ...runtime.Object) (*IdentityStore, *fake.Clientset) {
	t.Helper()
	client := fake.NewSimpleClientset(objects...)
	ctx := context.Background()

	store, err := NewIdentityStoreWithClient(ctx, client, "blip", ttl)
	require.NoError(t, err)

	return store, client
}

func TestIdentityStore_StoreAndLookup(t *testing.T) {
	store, _ := newFakeIdentityStore(t, 24*time.Hour)

	ctx := context.Background()

	// Store an identity with a linked pubkey.
	err := store.StoreIdentity(ctx, "oidc:alice", "https://issuer.example.com", "refresh-token-123", "SHA256:abc123", "ssh-ed25519 AAAA... oidc:alice")
	require.NoError(t, err)

	// Lookup by pubkey should return the identity.
	result, err := store.LookupByPubkey(ctx, "SHA256:abc123")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "oidc:alice", result.OIDCIdentity)
	assert.Equal(t, "https://issuer.example.com", result.Issuer)
	assert.Equal(t, "refresh-token-123", result.RefreshToken)

	// Unknown pubkey should return nil.
	result, err = store.LookupByPubkey(ctx, "SHA256:unknown")
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestIdentityStore_UpdateRefreshToken(t *testing.T) {
	store, _ := newFakeIdentityStore(t, 24*time.Hour)
	ctx := context.Background()

	err := store.StoreIdentity(ctx, "oidc:bob", "https://issuer.example.com", "old-token", "SHA256:bob-key", "ssh-ed25519 AAAA... oidc:bob")
	require.NoError(t, err)

	// Update the refresh token.
	err = store.UpdateRefreshToken(ctx, "oidc:bob", "new-token")
	require.NoError(t, err)

	// Verify the new token is returned.
	result, err := store.LookupByPubkey(ctx, "SHA256:bob-key")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "new-token", result.RefreshToken)
}

func TestIdentityStore_TouchPubkey(t *testing.T) {
	store, client := newFakeIdentityStore(t, 24*time.Hour)
	ctx := context.Background()

	err := store.StoreIdentity(ctx, "oidc:charlie", "https://issuer.example.com", "token", "SHA256:charlie-key", "ssh-ed25519 AAAA... oidc:charlie")
	require.NoError(t, err)

	// Touch the pubkey.
	err = store.TouchPubkey(ctx, "SHA256:charlie-key")
	require.NoError(t, err)

	// Verify the secret was updated (the last_used timestamp should be recent).
	secretName := identitySecretName("oidc:charlie")
	secret, err := client.CoreV1().Secrets("blip").Get(ctx, secretName, metav1.GetOptions{})
	require.NoError(t, err)

	record, err := parseIdentityRecord(secret)
	require.NoError(t, err)
	require.Len(t, record.LinkedPubkeys, 1)
	assert.WithinDuration(t, time.Now(), record.LinkedPubkeys[0].LastUsed, 5*time.Second)
}

func TestIdentityStore_ExpiredLinkReturnsNil(t *testing.T) {
	store, _ := newFakeIdentityStore(t, 1*time.Millisecond) // Very short TTL.
	ctx := context.Background()

	err := store.StoreIdentity(ctx, "oidc:dave", "https://issuer.example.com", "token", "SHA256:dave-key", "ssh-ed25519 AAAA... oidc:dave")
	require.NoError(t, err)

	// Wait for the TTL to expire.
	time.Sleep(10 * time.Millisecond)

	// Lookup should return nil because the link is expired.
	result, err := store.LookupByPubkey(ctx, "SHA256:dave-key")
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestIdentityStore_SweepExpiredLinks(t *testing.T) {
	store, client := newFakeIdentityStore(t, 1*time.Millisecond) // Very short TTL.
	ctx := context.Background()

	err := store.StoreIdentity(ctx, "oidc:eve", "https://issuer.example.com", "token", "SHA256:eve-key", "ssh-ed25519 AAAA... oidc:eve")
	require.NoError(t, err)

	// Wait for the link to expire.
	time.Sleep(10 * time.Millisecond)

	// Run the sweep.
	err = store.sweepExpiredLinks(ctx)
	require.NoError(t, err)

	// The secret should be deleted (no more linked pubkeys).
	secretName := identitySecretName("oidc:eve")
	_, err = client.CoreV1().Secrets("blip").Get(ctx, secretName, metav1.GetOptions{})
	assert.True(t, err != nil, "secret should be deleted after sweep")
}

func TestIdentityStore_MultiplePubkeysLinked(t *testing.T) {
	store, _ := newFakeIdentityStore(t, 24*time.Hour)
	ctx := context.Background()

	// Store identity with first pubkey.
	err := store.StoreIdentity(ctx, "oidc:frank", "https://issuer.example.com", "token", "SHA256:key1", "ssh-ed25519 AAAA1... oidc:frank")
	require.NoError(t, err)

	// Link a second pubkey to the same identity.
	err = store.StoreIdentity(ctx, "oidc:frank", "https://issuer.example.com", "token", "SHA256:key2", "ssh-ed25519 AAAA2... oidc:frank")
	require.NoError(t, err)

	// Both pubkeys should resolve to the same identity.
	result1, err := store.LookupByPubkey(ctx, "SHA256:key1")
	require.NoError(t, err)
	require.NotNil(t, result1)
	assert.Equal(t, "oidc:frank", result1.OIDCIdentity)

	result2, err := store.LookupByPubkey(ctx, "SHA256:key2")
	require.NoError(t, err)
	require.NotNil(t, result2)
	assert.Equal(t, "oidc:frank", result2.OIDCIdentity)
}

func TestIdentityStore_StoreWithoutPubkey(t *testing.T) {
	store, _ := newFakeIdentityStore(t, 24*time.Hour)
	ctx := context.Background()

	// Store identity without a pubkey.
	err := store.StoreIdentity(ctx, "oidc:grace", "https://issuer.example.com", "token", "", "")
	require.NoError(t, err)

	// No pubkey should be in the cache.
	result, err := store.LookupByPubkey(ctx, "SHA256:any")
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestIdentityStore_RebuildCache(t *testing.T) {
	// Create a pre-existing secret to simulate restart.
	secretName := identitySecretName("oidc:hank")
	record := IdentityRecord{
		OIDCIdentity: "oidc:hank",
		Issuer:       "https://issuer.example.com",
		RefreshToken: "pre-existing-token",
		LinkedPubkeys: []LinkedPubkey{
			{
				Fingerprint:   "SHA256:hank-key",
				AuthorizedKey: "ssh-ed25519 AAAA... oidc:hank",
				LastUsed:      time.Now(),
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	data, err := json.Marshal(record)
	require.NoError(t, err)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: "blip",
			Labels: map[string]string{
				identitySecretLabel: "true",
			},
		},
		Data: map[string][]byte{
			"identity": data,
		},
	}

	store, _ := newFakeIdentityStore(t, 24*time.Hour, secret)
	ctx := context.Background()

	// The cache should have been rebuilt from the existing secret.
	result, err := store.LookupByPubkey(ctx, "SHA256:hank-key")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "oidc:hank", result.OIDCIdentity)
	assert.Equal(t, "pre-existing-token", result.RefreshToken)
}

func TestIdentitySecretName(t *testing.T) {
	// Should be deterministic.
	name1 := identitySecretName("oidc:alice")
	name2 := identitySecretName("oidc:alice")
	assert.Equal(t, name1, name2)

	// Different identities should have different names.
	name3 := identitySecretName("oidc:bob")
	assert.NotEqual(t, name1, name3)

	// Should have the expected prefix.
	assert.True(t, len(name1) > len(identitySecretPrefix))
	assert.Contains(t, name1, identitySecretPrefix)
}
