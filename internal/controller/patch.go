package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"k8s.io/apimachinery/pkg/api/equality"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// newID returns 16 lowercase hex characters (attachment and commit IDs).
func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// patchStatus sends the status difference between base and obj as a merge
// patch that fails with a conflict if obj changed since base was read. Only
// changed fields are sent, so fields owned by other writers (for example
// BlipState.status.nodes) are never touched.
func patchStatus(ctx context.Context, c client.Client, obj, base client.Object) error {
	return c.Status().Patch(ctx, obj, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
}

// patchObject is patchStatus for metadata and spec.
func patchObject(ctx context.Context, c client.Client, obj, base client.Object) error {
	return c.Patch(ctx, obj, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
}

func semanticEqual(a, b any) bool { return equality.Semantic.DeepEqual(a, b) }
