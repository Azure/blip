package node

import (
	"errors"

	"github.com/example/blip/internal/node/nodestorage"
	pb "github.com/example/blip/internal/proto/nodepb"
	"github.com/example/blip/internal/storage"
)

// The storage interface and its types live in package nodestorage, so
// test fakes can implement it without importing this package.
type (
	Storage           = nodestorage.Storage
	VolumeSpec        = nodestorage.VolumeSpec
	ReceiveSpec       = nodestorage.ReceiveSpec
	CaptureResult     = nodestorage.CaptureResult
	SnapshotSource    = nodestorage.SnapshotSource
	StorageState      = nodestorage.StorageState
	AttachmentStorage = nodestorage.AttachmentStorage
	LocalSnapStorage  = nodestorage.LocalSnapStorage
	CodeError         = nodestorage.CodeError
)

// WithCode wraps err with code.
func WithCode(code pb.ErrorCode, err error) error { return nodestorage.WithCode(code, err) }

// Codef is WithCode with a formatted message.
func Codef(code pb.ErrorCode, format string, args ...any) error {
	return nodestorage.Codef(code, format, args...)
}

// ErrorCodeOf returns the code of err, or ERROR_CODE_UNSPECIFIED.
func ErrorCodeOf(err error) pb.ErrorCode {
	var ce *CodeError
	if errors.As(err, &ce) {
		return ce.Code
	}
	var rej *errReject
	if errors.As(err, &rej) {
		return rej.code
	}
	if errors.Is(err, storage.ErrStaleGeneration) {
		return pb.ErrorCode_ERROR_CODE_STALE_GENERATION
	}
	return pb.ErrorCode_ERROR_CODE_UNSPECIFIED
}
