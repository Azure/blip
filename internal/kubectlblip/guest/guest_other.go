//go:build !linux

package guest

import "context"

func metaIdentity() (Identity, bool, error) { return Identity{}, false, nil }

// Sync does nothing outside Linux.
func Sync() {}

// FindDevice returns "" outside Linux.
func FindDevice(string) string { return "" }

// WaitDevice fails outside Linux.
func WaitDevice(context.Context, string) (string, error) { return "", ErrUnsupported }

// Mount fails outside Linux.
func Mount(context.Context, string, string, bool) error { return ErrUnsupported }

// UnmountDevice fails outside Linux.
func UnmountDevice(string) ([]string, error) { return nil, ErrUnsupported }
