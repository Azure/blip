package blip

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// sshConn returns the SSH client, or ErrClosed if the blip is closed.
// The returned connection remains valid for use after the lock is released;
// concurrent Close calls will shut down the underlying transport, causing
// in-flight operations to fail with an I/O error.
func (b *Blip) sshConn() (*ssh.Client, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrClosed
	}
	return b.conn, nil
}

// SFTPClient returns an SFTP client connected to the blip VM.
// The client operates over the SSH connection proxied through the gateway
// and supports all standard SFTP operations: file transfer, directory
// listing, permissions, symlinks, etc.
//
// Callers are responsible for closing the returned client when done.
// The SFTP client uses a dedicated SSH subsystem channel; closing it
// does not affect the Blip connection or other sessions.
//
// For simple file transfers, prefer [Blip.Upload], [Blip.Download],
// [Blip.UploadDir], or [Blip.DownloadDir]. Use SFTPClient when you
// need full control (e.g. stat, symlinks, streaming).
func (b *Blip) SFTPClient() (*sftp.Client, error) {
	conn, err := b.sshConn()
	if err != nil {
		return nil, err
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		return nil, fmt.Errorf("open SFTP session: %w", err)
	}
	return client, nil
}

// Upload copies a local file to the blip VM. The remote file is created
// with the same permissions as the local file. Parent directories on the
// remote side must already exist.
//
// Upload does not support directories; use [Blip.UploadDir] for recursive
// transfers, or [Blip.UploadReader] to upload from an [io.Reader].
func (b *Blip) Upload(ctx context.Context, localPath, remotePath string) error {
	local, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local file: %w", err)
	}
	defer local.Close()

	info, err := local.Stat()
	if err != nil {
		return fmt.Errorf("stat local file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("cannot upload directory %s; use UploadDir instead", localPath)
	}

	sftpClient, err := b.SFTPClient()
	if err != nil {
		return err
	}
	defer sftpClient.Close()

	remote, err := sftpClient.Create(remotePath)
	if err != nil {
		return fmt.Errorf("create remote file %s: %w", remotePath, err)
	}

	if err := copyWithContext(ctx, remote, local); err != nil {
		remote.Close()
		return fmt.Errorf("upload %s -> %s: %w", localPath, remotePath, err)
	}

	if err := remote.Close(); err != nil {
		return fmt.Errorf("close remote file %s: %w", remotePath, err)
	}

	if err := sftpClient.Chmod(remotePath, info.Mode().Perm()); err != nil {
		return fmt.Errorf("chmod remote file %s: %w", remotePath, err)
	}

	return nil
}

// Download copies a file from the blip VM to the local filesystem.
// The local file is created with the remote file's permissions. Parent
// directories on the local side must already exist.
//
// The local file is written atomically: data is first written to a
// temporary file in the same directory, then renamed on success. If
// the transfer fails, no partial file is left behind.
//
// Download does not support directories; use [Blip.DownloadDir] for
// recursive transfers, or [Blip.DownloadWriter] to download to an
// [io.Writer].
func (b *Blip) Download(ctx context.Context, remotePath, localPath string) error {
	sftpClient, err := b.SFTPClient()
	if err != nil {
		return err
	}
	defer sftpClient.Close()

	remote, err := sftpClient.Open(remotePath)
	if err != nil {
		return fmt.Errorf("open remote file %s: %w", remotePath, err)
	}
	defer remote.Close()

	info, err := remote.Stat()
	if err != nil {
		return fmt.Errorf("stat remote file %s: %w", remotePath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("cannot download directory %s; use DownloadDir instead", remotePath)
	}

	perm := info.Mode().Perm()

	// Write to a temp file first, then rename atomically on success.
	dir := filepath.Dir(localPath)
	tmp, err := os.CreateTemp(dir, ".blip-download-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	if err := copyWithContext(ctx, tmp, remote); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("download %s -> %s: %w", remotePath, localPath, err)
	}

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("chmod temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpName, localPath); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename %s -> %s: %w", tmpName, localPath, err)
	}

	return nil
}

// UploadReader copies data from r to a file on the blip VM with the
// given permissions. Parent directories on the remote side must already
// exist.
func (b *Blip) UploadReader(ctx context.Context, r io.Reader, remotePath string, perm fs.FileMode) error {
	sftpClient, err := b.SFTPClient()
	if err != nil {
		return err
	}
	defer sftpClient.Close()

	remote, err := sftpClient.Create(remotePath)
	if err != nil {
		return fmt.Errorf("create remote file %s: %w", remotePath, err)
	}

	if err := copyWithContext(ctx, remote, r); err != nil {
		remote.Close()
		return fmt.Errorf("upload to %s: %w", remotePath, err)
	}

	if err := remote.Close(); err != nil {
		return fmt.Errorf("close remote file %s: %w", remotePath, err)
	}

	if err := sftpClient.Chmod(remotePath, perm); err != nil {
		return fmt.Errorf("chmod remote file %s: %w", remotePath, err)
	}

	return nil
}

// DownloadWriter copies a file from the blip VM to w.
func (b *Blip) DownloadWriter(ctx context.Context, remotePath string, w io.Writer) error {
	sftpClient, err := b.SFTPClient()
	if err != nil {
		return err
	}
	defer sftpClient.Close()

	remote, err := sftpClient.Open(remotePath)
	if err != nil {
		return fmt.Errorf("open remote file %s: %w", remotePath, err)
	}
	defer remote.Close()

	if err := copyWithContext(ctx, w, remote); err != nil {
		return fmt.Errorf("download %s: %w", remotePath, err)
	}

	return nil
}

// UploadDir recursively copies a local directory to the blip VM.
// File permissions are preserved. Symlinks are skipped.
func (b *Blip) UploadDir(ctx context.Context, localDir, remoteDir string) error {
	sftpClient, err := b.SFTPClient()
	if err != nil {
		return err
	}
	defer sftpClient.Close()

	return filepath.WalkDir(localDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		rel, err := filepath.Rel(localDir, path)
		if err != nil {
			return fmt.Errorf("relative path: %w", err)
		}
		remotePath := filepath.ToSlash(filepath.Join(remoteDir, rel))

		// WalkDir uses Lstat, so symlinks are reported with ModeSymlink set.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}

		if d.IsDir() {
			if err := sftpClient.MkdirAll(remotePath); err != nil {
				return fmt.Errorf("mkdir %s: %w", remotePath, err)
			}
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}

		local, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer local.Close()

		remote, err := sftpClient.Create(remotePath)
		if err != nil {
			return fmt.Errorf("create %s: %w", remotePath, err)
		}

		if err := copyWithContext(ctx, remote, local); err != nil {
			remote.Close()
			return fmt.Errorf("copy %s -> %s: %w", path, remotePath, err)
		}

		if err := remote.Close(); err != nil {
			return fmt.Errorf("close %s: %w", remotePath, err)
		}

		if err := sftpClient.Chmod(remotePath, info.Mode().Perm()); err != nil {
			return fmt.Errorf("chmod %s: %w", remotePath, err)
		}

		return nil
	})
}

// DownloadDir recursively copies a remote directory from the blip VM
// to the local filesystem. File permissions are preserved. Symlinks
// are skipped.
func (b *Blip) DownloadDir(ctx context.Context, remoteDir, localDir string) error {
	sftpClient, err := b.SFTPClient()
	if err != nil {
		return err
	}
	defer sftpClient.Close()

	return sftpWalk(ctx, sftpClient, remoteDir, func(remotePath string, info fs.FileInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		rel, err := filepath.Rel(remoteDir, remotePath)
		if err != nil {
			return fmt.Errorf("relative path: %w", err)
		}
		localPath := filepath.Join(localDir, filepath.FromSlash(rel))

		// Skip symlinks.
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil
		}

		if info.IsDir() {
			if err := os.MkdirAll(localPath, info.Mode().Perm()|0700); err != nil {
				return fmt.Errorf("mkdir %s: %w", localPath, err)
			}
			return nil
		}

		remote, err := sftpClient.Open(remotePath)
		if err != nil {
			return fmt.Errorf("open %s: %w", remotePath, err)
		}
		defer remote.Close()

		// Write to a temp file, then rename atomically.
		dir := filepath.Dir(localPath)
		tmp, err := os.CreateTemp(dir, ".blip-download-*")
		if err != nil {
			return fmt.Errorf("create temp file in %s: %w", dir, err)
		}
		tmpName := tmp.Name()

		if err := copyWithContext(ctx, tmp, remote); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return fmt.Errorf("copy %s -> %s: %w", remotePath, localPath, err)
		}

		if err := tmp.Chmod(info.Mode().Perm()); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return fmt.Errorf("chmod temp file: %w", err)
		}

		if err := tmp.Close(); err != nil {
			os.Remove(tmpName)
			return fmt.Errorf("close temp file: %w", err)
		}

		if err := os.Rename(tmpName, localPath); err != nil {
			os.Remove(tmpName)
			return fmt.Errorf("rename %s -> %s: %w", tmpName, localPath, err)
		}

		return nil
	})
}

// sftpWalk recursively walks a remote directory tree via SFTP, calling fn
// for each entry (directories first, then files). It is the remote
// equivalent of [filepath.WalkDir].
func sftpWalk(ctx context.Context, client *sftp.Client, root string, fn func(path string, info fs.FileInfo) error) error {
	info, err := client.Lstat(root)
	if err != nil {
		return fmt.Errorf("lstat %s: %w", root, err)
	}

	if err := fn(root, info); err != nil {
		return err
	}

	if !info.IsDir() {
		return nil
	}

	entries, err := client.ReadDir(root)
	if err != nil {
		return fmt.Errorf("readdir %s: %w", root, err)
	}

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		childPath := root + "/" + entry.Name()
		if entry.IsDir() {
			if err := sftpWalk(ctx, client, childPath, fn); err != nil {
				return err
			}
		} else {
			if err := fn(childPath, entry); err != nil {
				return err
			}
		}
	}

	return nil
}

// copyWithContext copies from src to dst, checking ctx for cancellation
// between chunks.
func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		nr, readErr := src.Read(buf)
		if nr > 0 {
			if _, writeErr := dst.Write(buf[:nr]); writeErr != nil {
				return writeErr
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}
