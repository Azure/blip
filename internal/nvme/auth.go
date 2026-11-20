// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package nvme

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
)

// Every export and connection uses bidirectional NVMe in-band
// authentication (DH-HMAC-CHAP). Both secrets of a host are derived from the
// cluster disk key and the host NQN, so nothing is exchanged and every
// exporter on a shared kernel writes the same values.

const minKeySize = 32

func checkKey(key []byte) error {
	if len(key) < minKeySize {
		return errors.New("nvme: the cluster disk key is missing or too short")
	}
	return nil
}

// secrets returns hostNQN's host and controller secrets.
func secrets(key []byte, hostNQN string) (host, ctrl string) {
	return dhchapSecret(key, "blip-nvme-host", hostNQN), dhchapSecret(key, "blip-nvme-ctrl", hostNQN)
}

func dhchapSecret(key []byte, label, hostNQN string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(label + "\x00" + hostNQN))
	return formatSecret(m.Sum(nil))
}

// formatSecret encodes a secret the way the kernel parses it
// (nvme_auth_extract_key): "DHHC-1:00:" (no key transformation), base64 of
// the secret followed by its CRC-32 (IEEE, little-endian), and ":".
func formatSecret(s []byte) string {
	s = binary.LittleEndian.AppendUint32(s, crc32.ChecksumIEEE(s))
	return "DHHC-1:00:" + base64.StdEncoding.EncodeToString(s) + ":"
}

// checkAuth fails unless the kernel's nvmet supports in-band authentication
// (CONFIG_NVME_TARGET_AUTH): only then do host entries have dhchap_key.
func checkAuth(node string) error {
	dir := filepath.Join(nvmetDir, "hosts", NQNPrefix+"probe:"+NodeHash(node))
	if err := mkdir(dir); err != nil {
		return err
	}
	_, err := os.Stat(filepath.Join(dir, "dhchap_key"))
	rmdir(dir)
	if err != nil {
		return fmt.Errorf("nvme: the kernel lacks NVMe in-band authentication (CONFIG_NVME_TARGET_AUTH, CONFIG_NVME_HOST_AUTH): %w", err)
	}
	return nil
}
