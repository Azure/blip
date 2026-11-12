// Package tlskeys derives NVMe/TCP TLS pre-shared keys and manages them in
// the kernel ".nvme" keyring.
//
// Findings for kernel 7.0 (see docs/spikes/storage.md):
//   - Keys have type "psk" and live in the ".nvme" keyring.
//   - The identity of a configured (retained) PSK with SHA-256 is
//     "NVMe0R01 <hostnqn> <subnqn>". The host sends the description of the
//     key named in tls_key= as the TLS PSK identity.
//   - On the target, tlshd searches its session keyring (with ".nvme"
//     linked into it through "keyrings=.nvme" in tlshd.conf) for a "psk" key
//     whose description starts with that identity. The match is a prefix
//     match, so a target key may carry a suffix after the identity.
//   - The payload is used as the TLS PSK as is. Both sides insert the same
//     32 bytes, HMAC-SHA256(clusterKey, hostNQN).
//
// When several nodes share one kernel (kind), a host key and a target key
// for the same pair can exist at once. Target keys therefore get the suffix
// " target" so each side removes only its own keys.
package tlskeys

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/example/blip/internal/storage/run"
)

// KeyType is the kernel key type for NVMe TLS PSKs.
const KeyType = "psk"

// KeyringName is the kernel keyring for NVMe keys.
const KeyringName = ".nvme"

// PSKSize is the size of a SHA-256 PSK.
const PSKSize = 32

// Role says which side of the connection a key is for.
type Role int

const (
	Host Role = iota
	Target
)

const targetSuffix = " target"

// DerivePSK returns HMAC-SHA256(clusterKey, hostNQN) (design section 7.3).
func DerivePSK(clusterKey []byte, hostNQN string) []byte {
	m := hmac.New(sha256.New, clusterKey)
	m.Write([]byte(hostNQN))
	return m.Sum(nil)
}

// Identity is the TLS PSK identity of a configured SHA-256 PSK.
func Identity(hostNQN, subNQN string) string {
	return "NVMe0R01 " + hostNQN + " " + subNQN
}

// Description is the key description for an identity and role.
func Description(identity string, r Role) string {
	if r == Target {
		return identity + targetSuffix
	}
	return identity
}

// Keyring returns the serial of the ".nvme" keyring, read from /proc/keys.
func Keyring() (int, error) {
	f, err := os.Open("/proc/keys")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return findKeyring(bufio.NewScanner(f))
}

func findKeyring(s *bufio.Scanner) (int, error) {
	for s.Scan() {
		// 1dc06b61 I------     1 perm 1f1f0000     0     0 keyring   .nvme: empty
		f := strings.Fields(s.Text())
		if len(f) >= 9 && f[7] == "keyring" && strings.TrimSuffix(f[8], ":") == KeyringName {
			id, err := strconv.ParseUint(f[0], 16, 32)
			if err != nil {
				return 0, err
			}
			return int(id), nil
		}
	}
	if err := s.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("keyring .nvme not found (is the nvme-keyring module loaded?)")
}

// Insert adds or updates a key and returns its serial. The key is created
// in the network namespace of the calling thread.
func Insert(keyring int, identity string, r Role, psk []byte) (int, error) {
	if len(psk) != PSKSize {
		return 0, fmt.Errorf("psk must be %d bytes, got %d", PSKSize, len(psk))
	}
	var id int
	err := run.Step("add_key", []string{Description(identity, r)}, func() (err error) {
		id, err = unix.AddKey(KeyType, Description(identity, r), psk, keyring)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("add_key %q: %w", identity, err)
	}
	return id, nil
}

// Key is a key in the keyring.
type Key struct {
	Serial      int
	Description string
}

// List returns the psk keys linked into the keyring.
func List(keyring int) ([]Key, error) {
	ids, err := readKeyring(keyring)
	if err != nil {
		return nil, err
	}
	var out []Key
	for _, id := range ids {
		d, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, id)
		if err != nil {
			continue // removed meanwhile
		}
		typ, desc, ok := parseDescribe(d)
		if ok && typ == KeyType {
			out = append(out, Key{Serial: id, Description: desc})
		}
	}
	return out, nil
}

// Find returns the serials of keys with exactly this identity and role.
func Find(keyring int, identity string, r Role) ([]int, error) {
	keys, err := List(keyring)
	if err != nil {
		return nil, err
	}
	want := Description(identity, r)
	var ids []int
	for _, k := range keys {
		if k.Description == want {
			ids = append(ids, k.Serial)
		}
	}
	return ids, nil
}

// Remove unlinks every key with this identity and role. Missing keys are
// not an error.
func Remove(keyring int, identity string, r Role) error {
	ids, err := Find(keyring, identity, r)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := unlinkKey(keyring, id); err != nil {
			return err
		}
	}
	return nil
}

// RemoveMatching unlinks keys of role r whose identity satisfies match.
func RemoveMatching(keyring int, r Role, match func(identity string) bool) error {
	keys, err := List(keyring)
	if err != nil {
		return err
	}
	for _, k := range keys {
		id := k.Description
		if r == Target {
			var ok bool
			if id, ok = strings.CutSuffix(id, targetSuffix); !ok {
				continue
			}
		} else if strings.HasSuffix(id, targetSuffix) {
			continue
		}
		if !match(id) {
			continue
		}
		if err := unlinkKey(keyring, k.Serial); err != nil {
			return err
		}
	}
	return nil
}

func readKeyring(keyring int) ([]int, error) {
	buf := make([]byte, 4096)
	for {
		n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyring, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("read keyring %d: %w", keyring, err)
		}
		if n <= len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, n)
	}
	ids := make([]int, 0, len(buf)/4)
	for i := 0; i+4 <= len(buf); i += 4 {
		ids = append(ids, int(int32(binary.NativeEndian.Uint32(buf[i:]))))
	}
	return ids, nil
}

// parseDescribe splits "type;uid;gid;perm;description".
func parseDescribe(s string) (typ, desc string, ok bool) {
	parts := strings.SplitN(s, ";", 5)
	if len(parts) != 5 {
		return "", "", false
	}
	return parts[0], parts[4], true
}

// TlshdConfig is a tlshd.conf for the tlshd sidecar. "keyrings=.nvme"
// links the keyring into tlshd's session keyring; without it the target
// side cannot find keys. tlshd must run in the same network namespace as
// the sockets it serves, with its own session keyring.
const TlshdConfig = `[main]
debug=0
tlsdebug=0
nl_debug=0
keyrings=.nvme

[authenticate.client]

[authenticate.server]
`

func unlinkKey(keyring, id int) error {
	return run.Step("unlink_key", []string{strconv.Itoa(id)}, func() error {
		if _, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, id, keyring, 0, 0); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOKEY) {
			return fmt.Errorf("unlink key %d: %w", id, err)
		}
		return nil
	})
}
