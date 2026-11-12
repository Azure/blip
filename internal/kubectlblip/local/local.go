// Package local manages the kubectl-blip state directory (~/.blip): the
// client SSH key pair, the known_hosts file and the optional config file.
package local

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"sigs.k8s.io/yaml"
)

// EnvHome overrides the state directory.
const EnvHome = "BLIP_HOME"

// File names in the state directory.
const (
	KeyFile        = "id_ed25519"
	PubKeyFile     = "id_ed25519.pub"
	KnownHostsFile = "known_hosts"
	ConfigFile     = "config.yaml"
)

// Dir is the state directory.
type Dir struct{ Path string }

// DefaultDir returns $BLIP_HOME or ~/.blip.
func DefaultDir() (Dir, error) {
	if p := os.Getenv(EnvHome); p != "" {
		return Dir{Path: p}, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return Dir{}, fmt.Errorf("home directory: %w (set %s)", err, EnvHome)
	}
	return Dir{Path: filepath.Join(h, ".blip")}, nil
}

// File returns the path of name in the directory.
func (d Dir) File(name string) string { return filepath.Join(d.Path, name) }

// Ensure creates the directory with mode 0700.
func (d Dir) Ensure() error {
	if err := os.MkdirAll(d.Path, 0o700); err != nil {
		return err
	}
	return os.Chmod(d.Path, 0o700)
}

// EnsureKey loads the ed25519 key pair, generating it if missing. It returns
// the authorized_keys line of the public key (without trailing newline).
func (d Dir) EnsureKey() (string, error) {
	if err := d.Ensure(); err != nil {
		return "", err
	}
	priv, pub := d.File(KeyFile), d.File(PubKeyFile)
	if _, err := os.Stat(priv); err == nil {
		return d.loadPub(priv, pub)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	comment := "blip@" + host
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(key, comment)
	if err != nil {
		return "", err
	}
	sshPub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + comment
	if err := writeAtomic(priv, pem.EncodeToMemory(block), 0o600); err != nil {
		return "", err
	}
	if err := writeAtomic(pub, []byte(line+"\n"), 0o644); err != nil {
		return "", err
	}
	return line, nil
}

func (d Dir) loadPub(priv, pub string) (string, error) {
	data, err := os.ReadFile(priv)
	if err != nil {
		return "", err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", priv, err)
	}
	want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if b, err := os.ReadFile(pub); err == nil {
		line := strings.TrimSpace(string(b))
		if KeyFields(line) == want {
			return line, nil
		}
	}
	// Missing or mismatched .pub: regenerate it from the private key.
	if err := writeAtomic(pub, []byte(want+"\n"), 0o644); err != nil {
		return "", err
	}
	return want, nil
}

// KeyFields returns "type base64" of an authorized_keys/known_hosts style
// key, dropping options-free trailing comments.
func KeyFields(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 {
		return strings.TrimSpace(line)
	}
	return f[0] + " " + f[1]
}

// ContainsKey reports whether the authorized keys text (one key per line)
// holds key (compared by type and base64 blob).
func ContainsKey(authorized, key string) bool {
	want := KeyFields(key)
	for _, l := range strings.Split(authorized, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l)); err == nil {
			if strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) == want {
				return true
			}
			continue
		}
		if KeyFields(l) == want {
			return true
		}
	}
	return false
}

// UpsertKnownHost sets the entry for alias in the known_hosts file to
// hostKey ("type base64 [comment]"), replacing older entries for alias.
func (d Dir) UpsertKnownHost(alias, hostKey string) error {
	if err := d.Ensure(); err != nil {
		return err
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey)); err != nil {
		return fmt.Errorf("invalid host key %q: %w", hostKey, err)
	}
	path := d.File(KnownHostsFile)
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var out bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(old))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if f := strings.Fields(line); len(f) > 0 && hostsMatch(f[0], alias) {
			continue
		}
		out.WriteString(line + "\n")
	}
	if err := sc.Err(); err != nil {
		return err
	}
	out.WriteString(alias + " " + KeyFields(hostKey) + "\n")
	return writeAtomic(path, out.Bytes(), 0o600)
}

func hostsMatch(field, alias string) bool {
	for _, h := range strings.Split(field, ",") {
		if h == alias {
			return true
		}
	}
	return false
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Config holds user defaults from config.yaml.
type Config struct {
	// Volume is the BlipVol used as the root volume of new sessions.
	Volume string `json:"volume,omitempty"`
	// Image is an image reference imported as a BlipVol for new sessions.
	Image string `json:"image,omitempty"`
	SKU   string `json:"sku,omitempty"`
	// TTL is a Go duration, e.g. "8h".
	TTL string `json:"ttl,omitempty"`
}

// LoadConfig reads config.yaml; a missing file is an empty config.
func (d Dir) LoadConfig() (Config, error) {
	var c Config
	b, err := os.ReadFile(d.File(ConfigFile))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", d.File(ConfigFile), err)
	}
	if c.TTL != "" {
		if _, err := time.ParseDuration(c.TTL); err != nil {
			return c, fmt.Errorf("%s: ttl: %w", d.File(ConfigFile), err)
		}
	}
	return c, nil
}

// Built-in defaults.
const (
	DefaultSKU = "default"
	DefaultTTL = time.Hour
)

// Options are the effective creation options.
type Options struct {
	Volume string
	Image  string
	SKU    string
	TTL    time.Duration
}

// Resolve merges flags (non-zero values win) over the config over built-in
// defaults. A flag volume or image overrides both config volume and image.
func Resolve(flags Options, c Config) (Options, error) {
	o := flags
	if o.Volume == "" && o.Image == "" {
		o.Volume, o.Image = c.Volume, c.Image
	}
	if o.SKU == "" {
		o.SKU = c.SKU
	}
	if o.SKU == "" {
		o.SKU = DefaultSKU
	}
	if o.TTL == 0 && c.TTL != "" {
		d, err := time.ParseDuration(c.TTL)
		if err != nil {
			return o, fmt.Errorf("config ttl: %w", err)
		}
		o.TTL = d
	}
	if o.TTL == 0 {
		o.TTL = DefaultTTL
	}
	if o.Volume != "" && o.Image != "" {
		return o, errors.New("set only one of --volume and --image")
	}
	if o.Volume == "" && o.Image == "" {
		return o, errors.New("no root volume: pass --volume <blipvol> or --image <ref>, or set volume or image in " + ConfigFile)
	}
	return o, nil
}
