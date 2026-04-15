package blip

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// resolveAuth returns the SSH auth methods to use for connecting to the gateway.
// It checks, in order:
//  1. An explicit OIDC token (from [WithOIDCToken] or BLIP_OIDC_TOKEN env var)
//  2. An explicit SSH key path (from [WithSSHKey])
//  3. The ssh-agent (via SSH_AUTH_SOCK)
//  4. Default SSH keys from ~/.ssh/ (id_ed25519, id_rsa, id_ecdsa)
func resolveAuth(cfg *clientConfig) ([]ssh.AuthMethod, error) {
	// OIDC token auth: passed as SSH password.
	// The gateway validates the JWT against the configured OIDC providers.
	token := cfg.oidcToken
	if token == "" {
		token = os.Getenv("BLIP_OIDC_TOKEN")
	}
	if token != "" {
		return []ssh.AuthMethod{ssh.Password(token)}, nil
	}

	// Explicit SSH key path.
	if cfg.sshKeyPath != "" {
		signer, err := loadSSHKey(cfg.sshKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load SSH key %s: %w", cfg.sshKeyPath, err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}

	// Try ssh-agent first (handles passphrase-protected keys, hardware tokens, etc.).
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			agentClient := agent.NewClient(conn)
			signers, err := agentClient.Signers()
			if err == nil && len(signers) > 0 {
				// Use PublicKeysCallback so the agent connection remains
				// available for signing during SSH handshakes.
				return []ssh.AuthMethod{ssh.PublicKeysCallback(agentClient.Signers)}, nil
			}
			// Agent available but has no keys — close and fall through to file-based keys.
			conn.Close()
		}
	}

	// Default SSH keys from ~/.ssh/.
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("determine home directory: %w", err)
	}

	keyNames := []string{"id_ed25519", "id_rsa", "id_ecdsa"}
	var signers []ssh.Signer
	for _, name := range keyNames {
		path := filepath.Join(home, ".ssh", name)
		signer, err := loadSSHKey(path)
		if err != nil {
			continue // skip keys that don't exist or can't be parsed
		}
		signers = append(signers, signer)
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("no authentication method available: set BLIP_OIDC_TOKEN, start ssh-agent, or provide an SSH key")
	}

	return []ssh.AuthMethod{ssh.PublicKeys(signers...)}, nil
}

// loadSSHKey reads and parses a PEM-encoded SSH private key.
func loadSSHKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}
