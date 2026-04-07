package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/project-unbounded/blip/internal/sshca"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})))

	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "kubectl-blip",
		Short:         "kubectl plugin for Blip SSH key management",
		Long:          "Signs your local SSH public key with the Blip SSH CA.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(newSignIdentityCmd())
	cmd.AddCommand(newGeneratePoolCmd())
	return cmd
}

func newSignIdentityCmd() *cobra.Command {
	var (
		identityFile string
		output       string
		namespace    string
		caSecret     string
		validityStr  string
		principal    string
	)

	home, _ := os.UserHomeDir()
	defaultIdentity := filepath.Join(home, ".ssh", "id_ed25519.pub")

	cmd := &cobra.Command{
		Use:   "sign-identity",
		Short: "Sign a local SSH public key with the Blip SSH CA",
		Long: `Signs your local SSH public key with the Blip SSH CA stored in a
Kubernetes secret. The resulting certificate can be used to authenticate
to Blip SSH gateways.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("output") {
				output = certPathFromPub(identityFile)
			}
			return runSignIdentity(identityFile, output, namespace, caSecret, validityStr, principal)
		},
	}

	cmd.Flags().StringVarP(&identityFile, "identity-file", "i", defaultIdentity, "SSH public key to sign")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Certificate output path (default: <identity>-cert.pub)")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "blip", "Kubernetes namespace")
	cmd.Flags().StringVar(&caSecret, "ca-secret", "ssh-ca-keypair", "CA secret name")
	cmd.Flags().StringVar(&validityStr, "validity", "720h", "Certificate validity duration")
	cmd.Flags().StringVar(&principal, "principal", "runner", "SSH principal/username")

	return cmd
}

func runSignIdentity(identityFile, output, namespace, caSecret, validityStr, principal string) error {
	validity, err := time.ParseDuration(validityStr)
	if err != nil {
		return fmt.Errorf("invalid --validity %q: %w", validityStr, err)
	}

	pubData, err := os.ReadFile(identityFile)
	if err != nil {
		return fmt.Errorf("read identity file %s: %w", identityFile, err)
	}
	userPub, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
	if err != nil {
		return fmt.Errorf("parse SSH public key from %s: %w", identityFile, err)
	}

	home, _ := os.UserHomeDir()
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("build kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("create kubernetes client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	secret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, caSecret, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get secret %s/%s: %w\nEnsure you have RBAC access to read secrets in the %s namespace", namespace, caSecret, err, namespace)
	}

	caPrivPEM, ok := secret.Data["ca"]
	if !ok {
		return fmt.Errorf("secret %s/%s does not contain 'ca' key", namespace, caSecret)
	}

	caSigner, err := sshca.ParseCAPrivateKey(caPrivPEM)
	if err != nil {
		return fmt.Errorf("parse CA key: %w", err)
	}

	keyID := fmt.Sprintf("blip:%s", ssh.FingerprintSHA256(userPub))

	cert, err := sshca.SignUserKey(caSigner, userPub, keyID, []string{principal}, validity)
	if err != nil {
		return fmt.Errorf("sign key: %w", err)
	}

	certBytes := sshca.MarshalCertificate(cert)

	if err := os.WriteFile(output, certBytes, 0o600); err != nil {
		return fmt.Errorf("write certificate to %s: %w", output, err)
	}

	fmt.Fprintf(os.Stderr, "Certificate written to %s\n", output)
	fmt.Fprintf(os.Stderr, "  Type:       %s\n", certTypeName(cert.CertType))
	fmt.Fprintf(os.Stderr, "  Key ID:     %s\n", cert.KeyId)
	fmt.Fprintf(os.Stderr, "  Serial:     %d\n", cert.Serial)
	fmt.Fprintf(os.Stderr, "  Principals: %s\n", strings.Join(cert.ValidPrincipals, ", "))
	fmt.Fprintf(os.Stderr, "  Valid:      %s to %s\n",
		time.Unix(int64(cert.ValidAfter), 0).UTC().Format(time.RFC3339),
		time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339),
	)
	return nil
}

func certPathFromPub(pubPath string) string {
	if strings.HasSuffix(pubPath, ".pub") {
		return pubPath[:len(pubPath)-4] + "-cert.pub"
	}
	return pubPath + "-cert.pub"
}

func certTypeName(ct uint32) string {
	switch ct {
	case ssh.UserCert:
		return "ssh-ed25519-cert-v01@openssh.com (user)"
	case ssh.HostCert:
		return "ssh-ed25519-cert-v01@openssh.com (host)"
	default:
		return fmt.Sprintf("unknown (%d)", ct)
	}
}
