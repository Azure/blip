// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMCPTLSConfigReloadsCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	first := writeTestCert(t, certPath, keyPath, 1)

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tlsConfig, stop, err := mcpTLSConfig(ctx, certPath, keyPath, errCh)
	if err != nil {
		t.Fatalf("mcpTLSConfig: %v", err)
	}
	defer stop()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	if got := servedSerial(t, ln.Addr().String()); got.Cmp(first) != 0 {
		t.Fatalf("served serial = %v, want %v", got, first)
	}

	second := writeTestCert(t, certPath, keyPath, 2)

	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case err := <-errCh:
			t.Fatalf("certificate watcher: %v", err)
		default:
		}
		cert, err := tlsConfig.GetCertificate(nil)
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		if cert != nil {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil && leaf.SerialNumber.Cmp(second) == 0 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the certificate to reload")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if got := servedSerial(t, ln.Addr().String()); got.Cmp(second) != 0 {
		t.Fatalf("served serial after reload = %v, want %v", got, second)
	}
}

// servedSerial dials addr and returns the serial number of the certificate the
// server presents.
func servedSerial(t *testing.T, addr string) *big.Int {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber
}

// writeTestCert writes a self-signed certificate and key to certPath and
// keyPath and returns the certificate serial number.
func writeTestCert(t *testing.T, certPath, keyPath string, serial int64) *big.Int {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "blipchat-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	writePEM(t, certPath, "CERTIFICATE", der, 0o644)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	writePEM(t, keyPath, "PRIVATE KEY", keyDER, 0o600)
	return tmpl.SerialNumber
}

func writePEM(t *testing.T, path, blockType string, der []byte, perm os.FileMode) {
	t.Helper()
	block := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, block, perm); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
