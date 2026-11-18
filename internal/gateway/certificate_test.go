package gateway

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func signUserCert(t *testing.T, ca ssh.Signer, user ssh.Signer, principals []string, after, before time.Time) *ssh.Certificate {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             user.PublicKey(),
		CertType:        ssh.UserCert,
		ValidPrincipals: principals,
		ValidAfter:      uint64(after.Unix()),
		ValidBefore:     uint64(before.Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return cert
}

func certSigner(t *testing.T, cert *ssh.Certificate, key ssh.Signer) ssh.Signer {
	t.Helper()
	s, err := ssh.NewCertSigner(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func requestCert(t *testing.T, endpoint, identity, key string) (certificate, hostKey string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint+CertificatePath, strings.NewReader(key))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-User", identity)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("certificate request: %s: %s", resp.Status, body)
	}
	var out certificateResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out.Certificate, out.HostKey
}

type certEnv struct {
	*env
	api      *httptest.Server
	identity string
	owner    string
	ca       ssh.Signer
}

func newCertEnv(t *testing.T) *certEnv {
	t.Helper()
	e := newEnv(t)
	e.srv.CA, _ = newKey(t)
	e.srv.IdentityHeader = "X-Forwarded-User"
	const identity = "subject-1"
	api := httptest.NewServer(e.srv.Handler())
	t.Cleanup(api.Close)
	return &certEnv{env: e, api: api, identity: identity, owner: ownerFor(identity), ca: e.srv.CA}
}

func TestCertificateAuthentication(t *testing.T) {
	e := newCertEnv(t)
	userKey, line := newKey(t)
	certificate, hostKey := requestCert(t, e.api.URL, e.identity, line)

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certificate))
	if err != nil {
		t.Fatal(err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatal("response is not a certificate")
	}
	if cert.CertType != ssh.UserCert {
		t.Fatalf("cert type = %d", cert.CertType)
	}
	if !slices.Equal(cert.ValidPrincipals, []string{e.owner}) {
		t.Fatalf("principals = %v, want %q", cert.ValidPrincipals, e.owner)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), e.ca.PublicKey().Marshal()) {
		t.Fatal("certificate is not signed by the gateway CA")
	}
	if cert.ValidBefore <= uint64(time.Now().Unix()) || cert.ValidBefore > uint64(time.Now().Add(certTTL+time.Minute).Unix()) {
		t.Fatalf("certificate lifetime is wrong: %d", cert.ValidBefore)
	}
	if want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(e.srv.HostKey.PublicKey()))); hostKey != want {
		t.Fatalf("host key = %q, want %q", hostKey, want)
	}

	if _, err := e.dial("default", certSigner(t, cert, userKey)); err != nil {
		t.Fatalf("certificate authentication failed: %v", err)
	}
	// Public keys from the ConfigMap keep working alongside certificates.
	if _, err := e.dial("default", e.userKey); err != nil {
		t.Fatalf("public key authentication failed with a CA configured: %v", err)
	}
}

func TestCertificateLifetime(t *testing.T) {
	e := newCertEnv(t)
	_, line := newKey(t)
	certificate, _ := requestCert(t, e.api.URL, e.identity, line)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certificate))
	if err != nil {
		t.Fatal(err)
	}
	cert := pub.(*ssh.Certificate)
	now := time.Now()
	if cert.ValidBefore < uint64(now.Add(certTTL-time.Minute).Unix()) {
		t.Fatalf("certificate expires too soon: %d", cert.ValidBefore)
	}
	if cert.ValidBefore > uint64(now.Add(certTTL+time.Minute).Unix()) {
		t.Fatalf("certificate expires too late: %d", cert.ValidBefore)
	}
}

func TestCertificateRejected(t *testing.T) {
	e := newCertEnv(t)
	userKey, _ := newKey(t)
	otherCA, _ := newKey(t)
	valid := func() time.Time { return time.Now().Add(-time.Minute) }
	expires := func() time.Time { return time.Now().Add(10 * time.Minute) }

	critical := &ssh.Certificate{
		Key: userKey.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{e.owner},
		ValidAfter: uint64(valid().Unix()), ValidBefore: uint64(expires().Unix()),
		CriticalOptions: map[string]string{"force-command": "true"},
	}
	if err := critical.SignCert(rand.Reader, e.ca); err != nil {
		t.Fatal(err)
	}
	host := &ssh.Certificate{
		Key: userKey.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: []string{e.owner},
		ValidAfter: uint64(valid().Unix()), ValidBefore: uint64(expires().Unix()),
	}
	if err := host.SignCert(rand.Reader, e.ca); err != nil {
		t.Fatal(err)
	}
	tamperedUser, _ := newKey(t)
	tampered := *signUserCert(t, e.ca, userKey, []string{e.owner}, valid(), expires())
	tampered.Key = tamperedUser.PublicKey()

	cases := []struct {
		name string
		cert *ssh.Certificate
		key  ssh.Signer
	}{
		{"other CA", signUserCert(t, otherCA, userKey, []string{e.owner}, valid(), expires()), userKey},
		{"wrong principal", signUserCert(t, e.ca, userKey, []string{"alice"}, valid(), expires()), userKey},
		{"sandbox principal", signUserCert(t, e.ca, userKey, []string{"default"}, valid(), expires()), userKey},
		{"two principals", signUserCert(t, e.ca, userKey, []string{e.owner, "alice"}, valid(), expires()), userKey},
		{"expired", signUserCert(t, e.ca, userKey, []string{e.owner}, time.Now().Add(-10*time.Minute), time.Now().Add(-time.Minute)), userKey},
		{"critical option", critical, userKey},
		{"host certificate", host, userKey},
		{"tampered key", &tampered, tamperedUser},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.dial("default", certSigner(t, tc.cert, tc.key)); err == nil {
				t.Fatal("connection succeeded with an invalid certificate")
			}
		})
	}
}

func TestCertificateHandlerErrors(t *testing.T) {
	e := newCertEnv(t)
	_, line := newKey(t)

	post := func(key string, identities ...string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, e.api.URL+CertificatePath, strings.NewReader(key))
		for _, identity := range identities {
			req.Header.Add("X-Forwarded-User", identity)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	if got := post(line).StatusCode; got != http.StatusUnauthorized {
		t.Fatalf("missing identity: %d", got)
	}
	if got := post(line, "").StatusCode; got != http.StatusUnauthorized {
		t.Fatalf("empty identity: %d", got)
	}
	if got := post(line, "one", "two").StatusCode; got != http.StatusUnauthorized {
		t.Fatalf("repeated identity: %d", got)
	}
	if got := post("not a key", e.identity).StatusCode; got != http.StatusBadRequest {
		t.Fatalf("bad key: %d", got)
	}
	certificate, _ := requestCert(t, e.api.URL, e.identity, line)
	if got := post(certificate, e.identity).StatusCode; got != http.StatusBadRequest {
		t.Fatalf("certificate as key: %d", got)
	}

	req, _ := http.NewRequest(http.MethodGet, e.api.URL+CertificatePath, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", resp.StatusCode)
	}

	plain := newEnv(t)
	plainAPI := httptest.NewServer(plain.srv.Handler())
	defer plainAPI.Close()
	req, _ = http.NewRequest(http.MethodPost, plainAPI.URL+CertificatePath, strings.NewReader(line))
	req.Header.Set("X-Forwarded-User", e.identity)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured server: %d", resp.StatusCode)
	}
}

func newClientCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "envoy-client-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, key, pool
}

func newEnvoyCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "envoy"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestCertificateAPIRequiresVerifiedClientCert(t *testing.T) {
	e := newCertEnv(t)
	ca, caKey, pool := newClientCA(t)
	e.srv.ClientCAs = pool

	api := httptest.NewUnstartedServer(e.srv.Handler())
	api.TLS = &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}
	api.StartTLS()
	t.Cleanup(api.Close)

	_, line := newKey(t)
	post := func(client *http.Client) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodPost, api.URL+CertificatePath, strings.NewReader(line))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Forwarded-User", e.identity)
		return client.Do(req)
	}

	// Without a client certificate the TLS handshake fails.
	if resp, err := post(api.Client()); err == nil {
		resp.Body.Close()
		t.Fatal("request without a client certificate succeeded")
	}

	// Envoy presents a certificate from the client CA.
	client := api.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{newEnvoyCert(t, ca, caKey)}
	resp, err := post(client)
	if err != nil {
		t.Fatalf("request with a client certificate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %s: %s", resp.Status, body)
	}
}

func TestCertificateHandlerRejectsDirectRequestsWhenClientCAConfigured(t *testing.T) {
	e := newCertEnv(t)
	e.srv.ClientCAs = x509.NewCertPool()
	_, line := newKey(t)
	req, err := http.NewRequest(http.MethodPost, e.api.URL+CertificatePath, strings.NewReader(line))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-User", e.identity)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
