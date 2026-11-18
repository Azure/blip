#!/usr/bin/env bash
# gen-gateway-certs.sh generates TLS material for the blip-gateway certificate
# API and stores the server side in the blip-gateway-tls Secret.
#
# The gateway serves TLS on :8443 and requires a client certificate from a
# dedicated client CA, so that only the Envoy gateway can set the identity
# header. This script creates:
#   - a server CA and a server certificate for blip-gateway.blip-ssh.svc and
#     the blip-gateway-https Service that Envoy connects to
#   - a client CA and a client certificate with CN=envoy for Envoy
#   - the Secret blip-gateway-tls with tls.crt, tls.key and client-ca.crt
#
# Nothing is written to the repository. Pass a directory to keep the files:
#   hack/gen-gateway-certs.sh [dir]
set -euo pipefail

namespace=blip-ssh
secret=blip-gateway-tls
days=825
host=blip-gateway.blip-ssh.svc
# Envoy verifies the server certificate against the hostname in its Backend,
# which is the blip-gateway-https Service.
sans="DNS:$host,DNS:$host.cluster.local,DNS:blip-gateway-https.blip-ssh.svc,DNS:blip-gateway-https.blip-ssh.svc.cluster.local"

dir=${1:-$(mktemp -d /tmp/blip-gateway-certs.XXXXXX)}
mkdir -p "$dir"
cd "$dir"

# Server CA.
openssl req -x509 -newkey rsa:2048 -nodes -days "$days" \
  -keyout server-ca.key -out server-ca.crt -subj "/CN=blip-gateway-server-ca"

# Server certificate for the ClusterIP service, valid for both the short and
# the FQDN service name.
openssl req -newkey rsa:2048 -nodes -keyout tls.key -out server.csr -subj "/CN=$host"
openssl x509 -req -in server.csr -CA server-ca.crt -CAkey server-ca.key -CAcreateserial \
  -days "$days" -out tls.crt \
  -extfile <(printf 'subjectAltName=%s\n' "$sans")

# Client CA and the certificate Envoy presents to the gateway.
openssl req -x509 -newkey rsa:2048 -nodes -days "$days" \
  -keyout client-ca.key -out client-ca.crt -subj "/CN=blip-gateway-client-ca"
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=envoy"
openssl x509 -req -in client.csr -CA client-ca.crt -CAkey client-ca.key -CAcreateserial \
  -days "$days" -out client.crt -extfile <(printf 'extendedKeyUsage=clientAuth\n')

chmod 600 tls.key client.key server-ca.key client-ca.key
chmod 644 tls.crt client.crt server-ca.crt client-ca.crt

kubectl create secret generic "$secret" --namespace "$namespace" \
  --from-file=tls.crt=tls.crt --from-file=tls.key=tls.key \
  --from-file=client-ca.crt=client-ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -

cat <<EOF
Created secret $namespace/$secret.

Envoy client certificate: $dir/client.crt
Envoy client key:         $dir/client.key  (put it in Envoy's client-certificate secret)
Envoy trusts server CA:   $dir/server-ca.crt
Server SANs:              $host, $host.cluster.local,
                          blip-gateway-https.blip-ssh.svc, blip-gateway-https.blip-ssh.svc.cluster.local

These files contain private keys. Keep them out of the repository and delete
them when Envoy has its copy: rm -rf "$dir"
EOF
