#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Starts OpenLDAP with its own TLS and Cyrus SASL in a container (Podman), for
# the sign-ins the test directory of start.sh cannot offer: a TLS client
# certificate (SASL EXTERNAL) and SCRAM-SHA-256.
#
#   TestDirectory/start-sasl.sh
#
#   ldap://localhost:12389 (StartTLS) and ldaps://localhost:12636
#   SCRAM: scram.user / Scram-Test-Password-2026!
#          scram.accents / Élène-Déjà-Vu-2026!
#   EXTERNAL: TestDirectory/.run/sasl/client.p12 (password "forester"), a
#          certificate for cn=Forester Client,o=Forester Test
#   the CA of both certificates: TestDirectory/.run/sasl/ca.crt
#
# Nothing is added to a keychain: the tests read client.p12 themselves. To try
# certificate sign-in in the app, import client.p12 into your login keychain
# (and remove it again afterwards). TestDirectory/stop-sasl.sh removes it all.
set -euo pipefail

HERE=${0:A:h}
NAME=forester-sasl
IMAGE=localhost/forester-sasl:latest
CERTS="$HERE/.run/sasl"
export LDAPTLS_REQCERT=never  # the test CA is not trusted on this Mac; this is the probe below only
rm -rf "$CERTS"
mkdir -p "$CERTS"

cat > "$CERTS/server.cnf" <<EOF
[ext]
subjectAltName = DNS:localhost,IP:127.0.0.1
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
cat > "$CERTS/client.cnf" <<EOF
[ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=Forester SASL Test CA" \
  -keyout "$CERTS/ca.key" -out "$CERTS/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
  -keyout "$CERTS/server.key" -out "$CERTS/server.csr" >/dev/null 2>&1
openssl x509 -req -in "$CERTS/server.csr" -CA "$CERTS/ca.crt" -CAkey "$CERTS/ca.key" -CAcreateserial \
  -days 825 -sha256 -extfile "$CERTS/server.cnf" -extensions ext -out "$CERTS/server.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/O=Forester Test/CN=Forester Client" \
  -keyout "$CERTS/client.key" -out "$CERTS/client.csr" >/dev/null 2>&1
openssl x509 -req -in "$CERTS/client.csr" -CA "$CERTS/ca.crt" -CAkey "$CERTS/ca.key" -CAcreateserial \
  -days 825 -sha256 -extfile "$CERTS/client.cnf" -extensions ext -out "$CERTS/client.crt" >/dev/null 2>&1
# A certificate from no CA the server knows: presented, and refused.
openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/O=Forester Test/CN=Stranger" \
  -keyout "$CERTS/stranger.key" -out "$CERTS/stranger.crt" >/dev/null 2>&1
for who in client stranger; do
  # -legacy: macOS's PKCS #12 reader does not take OpenSSL 3's default AES encryption.
  openssl pkcs12 -export -legacy -in "$CERTS/$who.crt" -inkey "$CERTS/$who.key" -name "Forester ${(C)who}" \
    -passout pass:forester -out "$CERTS/$who.p12" 2>/dev/null \
  || openssl pkcs12 -export -in "$CERTS/$who.crt" -inkey "$CERTS/$who.key" -name "Forester ${(C)who}" \
    -passout pass:forester -out "$CERTS/$who.p12"
done
chmod 644 "$CERTS"/*.key

podman build -q -t "$IMAGE" "$HERE/sasl" >/dev/null
podman rm -f "$NAME" >/dev/null 2>&1 || true
podman run -d --name "$NAME" -v "$CERTS:/certs:ro,Z" \
  -p 127.0.0.1:12389:389 -p 127.0.0.1:12636:636 "$IMAGE" >/dev/null

for _ in {1..50}; do
  if ldapsearch -o nettimeout=2 -x -H ldaps://localhost:12636 -b "" -s base \
       supportedSASLMechanisms >/dev/null 2>&1; then
    echo "OpenLDAP with SASL is up: ldap://localhost:12389 (StartTLS) and ldaps://localhost:12636"
    ldapsearch -x -H ldaps://localhost:12636 -b "" -s base supportedSASLMechanisms \
      | grep supportedSASLMechanisms | sed 's/^/  /'
    exit 0
  fi
  [[ "$(podman inspect -f '{{.State.Running}}' "$NAME")" == true ]] || { podman logs "$NAME" | tail -20; exit 1; }
  sleep 0.5
done
echo "slapd did not come up; its log follows" >&2
podman logs "$NAME" | tail -40 >&2
exit 1
