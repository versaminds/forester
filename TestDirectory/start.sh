#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Start a throwaway, Active Directory-shaped LDAP server for development.
#
#   ldap://127.0.0.1:10389   (plain, StartTLS available)
#   ldaps://127.0.0.1:10636  (TLS from the first byte)
#
# Uses the slapd macOS ships in /usr/libexec, so nothing is downloaded. Apple's
# slapd only takes a TLS identity from a keychain, so TLS (both ldaps:// and
# StartTLS) is terminated by tls_proxy.py in front of it; slapd itself listens
# on 127.0.0.1:10388. State lives in TestDirectory/.run, rebuilt on every start.
#
# Bind as:  CN=admin,DC=corp,DC=example / secret        (rootdn, AD suffix; may write)
#           cn=admin,dc=example,dc=org / secret         (rootdn, generic suffix; may write)
# or anonymously (read-only). Apple's slapd sends every other simple bind through
# its Open Directory Kerberos hook (odusers), so ordinary entries cannot bind.
set -euo pipefail

HERE=${0:A:h}
RUN="$HERE/.run"
SLAPD=/usr/libexec/slapd
SCHEMA=/etc/openldap/schema
PLAIN_PORT=${LDAP_TEST_PORT:-10389}
TLS_PORT=${LDAPS_TEST_PORT:-10636}
SLAPD_PORT=10388

# tls_proxy.py upgrades a connection in place with StreamWriter.start_tls, which
# needs Python 3.11; the python3 macOS ships is 3.9. Use the first new enough one.
PYTHON=""
for candidate in ${LDAP_TEST_PYTHON:-} python3 /opt/homebrew/bin/python3 /usr/local/bin/python3 \
                 python3.14 python3.13 python3.12 python3.11; do
  if command -v "$candidate" >/dev/null 2>&1 &&
     "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
    PYTHON=$(command -v "$candidate")
    break
  fi
done
if [[ -z $PYTHON ]]; then
  echo "The test server needs Python 3.11 or later (found $(python3 --version 2>&1))." >&2
  echo "Install one with 'brew install python', or point LDAP_TEST_PYTHON at it." >&2
  exit 1
fi

"$HERE/stop.sh" >/dev/null 2>&1 || true
rm -rf "$RUN"
mkdir -p "$RUN/ad" "$RUN/org"

# ── Certificates: a private CA and a server cert for localhost ───────────────
# The CA is deliberately not trusted by the system, so connecting exercises the
# app's "untrusted certificate" path; ca.crt can be imported to test the happy one.
cat > "$RUN/san.cnf" <<EOF
[req]
distinguished_name = dn
[dn]
[ext]
subjectAltName = DNS:localhost,IP:127.0.0.1
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=Forester Test CA" \
  -keyout "$RUN/ca.key" -out "$RUN/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost/O=Corp Example" \
  -keyout "$RUN/server.key" -out "$RUN/server.csr" >/dev/null 2>&1
openssl x509 -req -in "$RUN/server.csr" -CA "$RUN/ca.crt" -CAkey "$RUN/ca.key" -CAcreateserial \
  -days 825 -sha256 -extfile "$RUN/san.cnf" -extensions ext -out "$RUN/server.crt" >/dev/null 2>&1

ROOTPW=$(/usr/sbin/slappasswd -h '{SSHA}' -s secret)

# ── slapd.conf ───────────────────────────────────────────────────────────────
cat > "$RUN/slapd.conf" <<EOF
include $SCHEMA/core.schema
include $SCHEMA/cosine.schema
include $SCHEMA/inetorgperson.schema
include $SCHEMA/nis.schema
include $SCHEMA/dyngroup.schema
include $HERE/adtest.schema

pidfile  $RUN/slapd.pid
argsfile $RUN/slapd.args

# A page is capped at 200 entries and an unpaged search at 500, the way AD caps
# both at 1000: the app has to page to see the 1,500-user OU.
sizelimit size.soft=500 size.hard=500 size.pr=200 size.prtotal=unlimited

access to * by * read

database hdb
suffix   "DC=corp,DC=example"
rootdn   "CN=admin,DC=corp,DC=example"
rootpw   $ROOTPW
directory $RUN/ad
index objectClass,cn,sAMAccountName,member eq

# cn=Monitor: connection, operation and thread counters, for the server monitor.
database monitor

database hdb
suffix   "dc=example,dc=org"
rootdn   "cn=admin,dc=example,dc=org"
rootpw   $ROOTPW
directory $RUN/org
index objectClass,uid,cn eq
EOF

for db in ad org; do
  cat > "$RUN/$db/DB_CONFIG" <<EOF
set_cachesize 0 33554432 1
set_lg_regionmax 262144
set_lg_bsize 2097152
EOF
done

"$PYTHON" -I "$HERE/generate_ldif.py" ad  > "$RUN/ad.ldif"
"$PYTHON" -I "$HERE/generate_ldif.py" org > "$RUN/org.ldif"
/usr/sbin/slapadd -q -f "$RUN/slapd.conf" -b "DC=corp,DC=example" -l "$RUN/ad.ldif" 2>"$RUN/slapadd.log" \
  || { cat "$RUN/slapadd.log"; exit 1; }
/usr/sbin/slapadd -q -f "$RUN/slapd.conf" -b "dc=example,dc=org" -l "$RUN/org.ldif" 2>>"$RUN/slapadd.log" \
  || { cat "$RUN/slapadd.log"; exit 1; }

"$SLAPD" -f "$RUN/slapd.conf" -h "ldap://127.0.0.1:$SLAPD_PORT/" -d "${SLAPD_DEBUG:-0}" >"$RUN/slapd.log" 2>&1 &
"$PYTHON" -I "$HERE/tls_proxy.py" --backend "127.0.0.1:$SLAPD_PORT" --plain "$PLAIN_PORT" --ldaps "$TLS_PORT" \
  --cert "$RUN/server.crt" --key "$RUN/server.key" >"$RUN/proxy.log" 2>&1 &
echo $! > "$RUN/proxy.pid"

for _ in {1..50}; do
  if ldapsearch -x -H "ldap://127.0.0.1:$PLAIN_PORT" -b "" -s base namingContexts >/dev/null 2>&1; then
    echo "slapd is up: ldap://127.0.0.1:$PLAIN_PORT  ldaps://127.0.0.1:$TLS_PORT"
    echo "CA certificate: $RUN/ca.crt"
    exit 0
  fi
  sleep 0.2
done
echo "slapd did not come up; log follows" >&2
cat "$RUN/slapd.log" >&2
exit 1
