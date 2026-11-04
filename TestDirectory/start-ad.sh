#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Starts an Active Directory domain controller for testing Forester: Samba's AD
# DC in a container (Podman), filled with the same corp.example directory as
# start.sh. Unlike start.sh's OpenLDAP stand-in it enforces what AD enforces:
# password policy, unique account names, rights on password changes, locking
# out after failed sign-ins, and the rest.
#
#   TestDirectory/start-ad.sh
#
#   ldaps://localhost:11636, and ldap://localhost:11389 with StartTLS
#   the global catalog on ldap://localhost:13268 (StartTLS)
#   Kerberos: the DC's KDC on localhost:10088, and a ticket for Administrator in
#   TestDirectory/.run/krb5cc, for a client run with
#   KRB5_CONFIG=TestDirectory/.run/krb5.conf KRB5CCNAME=FILE:TestDirectory/.run/krb5cc
#   (your own Kerberos settings and tickets are not touched)
#   Administrator@corp.example, CORP\Administrator or CN=Administrator,CN=Users,DC=corp,DC=example
#   password Forester-Lab-Admin-2026!; every seeded account has Corp-Example-Test-Password-2026!
#
# Each start provisions a new domain, so it begins from the same state.
# TestDirectory/stop-ad.sh removes it.
set -euo pipefail

HERE=${0:A:h}
NAME=forester-ad
IMAGE=localhost/forester-samba-ad:latest
ADMIN=Administrator@corp.example
ADMIN_PASSWORD='Forester-Lab-Admin-2026!'
RUN="$HERE/.run"
mkdir -p "$RUN"
export LDAPTLS_REQCERT=never  # the DC's certificate is self-signed; this is the test client only

podman build -q -t "$IMAGE" "$HERE/samba" >/dev/null
podman rm -f "$NAME" >/dev/null 2>&1 || true
podman run -d --name "$NAME" --hostname dc1 -e ADMIN_PASSWORD="$ADMIN_PASSWORD" \
  -p 127.0.0.1:11389:389 -p 127.0.0.1:11636:636 -p 127.0.0.1:13268:3268 -p 127.0.0.1:10088:88 "$IMAGE" >/dev/null

echo -n "Provisioning corp.example"
for i in {1..90}; do
  if ldapsearch -o nettimeout=3 -H ldaps://localhost:11636 -x -D "$ADMIN" -w "$ADMIN_PASSWORD" \
       -b "" -s base "(objectClass=*)" dnsHostName >/dev/null 2>&1; then
    break
  fi
  [[ "$(podman inspect -f '{{.State.Running}}' "$NAME")" == true ]] || { echo; podman logs "$NAME" | tail -20; exit 1; }
  echo -n "."
  sleep 2
done
echo

python3 "$HERE/generate_ldif.py" samba > "$RUN/samba-seed.ldif"
echo "Loading $(grep -c '^dn:' "$RUN/samba-seed.ldif") entries"
if ! ldapadd -H ldaps://localhost:11636 -x -D "$ADMIN" -w "$ADMIN_PASSWORD" -f "$RUN/samba-seed.ldif" > "$RUN/samba-seed.log" 2>&1; then
  grep -B2 -A2 "additional info" "$RUN/samba-seed.log" | head -20
  echo "Loading failed; the whole log is in $RUN/samba-seed.log" >&2
  exit 1
fi

# Kerberos to "localhost": the DC answers to that name too, and a private
# configuration and ticket cache keep the test realm away from the Mac's own.
podman exec "$NAME" samba-tool spn add ldap/localhost 'DC1$' >/dev/null
cat > "$RUN/krb5.conf" <<'KRB5'
[libdefaults]
    default_realm = CORP.EXAMPLE
    dns_lookup_kdc = false
    dns_lookup_realm = false
    dns_canonicalize_hostname = false
    rdns = false
[realms]
    CORP.EXAMPLE = {
        kdc = tcp/127.0.0.1:10088
    }
[domain_realm]
    localhost = CORP.EXAMPLE
KRB5
rm -f "$RUN/krb5cc"
print -r -- "$ADMIN_PASSWORD" | KRB5_CONFIG="$RUN/krb5.conf" KRB5CCNAME="FILE:$RUN/krb5cc" \
  kinit --password-file=STDIN Administrator@CORP.EXAMPLE

# Locked out the way AD does it: wrong passwords until the domain's threshold (5).
LOCKED="CN=Thomas Wouters,OU=Sales,OU=Users,OU=Corp,DC=corp,DC=example"
for i in {1..6}; do
  ldapwhoami -H ldaps://localhost:11636 -x -D "$LOCKED" -w "not the password" >/dev/null 2>&1 || true
done

echo "Active Directory (Samba $(podman exec "$NAME" samba --version | awk '{print $2}')) is up:"
echo "  ldaps://localhost:11636 and ldap://localhost:11389 (StartTLS), as $ADMIN"
echo "  Thomas Wouters is locked out; stop with TestDirectory/stop-ad.sh"
