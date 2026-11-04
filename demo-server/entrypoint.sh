#!/bin/sh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Builds the directory and starts slapd. Expects:
#   /tls/fullchain.pem, /tls/privkey.pem   the server's certificate and key
#   REVIEWER_PASSWORD                      the review account's password
# Everything else is rebuilt on every start, so a restart puts back whatever
# a reviewer changed, and the dates in the data ("expires soon", "not seen for
# 90 days") are relative to the day it starts.
set -eu

: "${REVIEWER_PASSWORD:?REVIEWER_PASSWORD is not set}"
[ -r /tls/fullchain.pem ] && [ -r /tls/privkey.pem ] || { echo "No certificate in /tls" >&2; exit 1; }

DATA=/var/lib/ldap
CONF=/etc/ldap/slapd.conf
rm -rf "$DATA/ad" "$DATA/org"
mkdir -p "$DATA/ad" "$DATA/org" /etc/ldap/tls
# slapd runs as openldap and must read the key; the mounted one belongs to root.
cp /tls/fullchain.pem /tls/privkey.pem /etc/ldap/tls/
chown -R openldap:openldap "$DATA" /etc/ldap/tls
chmod 600 /etc/ldap/tls/privkey.pem

ROOTPW=$(slappasswd -h '{SSHA}' -s "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')")
REVIEWERPW=$(slappasswd -h '{SSHA}' -s "$REVIEWER_PASSWORD")
REVIEWER="CN=App Review,CN=Users,DC=corp,DC=example"
PLAYGROUND="OU=Playground,DC=corp,DC=example"

cat > "$CONF" <<CONF
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
include /etc/ldap/schema/nis.schema
include /etc/ldap/schema/dyngroup.schema
include /opt/forester/builtins.schema
include /opt/forester/adtest.schema

modulepath /usr/lib/ldap
moduleload back_mdb
moduleload back_monitor

pidfile  /run/slapd/slapd.pid
argsfile /run/slapd/slapd.args

TLSCertificateFile    /etc/ldap/tls/fullchain.pem
TLSCertificateKeyFile /etc/ldap/tls/privkey.pem
TLSProtocolMin 3.3

# Passwords travel encrypted only: a sign-in over plain LDAP without StartTLS
# is refused.
security simple_bind=128

# Pages of 200, at most 500 without paging, the way AD caps both: the app has
# to page through the 1,500-account OU. A search may take 30 seconds.
sizelimit size.soft=500 size.hard=500 size.pr=200 size.prtotal=unlimited
timelimit 30

# The server's own description and schema are public, as on any directory.
# Everything else needs the review account, which may change entries in the
# Playground OU only.
access to dn.base="" by * read
access to dn.base="cn=Subschema" by * read
# The review account may set a password in the Playground (Reset Password
# on an entry there), never read one.
access to dn.subtree="$PLAYGROUND" attrs=userPassword
    by dn.exact="$REVIEWER" =w
    by anonymous auth
    by * none
access to attrs=userPassword
    by anonymous auth
    by * none
access to dn.subtree="$PLAYGROUND"
    by dn.exact="$REVIEWER" write
    by users read
    by * none
access to *
    by users read
    by * none

database mdb
maxsize  268435456
suffix   "DC=corp,DC=example"
rootdn   "CN=admin,DC=corp,DC=example"
rootpw   $ROOTPW
directory $DATA/ad
index objectClass,cn,sAMAccountName,member eq

database monitor
access to dn.subtree="cn=Monitor"
    by users read
    by * none

database mdb
maxsize  268435456
suffix   "dc=example,dc=org"
rootdn   "cn=admin,dc=example,dc=org"
rootpw   $ROOTPW
directory $DATA/org
index objectClass,uid,cn eq
CONF

python3 -I /opt/forester/generate_ldif.py ad > /tmp/ad.ldif
python3 -I /opt/forester/generate_ldif.py org > /tmp/org.ldif
cat >> /tmp/ad.ldif <<LDIF
dn: $REVIEWER
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
structuralObjectClass: inetOrgPerson
cn: App Review
sn: Review
displayName: App Review
description: The account Apple's App Review signs in with. Reads everything; may change the Playground OU.
userPassword: $REVIEWERPW

dn: $PLAYGROUND
objectClass: top
objectClass: organizationalUnit
structuralObjectClass: organizationalUnit
ou: Playground
description: Change anything here: turn off Read-only in the toolbar first. Put back every night.

dn: CN=Try Editing Me,$PLAYGROUND
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
structuralObjectClass: user
cn: Try Editing Me
sn: Me
givenName: Try
displayName: Try Editing Me
sAMAccountName: try.me
userPrincipalName: try.me@corp.example
userAccountControl: 512
title: Demo account
mail: try.me@corp.example
telephoneNumber: +32 2 555 01 00
LDIF
# -s: see builtins.schema. A reviewer's own changes are checked as usual.
slapadd -q -s -f "$CONF" -b "DC=corp,DC=example" -l /tmp/ad.ldif
slapadd -q -s -f "$CONF" -b "dc=example,dc=org" -l /tmp/org.ldif
chown -R openldap:openldap "$DATA"
mkdir -p /run/slapd && chown openldap:openldap /run/slapd

echo "Directory built: $(grep -c '^dn:' /tmp/ad.ldif) + $(grep -c '^dn:' /tmp/org.ldif) entries"
exec slapd -f "$CONF" -u openldap -g openldap -h "ldap:/// ldaps:///" -d "${SLAPD_DEBUG:-256}"
