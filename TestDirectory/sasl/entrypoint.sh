#!/bin/sh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Writes slapd.conf, loads a few entries and runs slapd in the foreground.
# The certificates come from start-sasl.sh, mounted at /certs.
#
# A client certificate's subject (cn=…,o=Forester Test) names an entry under
# ou=people; so does a SCRAM user name (uid=…). SCRAM reads the password from
# the entry's userPassword, which therefore holds it as typed.
set -eu
mkdir -p /run/openldap /var/lib/openldap/data
cat > /etc/openldap/slapd.conf <<'EOF'
include /etc/openldap/schema/core.schema
include /etc/openldap/schema/cosine.schema
include /etc/openldap/schema/inetorgperson.schema
modulepath /usr/lib/openldap
moduleload back_mdb.so
pidfile /run/openldap/slapd.pid

TLSCACertificateFile /certs/ca.crt
TLSCertificateFile /certs/server.crt
TLSCertificateKeyFile /certs/server.key
# Asks every TLS client for a certificate and takes one signed by the test
# CA; a client without one still connects.
TLSVerifyClient try
# SCRAM-SHA-256-PLUS binds the TLS certificate, as Forester does.
sasl-cbinding tls-endpoint

authz-regexp "^cn=([^,]+),o=forester test$" "cn=$1,ou=people,dc=sasl,dc=example"
authz-regexp "^uid=([^,]+),(cn=[^,]+,)?cn=[^,]+,cn=auth$" "uid=$1,ou=people,dc=sasl,dc=example"

access to dn.base="" by * read
access to dn.base="cn=Subschema" by * read
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by anonymous auth by * none

database mdb
suffix "dc=sasl,dc=example"
rootdn "cn=admin,dc=sasl,dc=example"
rootpw secret
directory /var/lib/openldap/data
EOF
if [ ! -f /var/lib/openldap/data/data.mdb ]; then
    slapadd -f /etc/openldap/slapd.conf <<'EOF'
dn: dc=sasl,dc=example
objectClass: dcObject
objectClass: organization
dc: sasl
o: Forester SASL Test

dn: ou=people,dc=sasl,dc=example
objectClass: organizationalUnit
ou: people

dn: cn=Forester Client,ou=people,dc=sasl,dc=example
objectClass: inetOrgPerson
cn: Forester Client
sn: Client
description: Signs in with its certificate

dn: uid=scram.user,ou=people,dc=sasl,dc=example
objectClass: inetOrgPerson
cn: Scram User
sn: User
uid: scram.user
userPassword: Scram-Test-Password-2026!

dn: uid=scram.accents,ou=people,dc=sasl,dc=example
objectClass: inetOrgPerson
cn: Scram Accents
sn: Accents
uid: scram.accents
userPassword:: w4lsw6huZS1Ew6lqw6AtVnUtMjAyNiE=
EOF
fi
exec slapd -d 256 -f /etc/openldap/slapd.conf -h "ldap:/// ldaps:///"
