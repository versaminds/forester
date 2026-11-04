#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Checks the demo directory from outside, the way App Review will reach it:
#
#   demo-server/check.sh demo.forester.versaminds.live
#
# Asks for the review account's password (printed by setup.sh).
set -euo pipefail

HOST=${1:?usage: check.sh <host name>}
USER_DN="CN=App Review,CN=Users,DC=corp,DC=example"
read -rs "PASSWORD?Review account password: "
echo
# The tools read the password from a file only this user can read, so it is
# not on their command lines, where other processes can see it.
SECRET=$(mktemp)
trap 'rm -f "$SECRET"' EXIT
print -rn -- "$PASSWORD" > "$SECRET"
fails=0
check() { if eval "$2" >/dev/null 2>&1; then echo "ok    $1"; else echo "FAIL  $1"; fails=$((fails + 1)); fi; }

check "LDAPS answers on 636 with a certificate this Mac trusts for $HOST" \
  "echo | openssl s_client -connect $HOST:636 -servername $HOST -verify_hostname $HOST -verify_return_error"
check "the certificate is good for at least another 14 days" \
  "echo | openssl s_client -connect $HOST:636 -servername $HOST 2>/dev/null | openssl x509 -noout -checkend 1209600"
check "the review account signs in over LDAPS" \
  "ldapwhoami -x -H ldaps://$HOST -D '$USER_DN' -y '$SECRET'"
check "the review account signs in over StartTLS" \
  "ldapwhoami -x -ZZ -H ldap://$HOST -D '$USER_DN' -y '$SECRET'"
# A made-up password: the server refuses a sign-in without encryption
# (confidentiality required, 13) before it looks at the password, and the
# real one must not cross the internet unencrypted to prove it.
check "a password sent without encryption is refused" \
  "ldapwhoami -x -H ldap://$HOST -D '$USER_DN' -w not-the-password; [[ \$? == 13 ]]"
check "nothing but the server's description is readable without signing in" \
  "[[ \$(ldapsearch -x -H ldaps://$HOST -b DC=corp,DC=example -LLL '(objectClass=*)' dn 2>/dev/null | grep -c '^dn:') == 0 ]]"
check "the directory holds the demo data (over 1,500 accounts, read in pages)" \
  "[[ \$(ldapsearch -x -H ldaps://$HOST -D '$USER_DN' -y '$SECRET' -b DC=corp,DC=example -E pr=200/noprompt -LLL '(objectClass=user)' dn | grep -c '^dn:') -gt 1500 ]]"
echo
(( fails == 0 )) && echo "All good: the review notes can name $HOST." || { echo "$fails check(s) failed."; exit 1; }
