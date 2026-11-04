#!/bin/sh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Provisions the domain the first time (file ACLs kept in a database rather
# than in extended attributes, which an unprivileged container cannot set), with the password policy the test
# directory describes (a minimum password age of 0, so a password can be
# changed twice in a test), then runs Samba in the foreground.
set -eu
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    rm -f /etc/samba/smb.conf
    samba-tool domain provision --realm=CORP.EXAMPLE --domain=CORP --server-role=dc \
        --dns-backend=SAMBA_INTERNAL --adminpass="$ADMIN_PASSWORD" --use-rfc2307 \
        --option="dns forwarder = 127.0.0.1" \
        --option="vfs objects = dfs_samba4 acl_xattr xattr_tdb" \
        --option="xattr_tdb:file = /var/lib/samba/xattr.tdb"
    samba-tool domain passwordsettings set --complexity=on --min-pwd-length=12 --history-length=24 \
        --min-pwd-age=0 --max-pwd-age=42 --account-lockout-threshold=5 --account-lockout-duration=30 \
        --reset-account-lockout-after=30
fi
exec samba --interactive --no-process-group
