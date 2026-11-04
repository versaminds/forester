#!/bin/sh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Sets up the demo directory on a fresh Debian 13 or Ubuntu 24.04 machine, as
# root, from a copy of the repository:
#
#   sh demo-server/setup.sh demo.forester.versaminds.live you@example.com
#
# Before running it, point the name's DNS A record at this machine (in
# Cloudflare: DNS only, not proxied, since Cloudflare does not carry LDAP) and
# open ports 80 (certificate renewal), 389 and 636. It gets a Let's Encrypt
# certificate, builds the image, runs it as a systemd service that starts
# again every night at 04:00 UTC with fresh data, and prints the review
# account's password. Running it again keeps that password.
set -eu

HOST=${1:?usage: setup.sh <host name> <email for Let's Encrypt>}
EMAIL=${2:?usage: setup.sh <host name> <email for Let's Encrypt>}
REPO=$(cd "$(dirname "$0")/.." && pwd)
ETC=/etc/forester-demo
[ "$(id -u)" = 0 ] || { echo "Run as root." >&2; exit 1; }

apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q podman certbot openssl

if [ ! -d "/etc/letsencrypt/live/$HOST" ]; then
  certbot certonly --standalone --non-interactive --agree-tos -m "$EMAIL" -d "$HOST"
fi
# A renewed certificate reaches slapd when the container starts again.
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/forester-demo <<'EOF'
#!/bin/sh
systemctl restart forester-demo
EOF
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/forester-demo

mkdir -p "$ETC"
chmod 700 "$ETC"
if [ ! -f "$ETC/env" ]; then
  # Letters and digits only, so it can be typed from the review notes as is.
  PASSWORD=$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 20)
  printf 'REVIEWER_PASSWORD=%s\n' "$PASSWORD" > "$ETC/env"
  chmod 600 "$ETC/env"
fi

podman build -q -f "$REPO/demo-server/Containerfile" -t localhost/forester-demo "$REPO"

cat > /etc/systemd/system/forester-demo.service <<EOF
[Unit]
Description=Forester demo directory for App Review
Wants=network-online.target
After=network-online.target

[Service]
ExecStartPre=-/usr/bin/podman rm -f forester-demo
ExecStart=/usr/bin/podman run --rm --name forester-demo \\
  -p 389:389 -p 636:636 \\
  -v /etc/letsencrypt/live/$HOST/fullchain.pem:/tls/fullchain.pem:ro \\
  -v /etc/letsencrypt/live/$HOST/privkey.pem:/tls/privkey.pem:ro \\
  --env-file $ETC/env -e SLAPD_DEBUG=0 \\
  --memory 512m --pids-limit 200 \\
  localhost/forester-demo
ExecStop=/usr/bin/podman stop -t 10 forester-demo
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/forester-demo-reset.service <<'EOF'
[Unit]
Description=Put the Forester demo directory back as it was

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl restart forester-demo
EOF

cat > /etc/systemd/system/forester-demo-reset.timer <<'EOF'
[Unit]
Description=Every night, put the Forester demo directory back as it was

[Timer]
OnCalendar=*-*-* 04:00:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
EOF

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 389/tcp && ufw allow 636/tcp
fi

systemctl daemon-reload
systemctl enable --now forester-demo.service forester-demo-reset.timer
systemctl restart forester-demo.service

# The directory takes a few seconds to build.
for _ in $(seq 1 30); do
  podman logs forester-demo 2>&1 | grep -q "slapd starting" && break
  sleep 2
done
podman logs forester-demo 2>&1 | grep -q "slapd starting" || { podman logs forester-demo 2>&1 | tail -20; exit 1; }

. "$ETC/env"
echo
echo "The demo directory is up."
echo "  Host:      $HOST"
echo "  Security:  LDAPS, port 636 (or StartTLS on 389)"
echo "  User:      CN=App Review,CN=Users,DC=corp,DC=example"
echo "  Password:  $REVIEWER_PASSWORD"
echo "Check it from a Mac with demo-server/check.sh $HOST"
