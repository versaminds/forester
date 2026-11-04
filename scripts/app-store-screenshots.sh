#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Takes the Mac App Store screenshots (2880 by 1800, light) and the website's
# pictures from the real app, with the test directory running:
#
#   scripts/app-store-screenshots.sh
#
# The pictures come from the screen, so Forester must stay in front: leave
# the Mac alone for the minute it takes. The terminal needs the Screen
# Recording permission. Writes build/AppStore/Screenshots/01-… to 09-…, in
# the order to upload them, and refreshes site/img.
set -euo pipefail

ROOT=${0:A:h:h}
SHOTS=/tmp/forester-marketing
OUT="$ROOT/build/AppStore/Screenshots"

LOG=$(mktemp)
FORESTER_SCREEN_CAPTURE=1 "$ROOT/scripts/automation.sh" "$SHOTS" marketing > "$LOG" 2>&1 || true
grep -E "FAILED|done" "$LOG" || true
[[ -f "$SHOTS/M-overview-light.png" ]] || { print -u2 "app-store-screenshots: the marketing run wrote no pictures."; exit 1; }
# A window pictured while another app was in front is drawn grey: retake.
if grep -q "inactive:" "$LOG"; then
  grep "inactive:" "$LOG" | sed 's/.*inactive: /  /' >&2
  print -u2 "app-store-screenshots: these were taken with another app in front. Run it again and leave the Mac alone; nothing was copied."
  exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"
i=1
for name in overview service-account search membership attributes read-only password import edit-members; do
  cp "$SHOTS/M-$name-light.png" "$OUT/$(printf %02d $i)-$name.png"
  i=$((i + 1))
done
for file in "$OUT"/*.png; do
  size=$(sips -g pixelWidth -g pixelHeight "$file" | awk '/pixel/ { printf "%s ", $2 }')
  [[ "$size" == "2880 1800 " ]] || { print -u2 "app-store-screenshots: ${file:t} is $size, not 2880 by 1800."; exit 1; }
done
"$ROOT/scripts/make-site-images.sh" "$SHOTS" >/dev/null
echo "Screenshots in $OUT, every one taken with Forester in front."
