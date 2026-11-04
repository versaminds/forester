#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Makes the website's images from pictures of the real app.
#
#   1. Take the pictures from the screen (test directory running, see TESTING.md):
#        FORESTER_SCREEN_CAPTURE=1 scripts/automation.sh /tmp/forester-marketing marketing
#   2. scripts/make-site-images.sh /tmp/forester-marketing
#
# Needs cwebp (brew install webp). The main-window pictures (M-*.png, 2880 by
# 1800) are also the right size for the Mac App Store.
set -euo pipefail

ROOT=${0:A:h:h}
SHOTS=${1:?usage: scripts/make-site-images.sh <folder with the M-*.png pictures>}
OUT="$ROOT/site/img"
ICONS="$ROOT/build/AppIcon.iconset"
mkdir -p "$OUT"
command -v cwebp >/dev/null || { echo "cwebp not found: brew install webp" >&2; exit 1; }
[[ -d "$ICONS" ]] || swift "$ROOT/scripts/make-icon.swift" "$ICONS" >/dev/null

# libpng warns about the colour profile AppKit writes; the warning is harmless.
webp() { cwebp -quiet -q "${QUALITY:-84}" -m 6 "$@" 2> >(grep -v "iCCP" >&2); }

for theme in light dark; do
  for name in overview search; do
    webp -resize 1600 0 "$SHOTS/M-$name-$theme.png" -o "$OUT/$name-$theme-1600.webp"
    webp "$SHOTS/M-$name-$theme.png" -o "$OUT/$name-$theme-2880.webp"
  done
  # The detail column of the read-only window: the toolbar's Read-only button
  # and the greyed-out account options with the note under them.
  webp -crop 1384 0 1496 920 "$SHOTS/M-read-only-$theme.png" -o "$OUT/read-only-$theme.webp"
  # The detail column of the service account: its badges, password policy,
  # service principal names and last sign-in on this DC.
  webp -crop 1384 0 1496 1770 "$SHOTS/M-service-account-$theme.png" -o "$OUT/service-account-$theme.webp"
  for name in password import; do
    webp "$SHOTS/M-$name-$theme.png" -o "$OUT/$name-$theme.webp"
  done
done

sips -z 64 64 "$ICONS/icon_32x32@2x.png" --out "$OUT/icon-64.png" >/dev/null
cp "$OUT/icon-64.png" "$OUT/favicon-64.png"
sips -z 256 256 "$ICONS/icon_256x256.png" --out "$OUT/icon-256.png" >/dev/null
sips -z 180 180 "$ICONS/icon_256x256@2x.png" --out "$OUT/apple-touch-icon.png" >/dev/null
swift "$ROOT/scripts/make-og-image.swift" "$ICONS/icon_256x256@2x.png" "$SHOTS/M-overview-light.png" "$OUT/og.jpg"

# A picture keeps its name and browsers keep it for a day (site/_headers), so
# every link to one carries a version from its contents: a new picture is a
# new address, and nobody is shown the one before it.
for file in "$OUT"/*.webp; do
  name=${file:t}
  version=$(shasum -a 256 "$file" | cut -c1-10)
  perl -pi -e "s{img/\Q$name\E(\?v=[0-9a-f]+)?}{img/$name?v=$version}g" "$ROOT"/site/*.html
done

echo "Images written to $OUT:"
ls -l "$OUT" | awk 'NR > 1 { printf "  %-32s %6d KB\n", $NF, $5 / 1024 }'
