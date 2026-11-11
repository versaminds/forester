#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Builds "Forester.app" into ./build and signs it.
#
#   scripts/build-app.sh            release build for this Mac's architecture
#   scripts/build-app.sh universal  Apple silicon and Intel in one binary
#
# FORESTER_APP_STORE=1 builds the Mac App Store variant instead, into
# build/AppStore (scripts/make-appstore.sh signs and packages it).
#
# The build number (CFBundleVersion) is the time of the build in UTC,
# YYYYMMDD.HHMM, unless FORESTER_BUILD sets one. On the Mac, App Store
# Connect takes at most three numbers there and wants every upload higher
# than any before, across versions; the time always is, and Sparkle compares
# it the same way.
#
# The download updates itself through Sparkle once Resources/sparkle-public-key
# holds the public half of the key its releases are signed with (made once
# with Sparkle's generate_keys, see docs/DISTRIBUTION.md): the build then names
# the feed, FORESTER_FEED_URL or the website's. Without the key it has no
# updater. The App Store variant never has one: the App Store updates it.
#
# It signs with FORESTER_SIGN_IDENTITY if set, otherwise with the first
# "Developer ID Application" or "Apple Development" certificate in the
# keychain, otherwise ad hoc. Ad hoc runs on this Mac, but every build is a
# different app to the keychain: macOS asks for the Mac's password (twice)
# before the new build may read a saved connection password.
set -euo pipefail

ROOT=${0:A:h:h}
cd "$ROOT"
[[ -f "$ROOT/VERSION" ]] || { print -u2 "build-app: VERSION is missing."; exit 1; }
VERSION=$(tr -d '[:space:]' < "$ROOT/VERSION")
BUILD=${FORESTER_BUILD:-$(date -u +%Y%m%d.%H%M)}

if [[ "${1:-}" == "universal" ]]; then
  ARGS=(-c release --arch arm64 --arch x86_64)
else
  ARGS=(-c release)
fi
if [[ -n "${FORESTER_APP_STORE:-}" ]]; then
  OUT="$ROOT/build/AppStore"
  # Its own build folder, so the two variants never share compiled code.
  # Package.swift reads FORESTER_APP_STORE too, and leaves Sparkle out.
  export FORESTER_APP_STORE=1
  ARGS+=(-Xswiftc -DAPP_STORE --scratch-path "$ROOT/.build/appstore")
else
  OUT="$ROOT/build"
fi
APP="$OUT/Forester.app"
mkdir -p "$OUT"
# SwiftPM links through clang with --sysroot, from which clang does not read
# the SDK's version, so the binary would say it was built with the macOS 14
# SDK, and the App Store refuses an app built with an old SDK. The linker
# takes the last version it is given.
MINIMUM=$(plutil -extract LSMinimumSystemVersion raw "$ROOT/Resources/Info.plist")
SDK_VERSION=$(xcrun --sdk macosx --show-sdk-version)
ARGS+=(-Xlinker -platform_version -Xlinker macos -Xlinker "$MINIMUM" -Xlinker "$SDK_VERSION")
swift build "${ARGS[@]}"
# Asked rather than assumed: where SwiftPM puts the product depends on the
# toolchain and on whether more than one architecture is built.
BIN="$(swift build "${ARGS[@]}" --show-bin-path)/Forester"

rm -rf "$APP" "$OUT/Forester.dSYM"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Forester"
# Kept beside the app, not in it, so a crash report from a user can be read.
dsymutil "$BIN" -o "$OUT/Forester.dSYM" 2>/dev/null || echo "No dSYM: crash reports from this build cannot be symbolicated."
sed -e "s/__VERSION__/$VERSION/g" -e "s/__BUILD__/$BUILD/g" "$ROOT/Resources/Info.plist" > "$APP/Contents/Info.plist"
cp "$ROOT/Resources/PrivacyInfo.xcprivacy" "$APP/Contents/Resources/"

if [[ -z "${FORESTER_APP_STORE:-}" ]]; then
  mkdir -p "$APP/Contents/Frameworks"
  ditto "${BIN:h}/Sparkle.framework" "$APP/Contents/Frameworks/Sparkle.framework"
  # What a framework carries for building against it has no place in an app.
  for part in Headers PrivateHeaders Modules; do
    rm -rf "$APP/Contents/Frameworks/Sparkle.framework/$part" "$APP/Contents/Frameworks/Sparkle.framework/Versions/B/$part"
  done
  # Sparkle's licence travels with every copy; About links to it.
  SPARKLE_LICENSE="$ROOT/.build/artifacts/sparkle/Sparkle/LICENSE"
  [[ -s "$SPARKLE_LICENSE" ]] || { print -u2 "build-app: $SPARKLE_LICENSE is missing: the app may not ship without Sparkle's licence."; exit 1; }
  cp "$SPARKLE_LICENSE" "$APP/Contents/Resources/Sparkle-LICENSE.txt"
  FEED=${FORESTER_FEED_URL:-https://forester.versaminds.live/updates/appcast.xml}
  KEY=$(tr -d '[:space:]' < "$ROOT/Resources/sparkle-public-key" 2>/dev/null || true)
  if [[ "$FEED" == https://* && -n "$KEY" ]]; then
    # No SUEnableAutomaticChecks: Sparkle asks on the second launch whether to
    # check automatically, so nothing is fetched before the person says yes.
    /usr/libexec/PlistBuddy -c "Add :SUFeedURL string $FEED" -c "Add :SUPublicEDKey string $KEY" "$APP/Contents/Info.plist"
    echo "Updates from $FEED"
  else
    echo "No updater: Resources/sparkle-public-key is missing (see docs/DISTRIBUTION.md)."
  fi
fi

ICONSET="$ROOT/build/AppIcon.iconset"
if [[ ! -f "$ROOT/build/AppIcon.icns" || "$ROOT/scripts/make-icon.swift" -nt "$ROOT/build/AppIcon.icns" ]]; then
  rm -rf "$ICONSET"
  swift "$ROOT/scripts/make-icon.swift" "$ICONSET" >/dev/null
  iconutil -c icns "$ICONSET" -o "$ROOT/build/AppIcon.icns"
fi
cp "$ROOT/build/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"

IDENTITY=${FORESTER_SIGN_IDENTITY:-}
if [[ -z "$IDENTITY" ]]; then
  IDENTITIES=$(security find-identity -v -p codesigning 2>/dev/null || true)
  for kind in "Developer ID Application" "Apple Development"; do
    IDENTITY=$(print -r -- "$IDENTITIES" | grep -o "\"$kind: [^\"]*\"" | head -1 | tr -d '"' || true)
    [[ -n "$IDENTITY" ]] && break
  done
fi

# Sparkle's helpers inside its framework are signed before the app, innermost
# first, as its documentation says for an app outside the App Store: an app's
# signature covers the code inside it.
SPARKLE="$APP/Contents/Frameworks/Sparkle.framework"
sign_sparkle() {
  [[ -d "$SPARKLE" ]] || return 0
  for part in "$SPARKLE/Versions/B/XPCServices/Installer.xpc" "$SPARKLE/Versions/B/XPCServices/Downloader.xpc" \
              "$SPARKLE/Versions/B/Autoupdate" "$SPARKLE/Versions/B/Updater.app"; do
    [[ -e "$part" ]] && codesign --force "$@" "$part"
  done
  codesign --force "$@" "$SPARKLE"
}

if [[ -n "$IDENTITY" ]]; then
  sign_sparkle --options runtime --timestamp --sign "$IDENTITY"
  codesign --force --options runtime --timestamp --sign "$IDENTITY" "$APP"
  echo "Built $APP, signed by $IDENTITY"
else
  # With the hardened runtime like a release, so it behaves like one.
  sign_sparkle --options runtime --sign - --timestamp=none
  codesign --force --options runtime --sign - --timestamp=none "$APP"
  echo "Built $APP, signed ad hoc"
  echo "  Every ad hoc build is a new app to the keychain, so macOS asks before it reads a"
  echo "  saved password. Sign with a certificate (FORESTER_SIGN_IDENTITY) to keep access."
fi
