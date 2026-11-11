#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Builds the Mac App Store package, build/AppStore/Forester-<version>.pkg, to
# upload with Apple's Transporter app (docs/APP-STORE.md).
#
#   scripts/make-appstore.sh <Mac App Store provisioning profile>
#   scripts/make-appstore.sh --sandbox-test
#
# The first needs the "Apple Distribution" and "Mac Installer Distribution"
# certificates in the keychain, and the profile made for the App ID
# live.versaminds.Forester in the developer portal. The build number is the
# time of the build (scripts/build-app.sh), so every upload has a higher one
# than the last.
#
# --sandbox-test signs the same build with this Mac's "Apple Development"
# certificate and no profile, to try the sandbox here. It cannot be uploaded.
set -euo pipefail

ROOT=${0:A:h:h}
OUT="$ROOT/build/AppStore"
APP="$OUT/Forester.app"
BUNDLE_ID=live.versaminds.Forester
VERSION=$(tr -d '[:space:]' < "$ROOT/VERSION")
fail() { print -u2 "make-appstore: $1"; exit 1; }
trap 'rm -f "${PROFILE_PLIST:-}" "${ENTITLEMENTS:-}"' EXIT

PROFILE=${1:?usage: scripts/make-appstore.sh <provisioning profile> | --sandbox-test}
IDENTITIES=$(security find-identity -v -p codesigning 2>/dev/null || true)
identity() { print -r -- "$IDENTITIES" | grep -o "\"$1: [^\"]*\"" | head -1 | tr -d '"' || true; }

if [[ "$PROFILE" == "--sandbox-test" ]]; then
  SIGNER=$(identity "Apple Development")
  [[ -n "$SIGNER" ]] || fail "no Apple Development certificate in the keychain."
else
  [[ -f "$PROFILE" ]] || fail "no provisioning profile at $PROFILE."
  PROFILE_PLIST=$(mktemp -t forester-profile)
  security cms -D -i "$PROFILE" > "$PROFILE_PLIST" 2>/dev/null || fail "$PROFILE is not a provisioning profile."
  TEAM=$(plutil -extract TeamIdentifier.0 raw "$PROFILE_PLIST")
  APP_ID=$(plutil -extract Entitlements.com\\.apple\\.application-identifier raw "$PROFILE_PLIST" 2>/dev/null || true)
  [[ "$APP_ID" == "$TEAM.$BUNDLE_ID" ]] ||
    fail "the profile is for '$APP_ID', not $TEAM.$BUNDLE_ID. Make a Mac App Store profile for $BUNDLE_ID."
  plutil -extract ProvisionedDevices raw "$PROFILE_PLIST" >/dev/null 2>&1 &&
    fail "the profile lists devices, so it is a development profile. Make one of type Mac App Store Connect."
  EXPIRES=$(plutil -extract ExpirationDate raw "$PROFILE_PLIST")
  [[ "$EXPIRES" > "$(date -u +%Y-%m-%dT%H:%M:%SZ)" ]] || fail "the profile expired on $EXPIRES."

  # The certificates must belong to the profile's team.
  SIGNER=$(print -r -- "$IDENTITIES" | grep -o "\"Apple Distribution: [^\"]*($TEAM)\"" | head -1 | tr -d '"' || true)
  [[ -n "$SIGNER" ]] || SIGNER=$(print -r -- "$IDENTITIES" | grep -o "\"3rd Party Mac Developer Application: [^\"]*($TEAM)\"" | head -1 | tr -d '"' || true)
  [[ -n "$SIGNER" ]] || fail "no Apple Distribution certificate for team $TEAM in the keychain."
  # An installer certificate is not a code-signing identity, so it is listed separately.
  INSTALLERS=$(security find-identity -v 2>/dev/null || true)
  INSTALLER=$(print -r -- "$INSTALLERS" | grep -oE "\"(Mac Installer Distribution|3rd Party Mac Developer Installer): [^\"]*\($TEAM\)\"" | head -1 | tr -d '"' || true)
  [[ -n "$INSTALLER" ]] || fail "no Mac Installer Distribution certificate for team $TEAM in the keychain."
fi

FORESTER_APP_STORE=1 "$ROOT/scripts/build-app.sh" universal

ENTITLEMENTS=$(mktemp -t forester-entitlements)
cp "$ROOT/Resources/AppStore.entitlements" "$ENTITLEMENTS"
if [[ "$PROFILE" != "--sandbox-test" ]]; then
  cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
  # The identifiers the profile grants: without them the App Store refuses
  # the upload, and with them the app cannot start unless the profile is in it.
  plutil -insert com\\.apple\\.application-identifier -string "$APP_ID" "$ENTITLEMENTS"
  plutil -insert com\\.apple\\.developer\\.team-identifier -string "$TEAM" "$ENTITLEMENTS"
fi
codesign --force --options runtime --timestamp --entitlements "$ENTITLEMENTS" --sign "$SIGNER" "$APP"
codesign --verify --strict --verbose=2 "$APP"
# The App Store updates the app, and App Review refuses any other updater.
[[ ! -e "$APP/Contents/Frameworks" ]] && ! otool -L "$APP/Contents/MacOS/Forester" | grep -qi sparkle ||
  fail "the App Store build contains Sparkle; it must be built with FORESTER_APP_STORE=1."
codesign -d --entitlements - --xml "$APP" 2>/dev/null | plutil -extract com\\.apple\\.security\\.app-sandbox raw - | grep -qx true ||
  fail "the signed app is not sandboxed."
[[ "$(lipo -archs "$APP/Contents/MacOS/Forester")" == *arm64* && "$(lipo -archs "$APP/Contents/MacOS/Forester")" == *x86_64* ]] ||
  fail "the app is not universal."
vtool -show-build "$APP/Contents/MacOS/Forester" | grep -q "sdk $(xcrun --sdk macosx --show-sdk-version)" ||
  fail "the app does not say it was built with this Mac's SDK."

if [[ "$PROFILE" == "--sandbox-test" ]]; then
  echo "Sandboxed test build: $APP (signed by $SIGNER; it cannot be uploaded)"
  exit 0
fi

PKG="$OUT/Forester-$VERSION.pkg"
rm -f "$PKG"
productbuild --component "$APP" /Applications --sign "$INSTALLER" "$PKG"
pkgutil --check-signature "$PKG" >/dev/null || fail "the package's signature does not check out."
echo
echo "Built $PKG"
echo "  version $VERSION, build $(plutil -extract CFBundleVersion raw "$APP/Contents/Info.plist")"
echo "  app signed by $SIGNER"
echo "  package signed by $INSTALLER"
echo "Upload it with Transporter (free in the Mac App Store): sign in, drag the .pkg in, Deliver."
