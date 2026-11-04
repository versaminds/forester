#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Builds the download: build/Forester.dmg, for Apple silicon and Intel.
#
#   scripts/make-release.sh
#
# Signed with a "Developer ID Application" certificate (see build-app.sh) and
# given a notary profile, the app and the disk image are notarized and stapled,
# so they open on any Mac without a warning. Store the profile once:
#
#   xcrun notarytool store-credentials forester-notary --apple-id you@example.com --team-id TEAMID
#   FORESTER_NOTARY_PROFILE=forester-notary scripts/make-release.sh
#
# It refuses to make a release it cannot vouch for: from a tree with
# uncommitted changes, without both architectures, without a Developer ID
# signature with the hardened runtime, without notarization, or without the
# updater (a download that cannot update itself never can). Last, it signs
# the image with the update key in the keychain (Sparkle's sign_update),
# checks the signature against Resources/sparkle-public-key, and adds the
# release to site/updates/appcast.xml; publish the GitHub release first, then
# the site, so the feed never names a file that is not there yet. For trying
# the image on this Mac only, FORESTER_ALLOW_ADHOC=1 makes one signed ad hoc
# (Gatekeeper refuses it on any other Mac), and FORESTER_ALLOW_DIRTY=1 builds
# from uncommitted changes.
set -euo pipefail

ROOT=${0:A:h:h}
cd "$ROOT"
APP="$ROOT/build/Forester.app"
DMG="$ROOT/build/Forester.dmg"
NOTARY=${FORESTER_NOTARY_PROFILE:-}
ADHOC=${FORESTER_ALLOW_ADHOC:-0}

fail() { print -u2 -- "make-release: $1"; exit 1; }

[[ -f "$ROOT/VERSION" ]] || fail "VERSION is missing."
VERSION=$(tr -d '[:space:]' < "$ROOT/VERSION")
[[ "$VERSION" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] || fail "VERSION is \"$VERSION\", not a version like 1.0.0."
if [[ "${FORESTER_ALLOW_DIRTY:-0}" != 1 && -n "$(git status --porcelain)" ]]; then
  fail "the working tree has uncommitted changes; commit them, or set FORESTER_ALLOW_DIRTY=1 for a test build."
fi
TAG=$(git tag --points-at HEAD | head -1)
if [[ -n "$TAG" && "$TAG" != "v$VERSION" ]]; then
  fail "HEAD is tagged $TAG but VERSION says $VERSION."
fi
rm -f "$DMG"

"$ROOT/scripts/build-app.sh" universal
BINARY="$APP/Contents/MacOS/Forester"
ARCHS=$(lipo -archs "$BINARY")
[[ " $ARCHS " == *" arm64 "* && " $ARCHS " == *" x86_64 "* ]] || fail "the app is built for $ARCHS, not for both arm64 and x86_64."
# System libraries, and through @rpath only what ships inside the app.
for library in $(otool -L "$BINARY" | awk '/@rpath\// { print $1 }'); do
  [[ -e "$APP/Contents/Frameworks/${library#@rpath/}" ]] || fail "the app links $library, which is not in the app."
done
FEED=$(/usr/libexec/PlistBuddy -c "Print :SUFeedURL" "$APP/Contents/Info.plist" 2>/dev/null || true)
if [[ -z "$FEED" ]]; then
  [[ "$ADHOC" == 1 ]] || fail "the app has no updater: put the update key's public half in Resources/sparkle-public-key (docs/DISTRIBUTION.md)."
  echo "No updater in this test build: Resources/sparkle-public-key is missing."
fi

SIGNATURE=$(codesign -dvv "$APP" 2>&1)
IDENTITY=$(print -r -- "$SIGNATURE" | sed -n 's/^Authority=\(Developer ID Application: .*\)$/\1/p' | head -1)
codesign --verify --strict --verbose=2 "$APP"
if [[ -n "$IDENTITY" ]]; then
  print -r -- "$SIGNATURE" | grep -q "flags=.*runtime" || fail "the app is signed without the hardened runtime, which notarization requires."
  [[ -n "$NOTARY" ]] || fail "signed by $IDENTITY, but FORESTER_NOTARY_PROFILE is not set, so it cannot be notarized."
elif [[ "$ADHOC" != 1 ]]; then
  fail "no Developer ID Application certificate was used (see build-app.sh). FORESTER_ALLOW_ADHOC=1 makes an image for this Mac only."
fi

# Submits, waits, and on a refusal prints Apple's log, which says why.
notarize() {
  local out id notary_status
  out=$(xcrun notarytool submit "$1" --keychain-profile "$NOTARY" --wait --output-format json)
  id=$(print -r -- "$out" | plutil -extract id raw -o - -- -)
  notary_status=$(print -r -- "$out" | plutil -extract status raw -o - -- -)
  if [[ "$notary_status" != "Accepted" ]]; then
    xcrun notarytool log "$id" --keychain-profile "$NOTARY" >&2 || true
    fail "notarization of $(basename "$1") ended as $notary_status (submission $id)."
  fi
  xcrun stapler staple "$2"
  xcrun stapler validate "$2"
}

# The app first, so it carries its own ticket once copied out of the image.
if [[ -n "$IDENTITY" ]]; then
  ditto -c -k --keepParent "$APP" "$ROOT/build/Forester-notarize.zip"
  notarize "$ROOT/build/Forester-notarize.zip" "$APP"
  rm -f "$ROOT/build/Forester-notarize.zip"
  spctl --assess --type exec --verbose=2 "$APP"
fi

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
ditto "$APP" "$STAGE/Forester.app"
ln -s /Applications "$STAGE/Applications"
hdiutil create -quiet -volname "Forester $VERSION" -srcfolder "$STAGE" -fs HFS+ -format UDZO "$DMG"

if [[ -n "$IDENTITY" ]]; then
  codesign --force --timestamp --sign "$IDENTITY" "$DMG"
  notarize "$DMG" "$DMG"
  spctl --assess --type open --context context:primary-signature --verbose "$DMG"
else
  echo "The app is signed ad hoc and the image is not signed: for this Mac only, Gatekeeper refuses it on others."
fi

echo "Built $DMG, version $VERSION, for $ARCHS"
shasum -a 256 "$DMG"

# The Homebrew cask for this image, to copy over Casks/forester.rb in
# versaminds/homebrew-tap once the release with this image is published.
SHA256=$(shasum -a 256 "$DMG" | cut -d' ' -f1)
cat > "$ROOT/build/forester.rb" <<CASK
cask "forester" do
  version "$VERSION"
  sha256 "$SHA256"

  url "https://github.com/versaminds/forester/releases/download/v#{version}/Forester.dmg"
  name "Forester"
  desc "LDAP and Active Directory browser"
  homepage "https://forester.versaminds.live/"

  depends_on macos: :sonoma

  app "Forester.app"

  zap trash: [
    "~/Library/Application Support/Forester",
    "~/Library/Preferences/live.versaminds.Forester.plist",
    "~/Library/Saved Application State/live.versaminds.Forester.savedState",
  ]
end
CASK
echo "Homebrew cask written to build/forester.rb"

# The update feed. Sparkle installs only an image signed with the key whose
# public half the running app carries, so the signature is checked against
# that half before the release is listed.
[[ -n "$FEED" ]] || exit 0
SPARKLE_BIN="$ROOT/.build/artifacts/sparkle/Sparkle/bin"
# The key is in the keychain under the account "forester" (generate_keys
# --account forester); FORESTER_UPDATE_KEY_FILE names a file holding it instead.
SIGN_WITH=(--account forester)
[[ -n "${FORESTER_UPDATE_KEY_FILE:-}" ]] && SIGN_WITH=(--ed-key-file "$FORESTER_UPDATE_KEY_FILE")
if ! SIGNED=$("$SPARKLE_BIN/sign_update" "${SIGN_WITH[@]}" "$DMG"); then
  [[ "$ADHOC" == 1 ]] && { echo "Not added to the update feed: the update key is not in this Mac's keychain."; exit 0; }
  fail "sign_update could not sign the image: is the update key (account forester) in the keychain?"
fi
ED_SIGNATURE=$(print -r -- "$SIGNED" | sed -n 's/.*sparkle:edSignature="\([^"]*\)".*/\1/p')
LENGTH=$(print -r -- "$SIGNED" | sed -n 's/.*length="\([0-9]*\)".*/\1/p')
swift "$ROOT/scripts/check-update-signature.swift" "$DMG" "$ED_SIGNATURE" "$(tr -d '[:space:]' < "$ROOT/Resources/sparkle-public-key")" ||
  fail "the image's signature does not match Resources/sparkle-public-key: the keychain holds another update key."
BUILD_NUMBER=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$APP/Contents/Info.plist")
MINIMUM=$(/usr/libexec/PlistBuddy -c "Print :LSMinimumSystemVersion" "$APP/Contents/Info.plist")
APPCAST="$ROOT/site/updates/appcast.xml"
grep -q "<sparkle:version>$BUILD_NUMBER</sparkle:version>" "$APPCAST" && fail "the update feed already lists build $BUILD_NUMBER; raise VERSION or FORESTER_BUILD."
ITEM=$(mktemp)
cat > "$ITEM" <<XML
    <item>
      <title>Forester $VERSION</title>
      <pubDate>$(LC_ALL=C date -u "+%a, %d %b %Y %H:%M:%S +0000")</pubDate>
      <sparkle:version>$BUILD_NUMBER</sparkle:version>
      <sparkle:shortVersionString>$VERSION</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>$MINIMUM</sparkle:minimumSystemVersion>
      <sparkle:releaseNotesLink>https://github.com/versaminds/forester/releases/tag/v$VERSION</sparkle:releaseNotesLink>
      <enclosure url="https://github.com/versaminds/forester/releases/download/v$VERSION/Forester.dmg" sparkle:edSignature="$ED_SIGNATURE" length="$LENGTH" type="application/octet-stream"/>
    </item>
XML
# Newest first, under the marker line.
awk -v item="$ITEM" '{ print } /<!-- Releases, newest first/ { while ((getline line < item) > 0) print line }' "$APPCAST" > "$APPCAST.new"
mv "$APPCAST.new" "$APPCAST"
rm -f "$ITEM"
xmllint --noout "$APPCAST" || fail "site/updates/appcast.xml is not valid XML after adding the release."
echo "Added Forester $VERSION (build $BUILD_NUMBER) to site/updates/appcast.xml: publish the GitHub release, then commit and deploy the site."
