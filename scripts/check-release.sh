#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Checks what a Mac App Store submission needs, from the repository to the
# live website and the directory App Review signs in to, and names
# everything still missing:
#
#   scripts/check-release.sh
#
# It changes nothing. It reads the built App Store variant in build/AppStore
# when there is one (scripts/make-appstore.sh --sandbox-test makes it).
set -uo pipefail

ROOT=${0:A:h:h}
cd "$ROOT"
problems=0
ok() { print -r -- "ok    $1"; }
missing() { print -r -- "TODO  $1"; problems=$((problems + 1)); }
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else missing "${3:-$1}"; fi; }

SITE=https://forester.versaminds.live
REVIEW_HOST=ldap.forumsys.com
PLIST="$ROOT/Resources/Info.plist"
key() { /usr/libexec/PlistBuddy -c "Print :$1" "$PLIST" 2>/dev/null; }

print "The app"
check "VERSION is a version like 1.0.0 ($(tr -d '[:space:]' < VERSION))" "[[ \$(tr -d '[:space:]' < VERSION) =~ '^[0-9]+\\.[0-9]+\\.[0-9]+\$' ]]"
check "the bundle identifier is live.versaminds.Forester" "[[ \$(key CFBundleIdentifier) == live.versaminds.Forester ]]"
check "it says it uses no encryption beyond the system's (export compliance)" "[[ \$(key ITSAppUsesNonExemptEncryption) == false ]]"
check "it names its App Store category" "[[ -n \$(key LSApplicationCategoryType) ]]"
check "the privacy manifest is a valid property list" "plutil -lint Resources/PrivacyInfo.xcprivacy"
check "the App Store entitlements sandbox it, with network access and files the person picks" \
  "plutil -lint Resources/AppStore.entitlements && grep -q app-sandbox Resources/AppStore.entitlements && grep -q network.client Resources/AppStore.entitlements"
check "the icon has its 1024-pixel picture" "sips -g pixelWidth build/AppIcon.iconset/icon_512x512@2x.png | grep -q 1024" \
  "the icon: run scripts/build-app.sh, which draws it"
APP="$ROOT/build/AppStore/Forester.app"
if [[ -d "$APP" ]]; then
  check "the App Store build is sandboxed" "codesign -d --entitlements - --xml '$APP' 2>/dev/null | grep -q app-sandbox"
  check "the App Store build carries no other updater" "[[ ! -e '$APP/Contents/Frameworks' ]] && ! otool -L '$APP/Contents/MacOS/Forester' | grep -qi sparkle"
  check "the App Store build was linked with this Mac's SDK" "vtool -show-build '$APP/Contents/MacOS/Forester' | grep -q \"sdk \$(xcrun --sdk macosx --show-sdk-version)\""
  check "the App Store build is for Apple silicon and Intel" "[[ \$(lipo -archs '$APP/Contents/MacOS/Forester') == *arm64* && \$(lipo -archs '$APP/Contents/MacOS/Forester') == *x86_64* ]]"
fi
check "nine App Store screenshots of 2880 by 1800" \
  "[[ \$(ls build/AppStore/Screenshots/0*.png 2>/dev/null | wc -l) -eq 9 ]] && for f in build/AppStore/Screenshots/0*.png; do sips -g pixelWidth -g pixelHeight \$f | grep -q 2880 || exit 1; done" \
  "the App Store screenshots: run scripts/app-store-screenshots.sh"

print "\nSigning (from developer.apple.com and Xcode › Settings › Accounts)"
check "an Apple Distribution certificate" "security find-identity -v -p codesigning | grep -q 'Apple Distribution'" \
  "an Apple Distribution certificate (docs/APP-STORE.md step 2)"
check "a Mac Installer Distribution certificate" "security find-identity -v 2>/dev/null | grep -q '3rd Party Mac Developer Installer\\|Mac Installer Distribution'" \
  "a Mac Installer Distribution certificate (docs/APP-STORE.md step 2)"

print "\nThe website (App Store Connect needs the privacy and support pages to load)"
for page in "" privacy.html support.html terms.html legal.html; do
  check "$SITE/$page loads" "[[ \$(curl -sL -o /dev/null -w '%{http_code}' --max-time 10 $SITE/$page) == 200 ]]" \
    "$SITE/$page does not load yet: deploy site/ to Cloudflare Pages (docs/DISTRIBUTION.md)"
done
check "the Download buttons lead to Forester on the Mac App Store" "! grep -q APPLE_ID site/_redirects" \
  "site/_redirects still has the placeholder: put Forester's Apple ID from App Store Connect in it"

print "\nThe directory App Review signs in to (docs/APP-STORE.md step 3)"
check "$REVIEW_HOST answers and can be read anonymously" \
  "ldapsearch -x -o nettimeout=10 -H ldap://$REVIEW_HOST:389 -b dc=example,dc=com -s one -LLL dn | grep -q '^dn: uid='" \
  "$REVIEW_HOST does not answer: name the demo directory of our own in the review notes instead (docs/APP-STORE.md step 3)"

print
if (( problems == 0 )); then
  print "Ready: build and upload with scripts/make-appstore.sh <profile> (docs/APP-STORE.md step 5)."
else
  print "$problems thing(s) to do before submitting; docs/APP-STORE.md says how."
  exit 1
fi
