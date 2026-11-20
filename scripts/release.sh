#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Releases Forester from this Mac, everywhere at once:
#
#   scripts/release.sh            the next minor version (1.1.0 after 1.0.0)
#   scripts/release.sh patch      the next patch version (1.0.1)
#   scripts/release.sh 1.2.0      that version
#   scripts/release.sh --check    only the checks of step 1
#
# 1. Checks first, changing nothing: main, clean and pushed, every test green
#    on GitHub for this commit, the signing certificates, the App Store
#    profile, the notary profile and the update key.
# 2. VERSION raised and committed (tagged once both builds succeeded).
# 3. The App Store package (scripts/make-appstore.sh), uploaded to App Store
#    Connect with an API key when ASC_KEY_ID and ASC_ISSUER_ID are set
#    (the .p8 in ~/.appstoreconnect/private_keys), otherwise opened in
#    Transporter for one click on Deliver.
# 4. The download (scripts/make-release.sh): signed, notarized, stapled,
#    signed for Sparkle and added to the update feed, with its cask.
# 5. Pushed: the commit and tag, a published GitHub release with the image,
#    the feed on the website, and the cask in versaminds/homebrew-tap.
#
# What stays with a person: in App Store Connect, add the build to the new
# version and press Submit for Review.
#
# Needs, once: the Apple Distribution, Mac Installer Distribution and
# Developer ID Application certificates in the keychain; the App Store
# profile at build/Forester_App_Store.provisionprofile (or
# FORESTER_APPSTORE_PROFILE); notarytool credentials under the profile
# FORESTER_NOTARY_PROFILE (forester-notary, or another VersaMinds profile
# such as wayfinder-notary: notarization is per team); the update key in the
# keychain (generate_keys --account forester); write access to
# versaminds/forester and versaminds/homebrew-tap through git's credential
# helper; and wrangler signed in to the Cloudflare account.
set -euo pipefail

ROOT=${0:A:h:h}
cd "$ROOT"
REPO=versaminds/forester
TAP=versaminds/homebrew-tap
APPSTORE_PROFILE=${FORESTER_APPSTORE_PROFILE:-$ROOT/build/Forester_App_Store.provisionprofile}
fail() { print -u2 -- "release: $1"; exit 1; }
step() { print -- "\n== $1"; }

# --- the version -----------------------------------------------------------

KIND=minor
CHECK_ONLY=0
for argument in "$@"; do
  [[ "$argument" == --check ]] && CHECK_ONLY=1 || KIND=$argument
done
LAST=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-version:refname | head -1)
[[ -n "$LAST" ]] || fail "no release is tagged yet (v1.0.0 is the App Store's first)."
case "$KIND" in
  major|minor|patch)
    NEXT=$("$ROOT/scripts/release-due.sh" "$KIND" --force | sed -n 's/^version=//p') ;;
  [0-9]*.[0-9]*.[0-9]*) NEXT=$KIND ;;
  *) fail "usage: scripts/release.sh [major|minor|patch|X.Y.Z] [--check]" ;;
esac
[[ "$NEXT" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] || fail "\"$NEXT\" is not a version like 1.1.0."
[[ -z "$(git tag --list "v$NEXT")" ]] || fail "v$NEXT is already tagged."

# --- checks that change nothing --------------------------------------------

step "Checking before releasing $NEXT (last: $LAST)"
TOKEN=${GITHUB_TOKEN:-$(printf 'protocol=https\nhost=github.com\n\n' | git credential fill 2>/dev/null | sed -n 's/^password=//p')}
[[ -n "$TOKEN" ]] || fail "no GitHub token: set GITHUB_TOKEN, or sign in to github.com through git's credential helper."
api() { curl -fsS -m 60 -H "Authorization: Bearer $TOKEN" -H 'Accept: application/vnd.github+json' "$@"; }
json() { python3 -I -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

[[ "$(git branch --show-current)" == main ]] || fail "not on main."
[[ -z "$(git status --porcelain)" ]] || fail "the working tree has uncommitted changes."
git fetch -q origin main
[[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/main)" ]] || fail "main is not the same as origin/main: pull or push first."
HEAD_SHA=$(git rev-parse HEAD)
TESTS=$(api "https://api.github.com/repos/$REPO/actions/runs?head_sha=$HEAD_SHA&per_page=20" |
  json '"".join(sorted({r["conclusion"] or r["status"] for r in d["workflow_runs"] if r["name"] == "Tests"}))')
[[ "$TESTS" == success ]] || fail "the Tests workflow for $HEAD_SHA is \"${TESTS:-not run}\", not a success: release only what passed."

IDENTITIES=$(security find-identity -v 2>/dev/null)
for name in "Apple Distribution" "Developer ID Application"; do
  print -r -- "$IDENTITIES" | grep -q "\"$name: " || fail "no \"$name\" certificate in the keychain."
done
print -r -- "$IDENTITIES" | grep -qE '"(Mac Installer Distribution|3rd Party Mac Developer Installer): ' ||
  fail "no Mac Installer Distribution certificate in the keychain."
[[ -f "$APPSTORE_PROFILE" ]] || fail "no App Store profile at $APPSTORE_PROFILE (docs/APP-STORE.md step 2)."

if [[ -z "${FORESTER_NOTARY_PROFILE:-}" ]]; then
  for candidate in forester-notary wayfinder-notary; do
    xcrun notarytool history --keychain-profile "$candidate" >/dev/null 2>&1 && { FORESTER_NOTARY_PROFILE=$candidate; break; }
  done
fi
[[ -n "${FORESTER_NOTARY_PROFILE:-}" ]] ||
  fail "no notarytool profile: xcrun notarytool store-credentials forester-notary --apple-id … --team-id Z3CUYNS5ZQ"
export FORESTER_NOTARY_PROFILE
print "notarizing with the profile $FORESTER_NOTARY_PROFILE"

[[ -s "$ROOT/Resources/sparkle-public-key" ]] || fail "Resources/sparkle-public-key is missing."
KEY_IN_KEYCHAIN=$("$ROOT/.build/artifacts/sparkle/Sparkle/bin/generate_keys" --account forester -p 2>/dev/null || true)
[[ "$KEY_IN_KEYCHAIN" == "$(tr -d '[:space:]' < "$ROOT/Resources/sparkle-public-key")" ]] ||
  fail "the update key in the keychain (account forester) is not the one in Resources/sparkle-public-key."
api "https://api.github.com/repos/$TAP" >/dev/null || fail "cannot read $TAP with this token."
npx --yes wrangler@4.156.0 whoami >/dev/null 2>&1 || fail "wrangler is not signed in: npx wrangler login"
if (( CHECK_ONLY )); then print "Ready to release $NEXT."; exit 0; fi

# --- the version, committed and tagged ------------------------------------

step "Forester $NEXT"
# Until the push, everything is on this Mac only.
PUSHED=0
trap 'if (( $? != 0 && PUSHED == 0 )); then print -u2 "release: stopped before anything was pushed; to start over: git tag -d v$NEXT 2>/dev/null; git reset --hard origin/main"; fi' EXIT
print -- "$NEXT" > VERSION
git commit -q -m "Forester $NEXT" VERSION

# --- the App Store package -------------------------------------------------

step "The App Store package"
"$ROOT/scripts/make-appstore.sh" "$APPSTORE_PROFILE"
PKG="$ROOT/build/AppStore/Forester-$NEXT.pkg"
if [[ -n "${ASC_KEY_ID:-}" && -n "${ASC_ISSUER_ID:-}" ]]; then
  xcrun altool --upload-app -f "$PKG" -t macos --apiKey "$ASC_KEY_ID" --apiIssuer "$ASC_ISSUER_ID"
  UPLOADED="uploaded to App Store Connect"
else
  open -a Transporter "$PKG" 2>/dev/null || open -R "$PKG"
  UPLOADED="opened in Transporter: click Deliver"
fi

# --- the download ------------------------------------------------------------

step "The download"
"$ROOT/scripts/make-release.sh"
DMG="$ROOT/build/Forester.dmg"
CASK="$ROOT/build/forester.rb"

# --- published ---------------------------------------------------------------

step "Publishing"
git tag -a "v$NEXT" -m "Forester $NEXT"
git push -q origin main "v$NEXT"
PUSHED=1
NOTES=$(python3 -I -c 'import json,sys; print(json.dumps({"tag_name": sys.argv[1], "previous_tag_name": sys.argv[2]}))' "v$NEXT" "$LAST" |
  api -X POST "https://api.github.com/repos/$REPO/releases/generate-notes" --data-binary @- | json 'd["body"]')
RELEASE=$(python3 -I -c 'import json,sys; print(json.dumps({"tag_name": sys.argv[1], "name": "Forester " + sys.argv[2], "body": sys.argv[3]}))' \
  "v$NEXT" "$NEXT" "$NOTES" | api -X POST "https://api.github.com/repos/$REPO/releases" --data-binary @- | json 'd["id"]')
# Braced: zsh reads ":F" and ":f" after a bare $DMG or $CASK as modifiers.
for asset in "${DMG}:Forester.dmg:application/x-apple-diskimage" "${CASK}:forester.rb:text/plain"; do
  api -X POST -H "Content-Type: ${asset##*:}" --data-binary "@${asset%%:*}" \
    "https://uploads.github.com/repos/$REPO/releases/$RELEASE/assets?name=$(print -r -- "$asset" | cut -d: -f2)" >/dev/null
done
curl -fsSL -m 60 -o /dev/null "https://github.com/$REPO/releases/download/v$NEXT/Forester.dmg" ||
  fail "the release's Forester.dmg cannot be downloaded: the feed and the cask were not published."

# The feed only now, so it never names an image that is not there.
git commit -q -m "Update feed: Forester $NEXT" site/updates/appcast.xml
git push -q origin main
npx --yes wrangler@4.156.0 pages deploy --branch main --commit-hash "$(git rev-parse HEAD)" --commit-dirty=false >/dev/null

EXISTING=$(api "https://api.github.com/repos/$TAP/contents/Casks/forester.rb" 2>/dev/null | json 'd["sha"]' || true)
python3 -I -c '
import base64, json, sys
body = {"message": "forester " + sys.argv[2], "content": base64.b64encode(open(sys.argv[1], "rb").read()).decode()}
if sys.argv[3]: body["sha"] = sys.argv[3]
print(json.dumps(body))' "$CASK" "$NEXT" "$EXISTING" |
  api -X PUT "https://api.github.com/repos/$TAP/contents/Casks/forester.rb" --data-binary @- >/dev/null

print -- "
Forester $NEXT is out:
  the download   https://github.com/$REPO/releases/tag/v$NEXT (in the update feed)
  Homebrew       brew trust versaminds/tap (once), then brew install --cask versaminds/tap/forester
  App Store      $UPLOADED; then, in App Store Connect, add the build to
                 version $NEXT and press Submit for Review."
