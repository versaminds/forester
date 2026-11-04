#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Puts the release's signing material from the repository's secrets on a CI
# runner (.github/workflows/release.yml), and says what can be built with it:
#
#   APPLE_CERTIFICATES_P12       base64 of a .p12 holding the certificates and
#   APPLE_CERTIFICATES_PASSWORD  their private keys: Apple Distribution and Mac
#                                Installer Distribution for the App Store,
#                                Developer ID Application for the download
#   APPSTORE_PROFILE             base64 of the Mac App Store provisioning profile
#   ASC_KEY_ID, ASC_ISSUER_ID,   an App Store Connect API key (App Manager): it
#   ASC_KEY_P8                   uploads to App Store Connect and notarizes
#   SPARKLE_PRIVATE_KEY          the update key's private half, for the download
#
# The certificates go into a keychain of their own, made for this run and
# deleted with the runner. Writes appstore= and download= (true or false) and
# profile= and update_key= (paths) to the step's outputs. It refuses to run
# anywhere but CI: it changes the keychain search list.
set -euo pipefail

ROOT=${0:A:h:h:h}
[[ "${CI:-}" == true && -n "${RUNNER_TEMP:-}" ]] || { print -u2 "signing.sh: only on a CI runner; on a Mac, the certificates are in your keychain."; exit 1; }
WORK="$RUNNER_TEMP/signing"
mkdir -p "$WORK"
output() { print -- "$1" >> "${GITHUB_OUTPUT:-/dev/null}"; }
missing=()

KEYCHAIN="$WORK/release.keychain-db"
if [[ -n "${APPLE_CERTIFICATES_P12:-}" ]]; then
  PASSWORD=$(uuidgen)
  security create-keychain -p "$PASSWORD" "$KEYCHAIN"
  security set-keychain-settings -lut 21600 "$KEYCHAIN"
  security unlock-keychain -p "$PASSWORD" "$KEYCHAIN"
  print -r -- "$APPLE_CERTIFICATES_P12" | base64 --decode > "$WORK/certificates.p12"
  security import "$WORK/certificates.p12" -k "$KEYCHAIN" -P "${APPLE_CERTIFICATES_PASSWORD:-}" -f pkcs12 \
    -T /usr/bin/codesign -T /usr/bin/productbuild -T /usr/bin/security
  rm -f "$WORK/certificates.p12"
  # Lets codesign and productbuild use the keys without asking.
  security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$PASSWORD" "$KEYCHAIN" >/dev/null
  security list-keychains -d user -s "$KEYCHAIN" $(security list-keychains -d user | tr -d '"')
  security default-keychain -d user -s "$KEYCHAIN"
else
  missing+=(APPLE_CERTIFICATES_P12)
fi
IDENTITIES=$(security find-identity -v 2>/dev/null || true)
has() { print -r -- "$IDENTITIES" | grep -q "\"$1: "; }

if [[ -n "${ASC_KEY_ID:-}" && -n "${ASC_ISSUER_ID:-}" && -n "${ASC_KEY_P8:-}" ]]; then
  # Where altool looks for the key, by its id.
  mkdir -p "$HOME/.appstoreconnect/private_keys"
  P8="$HOME/.appstoreconnect/private_keys/AuthKey_$ASC_KEY_ID.p8"
  print -r -- "$ASC_KEY_P8" > "$P8"
  chmod 600 "$P8"
  if [[ -f "$KEYCHAIN" ]]; then
    xcrun notarytool store-credentials forester-notary --key "$P8" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID" \
      --keychain "$KEYCHAIN" >/dev/null
  fi
  ASC=1
else
  missing+=(ASC_KEY_ID ASC_ISSUER_ID ASC_KEY_P8)
  ASC=0
fi

PROFILE=""
if [[ -n "${APPSTORE_PROFILE:-}" ]]; then
  PROFILE="$WORK/Forester_App_Store.provisionprofile"
  print -r -- "$APPSTORE_PROFILE" | base64 --decode > "$PROFILE"
  output "profile=$PROFILE"
else
  missing+=(APPSTORE_PROFILE)
fi

UPDATE_KEY=""
if [[ -n "${SPARKLE_PRIVATE_KEY:-}" ]]; then
  UPDATE_KEY="$WORK/sparkle-private-key"
  print -r -- "$SPARKLE_PRIVATE_KEY" > "$UPDATE_KEY"
  chmod 600 "$UPDATE_KEY"
  output "update_key=$UPDATE_KEY"
fi

APPSTORE=false
if [[ -n "$PROFILE" ]] && (( ASC )) && has "Apple Distribution" && { has "Mac Installer Distribution" || has "3rd Party Mac Developer Installer"; }; then
  APPSTORE=true
fi
DOWNLOAD=false
if (( ASC )) && has "Developer ID Application" && [[ -n "$UPDATE_KEY" && -s "$ROOT/Resources/sparkle-public-key" ]]; then
  DOWNLOAD=true
fi
output "appstore=$APPSTORE"
output "download=$DOWNLOAD"

echo "App Store package: $APPSTORE. Download (DMG): $DOWNLOAD."
(( ${#missing} )) && echo "Secrets not set: ${missing[*]}."
if [[ "$DOWNLOAD" == false ]]; then
  echo "The download also needs SPARKLE_PRIVATE_KEY, Resources/sparkle-public-key in the repository and a Developer ID Application certificate in the .p12."
fi
exit 0
