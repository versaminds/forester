#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Runs the self-driving checks as the Mac App Store variant, inside the App
# Store's sandbox, against the test directory (TESTING.md § 5):
#
#   scripts/automation-sandboxed.sh [parts]
#
# What the sandbox would refuse (a connection, the keychain, a file) shows up
# here and nowhere else. The debug build is put in an app bundle of its own,
# live.versaminds.Forester.sandboxcheck, and signed with the App Store's
# entitlements, so it runs in a container of its own and never touches the
# real app's connections. A sandbox reads only files the person chose and its
# container, so the sample LDIF is handed over in the environment, and the
# pictures and the log of what it did stay inside the container.
set -euo pipefail

ROOT=${0:A:h:h}
cd "$ROOT"
PARTS=${1:-walkthrough,entrysheets,ui}
export FORESTER_APP_STORE=1
MINIMUM=$(plutil -extract LSMinimumSystemVersion raw "$ROOT/Resources/Info.plist")
SDK_VERSION=$(xcrun --sdk macosx --show-sdk-version)
ARGS=(-Xswiftc -DAPP_STORE --scratch-path "$ROOT/.build/automation-appstore"
      -Xlinker -platform_version -Xlinker macos -Xlinker "$MINIMUM" -Xlinker "$SDK_VERSION")
swift build "${ARGS[@]}"
BIN="$(swift build "${ARGS[@]}" --show-bin-path)/Forester"

ID=live.versaminds.Forester.sandboxcheck
APP="$ROOT/build/SandboxCheck/Forester.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Forester"
VERSION=$(tr -d '[:space:]' < "$ROOT/VERSION")
sed -e "s/__VERSION__/$VERSION/g" -e "s/__BUILD__/$VERSION/g" -e "s/live\.versaminds\.Forester</$ID</" \
  "$ROOT/Resources/Info.plist" > "$APP/Contents/Info.plist"
# Signed with a development certificate when there is one; without one (a CI
# runner), ad hoc: macOS sandboxes an app signed ad hoc all the same.
SIGNER=$(security find-identity -v -p codesigning | grep -o '"Apple Development: [^"]*"' | head -1 | tr -d '"' || true)
[[ "${FORESTER_SIGN_ADHOC:-0}" == 1 ]] && SIGNER=""
SIGNER=${SIGNER:--}
codesign --force --sign "$SIGNER" --entitlements "$ROOT/Resources/AppStore.entitlements" "$APP"

CONTAINER="$HOME/Library/Containers/$ID/Data/tmp"
# The connections stay between runs; the sample part starts from none.
PROFILES="$CONTAINER/profiles"
[[ ",$PARTS," == *,sample,* ]] && PROFILES="$CONTAINER/profiles-sample-$(date +%s)"
FORESTER_AUTOMATION="$CONTAINER/shots" FORESTER_AUTOMATION_ONLY="$PARTS" FORESTER_PROFILE_DIR="$PROFILES" \
  FORESTER_TEST_PASSWORD=${FORESTER_TEST_PASSWORD:-secret} FORESTER_SAMPLE_LDIF="$(< "$ROOT/TestDirectory/sample-import.ldif")" \
  "$APP/Contents/MacOS/Forester"
