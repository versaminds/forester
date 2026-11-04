#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Builds a debug Forester linked like a release (scripts/build-app.sh) and lets
# it drive itself through the app against the test directory (TESTING.md § 5).
#
#   scripts/automation.sh [output folder] [parts]
#
# Linked like a release because the SDK decides how AppKit and SwiftUI draw
# the app: a plain `swift build` says it was built with the macOS 14 SDK and
# gets the design from before macOS 26, which nobody downloading Forester sees.
# FORESTER_SCREEN_CAPTURE=1 takes the pictures from the screen (TESTING.md).
set -euo pipefail

ROOT=${0:A:h:h}
cd "$ROOT"
OUT=${1:-/tmp/forester-shots}
PARTS=${2:-walkthrough,layout,entrysheets,sheets,ui}
MINIMUM=$(plutil -extract LSMinimumSystemVersion raw "$ROOT/Resources/Info.plist")
SDK_VERSION=$(xcrun --sdk macosx --show-sdk-version)
ARGS=(--scratch-path "$ROOT/.build/automation" -Xlinker -platform_version -Xlinker macos -Xlinker "$MINIMUM" -Xlinker "$SDK_VERSION")
# The performance part measures what a download does, so it is optimised as a
# release is, with the automation compiled in.
if [[ ",$PARTS," == *,performance,* ]]; then
  ARGS=(-c release -Xswiftc -DDEBUG --scratch-path "$ROOT/.build/automation-release" "${ARGS[@]:2}")
fi
swift build "${ARGS[@]}"
BIN="$(swift build "${ARGS[@]}" --show-bin-path)/Forester"

rm -rf "$OUT" "$OUT-profiles"
FORESTER_AUTOMATION="$OUT" FORESTER_AUTOMATION_ONLY="$PARTS" FORESTER_PROFILE_DIR="$OUT-profiles" \
  FORESTER_TEST_PASSWORD=${FORESTER_TEST_PASSWORD:-secret} "$BIN"
