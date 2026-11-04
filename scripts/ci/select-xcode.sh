#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Chooses the newest Xcode on a CI runner that is not a beta: the App Store
# takes an app only when it is built with a recent SDK, and the image's
# default Xcode can be an older one.
set -euo pipefail

[[ "${CI:-}" == true ]] || { print -u2 "select-xcode.sh: only on a CI runner; on a Mac, xcode-select is yours to set."; exit 1; }
XCODES=(/Applications/Xcode_[0-9]*.app(N))
XCODE=$(print -l -- "${XCODES[@]}" | grep -v -i -E 'beta|_rc|release.candidate' | sort -V | tail -1 || true)
[[ -n "$XCODE" ]] || XCODE=$(xcode-select -p | sed 's|/Contents/Developer$||')
sudo xcode-select -s "$XCODE/Contents/Developer"
xcodebuild -version
echo "macOS SDK $(xcrun --sdk macosx --show-sdk-version), $(swift --version 2>&1 | sed -n 1p)"
