#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Whether Forester's one dependency, Sparkle, has a newer release, and which
# Xcode and SDK this Mac builds with:
#
#   scripts/check-updates.sh           reports; exits 0 when current, 10 when not
#   scripts/check-updates.sh --apply   also pins the newest release in
#                                      Package.swift and resolves it
#
# Sparkle is pinned to an exact release, the newest that is not a pre-release
# (GitHub's "latest"). Swift Package Manager checks the archive it downloads
# against the checksum in that release's own manifest. GITHUB_TOKEN, when
# set, lifts GitHub's limit on anonymous API calls. On GitHub Actions the
# result is also written to the step's outputs (current, latest, changed,
# major) and summary.
set -euo pipefail

ROOT=${0:A:h:h}
cd "$ROOT"
APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1
fail() { print -u2 "check-updates: $1"; exit 1; }

CURRENT=$(sed -n 's|.*github.com/sparkle-project/Sparkle", exact: "\([0-9.]*\)".*|\1|p' Package.swift)
[[ -n "$CURRENT" ]] || fail "Package.swift does not pin Sparkle to an exact version."
AUTH=()
[[ -n "${GITHUB_TOKEN:-}" ]] && AUTH=(-H "Authorization: Bearer $GITHUB_TOKEN")
RELEASE=$(curl -fsS --max-time 30 "${AUTH[@]}" -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/sparkle-project/Sparkle/releases/latest) || fail "could not ask GitHub for Sparkle's latest release."
LATEST=$(print -r -- "$RELEASE" | plutil -extract tag_name raw -o - -)
[[ "$LATEST" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] || fail "Sparkle's latest release is called \"$LATEST\", not a version."

NEWEST=$(printf '%s\n%s\n' "$CURRENT" "$LATEST" | sort -V | tail -1)
CHANGED=false
[[ "$NEWEST" == "$LATEST" && "$LATEST" != "$CURRENT" ]] && CHANGED=true
MAJOR=false
[[ "$CHANGED" == true && "${LATEST%%.*}" != "${CURRENT%%.*}" ]] && MAJOR=true
XCODE=$(xcodebuild -version 2>/dev/null | sed -n 1p || true)
[[ -n "$XCODE" ]] || XCODE="no Xcode"
SDK=$(xcrun --sdk macosx --show-sdk-version 2>/dev/null || echo "?")

if [[ "$CHANGED" == true ]]; then
  echo "Sparkle $CURRENT → $LATEST: https://github.com/sparkle-project/Sparkle/releases/tag/$LATEST"
  [[ "$MAJOR" == true ]] && echo "  A new major version: read its release notes before taking it."
else
  echo "Sparkle $CURRENT is the latest release."
fi
echo "Building with $XCODE, macOS SDK $SDK."

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  { echo "current=$CURRENT"; echo "latest=$LATEST"; echo "changed=$CHANGED"; echo "major=$MAJOR"; } >> "$GITHUB_OUTPUT"
fi
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### Updates"
    echo
    if [[ "$CHANGED" == true ]]; then
      echo "- Sparkle $CURRENT → [$LATEST](https://github.com/sparkle-project/Sparkle/releases/tag/$LATEST)$([[ $MAJOR == true ]] && echo ', a new major version')"
    else
      echo "- Sparkle $CURRENT is the latest release"
    fi
    echo "- Built with $XCODE, macOS SDK $SDK"
  } >> "$GITHUB_STEP_SUMMARY"
fi

[[ "$CHANGED" == true ]] || exit 0
(( APPLY )) || exit 10

sed -i '' "s|github.com/sparkle-project/Sparkle\", exact: \"$CURRENT\"|github.com/sparkle-project/Sparkle\", exact: \"$LATEST\"|" Package.swift
grep -q "exact: \"$LATEST\"" Package.swift || fail "could not pin $LATEST in Package.swift."
swift package resolve
RESOLVED=$(plutil -extract pins.0.state.version raw -o - Package.resolved)
[[ "$RESOLVED" == "$LATEST" ]] || fail "Package.resolved names $RESOLVED, not $LATEST."
# A precompiled module of the version before stays in every build folder and
# fails the next build ("has been modified since the module file").
for folder in .build/out .build/*/out(N); do
  rm -rf "$folder/Intermediates.noindex/SwiftExplicitPrecompiledModules" "$folder"/Products/*/Sparkle.framework(N)
done
# The documentation names the version the download carries.
perl -0pi -e "s/(\\[Sparkle\\]\\(https:\\/\\/sparkle-project\\.org\\)\\s+)\\Q$CURRENT\\E/\${1}$LATEST/" docs/DISTRIBUTION.md
echo "Pinned Sparkle $LATEST and resolved it."
exit 10
