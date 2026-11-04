#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Every check that needs no Active Directory domain controller, in the order
# CI runs them (.github/workflows/ci.yml), stopping at the first that fails:
#
#   scripts/test-all.sh                 unit and integration tests, the release
#                                       builds, the app driving itself, and the
#                                       App Store variant in its sandbox
#   scripts/test-all.sh --performance   also the big-directory part (TESTING.md § 5)
#
# Logs and pictures go to FORESTER_TEST_OUTPUT (/tmp/forester-test). The parts
# change the test directory, so it is started again before each; it is
# stopped at the end. The AD checks (TESTING.md § 6) need Podman and Samba,
# and stay a step of their own.
set -euo pipefail

ROOT=${0:A:h:h}
cd "$ROOT"
OUT=${FORESTER_TEST_OUTPUT:-/tmp/forester-test}
PERFORMANCE=0
[[ "${1:-}" == "--performance" ]] && PERFORMANCE=1
rm -rf "$OUT"
mkdir -p "$OUT"
trap 'TestDirectory/stop.sh >/dev/null 2>&1 || true' EXIT

step() {
  print -- "\n━━ $1"
  [[ -n "${GITHUB_ACTIONS:-}" ]] && print -- "::notice::$1" || true
}
# A fresh test directory: the parts before changed it.
fresh_directory() { TestDirectory/start.sh > "$OUT/directory-$1.log" 2>&1 }

step "Unit and integration tests"
fresh_directory tests
FORESTER_TEST_SERVER=1 swift test 2>&1 | tee "$OUT/tests.log"

step "Release builds of both variants"
# Optimised and linked as a release is, which a debug build does not show.
scripts/build-app.sh 2>&1 | tee "$OUT/build-download.log"
FORESTER_APP_STORE=1 scripts/build-app.sh 2>&1 | tee "$OUT/build-app-store.log"
[[ ! -e build/AppStore/Forester.app/Contents/Frameworks ]] || { print -u2 "The App Store variant contains frameworks (Sparkle?)."; exit 1; }

step "The app driving itself"
fresh_directory app
scripts/automation.sh "$OUT/app" walkthrough,layout,entrysheets,sheets,ui 2>&1 | tee "$OUT/app.log"

step "The App Store variant in its sandbox"
fresh_directory sandbox
scripts/automation-sandboxed.sh 2>&1 | tee "$OUT/sandbox.log"

if (( PERFORMANCE )); then
  step "A big directory"
  TestDirectory/stop.sh >/dev/null 2>&1 || true
  LDAP_TEST_BULK=50000 TestDirectory/start.sh > "$OUT/directory-performance.log" 2>&1
  scripts/automation.sh "$OUT/performance" performance 2>&1 | tee "$OUT/performance.log"
fi

step "Everything passed"
