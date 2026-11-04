#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Whether a release is due, and its version:
#
#   scripts/release-due.sh [patch|minor|major] [--force]
#
# Forester is released every two weeks: a release is due when the last one
# (the newest v* tag) is at least FORESTER_RELEASE_DAYS old (13, so a weekly
# schedule that runs a little early still counts two weeks) and the app has
# changed since: its code, resources or dependencies, not only the website or
# the documentation. --force skips the wait, not the need for a change.
# The version is the last one raised by the part asked for, minor by default:
# every scheduled release is 1.1.0, 1.2.0 and so on; a fix in between is a patch.
#
# The first release is not made here: VERSION is submitted and tagged by hand
# (docs/APP-STORE.md). Prints due=, reason=, last= and version=, also to the
# step's outputs on GitHub Actions; exits 0 either way.
set -euo pipefail

ROOT=${0:A:h:h}
cd "$ROOT"
PART=minor
FORCE=0
for argument in "$@"; do
  case "$argument" in
    patch|minor|major) PART=$argument ;;
    --force) FORCE=1 ;;
    *) print -u2 "usage: scripts/release-due.sh [patch|minor|major] [--force]"; exit 2 ;;
  esac
done
DAYS=${FORESTER_RELEASE_DAYS:-13}

report() {
  local lines=("due=$1" "reason=$2" "last=${LAST:-}" "version=${NEXT:-}")
  print -l -- "${lines[@]}"
  [[ -n "${GITHUB_OUTPUT:-}" ]] && print -l -- "${lines[@]}" >> "$GITHUB_OUTPUT"
  exit 0
}

LAST=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-version:refname | head -1)
[[ -n "$LAST" ]] || report no "no release is tagged yet; the first, $(tr -d '[:space:]' < VERSION), is submitted and tagged by hand (docs/APP-STORE.md)"

IFS=. read -r major minor patch <<< "${LAST#v}"
case "$PART" in
  major) NEXT="$((major + 1)).0.0" ;;
  minor) NEXT="$major.$((minor + 1)).0" ;;
  patch) NEXT="$major.$minor.$((patch + 1))" ;;
esac
[[ -z "$(git tag --list "v$NEXT")" ]] || report no "v$NEXT is already tagged"

CHANGED=$(git diff --name-only "$LAST" HEAD -- Sources Resources Package.swift Package.resolved | wc -l | tr -d ' ')
(( CHANGED > 0 )) || report no "the app has not changed since $LAST"

# When it was tagged (an annotated tag's own date), not when its commit was made.
AGE=$(( ($(date +%s) - $(git for-each-ref --format="%(creatordate:unix)" "refs/tags/$LAST")) / 86400 ))
if (( !FORCE && AGE < DAYS )); then
  report no "$LAST is $AGE days old; the next release is due after $DAYS"
fi
report yes "$CHANGED files of the app changed since $LAST, $AGE days ago"
