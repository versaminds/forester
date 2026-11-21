#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Checks that Forester 1.1.1 can still read and write back the connections
# this version saves, without losing the ones it cannot read (SCRAM and
# certificate sign-in live in connections-1.2.json; see ProfileStore).
#
#   scripts/check-connections-compatibility.sh
#
# Builds a small program in a temporary folder from this checkout's
# ConnectionProfile.swift and 1.1.1's own profile decoder (from the v1.1.1
# tag), and runs it against a temporary folder. Nothing of yours is read.
set -euo pipefail

ROOT=${0:A:h:h}
WORK=$(mktemp -d -t forester-compatibility)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/Sources/Probe"

cat > "$WORK/Package.swift" <<EOF
// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "Probe",
    platforms: [.macOS(.v14)],
    dependencies: [.package(name: "Forester", path: "$ROOT")],
    targets: [.executableTarget(name: "Probe", dependencies: [.product(name: "LDAPKit", package: "Forester")],
                                swiftSettings: [.swiftLanguageMode(.v5)])]
)
EOF
ln -s "$ROOT/Sources/Forester/Model/ConnectionProfile.swift" "$WORK/Sources/Probe/ConnectionProfile.swift"
cp "$ROOT/scripts/connections-compatibility/main.swift" "$WORK/Sources/Probe/main.swift"
# 1.1.1's ConnectionProfile, from its declaration to ProfileStore's, renamed.
{
  print "import Foundation\nimport LDAPKit"
  git -C "$ROOT" show v1.1.1:Sources/Forester/Model/ConnectionProfile.swift |
    awk '/^struct ConnectionProfile/ { on = 1 } /^\/\/\/ Saved profiles/ { on = 0 } on' |
    sed 's/ConnectionProfile/OldProfile/g'
} > "$WORK/Sources/Probe/OldProfile.swift"

swift run --package-path "$WORK" -c debug Probe 2>&1 | grep -vE '^(\[|Building|Compiling|Fetching|Fetched|Computing|Computed|Creating|Working copy|Write|Emitting|Linking|Applying|Planning|Build of)'
