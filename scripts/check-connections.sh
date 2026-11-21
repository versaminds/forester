#!/bin/zsh
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
# Checks the app's saved connections, which the unit tests (of LDAPKit only)
# cannot reach:
#
# - Forester 1.1.1 still reads and writes back the connections this version
#   saves, without losing the ones it cannot read (SCRAM and certificate
#   sign-in live in connections-1.2.json);
# - what the connections file may not decide on this Mac (pinned
#   certificates, certificate checking, allowing changes, the client
#   certificate and what it is shown to), what an import may not replace, the
#   trust of other connections made with a profile's settings, and what the
#   password prompt warns of;
# - "User cannot change password" changes and undoes only its own rules.
#
#   scripts/check-connections.sh
#
# Builds a small program in a temporary folder from this checkout's
# ConnectionProfile.swift and CannotChangePassword.swift, and 1.1.1's own
# profile decoder (from the v1.1.1 tag), and runs it against a temporary
# folder. Nothing of yours is read or written.
set -euo pipefail

ROOT=${0:A:h:h}
WORK=$(mktemp -d -t forester-connections)
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
for file in ConnectionProfile CannotChangePassword; do
  ln -s "$ROOT/Sources/Forester/Model/$file.swift" "$WORK/Sources/Probe/$file.swift"
done
cp "$ROOT/scripts/connections-checks/main.swift" "$WORK/Sources/Probe/main.swift"
# 1.1.1's ConnectionProfile, from its declaration to ProfileStore's, renamed.
{
  print "import Foundation\nimport LDAPKit"
  git -C "$ROOT" show v1.1.1:Sources/Forester/Model/ConnectionProfile.swift |
    awk '/^struct ConnectionProfile/ { on = 1 } /^\/\/\/ Saved profiles/ { on = 0 } on' |
    sed 's/ConnectionProfile/OldProfile/g'
} > "$WORK/Sources/Probe/OldProfile.swift"

swift run --package-path "$WORK" -c debug Probe 2>&1 | grep -vE '^(\[|Building|Compiling|Fetching|Fetched|Computing|Computed|Creating|Working copy|Write|Emitting|Linking|Applying|Planning|Build of)'
