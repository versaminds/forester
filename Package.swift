// swift-tools-version: 6.0
// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds
import Foundation
import PackageDescription

// The Mac App Store variant (scripts/build-app.sh with FORESTER_APP_STORE=1):
// the App Store updates it, and App Review allows no other updater, so it is
// built without Sparkle at all rather than with Sparkle switched off.
let appStore = ProcessInfo.processInfo.environment["FORESTER_APP_STORE"] == "1"

let package = Package(
    name: "Forester",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "Forester", targets: ["Forester"]),
        .library(name: "LDAPKit", targets: ["LDAPKit"]),
    ],
    // Updates of the download: signed (EdDSA) releases from an appcast, the
    // standard on the Mac. MIT-licensed; off until the app's Info.plist names
    // a feed and a public key (scripts/build-app.sh).
    dependencies: appStore ? [] : [
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.1"),
    ],
    targets: [
        // The LDAP client: BER, filters, messages, TLS transport and the connection.
        // No dependencies beyond Apple's Foundation, Security, CryptoKit and GSS (Kerberos).
        .target(
            name: "LDAPKit",
            swiftSettings: [.swiftLanguageMode(.v5)],
            linkerSettings: [.linkedFramework("GSS")]
        ),
        .executableTarget(
            name: "Forester",
            dependencies: appStore ? ["LDAPKit"] : ["LDAPKit", .product(name: "Sparkle", package: "Sparkle")],
            swiftSettings: [.swiftLanguageMode(.v5)] + (appStore ? [.define("APP_STORE")] : []),
            // Sparkle.framework sits in the bundle's Frameworks folder.
            linkerSettings: appStore ? [] : [.unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])]
        ),
        .testTarget(
            name: "LDAPKitTests",
            dependencies: ["LDAPKit"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
