// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds
// Checks an update's EdDSA signature as Sparkle will, against the public key
// the app carries, before the update is listed in the feed:
//
//   swift scripts/check-update-signature.swift <file> <signature> <public key>
//
// Both are base64, as sign_update prints the signature and generate_keys the key.

import CryptoKit
import Foundation

let arguments = CommandLine.arguments
guard arguments.count == 4,
      let data = FileManager.default.contents(atPath: arguments[1]),
      let signature = Data(base64Encoded: arguments[2]),
      let keyData = Data(base64Encoded: arguments[3]),
      let key = try? Curve25519.Signing.PublicKey(rawRepresentation: keyData) else {
    FileHandle.standardError.write(Data("usage: check-update-signature.swift <file> <base64 signature> <base64 public key>\n".utf8))
    exit(2)
}
guard key.isValidSignature(signature, for: data) else {
    FileHandle.standardError.write(Data("The signature does not match the public key.\n".utf8))
    exit(1)
}
print("Update signature checked against the app's public key.")
