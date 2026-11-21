// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import CryptoKit
import Foundation
import Security
import Testing
@testable import LDAPKit

/// SCRAM's arithmetic against the RFCs' own examples, and what a server's
/// challenge may and may not ask for. No server needed.
@Suite struct SCRAMTests {
    /// RFC 7677 §3: user "user", password "pencil".
    @Test func sha256MatchesRFC7677() throws {
        var scram = try SCRAM(user: "user", password: "pencil", binding: .none, hash: .sha256, nonce: "rOprNGfwEbeRWgbNEkqO")
        #expect(String(decoding: scram.clientFirst, as: UTF8.self) == "n,,n=user,r=rOprNGfwEbeRWgbNEkqO")
        let final = try scram.clientFinal(serverFirst: Array("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096".utf8))
        #expect(String(decoding: final, as: UTF8.self)
                == "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
        try scram.verify(serverFinal: Array("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=".utf8))
        #expect(throws: LDAPError.self) { try scram.verify(serverFinal: Array("v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=".utf8)) }
    }

    /// RFC 5802 §5, the same exchange with SHA-1.
    @Test func sha1MatchesRFC5802() throws {
        var scram = try SCRAM(user: "user", password: "pencil", binding: .none, hash: .sha1, nonce: "fyko+d2lbbFgONRv9qkxdawL")
        let final = try scram.clientFinal(serverFirst: Array("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096".utf8))
        #expect(String(decoding: final, as: UTF8.self) == "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
        try scram.verify(serverFinal: Array("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=".utf8))
    }

    /// The header says what this side could bind, and the bound data goes
    /// into the proof, so a server that sees another TLS connection refuses.
    @Test func channelBindingHeaders() throws {
        let hash = [UInt8](repeating: 0xAB, count: 32)
        for (binding, header) in [(SCRAM.Binding.none, "n,,"), (.notOffered, "y,,"), (.bound(type: "tls-server-end-point", data: hash), "p=tls-server-end-point,,")] {
            var scram = try SCRAM(user: "user", password: "pencil", binding: binding, nonce: "abc")
            #expect(String(decoding: scram.clientFirst, as: UTF8.self) == header + "n=user,r=abc")
            let final = String(decoding: try scram.clientFinal(serverFirst: Array("r=abcdef,s=QSXCR+Q6sek8bf92,i=4096".utf8)), as: UTF8.self)
            var expected = Array(header.utf8)
            if case .bound = binding { expected += hash }
            #expect(final.hasPrefix("c=\(Data(expected).base64EncodedString()),r=abcdef,p="))
        }
    }

    /// A name holding "=" or "," cannot end the field early.
    @Test func userNamesAreEscaped() throws {
        let scram = try SCRAM(user: "a=b,c", password: "x", binding: .none, nonce: "n")
        #expect(String(decoding: scram.clientFirst, as: UTF8.self) == "n,,n=a=3Db=2Cc,r=n")
    }

    /// What a server, or anyone on an unencrypted path, may not ask for:
    /// too few rounds (a recorded sign-in is then quick to crack), a nonce
    /// that is not this sign-in's, a mandatory extension, a malformed salt.
    @Test func challengesThatAreRefused() throws {
        let refused = ["r=abcdef,s=QSXCR+Q6sek8bf92,i=4095", "r=abcdef,s=QSXCR+Q6sek8bf92,i=2000001", "r=xyz123,s=QSXCR+Q6sek8bf92,i=4096",
                       "r=abc,s=QSXCR+Q6sek8bf92,i=4096", "m=ext,r=abcdef,s=QSXCR+Q6sek8bf92,i=4096", "r=abcdef,s=,i=4096",
                       "r=abcdef,s=QSXCR+Q6sek8bf92", "e=unknown-user", ""]
        for challenge in refused {
            var scram = try SCRAM(user: "user", password: "pencil", binding: .none, nonce: "abc")
            #expect(throws: LDAPError.self, "\(challenge)") { _ = try scram.clientFinal(serverFirst: Array(challenge.utf8)) }
        }
        let scram = try SCRAM(user: "user", password: "pencil", binding: .none, nonce: "abc")
        // Nothing to check a proof against before the challenge was answered.
        #expect(throws: LDAPError.self) { try scram.verify(serverFinal: Array("v=AAAA".utf8)) }
        #expect(SCRAM.serverError(Array("e=channel-bindings-dont-match".utf8))?.contains("not the one this Mac made") == true)
    }

    /// RFC 4013: other spaces become a space, soft hyphens go, compatibility
    /// forms are unified, control characters are refused.
    @Test func saslPrep() throws {
        #expect(try SCRAM.saslPrep("I\u{00AD}X") == "IX")
        #expect(try SCRAM.saslPrep("user") == "user")
        #expect(try SCRAM.saslPrep("USER") == "USER")
        #expect(try SCRAM.saslPrep("\u{00AA}") == "a")
        #expect(try SCRAM.saslPrep("\u{2168}") == "IX")
        #expect(try SCRAM.saslPrep("a\u{00A0}b") == "a b")
        #expect(try SCRAM.saslPrep("E\u{0301}l") == "\u{00C9}l")
        #expect(throws: LDAPError.self) { try SCRAM.saslPrep("\u{0007}") }
        #expect(throws: LDAPError.self) { try SCRAM.saslPrep("a\u{E000}") }
    }
}

/// Against OpenLDAP from TestDirectory/start-sasl.sh: SCRAM-SHA-256 with and
/// without the TLS channel bound, and a client certificate (SASL EXTERNAL).
///   FORESTER_TEST_SASL=1 swift test --filter SASLServerTests
@Suite(.enabled(if: ProcessInfo.processInfo.environment["FORESTER_TEST_SASL"] == "1"), .serialized)
struct SASLServerTests {
    static let certificates = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../../TestDirectory/.run/sasl").standardized
    static let password = "Scram-Test-Password-2026!"

    /// The test server's certificate, pinned as a person would trust it.
    static func trust() throws -> TrustPolicy {
        let pem = try String(contentsOf: certificates.appendingPathComponent("server.crt"), encoding: .utf8)
        let body = pem.components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined()
        let der = try #require(Data(base64Encoded: body))
        return TrustPolicy(pinnedFingerprints: [SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":")])
    }

    /// A certificate and key from a PKCS #12 file, held in memory: nothing
    /// is added to a keychain.
    static func identity(_ name: String) throws -> ClientIdentity {
        let data = try Data(contentsOf: certificates.appendingPathComponent("\(name).p12"))
        var options: [String: Any] = [kSecImportExportPassphrase as String: "forester"]
        if #available(macOS 15, *) { options[kSecImportToMemoryOnly as String] = true }
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)
        try #require(status == errSecSuccess, "SecPKCS12Import: \(status)")
        let first = try #require((items as? [[String: Any]])?.first)
        let identity = try #require(first[kSecImportItemIdentity as String])
        return try #require(ClientIdentity(identity as! SecIdentity))
    }

    static func connect(_ security: LDAPConnection.Security, identity: ClientIdentity? = nil,
                        trust: TrustPolicy? = nil) async throws -> LDAPConnection {
        let connection = LDAPConnection(.init(host: "localhost", port: security == .ldaps ? 12636 : 12389, security: security,
                                              timeout: 10, trust: try trust ?? Self.trust(), clientIdentity: identity))
        try await connection.open()
        return connection
    }

    @Test(arguments: [LDAPConnection.Security.startTLS, .ldaps, .none])
    func scramSignsIn(_ security: LDAPConnection.Security) async throws {
        let connection = try await Self.connect(security)
        try await connection.bindSCRAM(user: "scram.user", password: Self.password)
        let who = try await connection.whoAmI()
        let entry = try await connection.read("uid=scram.user,ou=people,dc=sasl,dc=example", attributes: ["cn"])
        await connection.close()
        #expect(who == "dn:uid=scram.user,ou=people,dc=sasl,dc=example")
        #expect(entry?.string("cn") == "Scram User")
    }

    @Test func scramWithAnAccentedPassword() async throws {
        let connection = try await Self.connect(.startTLS)
        // Typed decomposed, as some keyboards produce it; SASLprep composes it.
        try await connection.bindSCRAM(user: "scram.accents", password: "E\u{0301}le\u{0300}ne-De\u{0301}ja\u{0300}-Vu-2026!")
        let who = try await connection.whoAmI()
        await connection.close()
        #expect(who == "dn:uid=scram.accents,ou=people,dc=sasl,dc=example")
    }

    /// The reason a sign-in failed, in the words a person sees.
    static func failure(_ body: () async throws -> Void) async -> String {
        do {
            try await body()
            return "signed in"
        } catch {
            return error.localizedDescription
        }
    }

    @Test func scramWithAWrongPasswordIsRefused() async throws {
        let connection = try await Self.connect(.startTLS)
        let reason = await Self.failure { try await connection.bindSCRAM(user: "scram.user", password: "not the password") }
        let who = try? await connection.whoAmI()
        await connection.close()
        #expect(reason.contains("Invalid credentials (49)"), "\(reason)")
        #expect(who == nil || who == "anonymous")
    }

    /// Someone in between holds another TLS connection to the server: the
    /// certificate this side saw is not the one the server has, and the
    /// server refuses, though the password is right.
    @Test func scramBoundToAnotherCertificateIsRefused() async throws {
        let connection = try await Self.connect(.ldaps)
        _ = try await connection.rootDSE()
        let other = SHA256.hash(data: Data("someone else's certificate".utf8))
        let scram = try SCRAM(user: "scram.user", password: Self.password, binding: .bound(type: "ldap", data: Array("tls-server-end-point:".utf8) + Array(other)))
        let reason = await Self.failure { try await connection.bindSCRAM(mechanism: "SCRAM-SHA-256-PLUS", scram) }
        await connection.close()
        #expect(reason.contains("Channel bindings mismatch"), "\(reason)")
    }

    /// Someone in between hid the -PLUS mechanism: this side says it could
    /// have bound the channel, and the server, which can, refuses, though
    /// the password is right.
    @Test func hidingChannelBindingIsNoticed() async throws {
        let connection = try await Self.connect(.ldaps)
        _ = try await connection.rootDSE()
        let scram = try SCRAM(user: "scram.user", password: Self.password, binding: .notOffered)
        let reason = await Self.failure { try await connection.bindSCRAM(mechanism: "SCRAM-SHA-256", scram) }
        await connection.close()
        #expect(reason.contains("incorrectly assumed server had no channel binding"), "\(reason)")
    }

    @Test(arguments: [LDAPConnection.Security.startTLS, .ldaps])
    func certificateSignsIn(_ security: LDAPConnection.Security) async throws {
        let connection = try await Self.connect(security, identity: try Self.identity("client"))
        try await connection.bindExternal()
        let who = try await connection.whoAmI()
        await connection.close()
        #expect(who == "dn:cn=forester client,ou=people,dc=sasl,dc=example")
    }

    /// A certificate from an issuer the server does not trust ends the
    /// handshake; nothing is signed in as anyone.
    @Test func aCertificateTheServerDoesNotTrustIsRefused() async throws {
        let connection = try await Self.connect(.ldaps, identity: try Self.identity("stranger"))
        await #expect(throws: LDAPError.self) { try await connection.bindExternal() }
        await connection.close()
    }

    /// A server that never asks for a client certificate (the test directory
    /// of start.sh), and one that asks but cannot sign in with it (Samba's
    /// domain controller): each said so, and nothing is signed in.
    @Test(arguments: [("FORESTER_TEST_SERVER", 10636, "did not ask for a certificate"),
                      ("FORESTER_TEST_AD", 11636, "does not offer signing in with it")])
    func serversThatCannotAreNamed(_ variable: String, _ port: Int, _ expected: String) async throws {
        guard ProcessInfo.processInfo.environment[variable] == "1" else { return }
        let connection = LDAPConnection(.init(host: "localhost", port: port, security: .ldaps, timeout: 10,
                                              trust: TrustPolicy(trustAnyCertificate: true), clientIdentity: try Self.identity("client")))
        try await connection.open()
        let reason = await Self.failure { try await connection.bindExternal() }
        let who = try? await connection.whoAmI()
        await connection.close()
        #expect(reason.contains(expected), "\(reason)")
        #expect(who == nil || who == "anonymous")
    }

    /// Without TLS there is no certificate to show, and without one chosen
    /// there is nothing to sign in as: both refused before a bind is sent.
    @Test func certificateSignInNeedsTLSAndACertificate() async throws {
        let plain = try await Self.connect(.none, identity: try Self.identity("client"))
        await #expect(throws: LDAPError.signIn("Signing in with a certificate needs StartTLS or LDAPS: the certificate is shown in the TLS handshake.")) {
            try await plain.bindExternal()
        }
        await plain.close()
        let none = try await Self.connect(.startTLS)
        await #expect(throws: LDAPError.signIn("Choose the certificate to sign in with.")) { try await none.bindExternal() }
        await none.close()
    }
}
