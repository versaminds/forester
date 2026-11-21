// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import GSS
import Security
import Testing
@testable import LDAPKit

/// What a sign-in must not do, without a server: give a password away in an
/// error, sign in through a connection open to interception, take a weak
/// nonce, accept a server it did not mean, or a security layer without
/// numbering.
@Suite struct SignInHardeningTests {
    /// The character SCRAM refused can be one of the password's own: the
    /// message says only which field held it, since it reaches Diagnostics.
    @Test func saslPrepNamesTheFieldNotTheCharacter() throws {
        do {
            _ = try SCRAM(user: "user", password: "pa\u{0007}ss", binding: .none, nonce: "abc")
            Issue.record("a control character was taken")
        } catch {
            let message = error.localizedDescription
            #expect(message.contains("password"), "\(message)")
            #expect(!message.contains("U+") && !message.contains("0007") && !message.contains("user name"), "\(message)")
        }
        do {
            _ = try SCRAM(user: "us\u{E000}er", password: "pencil", binding: .none, nonce: "abc")
            Issue.record("a private-use character was taken")
        } catch {
            let message = error.localizedDescription
            #expect(message.contains("user name") && !message.contains("password") && !message.contains("E000"), "\(message)")
        }
    }

    /// RFC 4013 §2.4 (RFC 3454 §6): right-to-left text may not be mixed with
    /// left-to-right, and must start and end with a right-to-left character.
    @Test func saslPrepChecksBidirectionalText() throws {
        #expect(try SCRAM.saslPrep("\u{05D0}\u{05D1}") == "\u{05D0}\u{05D1}")
        #expect(try SCRAM.saslPrep("\u{0627}1\u{0628}") == "\u{0627}1\u{0628}")
        #expect(try SCRAM.saslPrep("abc1") == "abc1")
        #expect(try SCRAM.saslPrep("\u{05D0} \u{05D1}") == "\u{05D0} \u{05D1}")
        for refused in ["\u{05D0}a", "a\u{05D0}", "\u{05D0}1", "1\u{05D0}", "\u{0627}x\u{0628}", "\u{05D0}\u{00AA}\u{05D1}"] {
            #expect(throws: LDAPError.self, "\(refused.unicodeScalars.map { String($0.value, radix: 16) })") { try SCRAM.saslPrep(refused) }
        }
    }

    /// No randomness, no sign-in: a nonce of zeros is never sent.
    @Test func aNonceWithoutRandomnessIsRefused() throws {
        #expect(throws: LDAPError.self) { try SCRAM.makeNonce { _ in errSecAllocate } }
        let nonce = try SCRAM.makeNonce()
        #expect(Data(base64Encoded: nonce)?.count == 24)
        #expect(try SCRAM.makeNonce() != nonce)
    }

    /// The server's proof compared in time that does not depend on where it differs.
    @Test func signaturesCompareInConstantTime() {
        #expect(SCRAM.constantTimeEqual([1, 2, 3], [1, 2, 3]))
        #expect(!SCRAM.constantTimeEqual([1, 2, 3], [1, 2, 4]))
        #expect(!SCRAM.constantTimeEqual([1, 2, 3], [1, 2]))
        #expect(!SCRAM.constantTimeEqual([], [0]))
        #expect(SCRAM.constantTimeEqual([], []))
    }

    /// With any certificate accepted, whoever is in between would see the
    /// exchange and could guess the password from it at leisure: refused
    /// before anything is sent, as Kerberos is.
    @Test(arguments: [LDAPConnection.Security.ldaps, .startTLS])
    func scramIsRefusedWithAnyCertificateAccepted(_ security: LDAPConnection.Security) async throws {
        let connection = LDAPConnection(.init(host: "localhost", port: 1, security: security, timeout: 2,
                                              trust: TrustPolicy(trustAnyCertificate: true)))
        do {
            try await connection.bindSCRAM(user: "user", password: "pencil")
            Issue.record("signed in")
        } catch let error as LDAPError {
            #expect(error.localizedDescription.contains("Accept any certificate"), "\(error.localizedDescription)")
        }
    }

    /// Without TLS, Kerberos authenticates the server only as the name GSS
    /// asked for: that must be `ldap/` and the host connected to, in any realm
    /// and any case, never a name DNS turned it into.
    @Test func theServerKerberosAuthenticatedMustBeTheHost() {
        #expect(GSSContext.acceptorMatches("ldap/dc01.corp.example@CORP.EXAMPLE", host: "DC01.corp.example"))
        #expect(GSSContext.acceptorMatches("LDAP/dc01.corp.example@OTHER.REALM", host: "dc01.corp.example."))
        #expect(GSSContext.acceptorMatches("ldap@dc01.corp.example", host: "dc01.corp.example"))
        #expect(GSSContext.acceptorMatches("ldap/localhost@CORP.EXAMPLE", host: "localhost"))
        #expect(!GSSContext.acceptorMatches("ldap/evil.example@CORP.EXAMPLE", host: "dc01.corp.example"))
        #expect(!GSSContext.acceptorMatches("host/dc01.corp.example@CORP.EXAMPLE", host: "dc01.corp.example"))
        #expect(!GSSContext.acceptorMatches("ldap/dc01.corp.example.evil@CORP.EXAMPLE", host: "dc01.corp.example"))
        #expect(!GSSContext.acceptorMatches("ldap/dc01.corp.example/extra@CORP.EXAMPLE", host: "dc01.corp.example"))
        #expect(!GSSContext.acceptorMatches("", host: "dc01.corp.example"))
    }

    /// TLS below 1.2 is never used, and a certificate the person did not
    /// choose is never shown: without one chosen, the handshake goes on
    /// without, rather than the system picking one from the keychain.
    @Test func transportTLSFloorAndNoUnchosenCertificate() {
        #expect(LDAPTransport.configuration().tlsMinimumSupportedProtocolVersion == .TLSv12)
        #expect(LDAPTransport.configuration().connectionProxyDictionary?.isEmpty == true)
        let (disposition, credential) = LDAPTransport.clientCertificateDisposition(nil)
        #expect(disposition == .rejectProtectionSpace && credential == nil)
    }

    /// Against servers that speak one TLS version each (TESTING.md shows
    /// how to start them): 1.1 gets no connection, 1.2 does.
    ///   FORESTER_TEST_TLS11_PORT=14611 FORESTER_TEST_TLS12_PORT=14612
    @Test(.enabled(if: ProcessInfo.processInfo.environment["FORESTER_TEST_TLS11_PORT"] != nil))
    func tlsOlderThan12IsRefused() async throws {
        let environment = ProcessInfo.processInfo.environment
        func handshake(_ port: String?) async -> Error? {
            let connection = LDAPConnection(.init(host: "localhost", port: Int(port ?? "") ?? 1, security: .ldaps, timeout: 5,
                                                  trust: TrustPolicy(trustAnyCertificate: true)))
            defer { Task { await connection.close() } }
            do {
                try await connection.open()
                _ = try await connection.rootDSE()
                return nil
            } catch {
                return error
            }
        }
        // Each answers the first search with an empty success, over TLS.
        #expect(await handshake(environment["FORESTER_TEST_TLS11_PORT"]) != nil, "TLS 1.1 was used")
        let current = await handshake(environment["FORESTER_TEST_TLS12_PORT"])
        #expect(current == nil, "TLS 1.2: \(String(describing: current))")
    }

    /// Sealing needs every message numbered and replays refused, not only
    /// encryption and signing.
    @Test func sealingNeedsSequenceAndReplayDetection() {
        let all = OM_uint32(GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_REPLAY_FLAG)
        #expect(GSSContext.missingProtection(all, sealing: true) == nil)
        #expect(GSSContext.missingProtection(all & ~OM_uint32(GSS_C_SEQUENCE_FLAG), sealing: true) != nil)
        #expect(GSSContext.missingProtection(all & ~OM_uint32(GSS_C_REPLAY_FLAG), sealing: true) != nil)
        #expect(GSSContext.missingProtection(all & ~OM_uint32(GSS_C_CONF_FLAG), sealing: true) != nil)
        #expect(GSSContext.missingProtection(OM_uint32(GSS_C_MUTUAL_FLAG), sealing: false) == nil)
        #expect(GSSContext.missingProtection(0, sealing: false) != nil)
    }
}
