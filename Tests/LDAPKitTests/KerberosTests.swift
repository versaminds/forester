// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import CryptoKit
import Foundation
import Testing
@testable import LDAPKit

/// Signing in with a Kerberos ticket, against the Active Directory domain
/// controller of TestDirectory/start-ad.sh, which leaves a ticket in a cache
/// of its own. Run with
///   FORESTER_TEST_AD=1 KRB5_CONFIG=TestDirectory/.run/krb5.conf KRB5CCNAME=FILE:TestDirectory/.run/krb5cc swift test --filter KerberosTests
@Suite(.enabled(if: ProcessInfo.processInfo.environment["FORESTER_TEST_AD"] == "1"
                && ProcessInfo.processInfo.environment["KRB5CCNAME"] != nil))
struct KerberosTests {
    /// The test domain controller's certificate, pinned, as a person trusts
    /// a certificate from their organisation's own CA: Kerberos is refused
    /// with any certificate accepted.
    static func connection(_ security: LDAPConnection.Security, port: Int) async throws -> LDAPConnection {
        LDAPConnection(.init(host: "localhost", port: port, security: security, timeout: 10,
                             trust: TrustPolicy(pinnedFingerprints: [try await pin()])))
    }

    static func pin() async throws -> String {
        let probe = LDAPConnection(.init(host: "localhost", port: 11636, security: .ldaps, timeout: 10,
                                         trust: TrustPolicy(trustAnyCertificate: true)))
        try await probe.open()
        _ = try await probe.rootDSE()
        let certificate = try #require(await probe.serverCertificate)
        await probe.close()
        return SHA256.hash(data: certificate).map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    @Test(arguments: [(LDAPConnection.Security.startTLS, 11389), (.ldaps, 11636)])
    func signsInWithTheTicket(_ security: LDAPConnection.Security, _ port: Int) async throws {
        let connection = try await Self.connection(security, port: port)
        try await connection.open()
        try await connection.bindKerberos()
        let who = try await connection.whoAmI() ?? ""
        await connection.close()
        #expect(who.localizedCaseInsensitiveContains("Administrator"), "\(who)")
    }

    @Test func refusedWithoutEncryption() async throws {
        let connection = try await Self.connection(.none, port: 11389)
        try await connection.open()
        await #expect(throws: LDAPError.self) { try await connection.bindKerberos() }
        await connection.close()
    }

    /// With any certificate accepted, the ticket would be bound to whoever is
    /// in between, who could pass the exchange on: refused before it starts.
    @Test func refusedWithAnyCertificateAccepted() async throws {
        let connection = LDAPConnection(.init(host: "localhost", port: 11636, security: .ldaps, timeout: 10,
                                              trust: TrustPolicy(trustAnyCertificate: true)))
        try await connection.open()
        await #expect(throws: LDAPError.self) { try await connection.bindKerberos() }
        let who = try? await connection.whoAmI()
        await connection.close()
        #expect(who == nil || who == "anonymous", "signed in as \(who ?? "")")
    }

    /// The binding is checked: the domain controller refuses a ticket bound to
    /// another TLS connection.
    @Test func aWrongChannelBindingIsRefused() async throws {
        let connection = try await Self.connection(.ldaps, port: 11636)
        try await connection.open()
        _ = try await connection.rootDSE()
        let wrong = ChannelBinding.tlsServerEndPoint(Data("another certificate".utf8))
        await #expect(throws: LDAPError.self) { try await connection.bindKerberos(channelBinding: wrong) }
        await connection.close()
    }

    /// The channel binding hashes the certificate with its own signature hash.
    @Test func channelBindingFollowsTheSignatureHash() throws {
        let sha384 = Data([0x30, 0x12, 0x30, 0x00, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C, 0x03, 0x01, 0x00])
        #expect(ChannelBinding.signatureHash(sha384) == .sha384)
        #expect(ChannelBinding.signatureHash(Data([0x30, 0x00])) == .sha256)
        #expect(ChannelBinding.tlsServerEndPoint(sha384)?.count == "tls-server-end-point:".count + 48)
    }
}
