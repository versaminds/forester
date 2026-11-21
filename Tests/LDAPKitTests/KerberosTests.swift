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

    /// Without TLS, Kerberos encrypts every message after the bind: what
    /// crosses the network holds none of the directory's names, while the
    /// answers read in full. 1,500 entries come back in many encrypted frames.
    @Test func withoutTLSEveryMessageIsEncrypted() async throws {
        let connection = try await Self.connection(.none, port: 11389)
        try await connection.open()
        let wire = WireLog()
        await connection.observeReceivedBytes { wire.append($0) }
        try await connection.bindKerberos()
        let (sealed, secure, tls) = (await connection.isSealed, await connection.isSecure, await connection.usesTLS)
        #expect(sealed && secure && !tls)
        let before = wire.bytes.count
        let who = try await connection.whoAmI() ?? ""
        #expect(who.localizedCaseInsensitiveContains("Administrator"), "\(who)")
        let bulk = LDAPSearchRequest(base: "OU=Bulk Import,OU=Corp,DC=corp,DC=example", scope: .oneLevel,
                                     filter: .equality("objectClass", "user"), attributes: ["cn", "description"])
        let result = try await connection.pagedSearch(bulk, pageSize: 500)
        #expect(result.entries.count == 1_500)
        #expect(result.entries.contains { $0.dn.hasPrefix("CN=Bulk User 0001,") })
        let received = Data(wire.bytes[before...])
        #expect(received.count > 100_000)
        for readable in ["Bulk Import", "Bulk User 0001", "Administrator", "Synthetic"] {
            #expect(received.range(of: Data(readable.utf8)) == nil, "\(readable) crossed the network readable")
        }
        await connection.close()
    }

    /// Kerberos numbers every encrypted message, and the server refuses one
    /// out of order: many requests in flight at once, and a search abandoned
    /// midway, leave the connection working.
    @Test func manyRequestsInFlightStayInOrder() async throws {
        let connection = try await Self.connection(.none, port: 11389)
        try await connection.open()
        try await connection.bindKerberos()
        let dns = (1...300).map { String(format: "CN=Bulk User %04d,OU=Bulk Import,OU=Corp,DC=corp,DC=example", $0) }
        let entries = try await connection.readEach(dns, attributes: ["cn"], inFlight: 32)
        #expect(entries.count == 300)
        let search = Task {
            try await connection.search(LDAPSearchRequest(base: "DC=corp,DC=example", scope: .subtree, attributes: ["*"]))
        }
        try await Task.sleep(nanoseconds: 20_000_000)
        search.cancel()
        _ = try? await search.value
        let who = try await connection.whoAmI() ?? ""
        await connection.close()
        #expect(who.localizedCaseInsensitiveContains("Administrator"), "\(who)")
    }

    /// A new account with a password (which AD takes only over an encrypted
    /// connection) is created over plain LDAP encrypted by Kerberos, with a
    /// photo larger than one frame, so the request goes out in several.
    @Test func aRequestLargerThanOneFrameGoesInSeveral() async throws {
        let connection = try await Self.connection(.none, port: 11389)
        try await connection.open()
        try await connection.bindKerberos()
        let limit = try #require(await connection.sealedFrameLimit)
        let photo = Data((0..<90_000).map { UInt8(truncatingIfNeeded: $0 &* 2_654_435_761 >> 13) })
        #expect(photo.count > limit, "the server's frames hold \(limit) bytes")
        let dn = "CN=Sealed Check \(UInt32.random(in: 0..<1_000_000)),OU=Corp,DC=corp,DC=example"
        try await connection.add(dn, attributes: [
            LDAPAttribute(name: "objectClass", values: [Data("user".utf8)]),
            LDAPAttribute(name: "sAMAccountName", values: [Data("sealed\(UInt32.random(in: 0..<100_000))".utf8)]),
            LDAPAttribute(name: "unicodePwd", values: [ADValues.unicodePwd("Sealed-Check-Password-2026!")]),
            LDAPAttribute(name: "thumbnailPhoto", values: [photo]),
        ])
        let entry = try await connection.read(dn, attributes: ["pwdLastSet", "thumbnailPhoto"])
        try await connection.delete(dn)
        await connection.close()
        #expect((entry?.int("pwdLastSet") ?? 0) > 0)
        #expect(entry?.values("thumbnailPhoto").first == photo)
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
        await #expect(throws: LDAPError.self) { try await connection.bindKerberos(channelBinding: wrong, sealing: false) }
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

/// The security layer's framing, which needs no server: a frame outside the
/// agreed sizes is refused before Kerberos sees it, and a frame not yet whole
/// waits for the rest.
@Suite struct SecurityLayerFramingTests {
    @Test func framesOutsideTheAgreedSizesAreRefused() throws {
        #expect(SASLSecurityLayer.receiveLimit == 0xFF_FFFF)
        let layer = SASLSecurityLayer(context: try GSSContext(service: "ldap@localhost", channelBinding: nil, sealing: true),
                                      sendLimit: 1, receiveLimit: 16)
        var empty: [UInt8] = [0, 0, 0, 0]
        #expect(throws: LDAPError.self) { _ = try layer.unseal(&empty) }
        var oversized: [UInt8] = [0, 0, 0, 17] + [UInt8](repeating: 0, count: 17)
        #expect(throws: LDAPError.self) { _ = try layer.unseal(&oversized) }
        var partial: [UInt8] = [0, 0, 0, 8, 1, 2]
        #expect(try layer.unseal(&partial).isEmpty)
        #expect(partial == [0, 0, 0, 8, 1, 2])
        // Whole, but the exchange never ran: nothing is taken unencrypted.
        var whole: [UInt8] = [0, 0, 0, 2, 1, 2]
        #expect(throws: LDAPError.self) { _ = try layer.unseal(&whole) }
    }
}

/// Bytes seen on the network, from the connection's reader.
final class WireLog: @unchecked Sendable {
    private let lock = NSLock()
    private var received: [UInt8] = []

    func append(_ bytes: [UInt8]) { lock.withLock { received += bytes } }
    var bytes: [UInt8] { lock.withLock { received } }
}
