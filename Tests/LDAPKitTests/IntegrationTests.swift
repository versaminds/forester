// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import Testing
@testable import LDAPKit

/// Runs against the throwaway server from `TestDirectory/start.sh`. Skipped
/// unless FORESTER_TEST_SERVER=1, so `swift test` works without it.
private let serverEnabled = ProcessInfo.processInfo.environment["FORESTER_TEST_SERVER"] == "1"
/// The same overrides TestDirectory/start.sh reads.
private let plainPort = Int(ProcessInfo.processInfo.environment["LDAP_TEST_PORT"] ?? "") ?? 10389
private let tlsPort = Int(ProcessInfo.processInfo.environment["LDAPS_TEST_PORT"] ?? "") ?? 10636
private let adBase = "DC=corp,DC=example"
private let adminDN = "CN=admin,DC=corp,DC=example"

private func connect(_ security: LDAPConnection.Security = .none, port: Int? = nil, trust: TrustPolicy = TrustPolicy(),
                     timeout: TimeInterval = 10) async throws -> LDAPConnection {
    let connection = LDAPConnection(.init(host: "localhost", port: port ?? (security == .ldaps ? tlsPort : plainPort),
                                          security: security, timeout: timeout, trust: trust))
    try await connection.open()
    return connection
}

@Suite(.enabled(if: serverEnabled), .serialized)
struct IntegrationTests {
    @Test func rootDSEListsNamingContexts() async throws {
        let connection = try await connect()
        let root = try await connection.rootDSE()
        #expect(root.strings("namingContexts").map { $0.lowercased() }.contains("dc=corp,dc=example"))
        #expect(root.strings("supportedControl").contains(LDAPControl.pagedResultsOID))
        await connection.close()
    }

    @Test func bindSucceedsAndWrongPasswordIsInvalidCredentials() async throws {
        let connection = try await connect()
        try await connection.bind(dn: adminDN, password: "secret")
        #expect(try await connection.whoAmI()?.lowercased() == "dn:cn=admin,dc=corp,dc=example")

        let other = try await connect()
        await #expect(throws: LDAPError.self) { try await other.bind(dn: adminDN, password: "wrong") }
        do {
            try await other.bind(dn: adminDN, password: "wrong")
        } catch let error as LDAPError {
            #expect(error.resultCode == .invalidCredentials)
        }
        await connection.close()
        await other.close()
    }

    @Test func emptyPasswordIsRefusedBeforeReachingTheServer() async throws {
        let connection = try await connect()
        await #expect(throws: LDAPError.emptyPassword) { try await connection.bind(dn: adminDN, password: "") }
        await connection.close()
    }

    @Test func unpagedSearchStopsAtServerLimitAndPagedSearchGetsEverything() async throws {
        let connection = try await connect()
        let request = LDAPSearchRequest(base: "OU=Bulk Import,OU=Corp,\(adBase)", scope: .oneLevel,
                                        filter: .equality("objectClass", "user"), attributes: ["cn"])
        let unpaged = try await connection.search(request)
        #expect(unpaged.result.code == .sizeLimitExceeded)
        #expect(unpaged.entries.count == 500)

        let counter = Counter()
        let paged = try await connection.pagedSearch(request, pageSize: 500, progress: { counter.set($0) })
        #expect(paged.result.code == .success)
        #expect(paged.entries.count == 1500)
        #expect(counter.value == 1500)

        let limited = try await connection.pagedSearch(request, pageSize: 100, limit: 250)
        #expect(limited.stoppedAtLimit)
        #expect(limited.entries.count == 300)
        // The connection is still usable after releasing the paged search.
        #expect(try await connection.read("OU=Corp,\(adBase)") != nil)
        await connection.close()
    }

    @Test func pipelinedRequestsAreRoutedToTheirCallers() async throws {
        let connection = try await connect()
        let names = ["Engineering", "Finance", "Sales", "IT Operations"]
        let counts = try await withThrowingTaskGroup(of: (String, Int).self) { group in
            for name in names {
                group.addTask {
                    let r = try await connection.search(LDAPSearchRequest(
                        base: "OU=\(name),OU=Users,OU=Corp,\(adBase)", scope: .oneLevel, attributes: ["department"]))
                    #expect(r.entries.allSatisfy { $0.string("department") == name })
                    return (name, r.entries.count)
                }
            }
            return try await group.reduce(into: [String: Int]()) { $0[$1.0] = $1.1 }
        }
        #expect(counts == ["Engineering": 17, "Finance": 8, "Sales": 10, "IT Operations": 9])
        await connection.close()
    }

    @Test func binaryValuesSurviveAndFilterOnThem() async throws {
        let connection = try await connect()
        let admin = try #require(try await connection.read("CN=Administrator,CN=Users,\(adBase)", attributes: ["objectSid", "objectGUID"]))
        let sid = try #require(admin.values("objectSid").first)
        #expect(ADValues.sidString(sid) == "S-1-5-21-1004336348-1177238915-682003330-500")
        let found = try await connection.search(LDAPSearchRequest(
            base: adBase, scope: .subtree, filter: .equality("objectSid", [UInt8](sid)), attributes: ["cn"]))
        #expect(found.entries.map(\.dn) == [admin.dn])
        await connection.close()
    }

    @Test func missingEntryReadsAsNil() async throws {
        let connection = try await connect()
        #expect(try await connection.read("CN=Nobody,\(adBase)") == nil)
        await connection.close()
    }

    @Test(arguments: [LDAPConnection.Security.startTLS, .ldaps])
    func untrustedCertificateIsReportedWithItsFingerprint(_ security: LDAPConnection.Security) async throws {
        var failure: CertificateTrustFailure?
        do {
            let connection = try await connect(security)
            _ = try await connection.rootDSE()
            Issue.record("a certificate from an unknown CA was accepted")
        } catch LDAPError.untrustedCertificate(let f) {
            failure = f
        }
        let f = try #require(failure)
        #expect(f.subject == "localhost")
        #expect(f.sha256Fingerprint.count == 95)
        #expect(!f.chain.isEmpty)

        // Pinning that fingerprint is enough to connect, and the session is TLS.
        let pinned = try await connect(security, trust: TrustPolicy(pinnedFingerprints: [f.sha256Fingerprint]))
        let root = try await pinned.rootDSE()
        #expect(!root.strings("namingContexts").isEmpty)
        #expect(await pinned.isSecure)
        try await pinned.bind(dn: adminDN, password: "secret")
        await pinned.close()

        let anything = try await connect(security, trust: TrustPolicy(trustAnyCertificate: true))
        #expect(try await anything.whoAmI() == "anonymous")
        await anything.close()
    }

    @Test func refusedConnectionSaysSo() async throws {
        let connection = try await connect(port: 10999)
        do {
            _ = try await connection.rootDSE()
            Issue.record("expected a connection failure")
        } catch let error as LDAPError {
            #expect(error.errorDescription == "Could not connect to localhost:10999. The server refused the connection; check the host and port.")
        }
    }

    @Test func ldapsAgainstThePlainPortPointsAtThePort() async throws {
        let connection = try await connect(.ldaps, port: plainPort, timeout: 5)
        do {
            _ = try await connection.rootDSE()
            Issue.record("TLS against a plain LDAP port succeeded")
        } catch let error as LDAPError {
            #expect(error.errorDescription?.contains("\(plainPort) must be a TLS port") == true, "\(error.errorDescription ?? "")")
        }
    }

    @Test func unknownHostIsNamed() async throws {
        let connection = LDAPConnection(.init(host: "no-such-host.invalid", port: 389, security: .none, timeout: 10))
        try await connection.open()
        do {
            _ = try await connection.rootDSE()
            Issue.record("an unknown host connected")
        } catch let error as LDAPError {
            #expect(error.errorDescription == "The host “no-such-host.invalid” could not be found. Check the name, or your VPN.")
        }
    }

    @Test func plainLDAPAgainstTheLDAPSPortFailsQuickly() async throws {
        let connection = try await connect(port: tlsPort, timeout: 3)
        let start = Date()
        await #expect(throws: LDAPError.self) { _ = try await connection.rootDSE() }
        #expect(Date().timeIntervalSince(start) < 5)
    }

    @Test func cancellingASearchLeavesTheConnectionUsable() async throws {
        let connection = try await connect()
        let task = Task {
            try await connection.pagedSearch(LDAPSearchRequest(base: adBase, scope: .subtree, attributes: ["*"]), pageSize: 50)
        }
        try await Task.sleep(nanoseconds: 20_000_000)
        task.cancel()
        _ = await task.result
        #expect(try await connection.read(adBase) != nil)
        await connection.close()
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var _value = 0
    var value: Int { lock.lock(); defer { lock.unlock() }; return _value }
    func set(_ v: Int) { lock.lock(); _value = v; lock.unlock() }
}
