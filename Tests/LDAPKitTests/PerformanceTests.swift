// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import Testing
@testable import LDAPKit

/// Times what a large directory asks of the client, against the test server
/// started with a big Bulk Import OU:
///
///   LDAP_TEST_BULK=50000 TestDirectory/start.sh
///   FORESTER_BENCH=1 swift test --filter PerformanceTests
///
/// The times are printed, not asserted: they depend on the Mac. What is
/// asserted is that everything arrived.
private let benchEnabled = ProcessInfo.processInfo.environment["FORESTER_BENCH"] == "1"
private let port = Int(ProcessInfo.processInfo.environment["LDAP_TEST_PORT"] ?? "") ?? 10389
private let bulkBase = "OU=Bulk Import,OU=Corp,DC=corp,DC=example"

private func seconds(_ body: () async throws -> Void) async rethrows -> Double {
    let clock = ContinuousClock()
    let elapsed = try await clock.measure(body)
    return Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
}

@Suite(.enabled(if: benchEnabled), .serialized)
struct PerformanceTests {
    private func connect() async throws -> LDAPConnection {
        let connection = LDAPConnection(.init(host: "localhost", port: port, security: .none, timeout: 60))
        try await connection.open()
        try await connection.bind(dn: "CN=admin,DC=corp,DC=example", password: "secret")
        return connection
    }

    @Test func pagedSearchOfTheWholeOU() async throws {
        let connection = try await connect()
        let request = LDAPSearchRequest(base: bulkBase, scope: .oneLevel, filter: .equality("objectClass", "user"),
                                        attributes: ["objectClass", "displayName", "sAMAccountName", "mail", "description",
                                                     "userAccountControl"])
        var count = 0
        let time = try await seconds {
            count = try await connection.pagedSearch(request, pageSize: 1000).entries.count
        }
        print("bench: paged search, \(count) entries: \(String(format: "%.2f", time)) s")
        #expect(count > 1000)
        await connection.close()
    }

    @Test func everyAttributeOfTheWholeOU() async throws {
        let connection = try await connect()
        let request = LDAPSearchRequest(base: bulkBase, scope: .oneLevel, filter: .equality("objectClass", "user"),
                                        attributes: ["*"])
        var count = 0
        let time = try await seconds {
            count = try await connection.pagedSearch(request, pageSize: 1000).entries.count
        }
        print("bench: paged search with every attribute, \(count) entries: \(String(format: "%.2f", time)) s")
        #expect(count > 1000)
        await connection.close()
    }

    @Test func groupWithEveryBulkUser() async throws {
        let connection = try await connect()
        var members = 0
        let time = try await seconds {
            let group = try await connection.read("CN=UG-All-Staff,OU=Groups,OU=Corp,DC=corp,DC=example", attributes: ["*", "+"])
            members = group?.values("member").count ?? 0
        }
        print("bench: read a group of \(members) members: \(String(format: "%.2f", time)) s")
        #expect(members > 1000)
        await connection.close()
    }

    /// Decoding alone, without the network: a page of search entries as the
    /// server encodes them.
    @Test func decodingSearchEntries() throws {
        let attributes = (0..<12).map { i in
            BER.tlv(0x30, BER.tlv(0x04, Array("attribute\(i)".utf8))
                + BER.tlv(0x31, BER.tlv(0x04, Array("a value of some length for attribute \(i)".utf8))))
        }.reduce([], +)
        func entry(_ id: Int) -> [UInt8] {
            let dn = Array("CN=Bulk User \(id),OU=Bulk Import,OU=Corp,DC=corp,DC=example".utf8)
            let body = BER.tlv(0x64, BER.tlv(0x04, dn) + BER.tlv(0x30, attributes))
            return BER.tlv(0x30, BER.tlv(0x02, BER.integerContent(Int64(7))) + body)
        }
        var buffer: [UInt8] = []
        for id in 0..<50_000 { buffer += entry(id) }
        var decoded = 0
        let clock = ContinuousClock()
        let elapsed = try clock.measure {
            var offset = 0
            while let (element, next) = try BERDecoder.element(in: buffer, at: offset) {
                offset = next
                if case .searchEntry = try LDAPCodec.decodeResponse(element).kind { decoded += 1 }
            }
        }
        print("bench: decode \(decoded) entries (\(buffer.count / 1024) KB): \(elapsed)")
        #expect(decoded == 50_000)
    }
}
