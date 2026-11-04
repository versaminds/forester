// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import Testing
@testable import LDAPKit

private let serverEnabled = ProcessInfo.processInfo.environment["FORESTER_TEST_SERVER"] == "1"
private let plainPort = Int(ProcessInfo.processInfo.environment["LDAP_TEST_PORT"] ?? "") ?? 10389
private let base = "DC=corp,DC=example"

private func admin() async throws -> LDAPConnection {
    let connection = LDAPConnection(.init(host: "localhost", port: plainPort, security: .none, timeout: 10))
    try await connection.open()
    try await connection.bind(dn: "CN=admin,\(base)", password: "secret")
    return connection
}

/// Writes against the test directory. Each test cleans up after itself, and
/// restarting TestDirectory/start.sh rebuilds everything anyway.
@Suite(.enabled(if: serverEnabled), .serialized)
struct WriteTests {
    let ou = "OU=Write Tests,OU=Corp,\(base)"

    @Test func addModifyRenameMoveAndDelete() async throws {
        let c = try await admin()
        try? await c.deleteSubtree(ou, useTreeDelete: false)
        try await c.add(ou, attributes: [
            LDAPAttribute(name: "objectClass", values: [Data("top".utf8), Data("organizationalUnit".utf8)]),
            LDAPAttribute(name: "ou", values: [Data("Write Tests".utf8)]),
        ])
        let user = "CN=Test User,\(ou)"
        try await c.add(user, attributes: [
            LDAPAttribute(name: "objectClass", values: ["top", "person", "organizationalPerson", "user"].map { Data($0.utf8) }),
            LDAPAttribute(name: "cn", values: [Data("Test User".utf8)]),
            LDAPAttribute(name: "sn", values: [Data("User".utf8)]),
            LDAPAttribute(name: "sAMAccountName", values: [Data("testuser".utf8)]),
            LDAPAttribute(name: "userAccountControl", values: [Data("514".utf8)]),
        ])
        try await c.modify(user, [.replace("userAccountControl", ["512"]), .add("description", ["first", "second"])])
        var entry = try #require(try await c.read(user, attributes: ["userAccountControl", "description"]))
        #expect(entry.string("userAccountControl") == "512")
        #expect(Set(entry.strings("description")) == ["first", "second"])

        try await c.modify(user, [.delete("description", ["first"])])
        entry = try #require(try await c.read(user, attributes: ["description"]))
        #expect(entry.strings("description") == ["second"])

        // A modify that breaks the schema is refused with the server's reason.
        await #expect(throws: LDAPError.self) { try await c.modify(user, [.add("gidNumber", ["5"])]) }

        try await c.modifyDN(user, newRDN: "CN=Renamed User")
        #expect(try await c.read(user) == nil)
        let renamed = "CN=Renamed User,\(ou)"
        #expect(try await c.read(renamed, attributes: ["cn"])?.string("cn") == "Renamed User")

        try await c.add("OU=Sub,\(ou)", attributes: [
            LDAPAttribute(name: "objectClass", values: [Data("organizationalUnit".utf8)]),
            LDAPAttribute(name: "ou", values: [Data("Sub".utf8)]),
        ])
        try await c.modifyDN(renamed, newRDN: "CN=Renamed User", newSuperior: "OU=Sub,\(ou)")
        #expect(try await c.read("CN=Renamed User,OU=Sub,\(ou)") != nil)

        // The OU has children, so a plain delete fails; a subtree delete does not.
        await #expect(throws: LDAPError.self) { try await c.delete(ou) }
        let counter = Progress()
        try await c.deleteSubtree(ou, useTreeDelete: false, progress: { done, total in counter.record(done, total) })
        #expect(try await c.read(ou) == nil)
        #expect(counter.last?.0 == 3 && counter.last?.1 == 3)
        await c.close()
    }

    @Test func passwordValuesAndBinaryAttributes() async throws {
        let c = try await admin()
        let dn = "CN=svc_ldapread,OU=Service Accounts,OU=Corp,\(base)"
        try await c.modify(dn, [LDAPModification(.replace, "unicodePwd", [ADValues.unicodePwd("Pässword-1")])])
        let stored = try #require(try await c.read(dn, attributes: ["unicodePwd"])?.values("unicodePwd").first)
        #expect(stored == Data("\"Pässword-1\"".utf16.flatMap { [UInt8($0 & 0xFF), UInt8($0 >> 8)] }))
        await c.close()

        // The RFC 3062 operation is answered (Apple's slapd hands the password to
        // Open Directory). It needs the administrator of that naming context.
        let org = LDAPConnection(.init(host: "localhost", port: plainPort, security: .none, timeout: 10))
        try await org.open()
        try await org.bind(dn: "cn=admin,dc=example,dc=org", password: "secret")
        _ = try await org.passwordModify(user: "uid=ghopper,ou=people,dc=example,dc=org", oldPassword: nil, newPassword: "NewPass-1")
        await org.close()
    }

    @Test func securityDescriptorRoundTripsThroughTheServer() async throws {
        let c = try await admin()
        let dn = "CN=svc_backup,OU=Service Accounts,OU=Corp,\(base)"
        let raw = try #require(try await c.read(dn, attributes: ["nTSecurityDescriptor"], controls: [.sdFlags(4)])?
            .values("nTSecurityDescriptor").first)
        var sd = try SecurityDescriptor(data: raw)
        #expect(sd.userCannotChangePassword)
        sd.setUserCannotChangePassword(false)
        try await c.modify(dn, [LDAPModification(.replace, "nTSecurityDescriptor", [sd.encoded()])], controls: [.sdFlags(4)])
        let reread = try #require(try await c.read(dn, attributes: ["nTSecurityDescriptor"])?.values("nTSecurityDescriptor").first)
        #expect(try SecurityDescriptor(data: reread).userCannotChangePassword == false)
        sd.setUserCannotChangePassword(true)
        try await c.modify(dn, [LDAPModification(.replace, "nTSecurityDescriptor", [sd.encoded()])])
        await c.close()
    }

    @Test func schemaIsReadAndAnswersQuestions() async throws {
        let c = try await admin()
        let schema = try #require(try await c.schema(rootDSE: try await c.rootDSE()))
        #expect(schema.attributeType("CN")?.names.contains("commonName") == true)
        #expect(schema.syntax(of: "cn") == KnownSyntax.directoryString.rawValue) // inherited from 'name'
        #expect(schema.isSingleValued("userAccountControl"))
        #expect(!schema.isSingleValued("member"))
        let allowed = schema.allowedAttributes(for: ["user"])
        #expect(allowed.must.contains("cn") && allowed.must.contains("sn") && allowed.must.contains("objectClass"))
        #expect(allowed.may.contains("sAMAccountName") && allowed.may.contains("telephoneNumber"))
        #expect(schema.objectClass("groupOfURLs")?.kind == .structural)
        #expect(schema.unparsed.isEmpty, "\(schema.unparsed.prefix(3))")
        await c.close()
    }

    @Test func dynamicGroupURLIsRunnable() async throws {
        let c = try await admin()
        let group = try #require(try await c.read("CN=DYN-Engineering,OU=Groups,OU=Corp,\(base)", attributes: ["memberURL"]))
        let memberURL = try #require(group.string("memberURL"))
        let url = try #require(LDAPURL(memberURL))
        let members = try await c.search(LDAPSearchRequest(base: url.dn, scope: url.scope, filter: try LDAPFilter.parse(url.filter),
                                                           attributes: ["1.1"]))
        #expect(members.entries.count == 17)
        await c.close()
    }

    @Test func monitorIsReadable() async throws {
        let c = try await admin()
        let result = try await c.search(LDAPSearchRequest(base: "cn=Monitor", scope: .subtree, attributes: ["*", "+"]))
        #expect(result.entries.count > 20)
        #expect(result.entries.contains { $0.attribute("monitorCounter") != nil })
        await c.close()
    }

    /// The sample file does what TESTING.md says: seven records succeed and the
    /// seventh fails. Everything it changed is put back afterwards.
    @Test func sampleImportAppliesAsDocumented() async throws {
        let c = try await admin()
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("TestDirectory/sample-import.ldif")
        let records = try LDIFParser.parse(String(contentsOf: url, encoding: .utf8))
        let pieter = "CN=Pieter Van Damme,OU=Engineering,OU=Users,OU=Corp,\(base)"
        let legacy = "CN=GG-Empty-Legacy,OU=Groups,OU=Corp,\(base)"
        let imported = "OU=Imported,OU=Corp,\(base)"
        let before = try #require(try await c.read(pieter, attributes: ["title", "mobile"]))
        let legacyEntry = try #require(try await c.read(legacy, attributes: ["*"]),
                                       "GG-Empty-Legacy is missing: something already imported the sample. Restart TestDirectory/start.sh.")
        try #require(before.string("title") == "Head of Engineering",
                     "Pieter's title was changed: something already imported the sample. Restart TestDirectory/start.sh.")
        try? await c.deleteSubtree(imported, useTreeDelete: false)

        var failed: [Int] = []
        for (index, record) in records.enumerated() {
            do {
                switch record.change {
                case .add(let attributes): try await c.add(record.dn, attributes: attributes)
                case .modify(let changes): try await c.modify(record.dn, changes)
                case .modifyDN(let rdn, let deleteOld, let superior):
                    try await c.modifyDN(record.dn, newRDN: rdn, deleteOldRDN: deleteOld, newSuperior: superior)
                case .delete: try await c.delete(record.dn)
                }
            } catch {
                failed.append(index + 1)
            }
        }
        #expect(failed == [7])
        #expect(try await c.read("CN=Grace Hopper Import,\(imported)") != nil)
        #expect(try await c.read("CN=GG-Imported,\(imported)", attributes: ["member"])?.strings("member").count == 2)
        #expect(try await c.read(pieter, attributes: ["title"])?.string("title") == "VP Engineering")
        #expect(try await c.read(legacy) == nil)

        try await c.deleteSubtree(imported, useTreeDelete: false)
        try await c.add(legacy, attributes: legacyEntry.attributes)
        try await c.modify(pieter, [.replace("title", before.strings("title")), .replace("mobile", before.strings("mobile"))])
        await c.close()
    }

    /// An anonymous write is refused with code 8, and the message says to sign
    /// in rather than to encrypt, which would not help.
    @Test func anonymousWriteSaysToSignIn() async throws {
        let c = LDAPConnection(.init(host: "localhost", port: plainPort, security: .none, timeout: 10))
        try await c.open()
        let dn = "CN=Pieter Van Damme,OU=Engineering,OU=Users,OU=Corp,\(base)"
        let error = await #expect(throws: LDAPError.self) { try await c.modify(dn, [.replace("description", ["x"])]) }
        let text = error?.errorDescription ?? ""
        #expect(text.contains("(8)"))
        #expect(text.contains("name and password"))
        #expect(!text.contains("StartTLS"))
        await c.close()
    }
}

final class Progress: @unchecked Sendable {
    private let lock = NSLock()
    private var value: (Int, Int)?
    var last: (Int, Int)? { lock.lock(); defer { lock.unlock() }; return value }
    func record(_ done: Int, _ total: Int) { lock.lock(); value = (done, total); lock.unlock() }
}

// MARK: Unit tests (no server)

@Suite struct SchemaParserTests {
    @Test func rfcAndADDefinitionsParse() throws {
        let entry = LDAPEntry(dn: "cn=Subschema", attributes: [
            LDAPAttribute(name: "attributeTypes", values: [
                "( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
                "( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC4519: common name(s) for which the entity is known by' SUP name )",
                "( 1.2.840.113556.1.4.8 NAME 'userAccountControl' SYNTAX '1.3.6.1.4.1.1466.115.121.1.27' SINGLE-VALUE )",
                "( 2.5.18.1 NAME 'createTimestamp' EQUALITY generalizedTimeMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
                "( 1.1.1 NAME 'quoted' DESC 'It\\27s \\5c fine' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'test' )",
            ].map { Data($0.utf8) }),
            LDAPAttribute(name: "objectClasses", values: [
                "( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
                "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )",
                "( 1.2.840.113556.1.5.9 NAME 'user' SUP person STRUCTURAL MAY ( userAccountControl ) X-NDS_NAME 'User' )",
                "( 1.3.6.1.1.1.2.0 NAME 'posixAccount' DESC 'Abstraction of an account with POSIX attributes' SUP top AUXILIARY MUST ( cn $ uid ) )",
            ].map { Data($0.utf8) }),
        ])
        let schema = LDAPSchema(subschema: entry)
        #expect(schema.unparsed.isEmpty)
        let cn = try #require(schema.attributeType("commonName"))
        #expect(cn.name == "cn" && cn.superior == "name")
        #expect(cn.description == "RFC4519: common name(s) for which the entity is known by")
        #expect(schema.syntax(of: "cn") == "1.3.6.1.4.1.1466.115.121.1.15")
        #expect(schema.attributeType("name")?.syntaxLength == 32768)
        #expect(schema.attributeType("userAccountControl")?.syntax == "1.3.6.1.4.1.1466.115.121.1.27")
        #expect(schema.isSingleValued("userAccountControl;binary"))
        #expect(schema.attributeType("createTimestamp")?.isOperational == true)
        #expect(schema.attributeType("quoted")?.description == "It's \\ fine")
        #expect(schema.objectClass("user")?.superiors == ["person"])
        #expect(schema.objectClass("posixAccount")?.kind == .auxiliary)
        #expect(schema.objectClass("top")?.kind == .abstract)
        let allowed = schema.allowedAttributes(for: ["user"])
        #expect(allowed.must == ["sn", "cn", "objectClass"])
        #expect(allowed.may == ["userAccountControl", "userPassword", "telephoneNumber"])
        #expect(schema.classes(using: "commonName").map(\.name).sorted() == ["person", "posixAccount"])
    }
}

@Suite struct LDIFParserTests {
    @Test func contentAndChangeRecordsParse() throws {
        let text = """
        version: 1
        # A comment
         that continues

        dn: cn=Jane Doe,ou=people,dc=example,dc=org
        objectClass: inetOrgPerson
        cn: Jane Doe
        description:: IGxlYWRpbmcgc3BhY2U=
        sn: Doe and a very long value that wraps onto
         a second line

        dn: cn=old,dc=example,dc=org
        changetype: modify
        add: mail
        mail: a@example.org
        mail: b@example.org
        -
        replace: title
        title: Boss
        -
        delete: telephoneNumber
        -

        dn: cn=gone,dc=example,dc=org
        changetype: delete

        dn: cn=a,dc=example,dc=org
        changetype: modrdn
        newrdn: cn=b
        deleteoldrdn: 0
        newsuperior: ou=x,dc=example,dc=org
        """
        let records = try LDIFParser.parse(text)
        #expect(records.count == 4)
        guard case .add(let attributes) = records[0].change else { Issue.record("not an add"); return }
        #expect(records[0].isContent)
        #expect(records[0].dn == "cn=Jane Doe,ou=people,dc=example,dc=org")
        #expect(attributes.first { $0.name == "description" }?.values == [Data(" leading space".utf8)])
        #expect(attributes.first { $0.name == "sn" }?.stringValues == ["Doe and a very long value that wraps ontoa second line"])
        guard case .modify(let changes) = records[1].change else { Issue.record("not a modify"); return }
        #expect(changes.map(\.operation) == [.add, .replace, .delete])
        #expect(changes[0].values.count == 2)
        #expect(changes[2].values.isEmpty)
        guard case .delete = records[2].change else { Issue.record("not a delete"); return }
        guard case .modifyDN(let rdn, let deleteOld, let superior) = records[3].change else { Issue.record("not a moddn"); return }
        #expect(rdn == "cn=b" && !deleteOld && superior == "ou=x,dc=example,dc=org")
        #expect(records[3].line == 27)
    }

    @Test func exportReadsBackIdentically() throws {
        let entry = LDAPEntry(dn: "CN=Lučić,DC=x", attributes: [
            LDAPAttribute(name: "objectClass", values: [Data("top".utf8), Data("user".utf8)]),
            LDAPAttribute(name: "objectSid", values: [Data([1, 5, 0, 0, 0, 0, 0, 5])]),
            LDAPAttribute(name: "info", values: [Data(String(repeating: "word ", count: 40).utf8)]),
        ])
        let records = try LDIFParser.parse(LDIF.document([entry]))
        guard case .add(let attributes) = records.first?.change else { Issue.record("not parsed"); return }
        #expect(records.first?.dn == entry.dn)
        #expect(attributes == entry.attributes)
    }

    @Test func exportPutsParentsFirst() {
        let order = ["CN=b,OU=x,DC=y", "OU=x,DC=y", "CN=a,OU=Sub\\,1,OU=x,DC=y", "CN=c,OU=x,DC=y", "OU=Sub\\,1,OU=x,DC=y"]
        let sorted = LDIF.parentsFirst(order.map { LDAPEntry(dn: $0, attributes: []) }).map(\.dn)
        #expect(sorted == ["OU=x,DC=y", "CN=b,OU=x,DC=y", "CN=c,OU=x,DC=y", "OU=Sub\\,1,OU=x,DC=y", "CN=a,OU=Sub\\,1,OU=x,DC=y"])
    }

    @Test func sampleImportFileParses() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("TestDirectory/sample-import.ldif")
        let records = try LDIFParser.parse(String(contentsOf: url, encoding: .utf8))
        #expect(records.map(\.summary) == ["entry", "entry", "entry", "add", "modify (2 changes)", "rename",
                                            "modify (1 change)", "delete"])
        guard case .add(let attributes) = records[2].change else { Issue.record("not an add"); return }
        #expect(attributes.first { $0.name == "description" }?.stringValues == ["Imported with a base64 value: Lučić"])
    }

    @Test(arguments: [
        ("cn: x\n", "must start with “dn:”"),
        ("dn: cn=x\nchangetype: frobnicate\n", "Unknown changetype"),
        ("dn: cn=x\nchangetype: modify\nfoo: bar\n", "Expected add:"),
        ("dn: cn=x\nchangetype: modify\nadd: mail\ncn: oops\n", "is a “-” missing"),
        ("dn: cn=x\nchangetype: modrdn\ndeleteoldrdn: 1\n", "needs “newrdn:”"),
        ("dn: cn=x\nphoto:< http://example.org/a.png\n", "Only file: URLs"),
    ])
    func malformedRecordsSayWhere(_ text: String, _ fragment: String) {
        do {
            _ = try LDIFParser.parse(text)
            Issue.record("parsed")
        } catch let error as LDIFParseError {
            #expect(error.message.contains(fragment), "\(error.message)")
        } catch {
            Issue.record("\(error)")
        }
    }
}

@Suite struct SecurityDescriptorTests {
    /// A descriptor built by hand the way AD lays one out.
    func sample(cannotChange: Bool) -> Data {
        func le32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) } }
        func sid(_ s: String) -> [UInt8] { [UInt8](ADValues.sidData(s)!) }
        let changePassword = [UInt8](ADValues.guidData("ab721a53-1e2f-11d0-9819-00aa0040529b")!)
        func ace(_ type: UInt8, _ flags: UInt8, _ mask: UInt32, _ who: String, object: Bool = false) -> [UInt8] {
            var body = le32(mask)
            if object { body += le32(1) + changePassword }
            body += sid(who)
            return [type, flags, UInt8(4 + body.count), 0] + body
        }
        let kind: UInt8 = cannotChange ? 6 : 5
        var aces = [ace(0, 0, 0xF01FF, "S-1-5-18"), ace(0, 0x12, 0x20094, "S-1-5-32-554")]
        let change = [ace(kind, 0, 0x100, "S-1-1-0", object: true), ace(kind, 0, 0x100, "S-1-5-10", object: true)]
        aces = cannotChange ? change + aces : [aces[0]] + change + [aces[1]]
        let body = aces.flatMap { $0 }
        let dacl: [UInt8] = [4, 0, UInt8((8 + body.count) & 0xFF), UInt8((8 + body.count) >> 8), UInt8(aces.count), 0, 0, 0] + body
        let owner = sid("S-1-5-32-544")
        let header: [UInt8] = [1, 0, 0x04, 0x84] + le32(UInt32(20 + dacl.count)) + le32(0) + le32(0) + le32(20)
        return Data(header + dacl + owner)
    }

    @Test func parsesAndReencodesByteForByte() throws {
        for cannotChange in [false, true] {
            let data = sample(cannotChange: cannotChange)
            let sd = try SecurityDescriptor(data: data)
            #expect(sd.owner == "S-1-5-32-544")
            #expect(sd.dacl?.aces.count == 4)
            #expect(sd.userCannotChangePassword == cannotChange)
            #expect(try sd.encoded() == data)
        }
    }

    @Test func togglingKeepsCanonicalOrder() throws {
        var sd = try SecurityDescriptor(data: sample(cannotChange: false))
        sd.setUserCannotChangePassword(true)
        #expect(sd.userCannotChangePassword)
        let aces = try #require(sd.dacl?.aces)
        #expect(aces.prefix(2).allSatisfy { $0.type == SecurityDescriptor.ACE.accessDeniedObject })
        #expect(aces.last?.isInherited == true)
        #expect(aces.count == 4)
        let reparsed = try SecurityDescriptor(data: sd.encoded())
        #expect(reparsed == sd)
        sd.setUserCannotChangePassword(false)
        #expect(!sd.userCannotChangePassword)
        #expect(sd.dacl?.aces.filter { $0.type == SecurityDescriptor.ACE.accessAllowedObject }.count == 2)
    }

    @Test func truncatedDataIsRejected() {
        #expect(throws: SecurityDescriptorError.self) { try SecurityDescriptor(data: Data([1, 0, 4])) }
    }
}

@Suite struct MetadataAndURLTests {
    @Test func replicationMetadataParses() throws {
        let value = """
        <DS_REPL_ATTR_META_DATA>
        	<pszAttributeName>pwdLastSet</pszAttributeName>
        	<dwVersion>7</dwVersion>
        	<ftimeLastOriginatingChange>2026-09-01T10:20:30Z</ftimeLastOriginatingChange>
        	<uuidLastOriginatingDsaInvocationID>3f1c9a2e-0000-4000-8000-000000000001</uuidLastOriginatingDsaInvocationID>
        	<usnOriginatingChange>12345</usnOriginatingChange>
        	<usnLocalChange>12362</usnLocalChange>
        	<pszLastOriginatingDsaDN>CN=NTDS Settings,CN=DC02,CN=Servers,CN=Brussels,CN=Sites,CN=Configuration,DC=corp,DC=example</pszLastOriginatingDsaDN>
        </DS_REPL_ATTR_META_DATA>\0
        """
        let parsed = try #require(ReplicationMetadata.parse([value]).first)
        #expect(parsed.attribute == "pwdLastSet" && parsed.version == 7 && parsed.originatingUSN == 12345)
        #expect(parsed.originatingServer == "DC02")
        #expect(parsed.lastOriginatingChange == ISO8601DateFormatter().date(from: "2026-09-01T10:20:30Z"))
    }

    @Test func ldapURLsParse() throws {
        let url = try #require(LDAPURL("ldap:///ou=people,dc=example,dc=org??sub?(objectClass=person)"))
        #expect(url.host == nil && url.dn == "ou=people,dc=example,dc=org" && url.scope == .subtree)
        #expect(url.filter == "(objectClass=person)")
        let full = try #require(LDAPURL("ldaps://dc01.corp.example:636/OU=X,DC=corp?cn,mail?one?(cn=a%20b)"))
        #expect(full.host == "dc01.corp.example" && full.port == 636 && full.attributes == ["cn", "mail"])
        #expect(full.scope == .oneLevel && full.filter == "(cn=a b)")
        #expect(LDAPURL("ldap:///dc=x")?.filter == "(objectClass=*)")
        #expect(LDAPURL("http://example.org") == nil)
    }

    @Test func unicodePwdIsQuotedUTF16LE() {
        #expect(ADValues.unicodePwd("ab") == Data([0x22, 0, 0x61, 0, 0x62, 0, 0x22, 0]))
    }
}
