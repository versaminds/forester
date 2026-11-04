// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import Testing
@testable import LDAPKit

/// What a file, a server or directory data written by someone else must not
/// be able to do: read files from this Mac, crash the app, or slip a record
/// or a DN component past the escaping.
@Suite struct SecurityTests {
    // MARK: Filters

    /// A dynamic group's memberURL is directory data, and parsing and
    /// encoding a filter recurse: deep nesting is refused, never a crash.
    @Test func filterNestingIsBounded() throws {
        func nested(_ depth: Int) -> String { String(repeating: "(!", count: depth - 1) + "(cn=x)" + String(repeating: ")", count: depth - 1) }
        let deepest = try LDAPFilter.parse(nested(64))
        #expect(!deepest.encoded.isEmpty)
        #expect(throws: LDAPFilterError.self) { try LDAPFilter.parse(nested(65)) }
        #expect(throws: LDAPFilterError.self) { try LDAPFilter.parse(nested(200_000)) }
        let wide = "(&" + String(repeating: "(cn=x)", count: 10_000) + ")"
        #expect(throws: Never.self) { try LDAPFilter.parse(wide) }
    }

    // MARK: LDIF file references

    @Test func fileReferencesAreReadOnlyWithConsent() throws {
        let text = "dn: cn=x,dc=example\nobjectClass: person\ndescription:< file:///etc/hosts\n"
        #expect(LDIFParser.fileReferences(in: text).map(\.reference) == ["file:///etc/hosts"])
        #expect(LDIFParser.fileReferences(in: text).map(\.line) == [3])
        do {
            _ = try LDIFParser.parse(text)
            Issue.record("a file reference was read without consent")
        } catch let error as LDIFParseError {
            #expect(error.line == 3)
            #expect(error.message.contains("consent"))
        }
    }

    @Test func fileReferencesStayInTheFolder() throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("forester-ldif-\(UUID().uuidString)", isDirectory: true)
        let folder = root.appendingPathComponent("import", isDirectory: true)
        try fm.createDirectory(at: folder.appendingPathComponent("photos"), withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: root) }
        try Data("beside".utf8).write(to: folder.appendingPathComponent("note.txt"))
        try Data("below".utf8).write(to: folder.appendingPathComponent("photos/a.txt"))
        try Data("secret".utf8).write(to: root.appendingPathComponent("outside.txt"))
        try fm.createSymbolicLink(at: folder.appendingPathComponent("link.txt"), withDestinationURL: root.appendingPathComponent("outside.txt"))
        let big = folder.appendingPathComponent("big.bin")
        fm.createFile(atPath: big.path, contents: nil)
        let handle = try FileHandle(forWritingTo: big)
        try handle.truncate(atOffset: UInt64(LDIFFileReferences.maxFileBytes + 1))
        try handle.close()

        func read(_ reference: String) throws -> Data {
            let records = try LDIFParser.parse("dn: cn=x\ndescription:< \(reference)\n", files: .within(folder))
            guard case .add(let attributes) = records.first?.change else { throw CancellationError() }
            return attributes.first { $0.name == "description" }?.values.first ?? Data()
        }
        #expect(try read("note.txt") == Data("beside".utf8))
        #expect(try read("photos/a.txt") == Data("below".utf8))
        #expect(try read(folder.appendingPathComponent("note.txt").absoluteString) == Data("beside".utf8))
        for refused in ["../outside.txt", "photos/../../outside.txt", "link.txt", "photos", "big.bin", "/etc/hosts",
                        "file:///etc/hosts", "file://evil.example\(folder.path)/note.txt", "http://example.org/a", "missing.txt"] {
            #expect(throws: LDIFParseError.self, "\(refused)") { _ = try read(refused) }
        }
    }

    /// A control changes what an operation does; running the record without
    /// it could do more than the file asks for.
    @Test func ldifControlsAreRefused() {
        let text = "dn: cn=x,dc=example\ncontrol: 1.3.6.1.1.12 true:: KG9iamVjdENsYXNzPXRlbXAp\nchangetype: delete\n"
        #expect(throws: LDIFParseError.self) { try LDIFParser.parse(text) }
    }

    /// An attribute name from a hostile server cannot add a record to an export.
    @Test func ldifExportLeavesOutInvalidNames() throws {
        let entry = LDAPEntry(dn: "cn=x,dc=example", attributes: [
            LDAPAttribute(name: "cn", values: [Data("x".utf8)]),
            LDAPAttribute(name: "description\n\ndn: cn=victim,dc=example\nchangetype: delete", values: [Data("y".utf8)]),
        ])
        let records = try LDIFParser.parse(LDIF.document([entry]))
        #expect(records.count == 1)
        #expect(records.first?.dn == "cn=x,dc=example")
    }

    // MARK: DNs and security descriptors

    /// A combining mark after a comma makes one Character of both; escaping
    /// by Character would leave the comma bare and add a DN component.
    @Test func dnEscapingWorksByScalar() {
        let value = "x,\u{301}OU=Admins"
        let dn = "CN=\(DN.escape(value)),DC=example"
        #expect(DN.components(dn).count == 2)
        #expect(DN.unescape(DN.rdnValue(dn)) == value)
    }

    @Test func oversizedAccessListIsRefused() {
        let ace = SecurityDescriptor.ACE(type: SecurityDescriptor.ACE.accessAllowed, flags: 0, mask: 0x20094,
                                         objectType: nil, inheritedObjectType: nil, sid: "S-1-5-21-1-2-3-500")
        // Self-relative, a DACL and nothing else: an empty ACL at offset 20.
        let empty: [UInt8] = [1, 0, 0x04, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 2, 0, 8, 0, 0, 0, 0, 0]
        guard var descriptor = try? SecurityDescriptor(data: Data(empty)) else { Issue.record("not parsed"); return }
        descriptor.dacl?.aces = [ace]
        #expect((try? SecurityDescriptor(data: descriptor.encoded())) == descriptor)
        descriptor.dacl?.aces = Array(repeating: ace, count: 2_000)
        #expect(throws: SecurityDescriptorError.tooLarge) { try descriptor.encoded() }
    }
}
