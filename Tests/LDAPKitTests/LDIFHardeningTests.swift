// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import Testing
@testable import LDAPKit

/// LDIF out and in, where a file or a server's data could make an import do
/// more than it shows: an exported entry turned into a change record, a
/// change listed only as a count, a log line made up by a DN.
@Suite struct LDIFHardeningTests {
    static let base = "OU=Corp,DC=corp,DC=example"

    /// An entry with attributes named changetype, control or dn exports as
    /// the entry: imported again, it is the same plain add, those lines
    /// kept only as comments.
    @Test func exportedKeywordsStayComments() throws {
        let entry = LDAPEntry(dn: "CN=Odd,\(Self.base)", attributes: [
            LDAPAttribute(name: "changetype", values: [Data("delete".utf8)]),
            LDAPAttribute(name: "Control", values: [Data("1.2.840.113556.1.4.805 true".utf8)]),
            LDAPAttribute(name: "dn", values: [Data("CN=Someone Else,\(Self.base)".utf8)]),
            LDAPAttribute(name: "changeType;x-option", values: [Data(String(repeating: "modify ", count: 30).utf8)]),
            LDAPAttribute(name: "description", values: [Data("kept".utf8)]),
        ])
        let text = LDIF.document([entry])
        let records = try LDIFParser.parse(text)
        #expect(records.count == 1)
        let record = try #require(records.first)
        #expect(record.dn == entry.dn && record.isContent)
        guard case .add(let attributes) = record.change else { Issue.record("not an add: \(record.change)"); return }
        #expect(attributes.map(\.name) == ["description"])
        for line in text.split(separator: "\n") where line.lowercased().hasPrefix("changetype") || line.lowercased().hasPrefix("control") {
            Issue.record("an uncommented keyword line: \(line)")
        }
        #expect(text.components(separatedBy: "\ndn:").count == 2, "a second dn line")
        // The same in a change record written for a log or "copy as LDIF".
        let copied = LDIF.record(LDIFRecord(dn: entry.dn, change: .add(entry.attributes)))
        guard case .add(let again)? = try LDIFParser.parse(copied).first?.change else { Issue.record("not an add"); return }
        #expect(again.map(\.name) == ["description"])
    }

    static let file = """
    version: 1

    dn: CN=New User,OU=Sales,\(base)
    objectClass: user
    cn: New User

    dn: CN=Domain Admins,CN=Users,DC=corp,DC=example
    changetype: modify
    add: member
    member: CN=New User,OU=Sales,\(base)
    -

    dn: CN=Helpdesk,OU=Groups,\(base)
    changetype: modify
    add: member
    member: CN=New User,OU=Sales,\(base)
    -

    dn: CN=Web,OU=Servers,\(base)
    changetype: modify
    replace: userAccountControl
    userAccountControl: 528384
    -
    add: servicePrincipalName
    servicePrincipalName: HTTP/web.corp.example
    -

    dn: CN=File,OU=Servers,\(base)
    changetype: modify
    replace: msDS-AllowedToActOnBehalfOfOtherIdentity
    msDS-AllowedToActOnBehalfOfOtherIdentity:: AQAEgBQAAAAAAAAAAAAAACQAAAABAgAAAAAABSAAAAAgAgAA
    -

    dn: CN=Old,OU=Sales,\(base)
    changetype: delete

    dn: CN=Elsewhere,OU=Other,DC=corp,DC=example
    objectClass: contact

    dn: CN=Mover,OU=Sales,\(base)
    changetype: moddn
    newrdn: CN=Mover
    deleteoldrdn: 1
    newsuperior: CN=Users,DC=corp,DC=example

    dn: CN=Pw,OU=Sales,\(base)
    changetype: modify
    replace: unicodePwd
    unicodePwd:: IgBTAGUAYwByAGUAdAAiAA==
    -
    replace: nTSecurityDescriptor
    nTSecurityDescriptor:: AQAEgA==
    -

    """

    /// Every record that is not a plain add, or lands outside the chosen
    /// container, is listed with its DN and what it changes, and the
    /// sensitive ones say why.
    @Test func theReviewListsWhatTheCountsHid() throws {
        let records = try LDIFParser.parse(Self.file)
        let groups = LDIFImportReview.groupsChangingMembers(records)
        #expect(groups.contains("CN=Domain Admins,CN=Users,DC=corp,DC=example") && groups.contains("CN=Helpdesk,OU=Groups,\(Self.base)"))
        // Helpdesk is protected by AdminSDHolder, as the directory reports it.
        let privileged = Set(groups.filter {
            LDAPKit.LDIFImportReview.privilegedGroup(dn: $0, sid: nil, adminCount: $0.hasPrefix("CN=Helpdesk") ? 1 : nil)
        }.map(DN.normalized))
        let review = LDIFImportReview(records, container: Self.base, privilegedGroups: privileged)
        let byDN = Dictionary(uniqueKeysWithValues: review.items.map { ($0.dn, $0) })
        #expect(byDN["CN=New User,OU=Sales,\(Self.base)"] == nil, "a plain add where expected is not listed")
        let admins = try #require(byDN["CN=Domain Admins,CN=Users,DC=corp,DC=example"])
        #expect(admins.outside && admins.verb == "Change")
        #expect(admins.warnings.contains { $0.contains("administrator rights") })
        #expect(admins.changes == ["add member: CN=New User,OU=Sales,\(Self.base)"])
        #expect(byDN["CN=Helpdesk,OU=Groups,\(Self.base)"]?.warnings.contains { $0.contains("administrator rights") } == true)
        let web = try #require(byDN["CN=Web,OU=Servers,\(Self.base)"])
        #expect(web.warnings.count == 2 && web.changes.count == 2 && !web.outside)
        #expect(byDN["CN=File,OU=Servers,\(Self.base)"]?.warnings.first?.contains("act as any user") == true)
        #expect(byDN["CN=File,OU=Servers,\(Self.base)"]?.changes.first?.contains("not shown") == true)
        #expect(byDN["CN=Old,OU=Sales,\(Self.base)"]?.verb == "Delete")
        #expect(byDN["CN=Elsewhere,OU=Other,DC=corp,DC=example"]?.outside == true)
        let mover = try #require(byDN["CN=Mover,OU=Sales,\(Self.base)"])
        #expect(mover.verb == "Move" && mover.outside && mover.newDN == "CN=Mover,CN=Users,DC=corp,DC=example")
        let password = try #require(byDN["CN=Pw,OU=Sales,\(Self.base)"])
        #expect(password.warnings.count == 2)
        #expect(!password.changes.joined().contains("IgBT") && !password.changes.joined().contains("Secret"))
        #expect(review.items.count == 8 && review.warnings == 7)
        // No container: only what is not a plain add, or sensitive.
        #expect(LDIFImportReview(records, container: nil, privilegedGroups: privileged).items.count == 7)
    }

    @Test func wellKnownAdministratorsGroups() {
        #expect(LDIFImportReview.privilegedGroup(dn: "CN=x,DC=a", sid: "S-1-5-21-1-2-3-512", adminCount: nil))
        #expect(LDIFImportReview.privilegedGroup(dn: "CN=x,DC=a", sid: "S-1-5-32-544", adminCount: 0))
        #expect(LDIFImportReview.privilegedGroup(dn: "CN=Enterprise Admins,CN=Users,DC=a", sid: nil, adminCount: nil))
        #expect(!LDIFImportReview.privilegedGroup(dn: "CN=Sales,DC=a", sid: "S-1-5-21-1-2-3-1105", adminCount: 0))
    }

    /// A DN or message with a line break stays on its record's line, and an
    /// earlier log beside the LDIF is not overwritten.
    @Test func theImportLogKeepsOneLinePerRecordAndEarlierLogs() {
        let record = LDIFRecord(dn: "CN=Evil\nline 9\tadd\tCN=Admin\tOK,DC=a", change: .delete, line: 3)
        let line = LDIFImportLog.line(record, ok: false, message: "refused\r\nline 10\tOK")
        #expect(line.filter { $0 == "\n" }.count == 1 && line.hasSuffix("\n"))
        #expect(line.split(separator: "\t").count == 5)
        #expect(line.contains("CN=Evil\\nline 9\\tadd"))
        let file = URL(fileURLWithPath: "/tmp/import/users.ldif")
        #expect(LDIFImportLog.url(beside: file) { _ in false }.lastPathComponent == "users.import-log.txt")
        let taken: Set<String> = ["users.import-log.txt", "users.import-log-2.txt"]
        #expect(LDIFImportLog.url(beside: file) { taken.contains($0.lastPathComponent) }.lastPathComponent == "users.import-log-3.txt")
    }
}
