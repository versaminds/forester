// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import Testing
@testable import LDAPKit

/// Defects found by reviewing the code, each pinned by the case that showed it.
@Suite struct RegressionTests {
    @Test func escapedTrailingSpaceStaysInTheValue() {
        // AD allows a value ending in a space; RFC 4514 escapes it.
        let dn = "CN=Name\\ ,OU=Sales\\ ,DC=corp"
        #expect(DN.components(dn) == ["CN=Name\\ ", "OU=Sales\\ ", "DC=corp"])
        #expect(DN.rdnValue(dn) == "Name ")
        #expect(DN.parent(dn) == "OU=Sales\\ ,DC=corp")
        #expect(DN.path(from: "DC=corp", to: dn) == ["DC=corp", "OU=Sales\\ ,DC=corp"])
        // Unescaped spaces around separators are still dropped.
        #expect(DN.components("CN=a , OU=b") == ["CN=a", "OU=b"])
    }

    @Test func comparisonFormKeepsEscapedCommas() {
        // "OU=b\, OU=c" is one RDN whose value contains a comma, not two RDNs.
        #expect(!DN.isWithin("CN=foo,OU=b\\, OU=c,DC=x", "OU=c,DC=x"))
        #expect(DN.isWithin("CN=foo,OU=b\\, OU=c,DC=x", "OU=b\\, OU=c,DC=x"))
        #expect(DN.isSame("CN=Smith\\, John,DC=x", "cn=smith\\2C john,dc=x"))
        #expect(DN.isSame("CN=\"Smith, John\",DC=x", "CN=Smith\\, John,DC=x"))
    }

    @Test func olderFilterEscapesAreAccepted() throws {
        #expect(try LDAPFilter.parse("(cn=a\\*b)") == .equality("cn", Array("a*b".utf8)))
        #expect(try LDAPFilter.parse("(cn=f\\(x\\))") == .equality("cn", Array("f(x)".utf8)))
        #expect(try LDAPFilter.parse("(cn=a\\**)") == .substrings("cn", initial: Array("a*".utf8), any: [], final: nil))
        #expect(try LDAPFilter.parse("(cn=a\\2a*)") == .substrings("cn", initial: Array("a*".utf8), any: [], final: nil))
    }

    @Test func pastedDNKeepsItsEscapes() throws {
        let filter = try LDAPFilter.parse("(manager=CN=Smith\\, John,OU=Users,DC=corp)")
        #expect(filter == .equality("manager", Array("CN=Smith\\, John,OU=Users,DC=corp".utf8)))
    }

    @Test func textStartingWithBMIsNotAnImage() {
        let text = Data("BMC Software monitoring agent service account, created for the nightly checks".utf8)
        #expect(AttributeFormatter.imageType(text) == nil)
        #expect(AttributeFormatter.format("description", text).text.hasPrefix("BMC Software"))
        // A real BMP header: "BM", the file size, two reserved zero words.
        var bmp: [UInt8] = [0x42, 0x4D]
        let size = 70
        bmp += [UInt8(size), 0, 0, 0, 0, 0, 0, 0]
        bmp += [UInt8](repeating: 1, count: size - bmp.count)
        #expect(AttributeFormatter.imageType(Data(bmp)) == "BMP")
    }

    @Test func truncatedObjectACEIsAnErrorNotACrash() {
        // Revision 1, DACL present at offset 20; one object ACE of size 8.
        var b: [UInt8] = [1, 0, 0x04, 0x80]
        b += [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] // owner, group, SACL offsets
        b += [20, 0, 0, 0] // DACL offset
        b += [4, 0, 16, 0, 1, 0, 0, 0] // ACL: revision 4, size 16, one ACE
        b += [0x05, 0, 8, 0, 0, 1, 0, 0] // object ACE claiming 8 bytes
        #expect(throws: (any Error).self) { try SecurityDescriptor(data: Data(b)) }
    }

    @Test func generalizedTimeWithAnOffsetAndNoSeconds() {
        let date = ADValues.generalizedTime("202401150930+0100")
        #expect(date == ISO8601DateFormatter().date(from: "2024-01-15T08:30:00Z"))
        #expect(ADValues.generalizedTime("20240115093000Z") == ISO8601DateFormatter().date(from: "2024-01-15T09:30:00Z"))
    }
}
