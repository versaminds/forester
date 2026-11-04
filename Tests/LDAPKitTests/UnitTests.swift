// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import Testing
@testable import LDAPKit

private func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
private func bytes(_ hex: String) -> [UInt8] {
    var out: [UInt8] = []
    var chars = Array(hex.filter(\.isHexDigit))
    while chars.count >= 2 { out.append(UInt8(String(chars[0...1]), radix: 16)!); chars.removeFirst(2) }
    return out
}

@Suite struct BERTests {
    @Test(arguments: [
        (Int64(0), "00"), (127, "7f"), (128, "0080"), (255, "00ff"), (256, "0100"), (-1, "ff"),
        (-128, "80"), (-129, "ff7f"), (Int64.max, "7fffffffffffffff"), (Int64.min, "8000000000000000"),
    ])
    func integerContentIsMinimalTwosComplement(_ value: Int64, _ expected: String) throws {
        #expect(hex(BER.integerContent(value)) == expected)
        let element = BERElement(tag: 0x02, content: BER.integerContent(value))
        #expect(try element.integer() == value)
    }

    @Test(arguments: [(0, "00"), (127, "7f"), (128, "8180"), (255, "81ff"), (256, "820100"), (70000, "83011170")])
    func lengthsUseTheShortestForm(_ length: Int, _ expected: String) {
        #expect(hex(BER.length(length)) == expected)
    }

    @Test func partialElementReportsIncompleteRatherThanFailing() throws {
        let full = BER.octetString("hello world")
        for cut in 0..<full.count {
            #expect(try BERDecoder.element(in: Array(full.prefix(cut))) == nil)
        }
        let (element, next) = try #require(try BERDecoder.element(in: full))
        #expect(element.string == "hello world")
        #expect(next == full.count)
    }

    @Test func longLengthsDecode() throws {
        let payload = [UInt8](repeating: 0x41, count: 70000)
        let (element, _) = try #require(try BERDecoder.element(in: BER.octetString(payload)))
        #expect(element.content.count == 70000)
    }

    @Test func indefiniteLengthIsRejected() {
        #expect(throws: BERError.indefiniteLength) { try BERDecoder.element(in: [0x30, 0x80, 0x00, 0x00]) }
    }
}

@Suite struct FilterTests {
    @Test func simpleEqualityEncodesExactly() throws {
        #expect(hex(try LDAPFilter.parse("(cn=foo)").encoded) == "a3090402636e0403666f6f")
        #expect(hex(try LDAPFilter.parse("(objectClass=*)").encoded) == "870b6f626a656374436c617373")
    }

    // The examples from RFC 4515 §4, plus the forms people type.
    @Test(arguments: [
        "(cn=Babs Jensen)", "(!(cn=Tim Howes))", "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))",
        "(o=univ*of*mich*)", "(seeAlso=)", "(cn:caseExactMatch:=Fred Flintstone)", "(cn:=Betty Rubble)",
        "(sn:dn:2.4.6.8.10:=Barney Rubble)", "(o:dn:=Ace Industry)", "(:1.2.3:=Wilma Flintstone)",
        "(:DN:2.4.6.7:=Dino)", "(o=Parens R Us \\28for all your parenthetical needs\\29)", "(cn=*\\2A*)",
        "(filename=C:\\5cMyFile)", "(sn=Lu\\c4\\8di\\c4\\87)", "(1.3.6.1.4.1.1466.0=\\04\\02\\48\\69)",
        "(member:1.2.840.113556.1.4.1941:=CN=Jane,OU=Users,DC=corp,DC=example)",
        "(userAccountControl:1.2.840.113556.1.4.803:=2)", "(&)", "(lastLogonTimestamp<=133000000000000000)",
    ])
    func rfcExamplesParse(_ text: String) throws {
        let filter = try LDAPFilter.parse(text)
        // Rendering and re-parsing reaches the same filter.
        #expect(try LDAPFilter.parse(filter.description) == filter)
    }

    @Test func substringsSplitOnUnescapedStarsOnly() throws {
        #expect(try LDAPFilter.parse("(o=univ*of*mich*)") ==
                .substrings("o", initial: Array("univ".utf8), any: [Array("of".utf8), Array("mich".utf8)], final: nil))
        #expect(try LDAPFilter.parse("(cn=*\\2A*)") == .substrings("cn", initial: nil, any: [[0x2A]], final: nil))
        #expect(try LDAPFilter.parse("(cn=*smith)") == .substrings("cn", initial: nil, any: [], final: Array("smith".utf8)))
    }

    @Test func hexEscapesBecomeBytes() throws {
        #expect(try LDAPFilter.parse("(sn=Lu\\c4\\8di\\c4\\87)") == .equality("sn", Array("Lučić".utf8)))
    }

    @Test func extensibleMatchKeepsItsParts() throws {
        #expect(try LDAPFilter.parse("(sn:dn:2.4.6.8.10:=Barney Rubble)") ==
                .extensible(rule: "2.4.6.8.10", attribute: "sn", value: Array("Barney Rubble".utf8), dnAttributes: true))
        #expect(try LDAPFilter.parse("(:DN:2.4.6.7:=Dino)") ==
                .extensible(rule: "2.4.6.7", attribute: nil, value: Array("Dino".utf8), dnAttributes: true))
    }

    @Test func filterWithoutParenthesesAndWithSpacesIsAccepted() throws {
        #expect(try LDAPFilter.parse("cn=admin") == .equality("cn", "admin"))
        #expect(try LDAPFilter.parse("(& (a=b)\n  (c=d) )") == .and([.equality("a", "b"), .equality("c", "d")]))
    }

    @Test(arguments: [
        ("(cn=foo", "Missing ')'"), ("(&(a=b)", "Expected ')'"), ("(=foo)", "Missing attribute name"),
        ("(cn foo)", "operator"), ("(cn=a(b)", "Unescaped '('"), ("(cn=foo))", "Unexpected text"), ("", "empty"),
        ("(c n=x)", "not a valid attribute name"),
    ])
    func malformedFiltersExplainThemselves(_ text: String, _ fragment: String) {
        do {
            _ = try LDAPFilter.parse(text)
            Issue.record("\(text) parsed")
        } catch let error as LDAPFilterError {
            #expect(error.message.contains(fragment), "\(error.message)")
        } catch {
            Issue.record("unexpected \(error)")
        }
    }

    @Test func escapingProtectsSpecialCharactersAndBinary() {
        #expect(LDAPFilter.escape("a*b(c)d\\e") == "a\\2ab\\28c\\29d\\5ce")
        #expect(LDAPFilter.escape([0x01, 0x05, 0xFF]) == "\\01\\05\\ff")
    }
}

@Suite struct CodecTests {
    @Test func searchResponsesDecode() throws {
        let entry = BER.sequence([
            BER.integer(7),
            BER.sequence([
                BER.octetString("CN=Jane,DC=corp,DC=example"),
                BER.sequence([
                    BER.sequence([BER.octetString("cn"), BER.set([BER.octetString("Jane")])]),
                    BER.sequence([BER.octetString("member;range=0-1"), BER.set([BER.octetString("a"), BER.octetString("b")])]),
                ]),
            ], tag: 0x64),
        ])
        let response = try LDAPCodec.decodeResponse(try #require(try BERDecoder.element(in: entry)).element)
        #expect(response.messageID == 7)
        guard case .searchEntry(let decoded) = response.kind else { Issue.record("not an entry"); return }
        #expect(decoded.dn == "CN=Jane,DC=corp,DC=example")
        #expect(decoded.string("CN") == "Jane")
        #expect(decoded.strings("member") == ["a", "b"])
        #expect(!response.kind.isFinal)

        let control = LDAPControl.pagedResults(size: 0, cookie: [1, 2, 3])
        let done = BER.sequence([
            BER.integer(7),
            BER.sequence([BER.enumerated(4), BER.octetString(""), BER.octetString("limit")], tag: 0x65),
            BER.sequence([control.encoded], tag: 0xA0),
        ])
        let doneResponse = try LDAPCodec.decodeResponse(try #require(try BERDecoder.element(in: done)).element)
        guard case .searchDone(let result) = doneResponse.kind else { Issue.record("not done"); return }
        #expect(result.code == .sizeLimitExceeded)
        #expect(result.diagnosticMessage == "limit")
        #expect(doneResponse.controls.first?.pagedResultsCookie == [1, 2, 3])
    }

    @Test func rangedAttributeNamesParse() throws {
        let first = try #require(RangedAttribute("member;range=0-1499"))
        #expect(first.base == "member" && first.start == 0 && first.end == 1499)
        let last = try #require(RangedAttribute("member;Range=1500-*"))
        #expect(last.end == nil)
        #expect(RangedAttribute("member") == nil)
    }
}

@Suite struct ADValueTests {
    @Test func sidRoundTrips() throws {
        let sid = "S-1-5-21-1004336348-1177238915-682003330-512"
        let data = try #require(ADValues.sidData(sid))
        #expect(ADValues.sidString(data) == sid)
        #expect(ADValues.wellKnownName(sid) == "Domain Admins")
        #expect(ADValues.wellKnownName("S-1-5-32-544") == "Administrators")
        #expect(ADValues.rid(sid) == 512)
        #expect(ADValues.sidString(Data([1, 2, 3])) == nil)
    }

    @Test func guidUsesADByteOrder() throws {
        // Python: uuid.UUID('6ac1786c-016f-11d2-945f-00c04fb984f9').bytes_le
        let stored = Data(bytes("6c78c16a6f01d211945f00c04fb984f9"))
        #expect(ADValues.guidString(stored) == "6ac1786c-016f-11d2-945f-00c04fb984f9")
        #expect(ADValues.guidData("{6AC1786C-016F-11D2-945F-00C04FB984F9}") == stored)
    }

    @Test func fileTimes() {
        #expect(ADValues.fileTime(116_444_736_000_000_000) == .date(Date(timeIntervalSince1970: 0)))
        #expect(ADValues.fileTime(133_000_000_000_000_000) == .date(Date(timeIntervalSince1970: 1_655_526_400)))
        #expect(ADValues.fileTime(0) == .zero)
        #expect(ADValues.fileTime(Int64.max) == .never)
        #expect(ADValues.fileTimeValue(Date(timeIntervalSince1970: 0)) == 116_444_736_000_000_000)
        #expect(ADValues.interval(-36_288_000_000_000) == TimeInterval(42 * 86400))
    }

    @Test(arguments: [
        ("20240115093000.0Z", 1_705_311_000.0), ("20240115093000Z", 1_705_311_000), ("202401150930Z", 1_705_311_000),
        ("20240115103000+0100", 1_705_311_000), ("20240115093000.5Z", 1_705_311_000.5),
    ])
    func generalizedTimes(_ text: String, _ epoch: Double) throws {
        let date = try #require(ADValues.generalizedTime(text))
        #expect(abs(date.timeIntervalSince1970 - epoch) < 0.001)
    }

    @Test func flagWords() {
        #expect(ADValues.flags(66048, in: ADValues.userAccountControlFlags).map(\.name) == ["NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWORD"])
        #expect(ADValues.groupTypeDescription(-2147483646) == "Global security group")
        #expect(ADValues.groupTypeDescription(-2147483643) == "Builtin local security group")
        #expect(ADValues.groupTypeDescription(8) == "Universal distribution group")
        #expect(ADValues.samAccountTypeDescription(805306369) == "Computer account")
    }

    @Test func adBindDiagnosticsAreExplained() {
        let diag = "80090308: LdapErr: DSID-0C090447, comment: AcceptSecurityContext error, data 775, v4563"
        #expect(ADBindError.explain(diag) == "The account is locked out. (AD code 775)")
        #expect(ADBindError.explain("no data here") == nil)
        let error = LDAPError.server(LDAPResult(code: .invalidCredentials, diagnosticMessage: diag), operation: "Bind")
        #expect(error.errorDescription?.contains("locked out") == true)
    }

    @Test func strongerAuthRequiredNamesTheRightFix() {
        let anonymous = LDAPError.server(LDAPResult(code: .strongerAuthRequired, diagnosticMessage: "modifications require authentication"),
                                         operation: "Modify").errorDescription ?? ""
        #expect(anonymous == "Modify failed: Stronger authentication required (8). Modifications require authentication. Connect with a name and password to make changes.")
        let unsigned = LDAPError.server(LDAPResult(code: .strongerAuthRequired,
                                                   diagnosticMessage: "00002028: LdapErr: DSID-0C090256, comment: The server requires binds to turn on integrity checking if SSL\\TLS are not already active on the connection, data 0, v4563"),
                                        operation: "Bind").errorDescription ?? ""
        #expect(unsigned.hasSuffix("use StartTLS or LDAPS."))
    }
}

@Suite struct DNTests {
    @Test func escapedCommasDoNotSplit() {
        let dn = "CN=Smith\\, John,OU=Sales,DC=corp,DC=example"
        #expect(DN.components(dn) == ["CN=Smith\\, John", "OU=Sales", "DC=corp", "DC=example"])
        #expect(DN.rdnValue(dn) == "Smith, John")
        #expect(DN.parent(dn) == "OU=Sales,DC=corp,DC=example")
        #expect(DN.components("CN=\"Doe, Jane\",DC=x") == ["CN=\"Doe, Jane\"", "DC=x"])
        #expect(DN.rdnValue("CN=\"Doe, Jane\",DC=x") == "Doe, Jane")
    }

    @Test func hexEscapesDecodeAsUTF8() {
        #expect(DN.rdnValue("CN=Lu\\C4\\8Di\\C4\\87,DC=x") == "Lučić")
        #expect(DN.escape(" #a,b+c ") == "\\ #a\\,b\\+c\\ ")
        #expect(DN.escape("#a") == "\\#a")
    }

    @Test func comparisonIgnoresCaseSpacingAndEscapeStyle() {
        #expect(DN.isSame("cn=Jane Doe, ou=Users,dc=Corp", "CN=jane doe,OU=users,DC=corp"))
        #expect(DN.isSame("CN=a\\,b,DC=x", "cn=a\\2cb,dc=x"))
        #expect(DN.isWithin("CN=x,OU=a,DC=corp", "dc=CORP"))
        #expect(!DN.isWithin("DC=corp", "OU=a,DC=corp"))
    }

    @Test func pathRunsFromRootToParent() {
        #expect(DN.path(from: "DC=c,DC=d", to: "CN=x,OU=a,OU=b,DC=c,DC=d") == ["DC=c,DC=d", "OU=b,DC=c,DC=d", "OU=a,OU=b,DC=c,DC=d"])
        #expect(DN.path(from: "DC=c,DC=d", to: "CN=x,DC=other") == [])
    }

    @Test func canonicalNameAndDomain() {
        #expect(DN.canonicalName("CN=Jane,OU=Users,OU=Corp,DC=corp,DC=example") == "corp.example/Corp/Users/Jane")
        #expect(DN.dnsDomain("OU=x,DC=corp,DC=example") == "corp.example")
    }

    @Test func dnDetectionIsConservative() {
        #expect(DN.looksLikeDN("CN=Jane,OU=Users,DC=corp,DC=example"))
        #expect(DN.looksLikeDN("uid=ada,ou=people,dc=example,dc=org"))
        #expect(!DN.looksLikeDN("Set timeout=30, retries=5"))
        #expect(!DN.looksLikeDN("CN=only-one"))
    }
}

@Suite struct LDIFTests {
    @Test func unsafeValuesAreBase64AndLongLinesFold() {
        let entry = LDAPEntry(dn: "CN=Jane,DC=x", attributes: [
            LDAPAttribute(name: "cn", values: [Data("Jane".utf8)]),
            LDAPAttribute(name: "description", values: [Data(" leading space".utf8), Data("Lučić".utf8)]),
            LDAPAttribute(name: "objectSid", values: [Data([1, 5, 0, 0])]),
            LDAPAttribute(name: "info", values: [Data(String(repeating: "x", count: 100).utf8)]),
        ])
        let text = LDIF.entry(entry)
        #expect(text.contains("cn: Jane\n"))
        #expect(text.contains("description:: IGxlYWRpbmcgc3BhY2U=\n"))
        #expect(text.contains("description:: THXEjWnEhw==\n"))
        #expect(text.contains("objectSid:: AQUAAA==\n"))
        let lines = text.split(separator: "\n")
        #expect(lines.allSatisfy { $0.utf8.count <= 76 })
        #expect(lines.contains { $0.hasPrefix(" x") })
    }
}

@Suite struct FormatterTests {
    let now = Date(timeIntervalSince1970: 1_760_000_000)

    @Test func adValuesAreDecoded() throws {
        let sid = try #require(ADValues.sidData("S-1-5-32-544"))
        #expect(AttributeFormatter.format("objectSid", sid).text == "S-1-5-32-544  (Administrators)")
        #expect(AttributeFormatter.format("pwdLastSet", Data("0".utf8), now: now).text == "Must change at next sign-in")
        #expect(AttributeFormatter.format("accountExpires", Data("9223372036854775807".utf8)).text == "Never")
        #expect(AttributeFormatter.format("userAccountControl", Data("514".utf8)).text == "Account disabled, Normal account")
        #expect(AttributeFormatter.format("maxPwdAge", Data("-36288000000000".utf8)).text == "42 days")
        #expect(AttributeFormatter.format("pwdProperties", Data("1".utf8)).text == "Complexity required")
        #expect(AttributeFormatter.format("pwdProperties", Data("17".utf8)).text == "Complexity required, Reversible encryption")
        #expect(AttributeFormatter.format("whenCreated", Data("20240115093000.0Z".utf8), now: now).kind == .generalizedTime)
    }

    @Test func distinguishedNamesBecomeLinks() {
        let value = AttributeFormatter.format("manager", Data("CN=Boss,OU=Users,DC=corp,DC=example".utf8))
        #expect(value.kind == .distinguishedName)
        #expect(value.links == ["CN=Boss,OU=Users,DC=corp,DC=example"])
        let binary = AttributeFormatter.format("wellKnownObjects", Data("B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=corp,DC=example".utf8))
        #expect(binary.links == ["CN=Users,DC=corp,DC=example"])
        #expect(AttributeFormatter.format("description", Data("Plain words".utf8)).kind == .text)
    }

    @Test func gpLinksListTheirPolicies() {
        let links = AttributeFormatter.gpLinks("[LDAP://cn={A},cn=policies,cn=system,DC=x;0][LDAP://CN={B},CN=Policies,CN=System,DC=x;2]")
        #expect(links.map(\.dn) == ["cn={A},cn=policies,cn=system,DC=x", "CN={B},CN=Policies,CN=System,DC=x"])
        #expect(links.map(\.options) == ["", " (enforced)"])
    }

    @Test func binaryIsSummarisedNotPrinted() {
        let value = AttributeFormatter.format("logonHours", Data([0xFF, 0x00, 0x01]))
        #expect(value.kind == .binary)
        #expect(value.text.hasSuffix("ff 00 01"))
        let png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        #expect(AttributeFormatter.format("thumbnailPhoto", png).kind == .image)
    }
}
