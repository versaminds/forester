// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import Testing
@testable import LDAPKit

/// Everything a server, a file or a person can hand the parsers, at random:
/// garbage, and valid input corrupted (bits flipped, bytes cut, lengths made
/// absurd). The parsers must answer or throw; a crash would let a broken or
/// hostile server take the app down. And round trips: whatever is escaped into
/// a DN or a filter, or exported as LDIF, comes back exactly as it went in.
/// FORESTER_FUZZ=<iterations> runs more (the default is quick).
@Suite struct FuzzTests {
    static let iterations = ProcessInfo.processInfo.environment["FORESTER_FUZZ"].flatMap(Int.init) ?? 3_000

    /// SplitMix64: the same sequence every run, so a failure can be reproduced.
    struct Random: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
        mutating func bytes(_ count: Int) -> [UInt8] { (0..<count).map { _ in UInt8.random(in: 0...255, using: &self) } }
        mutating func string(_ count: Int, from alphabet: [Character]) -> String {
            String((0..<count).map { _ in alphabet.randomElement(using: &self)! })
        }
    }

    /// Valid input with damage done to it.
    static func mutate(_ input: [UInt8], _ random: inout Random) -> [UInt8] {
        var bytes = input
        for _ in 0..<Int.random(in: 1...4, using: &random) {
            guard !bytes.isEmpty else { return random.bytes(Int.random(in: 0...32, using: &random)) }
            let at = Int.random(in: 0..<bytes.count, using: &random)
            switch Int.random(in: 0..<6, using: &random) {
            case 0: bytes[at] ^= UInt8(1 << Int.random(in: 0..<8, using: &random))
            case 1: bytes[at] = UInt8.random(in: 0...255, using: &random)
            case 2: bytes.removeSubrange(at..<min(bytes.count, at + Int.random(in: 1...8, using: &random)))
            case 3: bytes.insert(contentsOf: random.bytes(Int.random(in: 1...8, using: &random)), at: at)
            case 4: bytes = Array(bytes.prefix(at))
            default: bytes.replaceSubrange(at..<at + 1, with: [0x84, 0xFF, 0xFF, 0xFF, 0xFF].shuffled(using: &random))
            }
        }
        return bytes
    }

    /// Server answers as they arrive on the wire.
    static let responses: [[UInt8]] = {
        let entry = BER.sequence([BER.integer(7), BER.sequence([
            BER.octetString("CN=Pieter Van Damme,OU=Users,DC=corp,DC=example"),
            BER.sequence([
                BER.sequence([BER.octetString("objectClass"), BER.set([BER.octetString("top"), BER.octetString("user")])]),
                BER.sequence([BER.octetString("member;range=0-1499"), BER.set([BER.octetString("CN=a,DC=x"), BER.octetString("CN=b,DC=x")])]),
                BER.sequence([BER.octetString("objectSid"), BER.set([BER.octetString([1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xF4, 1, 0, 0])])]),
            ]),
        ], tag: 0x64)])
        let done = BER.sequence([BER.integer(7),
                                 BER.sequence([BER.enumerated(0), BER.octetString(""), BER.octetString("")], tag: 0x65),
                                 BER.sequence([BER.sequence([BER.octetString("1.2.840.113556.1.4.319"),
                                                             BER.octetString(BER.sequence([BER.integer(0), BER.octetString([1, 2, 3])]))])], tag: 0xA0)])
        let bind = BER.sequence([BER.integer(1), BER.sequence([BER.enumerated(49), BER.octetString(""),
                                                               BER.octetString("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563")], tag: 0x61)])
        let referral = BER.sequence([BER.integer(3), BER.sequence([BER.octetString("ldap://other.example/DC=other,DC=example")], tag: 0x73)])
        let extended = BER.sequence([BER.integer(0), BER.sequence([BER.enumerated(2), BER.octetString(""), BER.octetString("unsupported"),
                                                                  BER.octetString("1.3.6.1.4.1.1466.20036", tag: 0x8A)], tag: 0x78)])
        return [entry, done, bind, referral, extended]
    }()

    static func walk(_ element: BERElement, depth: Int = 0) {
        _ = try? element.integer()
        _ = try? element.int()
        guard depth < 64, element.tag & 0x20 != 0, let children = try? element.children() else { return }
        for child in children { walk(child, depth: depth + 1) }
    }

    @Test func serverResponsesNeverCrash() {
        var random = Random(state: 1)
        for i in 0..<Self.iterations * 4 {
            let input = i % 5 == 0 ? random.bytes(Int.random(in: 0...96, using: &random))
                                   : Self.mutate(Self.responses[i % Self.responses.count], &random)
            guard let elements = try? BERDecoder.elements(in: input) else { continue }
            for element in elements {
                Self.walk(element)
                _ = try? LDAPCodec.decodeResponse(element)
            }
        }
    }

    @Test func filtersNeverCrashAndEscapingRoundTrips() {
        var random = Random(state: 2)
        let alphabet = Array("()&|!=~<>*:\\ ab0Z9-.,é\u{0}\n")
        let samples = ["(&(objectClass=user)(sAMAccountName=bulk*))", "(member:1.2.840.113556.1.4.1941:=CN=x\\2c y,DC=z)",
                       "(|(cn=*a*b*)(!(mail=*)))", "(userAccountControl:1.2.840.113556.1.4.803:=2)", "(cn=a\\2a\\28\\29)"]
        for i in 0..<Self.iterations * 2 {
            let text = i % 2 == 0 ? random.string(Int.random(in: 0...40, using: &random), from: alphabet)
                                  : String(decoding: Self.mutate(Array(samples[i % samples.count].utf8), &random), as: UTF8.self)
            if let filter = try? LDAPFilter.parse(text) { _ = filter.encoded }
            // Any value, escaped, is matched as exactly itself.
            let value = random.string(Int.random(in: 0...16, using: &random), from: alphabet)
            #expect((try? LDAPFilter.parse("(cn=\(LDAPFilter.escape(value)))")) == .equality("cn", Array(value.utf8)))
        }
    }

    @Test func distinguishedNamesNeverCrashAndEscapingRoundTrips() {
        var random = Random(state: 3)
        let alphabet = Array("=,+;\\\"<># ab0Z-é\u{0}")
        for _ in 0..<Self.iterations * 2 {
            let text = random.string(Int.random(in: 0...40, using: &random), from: alphabet)
            _ = DN.components(text); _ = DN.parent(text); _ = DN.rdnValue(text); _ = DN.rdnAttribute(text)
            _ = DN.normalized(text); _ = DN.canonicalName(text); _ = DN.dnsDomain(text); _ = DN.isMultiValued(rdn: text)
            _ = DN.isWithin(text, "DC=corp,DC=example"); _ = DN.path(from: "DC=corp", to: text); _ = DN.unescape(text)
            // Any name, escaped into an RDN, comes back as exactly itself, one level below its parent.
            let name = random.string(Int.random(in: 1...16, using: &random), from: alphabet)
            let dn = "CN=\(DN.escape(name)),OU=Users,DC=corp,DC=example"
            #expect(DN.rdnValue(dn) == name)
            #expect(DN.parent(dn) == "OU=Users,DC=corp,DC=example")
        }
    }

    @Test func ldifNeverCrashesAndExportRoundTrips() {
        var random = Random(state: 4)
        let sample = Array("""
            version: 1
            dn: CN=Ada,OU=Imported,DC=corp,DC=example
            changetype: modify
            replace: description
            description:: SW1wb3J0ZWQ=
            -
            add: member
            member: CN=x,DC=y
            -

            dn: CN=Old,DC=corp,DC=example
            changetype: modrdn
            newrdn: CN=New
            deleteoldrdn: 1
            newsuperior: OU=Other,DC=corp,DC=example

            """.utf8)
        for i in 0..<Self.iterations {
            let text = String(decoding: i % 4 == 0 ? random.bytes(Int.random(in: 0...120, using: &random)) : Self.mutate(sample, &random),
                              as: UTF8.self)
            _ = try? LDIFParser.parse(text)
            // A value of any bytes, exported, reads back as itself, and as one record.
            let value = Data(random.bytes(Int.random(in: 0...24, using: &random)))
            let printable = String(decoding: random.bytes(Int.random(in: 0...24, using: &random)).map { 32 + $0 % 95 }, as: UTF8.self)
            let entry = LDAPEntry(dn: "CN=Fuzz \(i),DC=corp,DC=example", attributes: [
                LDAPAttribute(name: "description", values: [value, Data((printable + "\n-\ndn: CN=Injected").utf8), Data((" :<" + printable).utf8)]),
            ])
            let records = try? LDIFParser.parse(LDIF.entry(entry))
            #expect(records?.count == 1)
            if case .add(let attributes)? = records?.first?.change {
                #expect(attributes.first?.values == entry.attributes.first?.values)
            } else {
                Issue.record("the exported entry did not read back as one add")
            }
        }
    }

    @Test func binaryValuesNeverCrash() {
        var random = Random(state: 5)
        let names = ["objectSid", "objectGUID", "nTSecurityDescriptor", "thumbnailPhoto", "jpegPhoto", "userCertificate",
                     "msExchMailboxGuid", "userAccountControl", "groupType", "accountExpires", "lastLogonTimestamp", "pwdLastSet",
                     "whenCreated", "gPLink", "logonHours", "msDS-ReplAttributeMetaData", "description", "maxPwdAge", "objectClass"]
        let sid: [UInt8] = [1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xF4, 1, 0, 0]
        for i in 0..<Self.iterations * 2 {
            let bytes = i % 2 == 0 ? random.bytes(Int.random(in: 0...80, using: &random)) : Self.mutate(sid, &random)
            let data = Data(bytes)
            for name in names { _ = AttributeFormatter.format(name, data) }
            _ = ADValues.sidString(data); _ = ADValues.guidString(data)
            if let sd = try? SecurityDescriptor(data: data) {
                var copy = sd
                copy.setUserCannotChangePassword(true)
                #expect((try? SecurityDescriptor(data: copy.encoded()))?.userCannotChangePassword == true)
            }
            let text = String(decoding: bytes, as: UTF8.self)
            _ = ADValues.generalizedTime(text); _ = ADValues.sidData(text); _ = ADValues.guidData(text)
            _ = AttributeFormatter.gpLinks(text); _ = LDAPURL(text)
            _ = ReplicationMetadata.parse([text]); _ = ValueReplicationMetadata.parse([text])
        }
    }

    @Test func schemaAndRootDSENeverCrash() {
        var random = Random(state: 6)
        let samples = ["( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )",
                       "( 2.5.6.0 NAME 'top' ABSTRACT MUST ( objectClass $ objectCategory ) MAY ( cn $ description ) )",
                       "( 1.2.840.113556.1.5.9 NAME 'user' SUP organizationalPerson STRUCTURAL MAY ( unicodePwd $ thumbnailPhoto ) )"]
        for i in 0..<Self.iterations {
            let text = String(decoding: Self.mutate(Array(samples[i % samples.count].utf8), &random), as: UTF8.self)
            let entry = LDAPEntry(dn: "CN=Aggregate", attributes: [
                LDAPAttribute(name: "attributeTypes", values: [Data(text.utf8)]),
                LDAPAttribute(name: "objectClasses", values: [Data(text.utf8)]),
                LDAPAttribute(name: "supportedCapabilities", values: [Data(text.utf8)]),
                LDAPAttribute(name: "namingContexts", values: [Data(text.utf8)]),
            ])
            let schema = LDAPSchema(subschema: entry)
            _ = schema.allowedAttributes(for: ["top", "user", text])
            _ = ServerInfo(rootDSE: entry)
        }
    }
}
