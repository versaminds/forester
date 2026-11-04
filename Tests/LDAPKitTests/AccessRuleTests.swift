// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import Testing
@testable import LDAPKit

/// Access control entries read as an administrator would say them.
@Suite struct AccessRuleTests {
    typealias ACE = SecurityDescriptor.ACE
    static let user = UUID(uuidString: "bf967aba-0de6-11d0-a285-00aa003049e2")!
    static let personalInformation = UUID(uuidString: "77b5b886-944a-11d1-aebd-0000f80367c1")!
    static let names: [String: SchemaGUIDName] = [
        user.uuidString.lowercased(): SchemaGUIDName(name: "user", kind: .objectClass),
        personalInformation.uuidString.lowercased(): SchemaGUIDName(name: "Personal Information", kind: .propertySet),
    ]

    static func ace(_ type: UInt8 = ACE.accessAllowed, flags: UInt8 = 0, mask: UInt32, object: UUID? = nil, inherited: UUID? = nil) -> ACE {
        ACE(type: object == nil && inherited == nil ? type : (type == ACE.accessDenied ? ACE.accessDeniedObject : ACE.accessAllowedObject),
            flags: flags, mask: mask, objectType: object, inheritedObjectType: inherited, sid: "S-1-5-11")
    }

    static func describe(_ ace: ACE) -> AccessRule { AccessRules.describe(ace) { names[$0] } }

    @Test func fullControlAndReading() {
        #expect(Self.describe(Self.ace(mask: 0xF01FF)).access == ["Full control"])
        #expect(Self.describe(Self.ace(mask: 0xF01FF)).isWrite)
        let read = Self.describe(Self.ace(mask: 0x20094))
        #expect(read.access == ["Read"])
        #expect(!read.isWrite)
        #expect(read.appliesTo == "This object only")
    }

    @Test func genericRightsAndUnreadKindsAreNotTakenForReading() {
        let generic = Self.describe(Self.ace(mask: 0x1000_0000))
        #expect(generic.access == ["Full control (generic)"])
        #expect(generic.isWrite)
        // A callback entry (type 0x09), which this code does not model: never
        // shown as an allow, and counted among the rules that grant more.
        let callback = Self.describe(ACE(type: 0x09, flags: 0, mask: 0xF01FF, sid: "", raw: Data([0x09, 0, 8, 0, 0, 0, 0, 0])))
        #expect(!callback.understood && !callback.allow && callback.isWrite)
        #expect(callback.access.first?.contains("does not read") == true)
    }

    @Test func namedRightsAndProperties() {
        let reset = Self.describe(Self.ace(mask: 0x100, object: UUID(uuidString: "00299570-246d-11d0-a768-00aa006e0529")))
        #expect(reset.access == ["Reset Password"])
        #expect(reset.isWrite)
        let personal = Self.describe(Self.ace(mask: 0x30, object: Self.personalInformation))
        #expect(personal.access == ["Read and write Personal Information (property set)"])
        let member = Self.describe(Self.ace(mask: 0x20, object: UUID(uuidString: "bf9679c0-0de6-11d0-a285-00aa003049e2")))
        #expect(member.access == ["Write member"])
        let create = Self.describe(Self.ace(mask: 0x3, object: Self.user))
        #expect(create.access == ["Create user objects", "Delete user objects"])
        let confidential = Self.describe(Self.ace(mask: 0x130, object: Self.personalInformation))
        #expect(confidential.access == ["Read and write Personal Information (property set)", "Read confidential Personal Information"])
        let unknown = UUID()
        #expect(Self.describe(Self.ace(mask: 0x100, object: unknown)).access == [unknown.uuidString.lowercased()])
    }

    @Test func whereARuleApplies() {
        #expect(Self.describe(Self.ace(flags: 0x2, mask: 0x20094)).appliesTo == "This object and all descendant objects")
        #expect(Self.describe(Self.ace(flags: 0xA, mask: 0x20094)).appliesTo == "All descendant objects")
        #expect(Self.describe(Self.ace(flags: 0xA, mask: 0x100, object: nil, inherited: Self.user)).appliesTo == "Descendant user objects")
        #expect(Self.describe(Self.ace(flags: 0x6, mask: 0x20094)).appliesTo == "This object and all descendant objects, one level down only")
        let inherited = Self.describe(Self.ace(flags: 0x12, mask: 0x20094))
        #expect(inherited.inherited)
    }

    @Test func denialsAndLeftovers() {
        let deny = Self.describe(Self.ace(ACE.accessDenied, mask: 0x1_0000))
        #expect(!deny.allow)
        #expect(deny.access == ["Delete"])
        #expect(Self.describe(Self.ace(mask: 0x4_0000 | 0x8_0000)).access == ["Modify permissions", "Modify owner"])
        #expect(Self.describe(Self.ace(mask: 0x2000_0000)).access == ["Other rights (0x20000000)"])
        #expect(Self.describe(Self.ace(mask: 0)).access == ["Nothing"])
    }

    /// The rules of a real DACL keep its order: the order AD evaluates them in.
    @Test func aDACLInOrder() {
        let acl = SecurityDescriptor.ACL(revision: 4, aces: [
            Self.ace(ACE.accessDenied, mask: 0x100, object: UUID(uuidString: "ab721a53-1e2f-11d0-9819-00aa0040529b")),
            Self.ace(mask: 0x20094),
            Self.ace(flags: 0x12, mask: 0xF01FF),
        ])
        let rules = AccessRules.describe(acl) { Self.names[$0] }
        #expect(rules.map(\.id) == [0, 1, 2])
        #expect(rules.map(\.allow) == [false, true, true])
        #expect(rules[0].access == ["Change Password"])
    }
}
