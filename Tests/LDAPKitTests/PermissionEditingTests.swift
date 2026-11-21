// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import Testing
@testable import LDAPKit

/// Changing permissions without a server: where a rule goes, what is
/// refused, the rule editor's drafts, and, over thousands of random access
/// lists and changes, that inherited rules never move and every change
/// undone gives back the very bytes it started from.
@Suite struct PermissionEditingTests {
    typealias ACE = SecurityDescriptor.ACE
    static let user = "S-1-5-21-1-2-3-1105", admins = "S-1-5-21-1-2-3-512", everyone = "S-1-1-0"
    static let description = UUID(uuidString: "bf967950-0de6-11d0-a285-00aa003049e2")!

    static func ace(_ type: UInt8, _ flags: UInt8 = 0, _ mask: UInt32 = 0x20094, _ sid: String = user, object: UUID? = nil) -> ACE {
        ACE(type: type, flags: flags, mask: mask, objectType: object, sid: sid)
    }

    /// Owner, group and a DACL of explicit denials, allowances and inherited
    /// rules, laid out as AD lays it out, from its bytes.
    static func descriptor(_ aces: [ACE]) throws -> SecurityDescriptor {
        var sd = try SecurityDescriptor(data: Data([1, 0, 0x04, 0x94, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 4, 0, 8, 0, 0, 0, 0, 0]))
        sd.dacl?.aces = aces
        sd.owner = admins
        sd.group = admins
        return try SecurityDescriptor(data: sd.encoded())
    }

    static let inherited = ace(ACE.accessAllowed, 0x12, 0x20094, "S-1-5-32-554")
    static let base = [ace(ACE.accessDenied, 0, 0x40000, everyone), ace(ACE.accessAllowed, 0, 0xF01FF, admins), inherited]

    @Test func rulesGoWhereWindowsPutsThem() throws {
        var sd = try Self.descriptor(Self.base)
        let deny = Self.ace(ACE.accessDeniedObject, 0, 0x20, object: Self.description)
        let allow = Self.ace(ACE.accessAllowed)
        try sd.apply(.add(allow))
        try sd.apply(.add(deny))
        #expect(sd.dacl?.aces == [Self.base[0], deny, Self.base[1], allow, Self.inherited])
        // A denial turned into an allowance stands where it was when that is
        // among the allowances, here the first of them.
        let allowed = Self.ace(ACE.accessAllowedObject, 0, 0x20, object: Self.description)
        try sd.apply(.replace(deny, with: allowed, at: 1))
        #expect(sd.dacl?.aces == [Self.base[0], allowed, Self.base[1], allow, Self.inherited])
        // An allowance turned into a denial moves after the denials.
        let denied = Self.ace(ACE.accessDenied)
        try sd.apply(.replace(allow, with: denied, at: 3))
        #expect(sd.dacl?.aces == [Self.base[0], denied, allowed, Self.base[1], Self.inherited])
        try sd.apply(PermissionChange.replace(allow, with: denied, at: 3).inverse)
        #expect(sd.dacl?.aces == [Self.base[0], allowed, Self.base[1], allow, Self.inherited])
        #expect(sd.dacl?.revision == 4)
    }

    @Test func whatIsRefused() throws {
        var sd = try Self.descriptor(Self.base)
        #expect(throws: PermissionEditError.inherited) { try sd.apply(.remove(Self.inherited)) }
        #expect(throws: PermissionEditError.inherited) { try sd.apply(.replace(Self.inherited, with: Self.ace(ACE.accessAllowed))) }
        #expect(throws: PermissionEditError.inherited) { try sd.apply(.add(Self.ace(ACE.accessAllowed, 0x12))) }
        #expect(throws: PermissionEditError.notFound) { try sd.apply(.remove(Self.ace(ACE.accessAllowed, 0, 0x1))) }
        #expect(throws: PermissionEditError.ownerChangedSince) { try sd.apply(.owner(from: Self.user, to: Self.everyone)) }
        for invalid in [Self.ace(ACE.accessAllowed, 0, 0), Self.ace(ACE.accessAllowed, 0x08), Self.ace(ACE.accessAllowed, 0x04),
                        Self.ace(ACE.accessAllowed, 0x40), Self.ace(ACE.accessAllowed, 0, 0x20, "not a SID"), Self.ace(0x02),
                        Self.ace(ACE.accessAllowed, 0, 0x20, object: Self.description), Self.ace(ACE.accessAllowedObject)] {
            #expect(throws: PermissionEditError.self, "\(invalid)") { try sd.apply(.add(invalid)) }
        }
        var single = try Self.descriptor([Self.base[1]])
        #expect(throws: PermissionEditError.emptyAccessList) { try single.apply(.remove(Self.base[1])) }
        // An allowance before a denial: nothing is added, but a rule may go.
        var disordered = try Self.descriptor([Self.base[1], Self.base[0], Self.inherited])
        #expect(throws: PermissionEditError.notCanonical) { try disordered.apply(.add(Self.ace(ACE.accessAllowed))) }
        try disordered.apply(.remove(Self.base[0]))
        #expect(sd == (try Self.descriptor(Self.base)))
    }

    /// Bytes this code would not write back as they were are not changed.
    @Test func onlyExactDescriptorsAreWritten() throws {
        let exact = try Self.descriptor(Self.base).encoded()
        #expect(try SecurityDescriptor.checkedForWriting(exact).dacl?.aces == Self.base)
        var gap = [UInt8](exact)
        gap.append(0)
        #expect(throws: SecurityDescriptorError.notExact) { try SecurityDescriptor.checkedForWriting(Data(gap)) }
        // An object ACE whose flags say more than it holds.
        var odd = [UInt8](try Self.descriptor([Self.ace(ACE.accessAllowedObject, 0, 0x20, object: Self.description)]).encoded())
        odd[20 + 8 + 8] |= 0x04
        #expect(throws: SecurityDescriptorError.notExact) { try SecurityDescriptor.checkedForWriting(Data(odd)) }
    }

    @Test func draftsAndRules() throws {
        var draft = AccessRuleDraft()
        #expect(throws: PermissionEditError.self) { try draft.ace() }
        draft.sid = Self.user
        draft.mask = 0x20
        #expect(try draft.ace() == Self.ace(ACE.accessAllowed, 0, 0x20))
        draft.objectType = Self.description
        draft.scope = .descendants
        draft.oneLevelOnly = true
        draft.allow = false
        let user = UUID(uuidString: "bf967aba-0de6-11d0-a285-00aa003049e2")!
        draft.inheritedObjectType = user
        let ace = try draft.ace()
        #expect(ace.type == ACE.accessDeniedObject && ace.flags == 0x0E && ace.inheritedObjectType == user)
        #expect(AccessRuleDraft(ace) == draft)
        // A class of descendants means nothing for this object alone.
        draft.scope = .thisObject
        #expect(try draft.ace().inheritedObjectType == nil && draft.ace().flags == 0)
        #expect(AccessRuleDraft(Self.inherited) == nil)
        for scope in AccessRuleDraft.Scope.allCases {
            var each = AccessRuleDraft()
            each.sid = Self.everyone
            each.mask = 0xF01FF
            each.scope = scope
            #expect(AccessRuleDraft(try each.ace()) == each)
            #expect(AccessRules.describe(try each.ace()) { _ in nil }.appliesTo == scope.label)
        }
    }

    @Test func changesInWords() {
        let names = ["bf967950-0de6-11d0-a285-00aa003049e2": SchemaGUIDName(name: "description", kind: .attribute)]
        let who = { (sid: String) in sid == Self.user ? "pieter" : sid }
        let rule = Self.ace(ACE.accessDeniedObject, 0x02, 0x20, object: Self.description)
        #expect(PermissionChange.add(rule).words(who: who, names: { names[$0] })
                == "Add the rule Deny pieter: Write description, on this object and all descendant objects.")
        #expect(PermissionChange.owner(from: Self.user, to: "S-1-1-0").words(who: who, names: { _ in nil })
                == "Change the owner from pieter to S-1-1-0.")
    }

    /// Thousands of random access lists and changes: what is applied keeps
    /// the inherited rules where they were and the list in canonical order,
    /// encodes to bytes that read back the same, and undone gives back the
    /// bytes it started from.
    @Test func randomChangesKeepInheritedRulesAndUndoExactly() throws {
        var random = FuzzTests.Random(state: 41)
        let sids = [Self.user, Self.admins, Self.everyone, "S-1-5-10", "S-1-5-11"]
        func randomACE(inherited: Bool) -> ACE {
            let object = Bool.random(using: &random)
            let deny = Bool.random(using: &random)
            let type = object ? (deny ? ACE.accessDeniedObject : ACE.accessAllowedObject) : (deny ? ACE.accessDenied : ACE.accessAllowed)
            let flags: UInt8 = inherited ? 0x10 | [0x02, 0x0A, 0x12 & 0x0F][Int.random(in: 0..<3, using: &random)]
                : [0, 0x02, 0x0A, 0x06][Int.random(in: 0..<4, using: &random)]
            return ACE(type: type, flags: flags, mask: UInt32.random(in: 1...0xF01FF, using: &random),
                       objectType: object ? UUID(uuid: (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, UInt8.random(in: 0...255, using: &random))) : nil,
                       sid: sids.randomElement(using: &random)!)
        }
        var applied = 0
        for _ in 0..<FuzzTests.iterations {
            let explicit = (0..<Int.random(in: 0...6, using: &random)).map { _ in randomACE(inherited: false) }
            let inherited = (0..<Int.random(in: 0...4, using: &random)).map { _ in randomACE(inherited: true) }
            let start = try Self.descriptor(explicit.filter(\.isDeny) + explicit.filter { !$0.isDeny } + inherited)
            let bytes = try start.encoded()
            // A rule picked as the window picks it: by its place in the list.
            let aces = start.dacl?.aces ?? []
            let target = aces.indices.filter { !aces[$0].isInherited }.randomElement(using: &random)
            let change: PermissionChange
            switch (Int.random(in: 0..<4, using: &random), target) {
            case (1, let target?): change = .remove(aces[target], at: target)
            case (2, let target?): change = .replace(aces[target], with: randomACE(inherited: false), at: target)
            case (3, _): change = .owner(from: Self.admins, to: sids.randomElement(using: &random)!)
            default: change = .add(randomACE(inherited: false))
            }
            var changed = start
            guard (try? changed.apply(change)) != nil else { continue }
            applied += 1
            #expect(changed.dacl?.aces.filter(\.isInherited) == inherited)
            #expect((try? SecurityDescriptor.checkCanonical(changed.dacl?.aces ?? [])) != nil)
            let encoded = try changed.encoded()
            #expect(try SecurityDescriptor.checkedForWriting(encoded) == changed)
            // Undoing the first rule of an empty list would empty it again,
            // which is refused: a list with no rules denies everyone.
            guard start.dacl?.aces.isEmpty == false else { continue }
            var undone = try SecurityDescriptor(data: encoded)
            try undone.apply(change.inverse)
            #expect(try undone.encoded() == bytes, "\(change)")
        }
        #expect(applied > FuzzTests.iterations / 2)
    }
}

/// Permissions changed against the Active Directory domain controller of
/// TestDirectory/start-ad.sh, and every security descriptor in its domain
/// read, decoded, encoded and compared byte for byte.
///   FORESTER_TEST_AD=1 swift test --filter ADPermissionTests
@Suite(.enabled(if: ProcessInfo.processInfo.environment["FORESTER_TEST_AD"] == "1"), .serialized)
struct ADPermissionTests {
    static let base = "DC=corp,DC=example"
    static let admin = "Administrator@corp.example"
    static let password = "Forester-Lab-Admin-2026!"
    static let seeded = "Corp-Example-Test-Password-2026!"

    static func connect(as user: String = admin, password: String = password) async throws -> LDAPConnection {
        let connection = LDAPConnection(.init(host: "localhost", port: 11636, security: .ldaps, timeout: 30,
                                              trust: TrustPolicy(trustAnyCertificate: true)))
        try await connection.open()
        try await connection.bind(dn: user, password: password)
        return connection
    }

    /// Every object's descriptor, in each part combination the app reads
    /// (owner, DACL, owner group and DACL) and with the SACL as well (the
    /// administrator may read it), encodes back to exactly the bytes read.
    @Test(arguments: [SecurityDescriptor.ownerPart, SecurityDescriptor.daclPart, 0x7, 0xF])
    func everyDescriptorInTheDomainRoundTrips(_ flags: Int) async throws {
        let connection = try await Self.connect()
        var checked = 0, withSACL = 0
        for base in [Self.base, "CN=Configuration,\(Self.base)"] {
            let request = LDAPSearchRequest(base: base, scope: .subtree, attributes: ["nTSecurityDescriptor"], controls: [.sdFlags(flags)])
            let entries = try await connection.pagedSearch(request, pageSize: 500).entries
            for entry in entries {
                guard let data = entry.values("nTSecurityDescriptor").first else { continue }
                let descriptor = try SecurityDescriptor(data: data)
                let encoded = try descriptor.encoded()
                #expect(encoded == data, "\(entry.dn) with flags \(flags)")
                #expect(try SecurityDescriptor.checkedForWriting(data) == descriptor)
                checked += 1
                if descriptor.sacl != nil { withSACL += 1 }
            }
        }
        await connection.close()
        #expect(checked > 2_000, "only \(checked) descriptors")
        if flags & SecurityDescriptor.saclPart != 0 { #expect(withSACL > 100, "only \(withSACL) with a SACL") }
    }

    static let pieter = "CN=Pieter Van Damme,OU=Engineering,OU=Users,OU=Corp,\(base)"
    /// The description attribute's schemaIDGUID.
    static let description = UUID(uuidString: "bf967950-0de6-11d0-a285-00aa003049e2")!

    /// A contact of its own for each test, removed afterwards.
    static func withTarget(_ body: (LDAPConnection, String) async throws -> Void) async throws {
        let connection = try await connect()
        let dn = "CN=Permissions Check \(UInt32.random(in: 0..<1_000_000)),OU=Corp,\(base)"
        try await connection.add(dn, attributes: [LDAPAttribute(name: "objectClass", values: [Data("contact".utf8)])])
        do {
            try await body(connection, dn)
        } catch {
            try? await connection.delete(dn)
            await connection.close()
            throw error
        }
        try await connection.delete(dn)
        await connection.close()
    }

    static func descriptor(_ connection: LDAPConnection, _ dn: String, flags: Int) async throws -> Data {
        try #require(try await connection.read(dn, attributes: ["nTSecurityDescriptor"], controls: [.sdFlags(flags)])?
            .values("nTSecurityDescriptor").first)
    }

    static func sid(of dn: String, on connection: LDAPConnection) async throws -> String {
        try #require(try await connection.read(dn, attributes: ["objectSid"])?.values("objectSid").first.flatMap(ADValues.sidString))
    }

    /// Whether Pieter, an ordinary user, may change the target's description.
    static func pieterMayWriteDescription(_ dn: String) async throws -> Bool {
        let connection = try await connect(as: pieter, password: seeded)
        defer { Task { await connection.close() } }
        do {
            try await connection.modify(dn, [.replace("description", ["Written by Pieter"])])
            return true
        } catch let error as LDAPError where error.resultCode == .insufficientAccessRights {
            return false
        }
    }

    /// A rule added is obeyed by the server, a rule removed is no longer, and
    /// afterwards the DACL is the very bytes it was: nothing else moved, and
    /// the SACL, read with it by the administrator, is untouched throughout.
    @Test func aRuleAddedIsObeyedAndRemovingItRestoresTheBytes() async throws {
        try await Self.withTarget { connection, dn in
            let original = try await Self.descriptor(connection, dn, flags: SecurityDescriptor.daclPart)
            let withSACL = try await Self.descriptor(connection, dn, flags: 0xF)
            #expect(try await Self.pieterMayWriteDescription(dn) == false)
            let pieter = try await Self.sid(of: Self.pieter, on: connection)
            var draft = AccessRuleDraft()
            draft.sid = pieter
            draft.mask = 0x20
            draft.objectType = Self.description
            let rule = try draft.ace()
            try await connection.changePermissions(of: dn, .add(rule))
            let added = try SecurityDescriptor(data: try await Self.descriptor(connection, dn, flags: SecurityDescriptor.daclPart))
            #expect(added.dacl?.aces.contains(rule) == true)
            #expect(try await Self.pieterMayWriteDescription(dn))
            try await connection.changePermissions(of: dn, PermissionChange.add(rule).inverse)
            #expect(try await Self.pieterMayWriteDescription(dn) == false)
            #expect(try await Self.descriptor(connection, dn, flags: SecurityDescriptor.daclPart) == original)
            let sacl = { (data: Data) in try SecurityDescriptor(data: data).sacl }
            #expect(try sacl(try await Self.descriptor(connection, dn, flags: 0xF)) == sacl(withSACL))
        }
    }

    /// A denial goes before the allowances and outweighs them; changed into
    /// an allowance it moves among them; each change undone puts the bytes
    /// back as they were before it.
    @Test func aDenialOutweighsAndChangesAreUndone() async throws {
        try await Self.withTarget { connection, dn in
            let original = try await Self.descriptor(connection, dn, flags: SecurityDescriptor.daclPart)
            var draft = AccessRuleDraft()
            draft.sid = try await Self.sid(of: Self.pieter, on: connection)
            draft.mask = 0x20
            draft.objectType = Self.description
            let allow = try draft.ace()
            draft.allow = false
            let deny = try draft.ace()
            try await connection.changePermissions(of: dn, .add(allow))
            let allowed = try await Self.descriptor(connection, dn, flags: SecurityDescriptor.daclPart)
            try await connection.changePermissions(of: dn, .add(deny))
            let aces = try #require(try SecurityDescriptor(data: try await Self.descriptor(connection, dn, flags: SecurityDescriptor.daclPart)).dacl?.aces)
            #expect(aces.first == deny)
            #expect(try await Self.pieterMayWriteDescription(dn) == false)
            // By its place in the list, as the window names a rule: the first.
            let change = PermissionChange.replace(deny, with: allow, at: 0)
            try await connection.changePermissions(of: dn, change)
            #expect(try await Self.pieterMayWriteDescription(dn))
            try await connection.changePermissions(of: dn, change.inverse)
            #expect(try await Self.pieterMayWriteDescription(dn) == false)
            try await connection.changePermissions(of: dn, .remove(deny, at: 0))
            #expect(try await Self.descriptor(connection, dn, flags: SecurityDescriptor.daclPart) == allowed)
            try await connection.changePermissions(of: dn, .remove(allow))
            #expect(try await Self.descriptor(connection, dn, flags: SecurityDescriptor.daclPart) == original)
        }
    }

    /// The owner changes alone: the group, the DACL and the SACL keep their
    /// bytes, and changing it back restores the descriptor exactly.
    @Test func theOwnerChangesAloneAndBack() async throws {
        try await Self.withTarget { connection, dn in
            let everything = try await Self.descriptor(connection, dn, flags: 0xF)
            let before = try SecurityDescriptor(data: everything)
            let owner = try #require(before.owner)
            let domainAdmins = try await Self.sid(of: "CN=Domain Admins,CN=Users,\(Self.base)", on: connection)
            let newOwner = owner == domainAdmins ? "S-1-5-32-544" : domainAdmins
            try await connection.changePermissions(of: dn, .owner(from: owner, to: newOwner))
            let after = try SecurityDescriptor(data: try await Self.descriptor(connection, dn, flags: 0xF))
            #expect(after.owner == newOwner)
            #expect(after.group == before.group && after.dacl == before.dacl && after.sacl == before.sacl)
            // Shown as the old owner, but changed since: not overwritten.
            await #expect(throws: PermissionEditError.ownerChangedSince) {
                try await connection.changePermissions(of: dn, .owner(from: owner, to: "S-1-5-32-544"))
            }
            try await connection.changePermissions(of: dn, PermissionChange.owner(from: owner, to: newOwner).inverse)
            #expect(try await Self.descriptor(connection, dn, flags: 0xF) == everything)
        }
    }

    /// A rule for descendant users, set on an OU, reaches a user created
    /// beneath it as an inherited rule, and the server obeys it there; an
    /// inherited rule cannot be removed from the user. Removed from the OU,
    /// it is gone from the user too.
    @Test func aRuleForDescendantsIsInheritedAndOnlyChangedWhereItIsSet() async throws {
        let connection = try await Self.connect()
        let ou = "OU=Permissions Check \(UInt32.random(in: 0..<1_000_000)),OU=Corp,\(Self.base)"
        let contact = "CN=Inherits,\(ou)"
        try await connection.add(ou, attributes: [LDAPAttribute(name: "objectClass", values: [Data("organizationalUnit".utf8)])])
        defer { Task { _ = try? await connection.deleteSubtree(ou, useTreeDelete: true); await connection.close() } }
        var draft = AccessRuleDraft()
        draft.sid = try await Self.sid(of: Self.pieter, on: connection)
        draft.mask = 0x20
        draft.objectType = Self.description
        draft.scope = .descendants
        draft.inheritedObjectType = UUID(uuidString: "5cb41ed0-0e4c-11d0-a286-00aa003049e2") // contact
        let rule = try draft.ace()
        try await connection.changePermissions(of: ou, .add(rule))
        try await connection.add(contact, attributes: [LDAPAttribute(name: "objectClass", values: [Data("contact".utf8)])])
        let inherited = try #require(try SecurityDescriptor(data: try await Self.descriptor(connection, contact, flags: SecurityDescriptor.daclPart))
            .dacl?.aces.first { $0.isInherited && $0.sid == draft.sid })
        #expect(inherited.objectType == Self.description)
        #expect(try await Self.pieterMayWriteDescription(contact))
        let before = try await Self.descriptor(connection, contact, flags: SecurityDescriptor.daclPart)
        await #expect(throws: PermissionEditError.inherited) { try await connection.changePermissions(of: contact, .remove(inherited)) }
        #expect(try await Self.descriptor(connection, contact, flags: SecurityDescriptor.daclPart) == before)
        try await connection.changePermissions(of: ou, .remove(rule))
        let after = try SecurityDescriptor(data: try await Self.descriptor(connection, contact, flags: SecurityDescriptor.daclPart))
        #expect(after.dacl?.aces.contains { $0.sid == draft.sid } == false)
        #expect(try await Self.pieterMayWriteDescription(contact) == false)
    }
}
