// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// One change to an object's permissions, as Active Directory Users and
/// Computers' Advanced Security makes it: an access rule set on the object
/// added, removed or changed, or the owner changed. Inherited rules come
/// from the containers above and are never touched; the SACL is never read
/// or written.
///
/// `at` is a place in the DACL: where the rule is, or is to go. A rule goes
/// there when that keeps the order Windows applies (denials, allowances,
/// inherited rules); otherwise after the last rule of its kind set on the
/// object. Undoing a change puts a rule back in the very place it was.
public enum PermissionChange: Equatable, Sendable {
    case add(SecurityDescriptor.ACE, at: Int? = nil)
    case remove(SecurityDescriptor.ACE, at: Int? = nil)
    case replace(SecurityDescriptor.ACE, with: SecurityDescriptor.ACE, at: Int? = nil)
    case owner(from: String, to: String)

    /// Which part of the descriptor it reads and writes, as AD's security
    /// descriptor flags control names it: the owner (1) or the DACL (4).
    public var sdFlags: Int {
        if case .owner = self { return SecurityDescriptor.ownerPart }
        return SecurityDescriptor.daclPart
    }

    /// The change that takes this one back.
    public var inverse: PermissionChange {
        switch self {
        case .add(let ace, let index): return .remove(ace, at: index)
        case .remove(let ace, let index): return .add(ace, at: index)
        case .replace(let old, let new, let index): return .replace(new, with: old, at: index)
        case .owner(let from, let to): return .owner(from: to, to: from)
        }
    }

    /// The change in words, for a person to read before it is sent.
    /// `who` names a SID; `names` names a schema GUID (lowercase).
    public func words(who: (String) -> String, names: (String) -> SchemaGUIDName?) -> String {
        func rule(_ ace: SecurityDescriptor.ACE) -> String {
            // Neither allow nor deny, and for no one this code can name.
            if ace.raw != nil { return String(format: "a rule of a kind Forester does not read (type 0x%02X)", ace.type) }
            let described = AccessRules.describe(ace, names: names)
            let scope = described.appliesTo.prefix(1).lowercased() + described.appliesTo.dropFirst()
            return "\(ace.isDeny ? "Deny" : "Allow") \(who(ace.sid)): \(described.access.joined(separator: "; ")), on \(scope)"
        }
        func the(_ ace: SecurityDescriptor.ACE) -> String { ace.raw == nil ? "the rule \(rule(ace))" : rule(ace) }
        switch self {
        case .add(let ace, _): return "Add \(the(ace))."
        case .remove(let ace, _): return "Remove \(the(ace))."
        case .replace(let old, let new, _): return "Change \(the(old)), to \(rule(new))."
        case .owner(let from, let to): return "Change the owner from \(who(from)) to \(who(to))."
        }
    }
}

extension SecurityDescriptor {
    /// The security descriptor flags for each part (MS-ADTS §3.1.1.3.4.1.11).
    public static let ownerPart = 0x1
    public static let groupPart = 0x2
    public static let daclPart = 0x4
    public static let saclPart = 0x8

    /// Makes the change, keeping the order Windows applies: rules set here
    /// that deny, then those that allow, then the inherited ones, untouched.
    public mutating func apply(_ change: PermissionChange) throws {
        switch change {
        case .owner(let from, let to):
            guard ADValues.sidData(to) != nil else { throw PermissionEditError.invalidRule("The new owner is not a valid SID.") }
            // Changed by someone else since it was shown: not overwritten.
            guard owner == from else { throw PermissionEditError.ownerChangedSince }
            owner = to
            layout = layout.contains(.owner) ? layout : layout + [.owner]
        case .add(let ace, let index):
            try ace.checkExplicit()
            guard var dacl else { throw SecurityDescriptorError.noAccessList }
            try Self.insert(ace, at: index, into: &dacl.aces)
            dacl.revision = max(dacl.revision, Self.revision(for: dacl.aces))
            self.dacl = dacl
        case .remove(let ace, let index):
            guard var dacl else { throw SecurityDescriptorError.noAccessList }
            try Self.checkChangeable(ace, in: dacl.aces)
            dacl.aces.remove(at: try Self.find(ace, at: index, in: dacl.aces))
            guard !dacl.aces.isEmpty else { throw PermissionEditError.emptyAccessList }
            self.dacl = dacl
        case .replace(let old, let new, let index):
            try new.checkExplicit()
            guard var dacl else { throw SecurityDescriptorError.noAccessList }
            try Self.checkChangeable(old, in: dacl.aces)
            let found = try Self.find(old, at: index, in: dacl.aces)
            dacl.aces.remove(at: found)
            try Self.insert(new, at: index ?? found, into: &dacl.aces)
            dacl.revision = max(dacl.revision, Self.revision(for: dacl.aces))
            self.dacl = dacl
        }
    }

    /// A rule is removed or changed only in a list in the order Windows
    /// applies. In another order, where a rule stands decides what it does,
    /// and putting it back (Undo) could not be sure to put it where it was
    /// once anyone else changed the list: a denial could end up ahead of an
    /// allowance it stood behind. A rule of a kind this code does not read
    /// is left as it is: what removing it would allow is unknown.
    private static func checkChangeable(_ ace: ACE, in aces: [ACE]) throws {
        guard ace.raw == nil else {
            throw PermissionEditError.invalidRule("Forester does not read this kind of rule, so it neither removes nor changes it. Active Directory Users and Computers can.")
        }
        guard !ace.isInherited else { throw PermissionEditError.inherited }
        try checkCanonical(aces)
    }

    /// The rule set here equal to `ace`: at `index` if it is there, else the
    /// last one, which is where a rule just added stands.
    private static func find(_ ace: ACE, at index: Int?, in aces: [ACE]) throws -> Int {
        guard !ace.isInherited else { throw PermissionEditError.inherited }
        if let index, aces.indices.contains(index), aces[index] == ace { return index }
        guard let last = aces.lastIndex(where: { $0 == ace && !$0.isInherited }) else { throw PermissionEditError.notFound }
        return last
    }

    /// At `index` when that keeps the order; otherwise after the last rule
    /// of its kind set here, which needs a list in order to say where that is.
    private static func insert(_ ace: ACE, at index: Int?, into aces: inout [ACE]) throws {
        try checkCanonical(aces)
        if let index, (0...aces.count).contains(index) {
            var candidate = aces
            candidate.insert(ace, at: index)
            if (try? checkCanonical(candidate)) != nil {
                aces = candidate
                return
            }
        }
        aces.insert(ace, at: place(for: ace, in: aces))
    }

    /// Explicit denials before explicit allowances before inherited rules,
    /// the order Windows evaluates and writes them in. A list in another
    /// order is not changed: where a rule belongs is then a guess.
    static func checkCanonical(_ aces: [ACE]) throws {
        var stage = 0
        for ace in aces {
            let rank = ace.isInherited ? 2 : (ace.raw == nil && ace.isDeny ? 0 : 1)
            guard rank >= stage else { throw PermissionEditError.notCanonical }
            stage = rank
        }
    }

    /// After the last rule of its own kind set here.
    private static func place(for ace: ACE, in aces: [ACE]) -> Int {
        if ace.isDeny {
            return aces.firstIndex { $0.isInherited || !$0.isDeny } ?? aces.count
        }
        return aces.firstIndex(where: \.isInherited) ?? aces.count
    }

    /// Object rules need ACL_REVISION_DS (4); others revision 2.
    private static func revision(for aces: [ACE]) -> UInt8 {
        aces.contains { $0.raw == nil && $0.isObjectACE } ? 4 : 2
    }
}

extension SecurityDescriptor.ACE {
    /// The inheritance flags a rule set on an object may carry: object and
    /// container inherit, no propagation, inherit only.
    static let inheritanceFlags: UInt8 = 0x0F

    /// A rule Forester may set on an object: allowed or denied, set here and
    /// not inherited, with something to grant, for someone, and applying to
    /// something.
    func checkExplicit() throws {
        guard raw == nil, [Self.accessAllowed, Self.accessDenied, Self.accessAllowedObject, Self.accessDeniedObject].contains(type) else {
            throw PermissionEditError.invalidRule("Only rules that allow or deny are set here.")
        }
        guard !isInherited else { throw PermissionEditError.inherited }
        guard flags & ~Self.inheritanceFlags == 0 else { throw PermissionEditError.invalidRule("The rule carries flags an access rule does not have.") }
        guard mask != 0 else { throw PermissionEditError.invalidRule("Choose what the rule allows or denies.") }
        guard ADValues.sidData(sid) != nil else { throw PermissionEditError.invalidRule("Choose who the rule is for.") }
        let inherits = flags & 0x03 != 0
        // Inherit-only or one level down, with nothing inheriting it, applies to nothing.
        guard inherits || flags & 0x0C == 0 else { throw PermissionEditError.invalidRule("The rule would apply to no object.") }
        guard isObjectACE == (objectType != nil || inheritedObjectType != nil) else {
            throw PermissionEditError.invalidRule("The rule's kind does not match what it names.")
        }
        guard inheritedObjectType == nil || inherits else {
            throw PermissionEditError.invalidRule("A rule for one kind of descendant object must be inherited by descendants.")
        }
    }
}

/// An access rule as the editor builds it, and back.
public struct AccessRuleDraft: Equatable, Sendable {
    public enum Scope: String, CaseIterable, Sendable {
        case thisObject, thisAndDescendants, descendants

        public var label: String {
            switch self {
            case .thisObject: return "This object only"
            case .thisAndDescendants: return "This object and all descendant objects"
            case .descendants: return "All descendant objects"
            }
        }
    }

    public var allow = true
    public var sid = ""
    public var mask: UInt32 = 0
    /// The attribute, property set, extended right, validated write or class
    /// the rule is about; nil for the object as a whole.
    public var objectType: UUID?
    public var scope: Scope = .thisObject
    /// Only descendants of this class, with `scope` reaching descendants.
    public var inheritedObjectType: UUID?
    /// No further than the objects right beneath.
    public var oneLevelOnly = false
    /// Object inherit, which AD itself does not use but a rule may carry:
    /// kept when a rule is changed.
    var objectInherit = false
    /// The flags of a rule without container inherit, which the scope
    /// choices do not show (object inherit with or without inherit only or
    /// no propagation): kept as they are while its scope stays "this
    /// object". Read as "this object" alone, 0x01 would be rebuilt as 0x03,
    /// reaching every descendant.
    var ownFlags: UInt8 = 0

    public init() {}

    /// The rule as the editor shows it; nil for an inherited rule, or one of
    /// a kind the editor does not build.
    public init?(_ ace: SecurityDescriptor.ACE) {
        guard (try? ace.checkExplicit()) != nil else { return nil }
        allow = !ace.isDeny
        sid = ace.sid
        mask = ace.mask
        objectType = ace.objectType
        inheritedObjectType = ace.inheritedObjectType
        // Container inherit is what reaches descendant directory objects.
        let containerInherit = ace.flags & 0x02 != 0
        scope = !containerInherit ? .thisObject : (ace.flags & 0x08 != 0 ? .descendants : .thisAndDescendants)
        oneLevelOnly = containerInherit && ace.flags & 0x04 != 0
        objectInherit = ace.flags & 0x01 != 0
        ownFlags = containerInherit ? 0 : ace.flags & Self.inheritanceFlags
    }

    static let inheritanceFlags: UInt8 = 0x0F

    /// The access control entry, checked as one Forester may set.
    public func ace() throws -> SecurityDescriptor.ACE {
        var flags: UInt8 = 0
        switch scope {
        case .thisObject: flags = ownFlags
        case .thisAndDescendants: flags = 0x02
        case .descendants: flags = 0x0A
        }
        if scope != .thisObject {
            if oneLevelOnly { flags |= 0x04 }
            if objectInherit { flags |= 0x01 }
        }
        // A class of descendants needs something that inherits.
        let classOnly = flags & 0x03 == 0 ? nil : inheritedObjectType
        let isObject = objectType != nil || classOnly != nil
        let type = allow ? (isObject ? SecurityDescriptor.ACE.accessAllowedObject : SecurityDescriptor.ACE.accessAllowed)
                         : (isObject ? SecurityDescriptor.ACE.accessDeniedObject : SecurityDescriptor.ACE.accessDenied)
        let ace = SecurityDescriptor.ACE(type: type, flags: flags, mask: mask, objectType: objectType,
                                         inheritedObjectType: classOnly, sid: ADValues.canonicalSID(sid) ?? sid)
        try ace.checkExplicit()
        return ace
    }

    /// The rights on an object as a whole, as Advanced Security lists them.
    public static let generalRights: [(name: String, mask: UInt32)] = [
        ("Full control", 0xF_01FF), ("List contents", 0x4), ("Read all properties", 0x10), ("Write all properties", 0x20),
        ("Delete", 0x1_0000), ("Delete subtree", 0x40), ("Read permissions", 0x2_0000), ("Modify permissions", 0x4_0000),
        ("Modify owner", 0x8_0000), ("All validated writes", 0x8), ("All extended rights", 0x100),
        ("Create all child objects", 0x1), ("Delete all child objects", 0x2), ("List object", 0x80),
    ]
}

public enum PermissionEditError: Error, Equatable, LocalizedError {
    case inherited, notFound, notCanonical, emptyAccessList, ownerChangedSince, notReadable
    case invalidRule(String)
    /// What the server kept is not what was sent.
    case storedDifferently

    public var errorDescription: String? {
        switch self {
        case .inherited:
            return "That rule is inherited from a container above; it can only be changed there."
        case .notFound:
            return "That rule is no longer set on the object: someone changed its permissions since. Look again before changing them."
        case .notCanonical:
            return "The object's rules are not in the order Windows applies them (denials, then allowances, then inherited rules), so Forester does not change them: in that order, where a rule stands decides what it does, and where one belongs would be a guess. Active Directory Users and Computers can put them in order."
        case .emptyAccessList:
            return "That would leave the object with no rules at all, which denies everyone everything; Forester does not do that."
        case .ownerChangedSince:
            return "The owner was changed by someone else since it was shown. Look again before changing it."
        case .notReadable:
            return "The server returned no security descriptor for this entry. Reading one needs the right to read its permissions."
        case .invalidRule(let why):
            return why
        case .storedDifferently:
            return "The change was made, but the server kept permissions other than the ones sent. Look at them again before changing anything else."
        }
    }
}

extension LDAPConnection {
    /// Makes one change to `dn`'s permissions: reads only the part it
    /// changes (the DACL, or the owner) with AD's security descriptor flags
    /// control, changes it, and writes that part alone back, never the SACL.
    /// The descriptor is changed only if it encodes back to the bytes read,
    /// and only in the rules set on the object; afterwards it is read again
    /// to check the server kept what was sent.
    ///
    /// Once the server has taken the change, it is made, whatever the read
    /// afterwards finds: that is returned rather than thrown, so the change
    /// is still recorded, and can be undone, with the doubt as a warning.
    @discardableResult
    public func changePermissions(of dn: String, _ change: PermissionChange) async throws -> PermissionWriteCheck {
        let control = LDAPControl.sdFlags(change.sdFlags)
        guard let data = try await read(dn, attributes: ["nTSecurityDescriptor"], controls: [control])?
            .values("nTSecurityDescriptor").first else { throw PermissionEditError.notReadable }
        let before = try SecurityDescriptor.checkedForWriting(data)
        var after = before
        try after.apply(change)
        let encoded = try after.encoded()
        // Nothing but the change: the inherited rules, the SACL, the group and
        // the control flags as they were, and the bytes reading back as meant.
        guard try SecurityDescriptor(data: encoded) == after,
              before.dacl?.aces.filter(\.isInherited) == after.dacl?.aces.filter(\.isInherited),
              before.sacl == after.sacl, before.group == after.group, before.control == after.control,
              change.sdFlags == SecurityDescriptor.ownerPart ? before.dacl == after.dacl : before.owner == after.owner else {
            throw SecurityDescriptorError.notExact
        }
        try await modify(dn, [LDAPModification(.replace, "nTSecurityDescriptor", [encoded])], controls: [control])
        let stored = try? await read(dn, attributes: ["nTSecurityDescriptor"], controls: [control])?.values("nTSecurityDescriptor").first
        return PermissionWriteCheck(stored: stored, sent: after, change: change)
    }
}

/// What reading the permissions back after a change found.
public enum PermissionWriteCheck: Equatable, Sendable {
    /// The server kept what was sent.
    case kept
    /// They could not be read back, so whether the server kept them is not known.
    case notReadBack
    /// The server kept something other than what was sent.
    case storedDifferently

    /// `stored`: the descriptor read back, if any. Only the part changed is
    /// compared, and of the access list only the rules set on the object:
    /// the server works out the inherited ones itself.
    public init(stored: Data?, sent: SecurityDescriptor, change: PermissionChange) {
        guard let stored, let descriptor = try? SecurityDescriptor(data: stored) else {
            self = .notReadBack
            return
        }
        let kept = change.sdFlags == SecurityDescriptor.ownerPart
            ? descriptor.owner == sent.owner
            : descriptor.dacl?.aces.filter { !$0.isInherited } == sent.dacl?.aces.filter { !$0.isInherited }
        self = kept ? .kept : .storedDifferently
    }

    /// For the change history and the window: the change was made either way.
    public var warning: String? {
        switch self {
        case .kept: return nil
        case .notReadBack: return "The change was made, but the permissions could not be read back to check what the server kept. Look at them again before changing anything else."
        case .storedDifferently: return PermissionEditError.storedDifferently.errorDescription
        }
    }
}
