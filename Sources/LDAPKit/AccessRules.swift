// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// What a GUID in an access rule stands for: a class, an attribute, an
/// extended right ("Reset Password"), a property set ("Personal
/// Information") or a validated write. Read from the schema and the
/// Extended-Rights container.
public struct SchemaGUIDName: Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        case objectClass, attribute, extendedRight, propertySet, validatedWrite
    }

    public var name: String
    public var kind: Kind

    public init(name: String, kind: Kind) {
        self.name = name
        self.kind = kind
    }

    /// A few that are worth naming even when the directory could not be asked.
    public static let builtIn: [String: SchemaGUIDName] = [
        "00299570-246d-11d0-a768-00aa006e0529": SchemaGUIDName(name: "Reset Password", kind: .extendedRight),
        "ab721a53-1e2f-11d0-9819-00aa0040529b": SchemaGUIDName(name: "Change Password", kind: .extendedRight),
        "ab721a54-1e2f-11d0-9819-00aa0040529b": SchemaGUIDName(name: "Send As", kind: .extendedRight),
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": SchemaGUIDName(name: "Replicating Directory Changes", kind: .extendedRight),
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": SchemaGUIDName(name: "Replicating Directory Changes All", kind: .extendedRight),
        "bf9679c0-0de6-11d0-a285-00aa003049e2": SchemaGUIDName(name: "member", kind: .attribute),
    ]
}

/// One access control entry, in words: who, allowed or denied what, on
/// which objects.
public struct AccessRule: Equatable, Sendable, Identifiable {
    public var id: Int
    public var allow: Bool
    public var sid: String
    public var access: [String]
    public var appliesTo: String
    public var inherited: Bool
    /// Grants more than reading (writes, creates, deletes, rights, ownership).
    public var isWrite: Bool
    /// The mask and GUIDs as stored, for whoever wants the raw detail.
    public var detail: String
    /// False for an entry of a type this code does not read (a callback or a
    /// conditional entry): it is shown as neither allowed nor denied.
    public var understood = true
}

public enum AccessRules {
    static let createChild: UInt32 = 0x1, deleteChild: UInt32 = 0x2, listChildren: UInt32 = 0x4
    static let validatedWrite: UInt32 = 0x8, readProperty: UInt32 = 0x10, writeProperty: UInt32 = 0x20
    static let deleteTree: UInt32 = 0x40, listObject: UInt32 = 0x80, controlAccess: UInt32 = 0x100
    static let delete: UInt32 = 0x1_0000, readControl: UInt32 = 0x2_0000, writeDAC: UInt32 = 0x4_0000, writeOwner: UInt32 = 0x8_0000
    static let fullControl: UInt32 = 0xF_01FF
    static let genericRead: UInt32 = 0x2_0094
    /// The generic rights, which AD normally maps to the specific ones above
    /// but a descriptor can still hold.
    static let genericAll: UInt32 = 0x1000_0000, genericWrite: UInt32 = 0x4000_0000
    /// Everything but reading: what makes a rule worth an administrator's attention.
    static let writeBits: UInt32 = createChild | deleteChild | validatedWrite | writeProperty | deleteTree | controlAccess | delete
        | writeDAC | writeOwner | genericAll | genericWrite

    /// Each ACE of a DACL in words, in the order the server evaluates them.
    /// `names` looks up a GUID (lowercase) in the directory's schema.
    public static func describe(_ dacl: SecurityDescriptor.ACL?, names: (String) -> SchemaGUIDName?) -> [AccessRule] {
        (dacl?.aces ?? []).enumerated().map { describe($1, id: $0, names: names) }
    }

    public static func describe(_ ace: SecurityDescriptor.ACE, id: Int = 0, names: (String) -> SchemaGUIDName?) -> AccessRule {
        if ace.raw != nil {
            // Counted as more than reading: what it grants is unknown.
            return AccessRule(id: id, allow: false, sid: ace.sid, access: [String(format: "A kind of rule Forester does not read (type 0x%02X)", ace.type)],
                              appliesTo: "Unknown", inherited: ace.isInherited, isWrite: true,
                              detail: String(format: "Type 0x%02X, mask 0x%X", ace.type, ace.mask), understood: false)
        }
        func name(_ uuid: UUID?) -> SchemaGUIDName? {
            guard let key = uuid?.uuidString.lowercased() else { return nil }
            return names(key) ?? SchemaGUIDName.builtIn[key]
        }
        let object = name(ace.objectType)
        let objectLabel = object?.name ?? ace.objectType?.uuidString.lowercased()
        let mask = ace.mask
        var access: [String] = []
        if mask & fullControl == fullControl {
            access = ["Full control"]
        } else {
            var rest = mask
            func take(_ bits: UInt32) -> Bool {
                guard rest & bits == bits else { return false }
                rest &= ~bits
                return true
            }
            if ace.objectType == nil, take(genericRead) { access.append("Read") }
            let reads = take(readProperty), writes = take(writeProperty)
            switch (reads, writes) {
            case (true, true): access.append(objectLabel.map { "Read and write \(propertyWords($0, object))" } ?? "Read and write all properties")
            case (true, false): access.append(objectLabel.map { "Read \(propertyWords($0, object))" } ?? "Read all properties")
            case (false, true): access.append(objectLabel.map { "Write \(propertyWords($0, object))" } ?? "Write all properties")
            case (false, false): break
            }
            if take(createChild) { access.append(objectLabel.map { "Create \($0) objects" } ?? "Create all child objects") }
            if take(deleteChild) { access.append(objectLabel.map { "Delete \($0) objects" } ?? "Delete all child objects") }
            if take(validatedWrite) { access.append(objectLabel.map { "Validated write: \($0)" } ?? "All validated writes") }
            if take(controlAccess) {
                // On a property set it opens its confidential attributes; on
                // anything but a right, say what it is attached to.
                if let label = objectLabel {
                    switch object?.kind {
                    case .propertySet?: access.append("Read confidential \(label)")
                    case .extendedRight?, nil: access.append(label)
                    case _?: access.append("Control access: \(label)")
                    }
                } else {
                    access.append("All extended rights")
                }
            }
            if take(listChildren) { access.append("List contents") }
            if take(listObject) { access.append("List object") }
            if take(deleteTree) { access.append("Delete subtree") }
            if take(delete) { access.append("Delete") }
            if take(readControl) { access.append("Read permissions") }
            if take(writeDAC) { access.append("Modify permissions") }
            if take(writeOwner) { access.append("Modify owner") }
            if take(genericAll) { access.append("Full control (generic)") }
            if take(genericWrite) { access.append("Write (generic)") }
            if rest != 0 { access.append(String(format: "Other rights (0x%X)", rest)) }
        }
        let flags = ace.flags
        let inheritOnly = flags & 0x8 != 0, containerInherit = flags & 0x2 != 0 || flags & 0x1 != 0, oneLevel = flags & 0x4 != 0
        let classLabel = name(ace.inheritedObjectType)?.name ?? ace.inheritedObjectType?.uuidString.lowercased()
        var appliesTo: String
        switch (containerInherit, inheritOnly, classLabel) {
        case (false, _, _): appliesTo = "This object only"
        case (true, false, nil): appliesTo = "This object and all descendant objects"
        case (true, true, nil): appliesTo = "All descendant objects"
        case (true, false, let type?): appliesTo = "This object and descendant \(type) objects"
        case (true, true, let type?): appliesTo = "Descendant \(type) objects"
        }
        if containerInherit, oneLevel { appliesTo += ", one level down only" }
        var detail = String(format: "Mask 0x%X", mask)
        if let type = ace.objectType { detail += ", object \(type.uuidString.lowercased())" }
        if let type = ace.inheritedObjectType { detail += ", inherited by \(type.uuidString.lowercased())" }
        return AccessRule(id: id, allow: !ace.isDeny, sid: ace.sid, access: access.isEmpty ? ["Nothing"] : access, appliesTo: appliesTo,
                          inherited: ace.isInherited, isWrite: mask & writeBits != 0, detail: detail)
    }

    private static func propertyWords(_ label: String, _ object: SchemaGUIDName?) -> String {
        object?.kind == .propertySet ? "\(label) (property set)" : label
    }
}
