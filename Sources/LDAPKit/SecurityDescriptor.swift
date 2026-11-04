// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// A self-relative Windows security descriptor (MS-DTYP §2.4.6), as AD
/// stores it in nTSecurityDescriptor.
///
/// Needed for one thing an administrator expects to toggle: "User cannot
/// change password" is not a flag but a pair of deny ACEs in the DACL, which
/// is also how Active Directory Users and Computers implements the checkbox.
public struct SecurityDescriptor: Equatable, Sendable {
    public var revision: UInt8 = 1
    public var control: UInt16
    public var owner: String?
    public var group: String?
    public var sacl: ACL?
    public var dacl: ACL?

    public struct ACL: Equatable, Sendable {
        public var revision: UInt8
        public var aces: [ACE]
    }

    public struct ACE: Equatable, Sendable {
        public var type: UInt8
        public var flags: UInt8
        public var mask: UInt32
        public var objectType: UUID?
        public var inheritedObjectType: UUID?
        public var sid: String
        /// ACE types this code does not model are carried through unchanged.
        public var raw: Data?

        public static let accessAllowed: UInt8 = 0x00
        public static let accessDenied: UInt8 = 0x01
        public static let accessAllowedObject: UInt8 = 0x05
        public static let accessDeniedObject: UInt8 = 0x06
        static let inherited: UInt8 = 0x10

        public var isInherited: Bool { flags & Self.inherited != 0 }
        public var isDeny: Bool { type == Self.accessDenied || type == Self.accessDeniedObject }
        var isObjectACE: Bool { type == Self.accessAllowedObject || type == Self.accessDeniedObject || type == 0x07 || type == 0x08 }
    }

    static let selfRelative: UInt16 = 0x8000
    static let daclPresent: UInt16 = 0x0004
    static let saclPresent: UInt16 = 0x0010

    public init(data: Data) throws {
        let b = [UInt8](data)
        guard b.count >= 20 else { throw SecurityDescriptorError.truncated }
        revision = b[0]
        control = Self.u16(b, 2)
        let ownerOffset = Int(Self.u32(b, 4)), groupOffset = Int(Self.u32(b, 8))
        let saclOffset = Int(Self.u32(b, 12)), daclOffset = Int(Self.u32(b, 16))
        owner = ownerOffset > 0 ? try Self.sid(b, ownerOffset).string : nil
        group = groupOffset > 0 ? try Self.sid(b, groupOffset).string : nil
        sacl = saclOffset > 0 && control & Self.saclPresent != 0 ? try Self.acl(b, saclOffset) : nil
        dacl = daclOffset > 0 && control & Self.daclPresent != 0 ? try Self.acl(b, daclOffset) : nil
    }

    /// Self-relative encoding. The DACL is placed first, then SACL, owner and
    /// group, which is the layout AD itself returns.
    public func encoded() throws -> Data {
        var body: [UInt8] = []
        var offsets = (owner: 0, group: 0, sacl: 0, dacl: 0)
        var flags = control | Self.selfRelative
        if let dacl { offsets.dacl = 20 + body.count; body += try Self.encode(dacl); flags |= Self.daclPresent } else { flags &= ~Self.daclPresent }
        if let sacl { offsets.sacl = 20 + body.count; body += try Self.encode(sacl); flags |= Self.saclPresent } else { flags &= ~Self.saclPresent }
        if let owner, let sid = ADValues.sidData(owner) { offsets.owner = 20 + body.count; body += [UInt8](sid) }
        if let group, let sid = ADValues.sidData(group) { offsets.group = 20 + body.count; body += [UInt8](sid) }
        var header: [UInt8] = [revision, 0]
        header += Self.le16(flags)
        header += Self.le32(UInt32(offsets.owner)) + Self.le32(UInt32(offsets.group))
        header += Self.le32(UInt32(offsets.sacl)) + Self.le32(UInt32(offsets.dacl))
        return Data(header + body)
    }

    // MARK: User cannot change password

    /// The "Change Password" extended right.
    public static let changePasswordRight = UUID(uuidString: "AB721A53-1E2F-11D0-9819-00AA0040529B")!
    static let everyone = "S-1-1-0"
    static let principalSelf = "S-1-5-10"
    static let controlAccess: UInt32 = 0x100

    private static func isChangePasswordACE(_ ace: ACE) -> Bool {
        !ace.isInherited && ace.isObjectACE && ace.objectType == changePasswordRight
            && (ace.sid == everyone || ace.sid == principalSelf)
    }

    /// True when the DACL denies Everyone or SELF the Change Password right.
    public var userCannotChangePassword: Bool {
        dacl?.aces.contains { Self.isChangePasswordACE($0) && $0.type == ACE.accessDeniedObject } ?? false
    }

    /// Replaces the explicit Change Password ACEs for Everyone and SELF with
    /// deny ACEs (cannot change) or allow ACEs (can change), keeping the DACL
    /// in canonical order: explicit deny, explicit allow, then inherited.
    public mutating func setUserCannotChangePassword(_ cannotChange: Bool) {
        var aces = dacl?.aces ?? []
        aces.removeAll(where: Self.isChangePasswordACE)
        let type = cannotChange ? ACE.accessDeniedObject : ACE.accessAllowedObject
        let new = [Self.everyone, Self.principalSelf].map {
            ACE(type: type, flags: 0, mask: Self.controlAccess, objectType: Self.changePasswordRight, inheritedObjectType: nil, sid: $0)
        }
        let explicit = aces.filter { !$0.isInherited }
        let inherited = aces.filter(\.isInherited)
        let denies = explicit.filter(\.isDeny), allows = explicit.filter { !$0.isDeny }
        let ordered = cannotChange ? new + denies + allows + inherited : denies + new + allows + inherited
        dacl = ACL(revision: max(dacl?.revision ?? 4, 4), aces: ordered)
    }

    // MARK: Decoding

    private static func u16(_ b: [UInt8], _ o: Int) -> UInt16 { UInt16(b[o]) | UInt16(b[o + 1]) << 8 }
    private static func u32(_ b: [UInt8], _ o: Int) -> UInt32 {
        UInt32(b[o]) | UInt32(b[o + 1]) << 8 | UInt32(b[o + 2]) << 16 | UInt32(b[o + 3]) << 24
    }
    private static func le16(_ v: UInt16) -> [UInt8] { [UInt8(v & 0xFF), UInt8(v >> 8)] }
    private static func le32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) } }

    private static func sid(_ b: [UInt8], _ offset: Int) throws -> (string: String, length: Int) {
        guard offset + 8 <= b.count else { throw SecurityDescriptorError.truncated }
        let length = 8 + Int(b[offset + 1]) * 4
        guard offset + length <= b.count, let string = ADValues.sidString(Data(b[offset..<(offset + length)])) else {
            throw SecurityDescriptorError.badSID
        }
        return (string, length)
    }

    private static func guid(_ b: [UInt8], _ offset: Int) -> UUID? {
        ADValues.guidString(Data(b[offset..<(offset + 16)])).flatMap(UUID.init(uuidString:))
    }

    private static func acl(_ b: [UInt8], _ offset: Int) throws -> ACL {
        guard offset + 8 <= b.count else { throw SecurityDescriptorError.truncated }
        let revision = b[offset]
        let count = Int(u16(b, offset + 4))
        var aces: [ACE] = []
        var position = offset + 8
        for _ in 0..<count {
            guard position + 4 <= b.count else { throw SecurityDescriptorError.truncated }
            let type = b[position], flags = b[position + 1]
            let size = Int(u16(b, position + 2))
            guard size >= 8, position + size <= b.count else { throw SecurityDescriptorError.truncated }
            let mask = u32(b, position + 4)
            switch type {
            case ACE.accessAllowed, ACE.accessDenied, 0x02:
                aces.append(ACE(type: type, flags: flags, mask: mask, sid: try sid(b, position + 8).string))
            case ACE.accessAllowedObject, ACE.accessDeniedObject, 0x07:
                // Everything an object ACE holds must lie inside its own size.
                let end = position + size
                guard position + 12 <= end else { throw SecurityDescriptorError.truncated }
                let objectFlags = u32(b, position + 8)
                var cursor = position + 12
                var objectType: UUID?, inheritedType: UUID?
                if objectFlags & 1 != 0 {
                    guard cursor + 16 <= end else { throw SecurityDescriptorError.truncated }
                    objectType = guid(b, cursor)
                    cursor += 16
                }
                if objectFlags & 2 != 0 {
                    guard cursor + 16 <= end else { throw SecurityDescriptorError.truncated }
                    inheritedType = guid(b, cursor)
                    cursor += 16
                }
                guard cursor + 8 <= end else { throw SecurityDescriptorError.truncated }
                aces.append(ACE(type: type, flags: flags, mask: mask, objectType: objectType,
                                inheritedObjectType: inheritedType, sid: try sid(b, cursor).string))
            default:
                aces.append(ACE(type: type, flags: flags, mask: mask, sid: "", raw: Data(b[position..<(position + size)])))
            }
            position += size
        }
        return ACL(revision: revision, aces: aces)
    }

    // MARK: Encoding

    private static func encode(_ ace: ACE) throws -> [UInt8] {
        if let raw = ace.raw { return [UInt8](raw) }
        var body = le32(ace.mask)
        if ace.isObjectACE {
            var objectFlags: UInt32 = 0
            if ace.objectType != nil { objectFlags |= 1 }
            if ace.inheritedObjectType != nil { objectFlags |= 2 }
            body += le32(objectFlags)
            for guid in [ace.objectType, ace.inheritedObjectType].compactMap({ $0 }) {
                body += [UInt8](ADValues.guidData(guid.uuidString) ?? Data(count: 16))
            }
        }
        body += [UInt8](ADValues.sidData(ace.sid) ?? Data())
        guard 4 + body.count <= Int(UInt16.max) else { throw SecurityDescriptorError.tooLarge }
        return [ace.type, ace.flags] + le16(UInt16(4 + body.count)) + body
    }

    private static func encode(_ acl: ACL) throws -> [UInt8] {
        let aces = try acl.aces.flatMap(encode)
        // An ACL's size is 16 bits; AD's own limit is 64 KB.
        guard 8 + aces.count <= Int(UInt16.max), acl.aces.count <= Int(UInt16.max) else { throw SecurityDescriptorError.tooLarge }
        return [acl.revision, 0] + le16(UInt16(8 + aces.count)) + le16(UInt16(acl.aces.count)) + [0, 0] + aces
    }
}

public enum SecurityDescriptorError: Error, Equatable {
    case truncated, badSID
    /// The changed access list would be larger than 64 KB.
    case tooLarge
}

extension SecurityDescriptorError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .truncated: return "The security descriptor is cut short."
        case .badSID: return "The security descriptor holds a malformed SID."
        case .tooLarge: return "The account's access list would grow past 64 KB, the most a security descriptor can hold."
        }
    }
}
