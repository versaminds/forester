// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import LDAPKit

/// "User cannot change password", written the way permissions are changed:
/// the access list read fresh, only the Change Password rules for Everyone
/// and SELF touched, and undone by putting back just those rules where they
/// were, so a change someone else made to the account's permissions in
/// between stays.
enum CannotChangePassword {
    /// The rules the checkbox owns: set on the account (not inherited), for
    /// the Change Password right, for Everyone or SELF.
    static func owns(_ ace: SecurityDescriptor.ACE) -> Bool {
        !ace.isInherited && ace.raw == nil
            && (ace.type == SecurityDescriptor.ACE.accessAllowedObject || ace.type == SecurityDescriptor.ACE.accessDeniedObject)
            && ace.objectType == SecurityDescriptor.changePasswordRight && (ace.sid == "S-1-1-0" || ace.sid == "S-1-5-10")
    }

    /// Those rules, each with its place in the access list.
    static func rules(_ descriptor: SecurityDescriptor) -> [Placed] {
        (descriptor.dacl?.aces ?? []).enumerated().filter { owns($0.element) }.map { Placed(index: $0.offset, ace: $0.element) }
    }

    struct Placed: Equatable {
        var index: Int
        var ace: SecurityDescriptor.ACE
    }

    /// Takes out the rules the checkbox owns and puts `rules` back, each at
    /// its place when that keeps the order Windows applies (denials,
    /// allowances, inherited rules), otherwise after the last rule of its
    /// kind set on the account. A list that would still be out of order (one
    /// someone else put out of order meanwhile) is refused.
    static func restore(_ rules: [Placed], in descriptor: inout SecurityDescriptor) throws {
        guard var dacl = descriptor.dacl else { throw SecurityDescriptorError.noAccessList }
        dacl.aces.removeAll(where: owns)
        for rule in rules.sorted(by: { $0.index < $1.index }) {
            var candidate = dacl.aces
            candidate.insert(rule.ace, at: min(rule.index, candidate.count))
            if !SecurityDescriptor.isCanonical(candidate) {
                candidate = dacl.aces
                let place = rule.ace.isDeny
                    ? candidate.firstIndex { $0.isInherited || !$0.isDeny } ?? candidate.count
                    : candidate.firstIndex(where: \.isInherited) ?? candidate.count
                candidate.insert(rule.ace, at: place)
            }
            dacl.aces = candidate
        }
        guard SecurityDescriptor.isCanonical(dacl.aces) else { throw PermissionEditError.notCanonical }
        descriptor.dacl = dacl
    }

    /// Reads `dn`'s access list fresh (only the DACL, with the security
    /// descriptor flags control), changes it, and writes the DACL alone back:
    /// only a descriptor that encodes back to the bytes read, and only when
    /// the change left the inherited rules, the owner, the group and the
    /// SACL as they were.
    static func rewrite(_ dn: String, on connection: LDAPConnection, _ edit: (inout SecurityDescriptor) throws -> Void) async throws {
        let control = LDAPControl.sdFlags(SecurityDescriptor.daclPart)
        guard let data = try await connection.read(dn, attributes: ["nTSecurityDescriptor"], controls: [control])?
            .values("nTSecurityDescriptor").first else { throw PermissionEditError.notReadable }
        let before = try SecurityDescriptor.checkedForWriting(data)
        var after = before
        try edit(&after)
        let encoded = try checked(before, after)
        try await connection.modify(dn, [LDAPModification(.replace, "nTSecurityDescriptor", [encoded])], controls: [control])
    }

    /// `after` encoded, when it differs from `before` in the checkbox's rules only.
    static func checked(_ before: SecurityDescriptor, _ after: SecurityDescriptor) throws -> Data {
        let encoded = try after.encoded()
        guard try SecurityDescriptor(data: encoded) == after,
              (before.dacl?.aces ?? []).filter({ !owns($0) }) == (after.dacl?.aces ?? []).filter({ !owns($0) }),
              before.owner == after.owner, before.group == after.group, before.sacl == after.sacl else {
            throw SecurityDescriptorError.notExact
        }
        return encoded
    }

    /// What the forward change found, for its undo to put back.
    final class Found: @unchecked Sendable {
        var rules: [Placed] = []
    }
}
