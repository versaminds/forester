// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// What an LDIF file would do beyond adding entries where they were
/// expected, record by record, before anything is sent: a count of
/// "3 modifications" does not say that one of them adds someone to Domain
/// Admins, or sets an account's delegation.
public struct LDIFImportReview: Sendable, Equatable {
    public struct Item: Sendable, Equatable, Identifiable {
        /// The record's place in the file's records.
        public var id: Int
        public var line: Int
        /// "Change", "Delete", "Rename", "Move" or "Add".
        public var verb: String
        public var dn: String
        /// Where a rename or move puts the entry.
        public var newDN: String?
        /// Each attribute it changes, in words ("add member: CN=…").
        public var changes: [String]
        /// The entry, or where it is moved, is not under the chosen container.
        public var outside: Bool
        /// What makes the record worth a second look before it is sent.
        public var warnings: [String]
    }

    /// Every record that is not a plain add, is outside the container, or
    /// touches something sensitive, in the file's order.
    public var items: [Item]

    public var warnings: Int { items.reduce(0) { $0 + $1.warnings.count } }
    public var outside: Int { items.filter(\.outside).count }

    /// `container`: where the file's entries are expected (nil or empty: no
    /// check). `privilegedGroups`: normalized DNs of groups that hold power
    /// in the domain (adminCount 1, or a well-known administrators' group),
    /// as `privilegedGroup` decides from what the directory says of them.
    public init(_ records: [LDIFRecord], container: String?, privilegedGroups: Set<String>) {
        let container = container?.trimmingCharacters(in: .whitespaces) ?? ""
        func isOutside(_ dn: String) -> Bool {
            !container.isEmpty && !DN.isSame(dn, container) && !DN.isWithin(dn, container)
        }
        items = records.enumerated().compactMap { index, record in
            var item = Item(id: index, line: record.line, verb: "Add", dn: record.dn, changes: [], outside: isOutside(record.dn), warnings: [])
            // An entry named by GUID or SID could be any entry, an
            // administrators' group among them: it is never taken for harmless.
            let extended = DN.isExtended(record.dn)
            let privileged = extended || privilegedGroups.contains(DN.normalized(record.dn)) || Self.isWellKnownAdminGroupName(record.dn)
            if extended {
                item.warnings.append("Names its entry by GUID or SID rather than by its place, so which entry it is, and what that entry is, cannot be told from the file.")
            }
            switch record.change {
            case .add(let attributes):
                // Listed only when it is not where expected or sets something sensitive.
                for attribute in attributes {
                    if let warning = Self.warning(attribute.baseName, privilegedGroup: privileged, dn: record.dn) {
                        item.warnings.append(warning)
                        item.changes.append(Self.describe(.add, attribute.name, attribute.values))
                    }
                }
            case .delete:
                item.verb = "Delete"
            case .modify(let modifications):
                item.verb = "Change"
                for modification in modifications {
                    item.changes.append(Self.describe(modification.operation, modification.attribute, modification.values))
                    let base = modification.attribute.split(separator: ";", maxSplits: 1).first.map(String.init) ?? modification.attribute
                    // Removing members takes power away; adding or replacing gives it.
                    let grants = modification.operation != .delete || base.caseInsensitiveCompare("member") != .orderedSame
                    if grants, let warning = Self.warning(base, privilegedGroup: privileged, dn: record.dn),
                       !item.warnings.contains(warning) {
                        item.warnings.append(warning)
                    }
                }
            case .modifyDN(let newRDN, _, let superior):
                item.verb = superior == nil ? "Rename" : "Move"
                let parent = superior ?? DN.parent(record.dn) ?? ""
                let target = parent.isEmpty ? newRDN : "\(newRDN),\(parent)"
                item.newDN = target
                item.outside = item.outside || isOutside(target)
                if privileged { item.warnings.append("Renames or moves a group that holds administrator rights.") }
            }
            let plainAdd: Bool
            if case .add = record.change { plainAdd = true } else { plainAdd = false }
            return plainAdd && !item.outside && item.warnings.isEmpty ? nil : item
        }
    }

    /// The groups whose members a file changes: what the directory is asked
    /// about (adminCount, objectSid) to tell which of them are privileged.
    public static func groupsChangingMembers(_ records: [LDIFRecord]) -> [String] {
        var seen = Set<String>(), groups: [String] = []
        for record in records {
            let touches: Bool
            switch record.change {
            case .modify(let modifications): touches = modifications.contains { isMember($0.attribute) }
            case .add(let attributes): touches = attributes.contains { isMember($0.name) }
            case .modifyDN: touches = true
            case .delete: touches = false
            }
            if touches, seen.insert(DN.normalized(record.dn)).inserted { groups.append(record.dn) }
        }
        return groups
    }

    /// A group that holds power in the domain: protected by AdminSDHolder
    /// (adminCount 1), or one of the built-in administrators' groups by SID,
    /// or by name when the directory said nothing.
    public static func privilegedGroup(dn: String, sid: String?, adminCount: Int?) -> Bool {
        if adminCount == 1 { return true }
        if let sid {
            if ["S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551"].contains(sid) { return true }
            if sid.hasPrefix("S-1-5-21-"), let rid = ADValues.rid(sid), [512, 518, 519, 520, 526, 527].contains(rid) { return true }
        }
        return isWellKnownAdminGroupName(dn)
    }

    static let adminGroupNames: Set<String> = [
        "domain admins", "enterprise admins", "schema admins", "administrators", "account operators", "server operators",
        "backup operators", "print operators", "group policy creator owners", "key admins", "enterprise key admins", "dnsadmins",
    ]

    static func isWellKnownAdminGroupName(_ dn: String) -> Bool {
        adminGroupNames.contains(DN.rdnValue(dn).lowercased())
    }

    private static func isMember(_ attribute: String) -> Bool {
        (attribute.split(separator: ";", maxSplits: 1).first.map(String.init) ?? attribute).caseInsensitiveCompare("member") == .orderedSame
    }

    /// Why setting `attribute` deserves a look, or nil.
    static func warning(_ attribute: String, privilegedGroup: Bool, dn: String) -> String? {
        switch attribute.lowercased() {
        case "member" where privilegedGroup:
            return "Changes the members of \(DN.displayName(dn)), a group that holds administrator rights."
        case "ntsecuritydescriptor":
            return "Sets the entry's permissions and owner (nTSecurityDescriptor)."
        case "useraccountcontrol":
            return "Sets account flags (userAccountControl), which can turn on delegation, turn off the password requirement or enable an account."
        case "serviceprincipalname":
            return "Sets service principal names, which decide what Kerberos issues tickets for, and to whom."
        case "msds-allowedtoactonbehalfofotheridentity":
            return "Sets who may act as any user towards this account (resource-based constrained delegation)."
        case "msds-allowedtodelegateto":
            return "Sets the services this account may act as any user towards (constrained delegation)."
        case "msds-keycredentiallink":
            return "Sets keys that sign in as this account without its password (msDS-KeyCredentialLink)."
        case "sidhistory":
            return "Sets SID history, which gives the account the rights of other accounts."
        case "unicodepwd", "userpassword":
            return "Sets a password."
        case "altsecurityidentities":
            return "Sets which certificates or Kerberos names sign in as this account (altSecurityIdentities)."
        case "msds-groupmsamembership":
            return "Sets who may read this managed service account's password (msDS-GroupMSAMembership)."
        case "gplink":
            return "Links group policies to this container (gPLink), which then apply to everything beneath it."
        case "primarygroupid":
            return "Sets the account's primary group (primaryGroupID), a membership the group's member list does not show."
        default:
            return nil
        }
    }

    /// "add member: CN=A,…; CN=B,… and 3 more". Passwords and binary values
    /// are counted, never shown.
    static func describe(_ operation: LDAPModification.Operation, _ attribute: String, _ values: [Data]) -> String {
        let base = attribute.lowercased()
        let hidden = ["unicodepwd", "userpassword", "ntsecuritydescriptor", "msds-keycredentiallink"].contains(base)
            || values.contains(where: AttributeFormatter.isBinary)
        guard !values.isEmpty else { return operation == .delete ? "delete \(attribute) (every value)" : "\(operation.label) \(attribute)" }
        if hidden { return "\(operation.label) \(attribute) (\(values.count == 1 ? "1 value" : "\(values.count) values"), not shown)" }
        let shown = values.prefix(3).map { VisibleText.reveal(String(decoding: $0.prefix(300), as: UTF8.self)) }
        let more = values.count > 3 ? " and \(values.count - 3) more" : ""
        return "\(operation.label) \(attribute): \(shown.joined(separator: "; "))\(more)"
    }
}

/// The import log: one line per record. A DN or a server's message can
/// hold a line break, which would otherwise start a line of its own and
/// make the log say something that did not happen.
public enum LDIFImportLog {
    public static func line(_ record: LDIFRecord, ok: Bool, message: String) -> String {
        var text = "line \(record.line)\t\(record.summary)\t\(escape(record.dn))\t\(ok ? "OK" : "FAILED")"
        if !message.isEmpty { text += "\t\(escape(message))" }
        return text + "\n"
    }

    /// Line breaks, tabs and other controls written out (\n, \t, \u{…}).
    public static func escape(_ text: String) -> String {
        var out = ""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.properties.generalCategory == .control || scalar.properties.generalCategory == .lineSeparator
                    || scalar.properties.generalCategory == .paragraphSeparator {
                    out += String(format: "\\u{%X}", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out
    }

    /// `name.import-log.txt` beside the LDIF, or, when that exists already,
    /// `name.import-log-2.txt` and on: an earlier import's log is kept.
    public static func url(beside file: URL, exists: (URL) -> Bool = { FileManager.default.fileExists(atPath: $0.path) }) -> URL {
        let stem = file.deletingPathExtension()
        let first = stem.appendingPathExtension("import-log.txt")
        guard exists(first) else { return first }
        for number in 2...9_999 {
            let next = URL(fileURLWithPath: stem.path + ".import-log-\(number).txt")
            if !exists(next) { return next }
        }
        return URL(fileURLWithPath: stem.path + ".import-log-\(UUID().uuidString).txt")
    }
}
