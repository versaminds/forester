// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

/// What an entry is, decided from its object classes, for icons and for which
/// overview to show.
enum ObjectKind: String, CaseIterable, Sendable {
    case rootDSE, domain, organizationalUnit, container, builtin, organization
    case user, computer, domainController, serviceAccount, contact, group
    case foreignSecurityPrincipal, groupPolicy, printer, sharedFolder, other

    /// The attributes the tree asks for, enough to pick an icon and dim disabled accounts.
    static let treeAttributes = ["objectClass", "hasSubordinates", "groupType"] + disabledAttributes

    /// What says an account is disabled, on each kind of server (see `isDisabled`).
    static let disabledAttributes = ["userAccountControl", "nsAccountLock", "loginDisabled", "pwdAccountLockedTime"]

    static func classify(_ entry: LDAPEntry) -> ObjectKind {
        if entry.dn.isEmpty { return .rootDSE }
        let classes = Set(entry.objectClasses.map { $0.lowercased() })
        let uac = entry.int("userAccountControl") ?? 0
        if classes.contains("msds-groupmanagedserviceaccount") || classes.contains("msds-managedserviceaccount")
            || classes.contains("msds-delegatedmanagedserviceaccount") {
            return .serviceAccount
        }
        if classes.contains("computer") { return uac & 0x2000 != 0 ? .domainController : .computer }
        if classes.contains("user") || classes.contains("inetorgperson") || classes.contains("posixaccount")
            || classes.contains("organizationalperson") || classes.contains("person") || classes.contains("account") {
            return classes.contains("contact") ? .contact : .user
        }
        if classes.contains("contact") { return .contact }
        if classes.contains("group") || classes.contains("groupofnames") || classes.contains("groupofuniquenames")
            || classes.contains("posixgroup") || classes.contains("groupofurls") {
            return .group
        }
        if classes.contains("foreignsecurityprincipal") { return .foreignSecurityPrincipal }
        if classes.contains("grouppolicycontainer") { return .groupPolicy }
        if classes.contains("organizationalunit") { return .organizationalUnit }
        if classes.contains("domaindns") || classes.contains("domain") || classes.contains("dcobject") { return .domain }
        if classes.contains("builtindomain") { return .builtin }
        if classes.contains("organization") { return .organization }
        if classes.contains("printqueue") { return .printer }
        if classes.contains("volume") { return .sharedFolder }
        if classes.contains("container") || classes.contains("lostandfound") || classes.contains("configuration")
            || classes.contains("dmd") || classes.contains("msds-quotacontainer") || classes.contains("subschema") {
            return .container
        }
        return .other
    }

    var label: String {
        switch self {
        case .rootDSE: return "Root DSE"
        case .domain: return "Domain"
        case .organizationalUnit: return "Organizational unit"
        case .container: return "Container"
        case .builtin: return "Built-in domain"
        case .organization: return "Organization"
        case .user: return "User"
        case .computer: return "Computer"
        case .domainController: return "Domain controller"
        case .serviceAccount: return "Managed service account"
        case .contact: return "Contact"
        case .group: return "Group"
        case .foreignSecurityPrincipal: return "Foreign security principal"
        case .groupPolicy: return "Group Policy object"
        case .printer: return "Printer"
        case .sharedFolder: return "Shared folder"
        case .other: return "Entry"
        }
    }

    var symbol: String {
        switch self {
        case .rootDSE: return "info.circle"
        case .domain: return "globe"
        case .organizationalUnit: return "folder"
        case .container, .builtin: return "archivebox"
        case .organization: return "building.2"
        case .user: return "person.fill"
        case .computer: return "desktopcomputer"
        case .domainController: return "server.rack"
        case .serviceAccount: return "gearshape.fill"
        case .contact: return "person.crop.square"
        case .group: return "person.3.fill"
        case .foreignSecurityPrincipal: return "person.badge.key"
        case .groupPolicy: return "doc.badge.gearshape"
        case .printer: return "printer"
        case .sharedFolder: return "externaldrive.connected.to.line.below"
        case .other: return "doc"
        }
    }

    var tint: Color {
        switch self {
        case .rootDSE: return .secondary
        case .domain: return .blue
        case .organizationalUnit: return .orange
        case .container, .builtin: return .brown
        case .organization: return .indigo
        case .user, .contact: return .teal
        case .computer, .domainController: return .gray
        case .serviceAccount: return .gray
        case .group: return .purple
        case .foreignSecurityPrincipal: return .pink
        case .groupPolicy: return .green
        case .printer, .sharedFolder, .other: return .secondary
        }
    }

    /// Whether the tree should offer to expand it before knowing. Users and
    /// groups rarely hold children and showing a disclosure triangle on every
    /// one of thousands is noise; computers often do (BitLocker keys, SCPs).
    var mayHaveChildren: Bool {
        switch self {
        case .user, .contact, .group, .foreignSecurityPrincipal, .printer, .sharedFolder, .serviceAccount: return false
        default: return true
        }
    }

    var isContainer: Bool {
        switch self {
        case .domain, .organizationalUnit, .container, .builtin, .organization, .rootDSE: return true
        default: return false
        }
    }

    /// Sort containers before leaves, the way Finder and ADUC do.
    var sortRank: Int { isContainer ? 0 : 1 }
}

/// An account is disabled: bit 0x2 of userAccountControl (Active Directory),
/// nsAccountLock (389 Directory Server), loginDisabled (eDirectory), or a
/// permanent password-policy lock (OpenLDAP). The same tests as
/// `AccountLockMethod.isDisabled`, for an entry of any kind.
func isDisabled(_ entry: LDAPEntry) -> Bool {
    if let uac = entry.int("userAccountControl") { return uac & 0x2 != 0 }
    return entry.string("nsAccountLock")?.uppercased() == "TRUE" || entry.string("loginDisabled")?.uppercased() == "TRUE"
        || entry.string("pwdAccountLockedTime") == "000001010000Z"
}

struct EntryIcon: View {
    let kind: ObjectKind
    var disabled = false
    var size: CGFloat? = nil

    var body: some View {
        Image(systemName: disabled && kind == .user ? "person.fill.xmark" : kind.symbol)
            .foregroundStyle(disabled ? Color.secondary : kind.tint)
            .opacity(disabled && kind != .user ? 0.5 : 1)
            .font(size.map { .system(size: $0) } ?? .system(size: 13))
            .frame(width: size.map { $0 * 1.6 } ?? 24, alignment: .center)
            .accessibilityLabel(disabled ? "\(kind.label), disabled" : kind.label)
    }
}
