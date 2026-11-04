// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

/// The readable summary: the attributes an administrator looks for first,
/// labelled in words and decoded, grouped by what kind of entry this is.
struct OverviewView: View {
    let session: DirectorySession
    let entry: LDAPEntry
    let kind: ObjectKind

    struct Field {
        let label: String
        let attributes: [String]
        init(_ label: String, _ attributes: String...) {
            self.label = label
            self.attributes = attributes
        }
    }

    struct Section: Identifiable {
        let title: String
        let fields: [Field]
        var id: String { title }
    }

    var body: some View {
        ScrollView {
            if kind == .rootDSE, let server = session.server {
                ServerInfoContent(session: session, server: server)
                    .padding(16)
            } else {
                VStack(alignment: .leading, spacing: 16) {
                if [.user, .computer, .serviceAccount].contains(kind), AccountLockMethod.method(for: entry, session: session) != nil {
                    AccountPanel(session: session, entry: entry)
                }
                // One grid for every section, so the labels line up down the page.
                Grid(alignment: .topLeading, horizontalSpacing: 14, verticalSpacing: 7) {
                    ForEach(Self.sections(for: kind)) { section in
                        let rows = section.fields.compactMap { field -> (Field, String, [Data])? in
                            guard let attribute = field.attributes.first(where: { !entry.values($0).isEmpty }) else { return nil }
                            return (field, attribute, entry.values(attribute))
                        }
                        if !rows.isEmpty {
                            GridRow {
                                Text(section.title)
                                    .font(.headline)
                                    .padding(.top, section.id == Self.sections(for: kind).first?.id ? 0 : 12)
                                    .gridCellColumns(2)
                            }
                            ForEach(rows, id: \.0.label) { field, attribute, values in
                                GridRow {
                                    Text(field.label)
                                        .foregroundStyle(.secondary)
                                        .gridColumnAlignment(.trailing)
                                        .help(attribute)
                                    ValueList(session: session, attribute: attribute, values: values)
                                }
                            }
                        }
                    }
                }
                .font(.callout)
                .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(16)
            }
        }
    }

    static func sections(for kind: ObjectKind) -> [Section] {
        let object = Section(title: "Object", fields: [
            Field("SID", "objectSid"), Field("GUID", "objectGUID", "entryUUID"),
            Field("Created", "whenCreated", "createTimestamp"), Field("Modified", "whenChanged", "modifyTimestamp"),
            Field("Canonical name", "canonicalName"), Field("Object classes", "objectClass"),
        ])
        switch kind {
        case .user, .contact, .serviceAccount:
            return [
                Section(title: "Identity", fields: [
                    Field("Display name", "displayName"), Field("First name", "givenName"), Field("Last name", "sn"),
                    Field("Account name", "sAMAccountName"), Field("Sign-in name", "userPrincipalName"),
                    Field("User ID", "uid"), Field("Email", "mail"), Field("Employee ID", "employeeID", "employeeNumber"),
                ]),
                Section(title: "Organisation", fields: [
                    Field("Job title", "title"), Field("Department", "department", "ou"), Field("Company", "company", "o"),
                    Field("Manager", "manager"), Field("Direct reports", "directReports"),
                    Field("Office", "physicalDeliveryOfficeName", "roomNumber"), Field("Phone", "telephoneNumber"),
                    Field("Mobile", "mobile"), Field("Description", "description"),
                ]),
                Section(title: "Account", fields: [
                    Field("Status", "userAccountControl"),
                    Field("Password last set", "pwdLastSet", "pwdChangedTime"),
                    Field("Password expires", "msDS-UserPasswordExpiryTimeComputed", "shadowExpire"),
                    Field("Account expires", "accountExpires"),
                    Field("Last sign-in", "lastLogonTimestamp"), Field("Last sign-in on this DC", "lastLogon"),
                    Field("Failed sign-ins", "badPwdCount"), Field("Last failed sign-in", "badPasswordTime"),
                    Field("Locked out at", "lockoutTime", "pwdAccountLockedTime"), Field("Sign-in count", "logonCount"),
                    Field("Password policy", "msDS-ResultantPSO"),
                    Field("Service principal names", "servicePrincipalName"),
                ]),
                Section(title: "Unix", fields: [
                    Field("UID number", "uidNumber"), Field("GID number", "gidNumber"),
                    Field("Home directory", "homeDirectory", "unixHomeDirectory"), Field("Shell", "loginShell"),
                ]),
                object,
            ]
        case .computer, .domainController:
            return [
                Section(title: "Computer", fields: [
                    Field("DNS name", "dNSHostName"), Field("Account name", "sAMAccountName"),
                    Field("Operating system", "operatingSystem"), Field("Version", "operatingSystemVersion"),
                    Field("Description", "description"), Field("Location", "location"), Field("Managed by", "managedBy"),
                ]),
                Section(title: "Account", fields: [
                    Field("Status", "userAccountControl"), Field("Last seen", "lastLogonTimestamp"),
                    Field("Machine password set", "pwdLastSet"),
                    Field("LAPS password expires", "msLAPS-PasswordExpirationTime", "ms-Mcs-AdmPwdExpirationTime"),
                    Field("Encryption types", "msDS-SupportedEncryptionTypes"),
                    Field("Delegates to", "msDS-AllowedToDelegateTo"),
                    Field("Service principal names", "servicePrincipalName"),
                ]),
                object,
            ]
        case .group:
            return [
                Section(title: "Group", fields: [
                    Field("Account name", "sAMAccountName"), Field("Type", "groupType"), Field("Description", "description"),
                    Field("Email", "mail"), Field("Managed by", "managedBy", "owner"), Field("Notes", "info"),
                    Field("GID number", "gidNumber"),
                ]),
                object,
            ]
        case .domain:
            return [
                Section(title: "Domain", fields: [
                    Field("Description", "description"), Field("Functional level", "msDS-Behavior-Version"),
                    Field("Linked policies", "gPLink"), Field("Managed by", "managedBy"),
                ]),
                Section(title: "Password and lockout policy", fields: [
                    Field("Maximum password age", "maxPwdAge"), Field("Minimum password age", "minPwdAge"),
                    Field("Minimum length", "minPwdLength"), Field("History length", "pwdHistoryLength"),
                    Field("Properties", "pwdProperties"), Field("Lockout threshold", "lockoutThreshold"),
                    Field("Lockout duration", "lockoutDuration"), Field("Lockout counter reset", "lockoutObservationWindow"),
                ]),
                object,
            ]
        case .organizationalUnit, .container, .builtin, .organization:
            return [
                Section(title: "Container", fields: [
                    Field("Name", "ou", "cn", "o"), Field("Description", "description"),
                    Field("Linked policies", "gPLink"), Field("Managed by", "managedBy"),
                ]),
                object,
            ]
        case .groupPolicy:
            return [
                Section(title: "Group Policy object", fields: [
                    Field("Name", "displayName"), Field("SYSVOL path", "gPCFileSysPath"), Field("Version", "versionNumber"),
                    Field("Flags", "flags"), Field("WMI filter", "gPCWQLFilter"),
                ]),
                object,
            ]
        default:
            return [
                Section(title: "Entry", fields: [
                    Field("Name", "cn", "ou", "o", "dc", "uid"), Field("Description", "description"),
                    Field("Email", "mail"), Field("Members", "member", "uniqueMember", "memberUid"),
                ]),
                object,
            ]
        }
    }
}

/// One attribute's values, decoded; DNs become links.
struct ValueList: View {
    let session: DirectorySession
    let attribute: String
    let values: [Data]
    var limit = 8

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            ForEach(Array(values.prefix(limit).enumerated()), id: \.offset) { _, value in
                ValueText(session: session, attribute: attribute, value: value)
            }
            if values.count > limit {
                Button("\(values.count - limit) more…") { session.inspector.tab = .attributes }
                    .buttonStyle(.link)
                    .font(.caption)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct ValueText: View {
    let session: DirectorySession
    let attribute: String
    let value: Data

    var body: some View {
        let formatted = AttributeFormatter.format(attribute, value)
        if formatted.kind == .distinguishedName, let target = formatted.links.first {
            Button(DN.displayName(target)) { session.open(target) }
                .buttonStyle(.link)
                .help(target)
                .contextMenu { Button("Copy DN") { Pasteboard.copy(target) } }
        } else if formatted.kind == .gpLink, !formatted.links.isEmpty {
            GPOLinkList(session: session, links: AttributeFormatter.gpLinks(formatted.detail ?? ""))
        } else {
            Text(formatted.text)
                .textSelection(.enabled)
                .help(formatted.detail ?? "")
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Linked Group Policy objects by their display name rather than `{GUID}`.
struct GPOLinkList: View {
    let session: DirectorySession
    let links: [AttributeFormatter.GPLink]
    @State private var names: [String: String] = [:]

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(links, id: \.self) { link in
                Button((names[DN.normalized(link.dn)] ?? DN.rdnValue(link.dn)) + link.options) { session.open(link.dn) }
                    .buttonStyle(.link)
                    .help(link.dn)
            }
        }
        .task(id: links) {
            for link in links {
                if let entry = try? await session.run({ try await $0.read(link.dn, attributes: ["displayName"]) }),
                   let name = entry.string("displayName") {
                    names[DN.normalized(link.dn)] = name
                }
            }
        }
    }
}
