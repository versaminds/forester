// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

/// Who may do what with an Active Directory object: its owner and access
/// rules in words, in the order the server applies them, and what the
/// signed-in account itself may do here. With changes allowed, rules set on
/// the object are added, changed and removed, and the owner changed, as
/// Advanced Security in Active Directory Users and Computers does it.
struct PermissionsView: View {
    let session: DirectorySession
    let entry: LDAPEntry
    @State private var permissions: Permissions?
    @State private var names: [String: (name: String, dn: String?)] = [:]
    /// Names for the editor, with whoever it is given.
    @State private var labels: [String: String] = [:]
    @State private var guidNames: [String: SchemaGUIDName] = [:]
    @State private var loading = true
    @State private var error: String?
    @State private var filter = ""
    @State private var showInherited = true
    @State private var onlyChanges = false
    @State private var selection: Set<AccessRule.ID> = []
    @State private var editing: Editing?
    @State private var removing: AccessRule?

    enum Editing: Identifiable {
        case add
        case change(SecurityDescriptor.ACE, at: Int)
        case owner(String)

        var id: String {
            switch self {
            case .add: return "add"
            case .change(_, let index): return "change \(index)"
            case .owner: return "owner"
            }
        }
    }

    /// The one rule chosen in the table.
    private var chosen: AccessRule? {
        guard selection.count == 1, let id = selection.first else { return nil }
        return permissions?.rules.first { $0.id == id }
    }

    private var mayChangeRules: Bool { session.canWrite && permissions?.mayChangePermissions != false }
    private var mayChangeOwner: Bool { session.canWrite && permissions?.mayChangeOwner != false && permissions?.owner != nil }

    private var rules: [AccessRule] {
        let words = filter.lowercased().split(separator: " ").map(String.init)
        return (permissions?.rules ?? []).filter { rule in
            (showInherited || !rule.inherited) && (!onlyChanges || rule.isWrite)
                && words.allSatisfy { word in
                    name(rule.sid).lowercased().contains(word) || rule.access.contains { $0.lowercased().contains(word) }
                        || rule.appliesTo.lowercased().contains(word)
                }
        }
    }

    private func name(_ sid: String) -> String { names[sid]?.name ?? sid }

    var body: some View {
        Group {
            if loading {
                ProgressView("Reading permissions…").frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error {
                ContentUnavailableView("No Permissions", systemImage: "lock.shield", description: Text(error))
            } else if let permissions {
                VStack(alignment: .leading, spacing: 0) {
                    summary(permissions)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 10)
                    HStack(spacing: 12) {
                        TextField("Filter by who or what", text: $filter)
                            .textFieldStyle(.roundedBorder)
                            .frame(maxWidth: 260)
                        Toggle("Inherited", isOn: $showInherited)
                            .help("Rules this object takes from the containers above it")
                        Toggle("More than reading", isOn: $onlyChanges)
                            .help("Only rules that let someone change, create, delete or take over something")
                        Spacer()
                        Text("\(rules.count) of \(permissions.rules.count)").font(.callout).foregroundStyle(.secondary).monospacedDigit()
                    }
                    .toggleStyle(.checkbox)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 8)
                    Divider()
                    table
                    Divider()
                    editBar(permissions)
                    Text("In the order Active Directory applies them: rules set on this object first (denials before allowances), then inherited ones. A denial set here outweighs an allowance, and an allowance set here outweighs an inherited denial.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.horizontal, 16)
                        .padding(.bottom, 8)
                }
            }
        }
        // Again after every change in this window, an undo among them.
        .task(id: "\(entry.dn)|\(session.history.first?.id.uuidString ?? "")") { await load() }
        .sheet(item: $editing) { editing in
            switch editing {
            case .add:
                PermissionRuleSheet(session: session, dn: entry.dn, original: nil, guidNames: guidNames, names: $labels) {}
            case .change(let ace, let index):
                PermissionRuleSheet(session: session, dn: entry.dn, original: (ace, index), guidNames: guidNames, names: $labels) {}
            case .owner(let owner):
                OwnerSheet(session: session, dn: entry.dn, owner: owner, names: $labels) {}
            }
        }
        .alert("Remove this rule?", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } })) {
            Button("Remove Rule", role: .destructive) {
                guard let rule = removing, let change = removal(rule) else { return }
                Task { await session.changePermissions(of: entry.dn, change, words: words(change)) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            if let rule = removing, let change = removal(rule) {
                Text(words(change) + " The other rules stay as they are. Edit › Undo takes it back.")
            }
        }
    }

    private func removal(_ rule: AccessRule) -> PermissionChange? {
        guard let aces = permissions?.aces, aces.indices.contains(rule.id) else { return nil }
        return .remove(aces[rule.id], at: rule.id)
    }

    private func words(_ change: PermissionChange) -> String {
        change.words(who: { labels[$0] ?? name($0) }, names: { guidNames[$0] ?? SchemaGUIDName.builtIn[$0] })
    }

    /// Add, change and remove the rules set here, and change the owner.
    @ViewBuilder
    private func editBar(_ permissions: Permissions) -> some View {
        if session.canWrite {
            editButtons(permissions)
        } else {
            Text("Read-only. Click Read-only in the toolbar, or press ⌥⌘E, to change permissions.")
                .font(.caption).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
        }
    }

    private func editButtons(_ permissions: Permissions) -> some View {
        HStack(spacing: 8) {
            Button("Add Rule…") { editing = .add }
                .disabled(!mayChangeRules)
            Button("Change…") {
                if let rule = chosen { editing = .change(permissions.aces[rule.id], at: rule.id) }
            }
            .disabled(!mayChangeRules || chosen.map { $0.inherited || AccessRuleDraft(permissions.aces[$0.id]) == nil } ?? true)
            .help(chosen?.inherited == true ? "Inherited from a container above: change it there." : "Change the chosen rule")
            Button("Remove") { removing = chosen }
                .disabled(!mayChangeRules || chosen.map(\.inherited) ?? true)
                .help(chosen?.inherited == true ? "Inherited from a container above: remove it there." : "Remove the chosen rule")
            Spacer()
            Button("Change Owner…") { if let owner = permissions.owner { editing = .owner(owner) } }
                .disabled(!mayChangeOwner)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    private func summary(_ permissions: Permissions) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text("Owner").foregroundStyle(.secondary)
                if let owner = permissions.owner {
                    principal(owner)
                } else {
                    Text("Not readable")
                }
            }
            Text(youMay(permissions)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                .help("Attributes: " + permissions.writableAttributes.joined(separator: ", ")
                      + (permissions.creatableClasses.isEmpty ? "" : "\n\nObjects: " + permissions.creatableClasses.joined(separator: ", ")))
        }
        .font(.callout)
    }

    /// What the signed-in account may do here, as Active Directory reports it.
    private func youMay(_ permissions: Permissions) -> String {
        var parts: [String] = []
        let attributes = permissions.writableAttributes.count
        parts.append(attributes == 0 ? "write none of its attributes" : "write \(attributes) of its attributes")
        if !permissions.creatableClasses.isEmpty {
            let count = permissions.creatableClasses.count
            parts.append("create \(count == 1 ? "one kind" : "\(count) kinds") of object beneath it")
        }
        if permissions.mayChangePermissions == true { parts.append("change its permissions") }
        if permissions.mayChangeOwner == true { parts.append("change its owner") }
        // whoami answers "dn:CN=…" or, on AD, "u:DOMAIN\\user".
        let who = session.identity.map { identity -> String in
            if identity.hasPrefix("dn:") { return DN.displayName(String(identity.dropFirst(3))) }
            return identity.hasPrefix("u:") ? String(identity.dropFirst(2)) : identity
        } ?? "This account"
        return "\(who) may " + ListFormatter.localizedString(byJoining: parts) + "."
    }

    @ViewBuilder
    private func principal(_ sid: String) -> some View {
        if sid.isEmpty {
            Text("Unknown").foregroundStyle(.secondary)
        } else if let dn = names[sid]?.dn {
            Button(name(sid)) { session.open(dn) }.buttonStyle(.link).lineLimit(1).truncationMode(.middle).help("\(dn)\n\(sid)")
        } else {
            Text(name(sid)).lineLimit(1).truncationMode(.middle).help(sid)
        }
    }

    private var table: some View {
        Table(rules, selection: $selection) {
            TableColumn("") { rule in
                Image(systemName: !rule.understood ? "questionmark.circle" : (rule.allow ? "checkmark.circle" : "nosign"))
                    .foregroundStyle(rule.allow || !rule.understood ? Color.secondary : Color.red)
                    .help(verdict(rule))
                    .accessibilityLabel(verdict(rule))
            }
            .width(22)
            TableColumn("Who") { rule in principal(rule.sid) }
                .width(min: 90, ideal: 130)
            TableColumn("Access") { rule in
                Text((rule.allow || !rule.understood ? "" : "Deny: ") + rule.access.joined(separator: "; "))
                    .foregroundStyle(rule.allow || !rule.understood ? Color.primary : Color.red)
                    .lineLimit(2)
                    .help(rule.access.joined(separator: "\n") + "\n" + rule.detail)
            }
            .width(min: 150, ideal: 215)
            TableColumn("Applies to") { rule in
                Text(rule.appliesTo + (rule.inherited ? " (inherited)" : ""))
                    .foregroundStyle(rule.inherited ? Color.secondary : Color.primary)
                    .lineLimit(2)
                    .help(rule.appliesTo + (rule.inherited ? "\nInherited from a container above" : "\nSet on this object"))
            }
            .width(min: 110, ideal: 150)
        }
        .tableStyle(.inset(alternatesRowBackgrounds: true))
        .contextMenu(forSelectionType: AccessRule.ID.self) { ids in
            let picked = rules.filter { ids.contains($0.id) }
            Button("Copy") { Pasteboard.copy(picked.map(describe).joined(separator: "\n")) }
            if picked.count == 1, let rule = picked.first {
                Button("Copy SID") { Pasteboard.copy(rule.sid) }
                if let dn = names[rule.sid]?.dn { Button("Show \(name(rule.sid))") { session.open(dn) } }
            }
        }
    }

    private func verdict(_ rule: AccessRule) -> String {
        rule.understood ? (rule.allow ? "Allow" : "Deny") : "Not read"
    }

    private func describe(_ rule: AccessRule) -> String {
        "\(verdict(rule))\t\(name(rule.sid))\t\(rule.access.joined(separator: "; "))\t\(rule.appliesTo)\(rule.inherited ? "\tinherited" : "")"
    }

    private func load() async {
        loading = true
        error = nil
        do {
            let found = try await session.permissions(of: entry.dn)
            var sids = Set(found.rules.map(\.sid))
            if let owner = found.owner { sids.insert(owner) }
            let resolved = await session.principalNames(sids)
            let schemaNames = await session.schemaGUIDNames()
            // Another entry chosen meanwhile has its own load running.
            guard !Task.isCancelled else { return }
            names = resolved
            labels.merge(resolved.mapValues(\.name)) { _, new in new }
            guidNames = schemaNames
            permissions = found
            selection = []
        } catch {
            guard !Task.isCancelled else { return }
            permissions = nil
            self.error = error.localizedDescription
        }
        loading = false
    }
}
