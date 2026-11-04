// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

/// Deletes an entry, and with it everything beneath it when the user agrees.
struct DeleteEntrySheet: View {
    let session: DirectorySession
    let dn: String
    @Environment(\.dismiss) private var dismiss
    @State private var descendants: Int?
    /// The count stopped early (the server's limits, or 100,000), so there may be more.
    @State private var atLeast = false
    @State private var counting = true
    @State private var deleting = false
    @State private var progress: (Int, Int)?
    @State private var error: String?
    @State private var confirmText = ""

    private var name: String { DN.displayName(dn) }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "trash.fill").font(.system(size: 30)).foregroundStyle(.red)
                VStack(alignment: .leading, spacing: 6) {
                    Text("Delete “\(name)”?").font(.headline)
                    Text(dn).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            if counting {
                HStack { ProgressView().controlSize(.small); Text("Checking for entries beneath it…").foregroundStyle(.secondary) }
            } else if let descendants, descendants > 0 {
                Label("It contains \(atLeast ? "at least " : "")\(descendants.formatted()) \(descendants == 1 && !atLeast ? "entry" : "entries"), which will be deleted too.",
                      systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                Text(session.server?.supportsTreeDelete == true
                     ? "The server deletes the subtree in one operation (tree delete)."
                     : "They are deleted one by one, deepest first.")
                    .font(.caption).foregroundStyle(.secondary)
                TextField("Type \(name) to confirm", text: $confirmText).textFieldStyle(.roundedBorder)
            } else {
                Text("This cannot be undone.").foregroundStyle(.secondary)
            }
            if let progress {
                ProgressView(value: Double(progress.0), total: Double(max(progress.1, 1))) {
                    Text("Deleted \(progress.0) of \(progress.1)")
                }
            }
            if let error { Text(error).foregroundStyle(.red).font(.callout).textSelection(.enabled) }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).disabled(deleting)
                Button(role: .destructive) { delete() } label: {
                    if deleting { ProgressView().controlSize(.small) } else { Text((descendants ?? 0) > 0 ? "Delete All" : "Delete") }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(counting || deleting || ((descendants ?? 0) > 0 && confirmText != name))
            }
        }
        .padding(20)
        .frame(width: 480)
        .task { await count() }
    }

    private func count() async {
        let request = LDAPSearchRequest(base: dn, scope: .subtree, attributes: ["1.1"])
        let found = try? await session.run { try await $0.pagedSearch(request, pageSize: 500, limit: 100_000) }
        descendants = max(0, (found?.entries.count ?? 1) - 1)
        atLeast = found.map { $0.stoppedAtLimit || $0.result.code != .success } ?? false
        counting = false
    }

    private func delete() {
        deleting = true
        error = nil
        let parent = DN.parent(dn) ?? ""
        let useTreeDelete = (descendants ?? 0) > 0 && session.server?.supportsTreeDelete == true
        let hasChildren = (descendants ?? 0) > 0
        Task {
            let gone = UndoPlan.impossible(dn: dn, why: "A deleted entry cannot be brought back here. Active Directory keeps deleted objects in its Recycle Bin when that is turned on.")
            let ok = await session.change("Deleted \(name).", refreshing: [parent], select: parent.isEmpty ? nil : parent, undo: gone) { connection in
                if hasChildren {
                    try await connection.deleteSubtree(dn, useTreeDelete: useTreeDelete, progress: { done, total in
                        Task { @MainActor in progress = (done, total) }
                    })
                } else {
                    try await connection.delete(dn)
                }
            }
            deleting = false
            if ok { dismiss() } else { error = session.notice?.message }
        }
    }
}

/// Renames an entry (new RDN value) and/or moves it to another container.
struct RenameMoveSheet: View {
    let session: DirectorySession
    let dn: String
    var startWithMove = false
    @Environment(\.dismiss) private var dismiss
    @State private var newValue = ""
    @State private var newParent = ""
    @State private var keepOldValue = false
    @State private var saving = false
    @State private var error: String?
    @State private var choosingParent = false

    private var rdnAttribute: String { DN.rdnAttribute(dn) ?? "cn" }
    private var oldParent: String { DN.parent(dn) ?? "" }
    /// Named by several values (`cn=John+uid=jdoe`): the whole RDN is edited as
    /// written, since rebuilding it from one value would drop the others.
    private var multiValued: Bool { DN.isMultiValued(rdn: DN.rdn(dn)) }
    private var newRDN: String {
        let typed = newValue.trimmingCharacters(in: .whitespaces)
        return multiValued ? typed : "\(rdnAttribute)=\(DN.escape(typed))"
    }
    private var targetParent: String { newParent.trimmingCharacters(in: .whitespaces) }
    private var moving: Bool { !targetParent.isEmpty && !DN.isSame(targetParent, oldParent) }
    private var renaming: Bool {
        let typed = newValue.trimmingCharacters(in: .whitespaces)
        return multiValued ? !DN.isSame(typed, DN.rdn(dn)) : typed != DN.rdnValue(dn)
    }
    private var newDN: String { "\(newRDN),\(moving ? targetParent : oldParent)" }

    private var problem: String? {
        if newValue.trimmingCharacters(in: .whitespaces).isEmpty { return "Enter a name." }
        if !moving && !renaming { return startWithMove ? "Choose another container." : "Change the name or the container." }
        return nil
    }

    var body: some View {
        SheetLayout(title: startWithMove ? "Move “\(DN.displayName(dn))”" : "Rename “\(DN.displayName(dn))”",
                    subtitle: dn, width: 580) {
            Form {
                Section {
                    FieldRow(label: "Name", help: multiValued ? "The entry's RDN, with each of its values, such as cn=John+uid=jdoe."
                                                              : "The new value of \(rdnAttribute), the attribute this entry is named by.") {
                        HStack(spacing: 6) {
                            if !multiValued { Text("\(rdnAttribute)=").foregroundStyle(.secondary) }
                            TextField("Name", text: $newValue).labelsHidden().textFieldStyle(.roundedBorder)
                        }
                    }
                    Toggle("Keep the old name as an extra value of \(rdnAttribute)", isOn: $keepOldValue)
                        .formSwitch("Keep the old name as an extra value of \(rdnAttribute)")
                        .disabled(!renaming)
                }
                Section {
                    DNFieldRow(label: "In", dn: $newParent) { choosingParent = true }
                    if session.isMicrosoft, moving {
                        Label("Moving to another OU changes which Group Policy applies to it.", systemImage: "info.circle")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
                Section {
                    ValueRow(label: "New DN", value: newDN, monospaced: true)
                }
            }
            .formStyle(.grouped)
            .formLabelWidth(64)
            .hugsContent()
        } status: {
            SheetStatus(problem: problem, error: error)
        } buttons: {
            Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
            Button(moving ? (renaming ? "Rename and Move" : "Move") : "Rename") { save() }
                .keyboardShortcut(.defaultAction)
                .disabled(saving || problem != nil)
        }
        .onAppear {
            newValue = multiValued ? DN.rdn(dn) : DN.rdnValue(dn)
            newParent = oldParent
        }
        .sheet(isPresented: $choosingParent) {
            DNPickerSheet(session: session, containersOnly: true, startAt: targetParent.isEmpty ? oldParent : targetParent) { picked in
                if let first = picked.first { newParent = first }
            }
        }
    }

    private func save() {
        saving = true
        error = nil
        let target = newDN
        let rdn = newRDN
        let superior = moving ? targetParent : nil
        let deleteOld = !keepOldValue
        let containers = [oldParent] + (moving ? [targetParent] : [])
        let oldRDN = DN.rdn(dn)
        let oldParent = self.oldParent
        // Back under its old name and, if it moved, its old parent. A kept old
        // value is still there, so renaming back removes only the new one.
        let back = UndoPlan.inverse(dn: target, undoneAt: dn) {
            try await $0.modifyDN(target, newRDN: oldRDN, deleteOldRDN: true, newSuperior: superior == nil ? nil : oldParent)
        }
        Task {
            let ok = await session.change(moving ? "Moved to \(DN.canonicalName(targetParent))." : "Renamed.",
                                          refreshing: containers, select: target, undo: back) {
                try await $0.modifyDN(dn, newRDN: rdn, deleteOldRDN: deleteOld, newSuperior: superior)
            }
            saving = false
            if ok { dismiss() } else { error = session.notice?.message }
        }
    }
}
