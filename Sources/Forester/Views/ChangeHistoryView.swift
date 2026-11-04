// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

/// Every change made in this window since connecting, newest first, each with
/// Undo where it can be taken back and the reason where it cannot.
struct ChangeHistorySheet: View {
    let session: DirectorySession
    @Environment(\.dismiss) private var dismiss
    @State private var working: UUID?
    /// A change whose attributes moved on since, waiting for "undo anyway".
    @State private var conflict: (id: UUID, message: String)?

    var body: some View {
        SheetLayout(title: "Change History", subtitle: "Changes made in this window since it connected to \(session.profile.displayName).",
                    width: 640, height: 460) {
            if session.history.isEmpty {
                ContentUnavailableView("No Changes Yet", systemImage: "clock.arrow.circlepath",
                                       description: Text("Changes you make to the directory are listed here, and most can be undone."))
                    .frame(maxHeight: .infinity)
            } else {
                List(session.history) { record in row(record) }
                    .listStyle(.inset(alternatesRowBackgrounds: true))
            }
        } status: {
            Text("Edit › Undo (⌘Z) takes back the latest.").foregroundStyle(.secondary)
        } buttons: {
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
        }
        .alert("Undo anyway?", isPresented: Binding(get: { conflict != nil }, set: { if !$0 { conflict = nil } })) {
            Button("Undo Anyway", role: .destructive) {
                if let id = conflict?.id { run(id, force: true) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("\(conflict?.message ?? "") Undoing puts back what was there before your change and replaces what someone set since.")
        }
    }

    private func row(_ record: ChangeRecord) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: record.undone ? "arrow.uturn.backward.circle" : (record.undo == nil ? "minus.circle" : "checkmark.circle"))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(record.summary).strikethrough(record.undone)
                Text(record.dn.isEmpty ? "—" : DN.displayName(record.dn) + " · " + record.date.formatted(date: .omitted, time: .shortened))
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    .help(record.dn)
                if let why = record.notUndoable {
                    Text(why).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                } else if record.undone {
                    Text("Undone.").font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if record.canUndo {
                if working == record.id {
                    ProgressView().controlSize(.small)
                } else {
                    // Taking back an undo makes the change again, and says so.
                    let redo = record.summary.hasPrefix("Undid: ")
                    Button(redo ? "Redo" : "Undo") { check(record.id) }
                        .disabled(working != nil || !session.canWrite)
                        .help(session.canWrite ? (redo ? "Make this change again." : "Put back what this change replaced.")
                                               : (redo ? "Turn on editing to redo." : "Turn on editing to undo."))
                }
            }
        }
        .accessibilityElement(children: .combine)
        .padding(.vertical, 2)
    }

    private func check(_ id: UUID) {
        working = id
        Task {
            if let message = await session.undoConflict(id) {
                working = nil
                conflict = (id, message)
            } else {
                run(id, force: true)
            }
        }
    }

    private func run(_ id: UUID, force: Bool) {
        working = id
        Task {
            await session.undo(id, force: force)
            working = nil
        }
    }
}
