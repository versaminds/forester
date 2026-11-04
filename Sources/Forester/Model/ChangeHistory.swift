// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import LDAPKit

/// A change made through this window since connecting, and how to take it back.
struct ChangeRecord: Identifiable {
    let id = UUID()
    let date = Date()
    let summary: String
    let dn: String
    /// How to take the change back; nil when it cannot be, for `notUndoable`.
    var undo: UndoStep?
    var notUndoable: String?
    var undone = false

    var canUndo: Bool { undo != nil && !undone }
}

/// How the caller of `DirectorySession.change` wants its change taken back.
enum UndoPlan {
    /// The values of these attributes are read before and after the change;
    /// undoing puts the earlier ones back, after checking that nobody changed
    /// them since. `controls` go with both reads and the undo itself (the
    /// security descriptor needs one to be read at all).
    case attributes(dn: String, names: [String], controls: [LDAPControl] = [])
    /// The caller knows the opposite operation (a rename back, deleting what
    /// was created). Undoing it is refused, unless confirmed, once the entry
    /// has changed since. `keepsChange` false: the change itself is not kept
    /// for a redo, because it holds something secret (a new user's password).
    /// `undoneAt`: where the entry is once undone, when that is not `dn` (a
    /// rename goes back to its old name).
    case inverse(dn: String, undoneAt: String? = nil, keepsChange: Bool = true, (LDAPConnection) async throws -> Void)
    /// Cannot be taken back, for this reason (shown in the change history).
    case impossible(dn: String, why: String)

    var dn: String {
        switch self {
        case .attributes(let dn, _, _), .inverse(let dn, _, _, _), .impossible(let dn, _): return dn
        }
    }

    /// Passwords cannot be read back, so a change to one cannot be put back.
    static let unreadable: Set<String> = ["unicodepwd", "userpassword", "clearpassword", "sambantpassword", "sambalmpassword"]

    /// Attribute values on one entry, put back as they were.
    static func values(_ dn: String, _ names: [String], controls: [LDAPControl] = []) -> UndoPlan {
        if names.contains(where: { unreadable.contains($0.lowercased()) }) {
            return .impossible(dn: dn, why: "A password cannot be read back, so it cannot be put back.")
        }
        return .attributes(dn: dn, names: names, controls: controls)
    }
}

/// The inverse of one recorded change.
struct UndoStep {
    let dn: String
    let names: [String]
    let controls: [LDAPControl]
    /// For an attribute change: the values it left, checked before undoing.
    let expected: LDAPEntry?
    /// For an attribute change: the modifications that put the old values back.
    let modifications: [LDAPModification]
    /// For a change with a known opposite.
    let action: ((LDAPConnection) async throws -> Void)?
    /// The change itself, for redoing it after `action` undid it.
    var redo: ((LDAPConnection) async throws -> Void)?
    /// Where the entry is once `action` has run.
    var undoneAt: String?
}

extension DirectorySession {
    /// What the attributes of a plan hold now. nil when they could not be read
    /// whole, which makes the change not undoable rather than undone wrongly.
    func snapshot(_ dn: String, _ names: [String], controls: [LDAPControl]) async -> LDAPEntry?? {
        do {
            let entry = try await run { connection -> LDAPEntry? in
                guard let read = try await connection.read(dn, attributes: names, controls: controls) else { return nil }
                return try await connection.completingRangedAttributes(read)
            }
            // A range the server would not finish is part of a list, not all of it.
            if let entry, entry.attributes.contains(where: { $0.name.lowercased().contains(";range=") }) { return .none }
            return .some(entry)
        } catch {
            return .none
        }
    }

    /// Records a change that worked, with its way back, and offers it to
    /// Edit › Undo unless the change is itself an undo or redo (whose way
    /// back is already there as Redo or Undo).
    func record(_ summary: String, plan: UndoPlan, before: LDAPEntry??, registering: Bool,
                change body: ((LDAPConnection) async throws -> Void)? = nil) async {
        var record: ChangeRecord
        switch plan {
        case .impossible(let dn, let why):
            record = ChangeRecord(summary: summary, dn: dn, undo: nil, notUndoable: why)
        case .inverse(let dn, let undoneAt, let keepsChange, let action):
            // When the entry last changed, to notice a change made since.
            let after = await snapshot(dn, Self.changeStamps, controls: [])
            record = ChangeRecord(summary: summary, dn: dn,
                                  undo: UndoStep(dn: dn, names: Self.changeStamps, controls: [], expected: after ?? nil, modifications: [],
                                                 action: action, redo: keepsChange ? body : nil, undoneAt: undoneAt ?? dn))
        case .attributes(let dn, let names, let controls):
            guard let before, let after = await snapshot(dn, names, controls: controls) else {
                record = ChangeRecord(summary: summary, dn: dn, undo: nil,
                                      notUndoable: "The values could not be read in full before and after the change.")
                break
            }
            let modifications = Self.inverse(names: names, before: before, after: after, schema: schema)
            record = modifications.isEmpty
                ? ChangeRecord(summary: summary, dn: dn, undo: nil, notUndoable: "Nothing changed.")
                : ChangeRecord(summary: summary, dn: dn,
                               undo: UndoStep(dn: dn, names: names, controls: controls, expected: after,
                                              modifications: modifications, action: nil))
        }
        history.insert(record, at: 0)
        if history.count > Self.historyLimit { history.removeLast(history.count - Self.historyLimit) }
        if record.canUndo, registering {
            let box = RecordBox()
            box.id = record.id
            registerReversal(of: box, name: summary.trimmingCharacters(in: CharacterSet(charactersIn: ".")))
        }
    }

    /// The change a menu item reverses. Undoing runs on the network, after
    /// the menu has already moved the item to Redo, so the record the undo
    /// makes is filled in when it exists.
    final class RecordBox {
        var id: UUID?
    }

    /// Puts the reversal of `box`'s change on the window's undo stack: as Undo
    /// normally, and as Redo when called while undoing (and back again).
    private func registerReversal(of box: RecordBox, name: String) {
        guard let undoManager else { return }
        undoManager.registerUndo(withTarget: self) { session in
            let next = RecordBox()
            session.registerReversal(of: next, name: name)
            Task { @MainActor in
                guard let id = box.id else {
                    session.report("The change before this one did not finish, so there is nothing to reverse.", isError: true)
                    return
                }
                next.id = await session.undo(id, registering: false)
            }
        }
        undoManager.setActionName(name)
    }

    static let historyLimit = 200
    /// What every change to an entry moves: AD's and the LDAP standard's.
    /// The timestamps count in seconds; the counters (AD's update sequence
    /// number, OpenLDAP's change sequence number) move with every change.
    static let changeStamps = ["whenChanged", "modifyTimestamp", "uSNChanged", "entryCSN"]

    /// "Saved description." undone reads "Undid: Saved description.", and
    /// undone again "Redid: Saved description.", never "Undid: Undid: …".
    static func reversal(of summary: String) -> String {
        let bare = summary.trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if bare.hasPrefix("Undid: ") { return "Redid: " + bare.dropFirst(7) + "." }
        if bare.hasPrefix("Redid: ") { return "Undid: " + bare.dropFirst(7) + "." }
        return "Undid: \(bare)."
    }

    /// The modifications that turn `after` back into `before` for `names`:
    /// a single value is replaced, and in a list only the values the change
    /// added or removed are touched, so values others added meanwhile stay.
    static func inverse(names: [String], before: LDAPEntry?, after: LDAPEntry?, schema: LDAPSchema?) -> [LDAPModification] {
        var modifications: [LDAPModification] = []
        for name in names {
            let old = before?.values(name) ?? []
            let new = after?.values(name) ?? []
            guard Set(old) != Set(new) else { continue }
            if old.isEmpty {
                modifications.append(LDAPModification(.delete, name))
            } else if new.isEmpty || schema?.isSingleValued(name) == true || (old.count == 1 && new.count == 1) {
                modifications.append(LDAPModification(.replace, name, old))
            } else {
                let removed = old.filter { !new.contains($0) }
                let added = new.filter { !old.contains($0) }
                // Deleting first: a value the server takes for the same one
                // (case differs) must be gone before the old spelling returns.
                if !added.isEmpty { modifications.append(LDAPModification(.delete, name, added)) }
                if !removed.isEmpty { modifications.append(LDAPModification(.add, name, removed)) }
            }
        }
        return modifications
    }

    /// Something that undoing would overwrite: the attributes no longer hold
    /// what the change left. nil when they still do.
    func undoConflict(_ id: UUID) async -> String? {
        guard let record = history.first(where: { $0.id == id }), let step = record.undo else { return nil }
        guard let current = await snapshot(step.dn, step.names, controls: step.controls) else {
            return "The values could not be read to check them."
        }
        if step.action != nil {
            // A known opposite: the entry must still be as the change left it.
            guard let expected = step.expected else { return nil }
            guard let current else { return "\(DN.displayName(step.dn)) no longer exists." }
            let moved = step.names.contains { Set(current.values($0)) != Set(expected.values($0)) }
            return moved ? "\(DN.displayName(step.dn)) has changed since." : nil
        }
        let changed = step.names.filter { Set(current?.values($0) ?? []) != Set(step.expected?.values($0) ?? []) }
        return changed.isEmpty ? nil : "\(changed.joined(separator: ", ")) changed again since."
    }

    /// Takes a recorded change back. Unless `force`, an attribute change is
    /// undone only if nobody changed those attributes since; otherwise the
    /// change history offers to undo it anyway.
    /// Returns the record of the undo itself, which can be undone in turn.
    @discardableResult
    func undo(_ id: UUID, force: Bool = false, registering: Bool = true) async -> UUID? {
        guard let index = history.firstIndex(where: { $0.id == id }) else { return nil }
        guard let step = history[index].undo, !history[index].undone else {
            report(history[index].undone ? "That change is already undone." : (history[index].notUndoable ?? "That change cannot be undone."),
                   isError: true)
            return nil
        }
        let summary = history[index].summary
        if !force, let conflict = await undoConflict(id) {
            report("Not undone: \(conflict) Open Change History to undo it anyway.", isError: true)
            return nil
        }
        // Undoing is a change like any other, so it can be undone in turn: an
        // attribute change by its values, a known opposite by the change itself.
        let plan: UndoPlan
        if step.action == nil {
            plan = .attributes(dn: step.dn, names: step.names, controls: step.controls)
        } else if let redo = step.redo {
            plan = .inverse(dn: step.undoneAt ?? step.dn, undoneAt: step.dn, redo)
        } else {
            plan = .impossible(dn: step.dn, why: "To redo it, make the change again: what it sent (such as a password) is not kept.")
        }
        let done = Self.reversal(of: summary)
        let ok = await change(done, undo: plan, registersUndo: registering) { connection in
            if let action = step.action {
                try await action(connection)
            } else {
                try await connection.modify(step.dn, step.modifications, controls: step.controls)
            }
        }
        guard ok else { return nil }
        if let index = history.firstIndex(where: { $0.id == id }) { history[index].undone = true }
        return history.first?.id
    }
}
