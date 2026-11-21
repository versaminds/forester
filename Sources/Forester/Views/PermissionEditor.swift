// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

/// Who a rule is for, or who owns the object: someone from the directory,
/// one of the well-known groups, or a SID typed in.
struct PrincipalField: View {
    let session: DirectorySession
    @Binding var sid: String
    /// Names known for SIDs, extended with whoever is chosen here.
    @Binding var names: [String: PrincipalLabel]
    @State private var picking = false
    @State private var typing = false
    @State private var typed = ""
    @State private var problem: String?

    /// The well-known principals a rule is most often for, with this
    /// domain's own groups when its SID is known.
    private var wellKnown: [(String, String)] {
        var list = [("Everyone", "S-1-1-0"), ("Authenticated Users", "S-1-5-11"), ("Self", "S-1-5-10"),
                    ("Creator Owner", "S-1-3-0"), ("Administrators", "S-1-5-32-544"), ("Account Operators", "S-1-5-32-548"),
                    ("Pre-Windows 2000 Compatible Access", "S-1-5-32-554"), ("Enterprise Domain Controllers", "S-1-5-9")]
        if let domain = session.domainSID {
            list += [("Domain Admins", "\(domain)-512"), ("Domain Users", "\(domain)-513"), ("Domain Computers", "\(domain)-515")]
        }
        return list
    }

    var body: some View {
        FieldRow(label: "Who") {
            HStack {
                VStack(alignment: .leading, spacing: 1) {
                    Text(sid.isEmpty ? "No one chosen" : PrincipalLabel.name(sid, names[sid], domainSID: session.domainSID))
                        .foregroundStyle(sid.isEmpty ? .secondary : .primary)
                        .lineLimit(1).truncationMode(.middle)
                    // The DN tells two groups of one name apart; the SID is
                    // what a name typed or well known stands for.
                    if !sid.isEmpty {
                        Text(VisibleText.reveal(names[sid]?.dn ?? sid))
                            .font(.caption).foregroundStyle(.secondary)
                            .lineLimit(1).truncationMode(.middle)
                            .textSelection(.enabled)
                    }
                }
                .help(sid)
                Spacer()
                Menu("Choose") {
                    Button("From the Directory…") { picking = true }
                    Divider()
                    ForEach(wellKnown, id: \.1) { name, value in
                        Button(name) { choose(value, label: PrincipalLabel(name: name)) }
                    }
                    Divider()
                    Button("By SID…") { typed = sid; typing = true }
                }
                .fixedSize()
            }
        }
        .sheet(isPresented: $picking) {
            DNPickerSheet(session: session, title: "Choose Who the Rule Is For") { picked in
                guard let dn = picked.first else { return }
                Task {
                    do {
                        guard let found = try await session.sid(of: dn) else {
                            problem = "\(VisibleText.reveal(DN.displayName(dn))) has no SID: only users, groups, computers and other security principals can be given permissions."
                            return
                        }
                        choose(found, label: PrincipalLabel(name: DN.displayName(dn), dn: dn))
                    } catch {
                        problem = error.localizedDescription
                    }
                }
            }
        }
        if typing {
            FieldRow(label: "SID") {
                HStack {
                    TextField("SID", text: $typed, prompt: Text("S-1-5-21-…"))
                        .labelsHidden().textFieldStyle(.roundedBorder).autocorrectionDisabled()
                        .onSubmit(useTyped)
                    Button("Use", action: useTyped).disabled(ADValues.canonicalSID(typed) == nil)
                }
            }
        }
        if let problem {
            FormFooter(problem)
        }
    }

    /// A pick from the directory names the entry it was picked as, so the
    /// review shows its DN, even for a SID known under another name.
    private func choose(_ value: String, label: PrincipalLabel?) {
        sid = value
        if let label, label.dn != nil || names[value] == nil { names[value] = label }
        problem = nil
        typing = false
    }

    /// Kept as the SID reads back from its bytes, so it compares equal to the
    /// same SID read from the directory. Named only if it is one of this
    /// domain's well-known groups (or a SID that is the same everywhere);
    /// anything else is shown as the SID it is.
    private func useTyped() {
        guard let value = ADValues.canonicalSID(typed) else { return }
        choose(value, label: ADValues.wellKnownName(value, inDomain: session.domainSID).map { PrincipalLabel(name: $0) })
        // An account found in the directory by its SID is named, with its DN.
        Task {
            guard let found = await session.principalNames([value])[value], let dn = found.dn, sid == value else { return }
            names[value] = PrincipalLabel(name: found.name, dn: dn)
        }
    }
}

/// Adds an access rule, or changes one set on the object, the way Advanced
/// Security does: who, allow or deny, what, and where it applies. The rule
/// is shown in words before anything is sent.
struct PermissionRuleSheet: View {
    let session: DirectorySession
    let dn: String
    /// The rule being changed and its place in the access list; nil to add one.
    let original: (ace: SecurityDescriptor.ACE, index: Int)?
    let guidNames: [String: SchemaGUIDName]
    @Binding var names: [String: PrincipalLabel]
    let done: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var draft = AccessRuleDraft()
    @State private var target: Target = .object
    @State private var find = ""
    @State private var reviewing = false
    @State private var busy = false
    @State private var error: String?
    /// Rights a rule being changed holds that the editor's choices do not
    /// show; kept as they are.
    @State private var kept: UInt32 = 0

    init(session: DirectorySession, dn: String, original: (ace: SecurityDescriptor.ACE, index: Int)?,
         guidNames: [String: SchemaGUIDName], names: Binding<[String: PrincipalLabel]>, done: @escaping () -> Void) {
        self.session = session
        self.dn = dn
        self.original = original
        self.guidNames = guidNames
        _names = names
        self.done = done
        // The rule being changed, set up before the form first shows, so
        // choosing what it is about does not clear it.
        guard let original, let existing = AccessRuleDraft(original.ace) else { return }
        var target = Target.object
        if let object = existing.objectType?.uuidString.lowercased() {
            switch guidNames[object]?.kind ?? SchemaGUIDName.builtIn[object]?.kind {
            case .objectClass?: target = .childObjects
            case .extendedRight?: target = .extendedRight
            case .validatedWrite?: target = .validatedWrite
            case .attribute?, .propertySet?, nil: target = .property
            }
        }
        var shown = existing
        // Only the rights this target shows can be ticked; the rest stay.
        shown.mask = existing.mask & target.bits
        _draft = State(initialValue: shown)
        _target = State(initialValue: target)
        _kept = State(initialValue: existing.mask & ~target.bits)
    }

    /// What the rule is about.
    enum Target: String, CaseIterable, Identifiable {
        case object, property, extendedRight, childObjects, validatedWrite
        var id: String { rawValue }

        var label: String {
            switch self {
            case .object: return "The object as a whole"
            case .property: return "A property or property set"
            case .extendedRight: return "An extended right"
            case .childObjects: return "Creating or deleting objects of a class"
            case .validatedWrite: return "A validated write"
            }
        }

        /// The rights each target's choices can set.
        var bits: UInt32 {
            switch self {
            case .object: return AccessRuleDraft.generalRights.reduce(0) { $0 | $1.mask }
            case .property: return 0x30
            case .extendedRight: return 0x100
            case .childObjects: return 0x3
            case .validatedWrite: return 0x8
            }
        }

        var kinds: [SchemaGUIDName.Kind] {
            switch self {
            case .object: return []
            case .property: return [.attribute, .propertySet]
            case .extendedRight: return [.extendedRight]
            case .childObjects: return [.objectClass]
            case .validatedWrite: return [.validatedWrite]
            }
        }
    }

    private var classes: [(String, String)] { choices(of: [.objectClass]) }

    private func choices(of kinds: [SchemaGUIDName.Kind]) -> [(String, String)] {
        guidNames.filter { kinds.contains($0.value.kind) }
            .map { ($0.key, $0.value.kind == .propertySet ? "\($0.value.name) (property set)" : $0.value.name) }
            .sorted { $0.1.localizedStandardCompare($1.1) == .orderedAscending }
    }

    private var rule: SecurityDescriptor.ACE? {
        var built = draft
        built.mask = draft.mask | kept
        return try? built.ace()
    }

    private var problem: String? {
        if draft.sid.isEmpty { return "Choose who the rule is for." }
        if target != .object, draft.objectType == nil { return "Choose what the rule is about." }
        if draft.mask | kept == 0 { return "Choose what the rule allows or denies." }
        do {
            var built = draft
            built.mask = draft.mask | kept
            _ = try built.ace()
        } catch {
            return error.localizedDescription
        }
        if let original, rule == original.ace { return "Nothing changed." }
        return nil
    }

    private var change: PermissionChange? {
        guard let rule else { return nil }
        if let original { return .replace(original.ace, with: rule, at: original.index) }
        return .add(rule)
    }

    private func words(_ change: PermissionChange) -> String {
        change.words(who: { PrincipalLabel.reviewed($0, names[$0], domainSID: session.domainSID) }, names: { guidNames[$0] ?? SchemaGUIDName.builtIn[$0] })
    }

    var body: some View {
        SheetLayout(title: original == nil ? "Add an Access Rule" : "Change an Access Rule", subtitle: dn, width: 620, height: 640) {
            if reviewing, let change {
                review(change)
            } else {
                form
            }
        } status: {
            SheetStatus(problem: reviewing ? nil : problem, error: error)
        } buttons: {
            Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
            if reviewing {
                Button("Back") { reviewing = false; error = nil }
                Button(original == nil ? "Add Rule" : "Change Rule") { apply() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy || !session.canWrite)
            } else {
                Button("Review…") { reviewing = true }
                    .keyboardShortcut(.defaultAction)
                    .disabled(problem != nil)
            }
        }
    }

    private func review(_ change: PermissionChange) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("This change is sent to the directory:").font(.callout).foregroundStyle(.secondary)
            Text(words(change))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            if let rule, rule.isDeny, rule.mask & 0x4_0000 != 0 || rule.mask & 0xF_01FF == 0xF_01FF,
               ["S-1-1-0", "S-1-5-11"].contains(rule.sid) {
                Label("This denies everyone the right to change these permissions, administrators included. Only the owner could then undo it.",
                      systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("Only this rule changes: the other rules set here and the inherited ones stay as they are, and the audit settings (the SACL) are neither read nor written. Edit › Undo or Change History takes it back.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var form: some View {
        Form {
            Section {
                PrincipalField(session: session, sid: $draft.sid, names: $names)
                PickerRow(label: "Type", selection: $draft.allow) {
                    Text("Allow").tag(true)
                    Text("Deny").tag(false)
                }
            }
            Section("Applies To") {
                PickerRow(label: "Objects", selection: $draft.scope) {
                    ForEach(AccessRuleDraft.Scope.allCases, id: \.self) { Text($0.label).tag($0) }
                }
                if draft.scope != .thisObject {
                    PickerRow(label: "Of class", selection: $draft.inheritedObjectType) {
                        Text("Any").tag(UUID?.none)
                        ForEach(classes, id: \.0) { key, name in Text(name).tag(UUID(uuidString: key)) }
                    }
                    Toggle("Only objects right beneath this one", isOn: $draft.oneLevelOnly)
                        .formSwitch("Only objects right beneath this one")
                }
            }
            Section("Access") {
                PickerRow(label: "To", selection: $target) {
                    ForEach(Target.allCases) { Text($0.label).tag($0) }
                }
                .onChange(of: target) { _, _ in
                    draft.objectType = nil
                    draft.mask = 0
                    kept = 0
                }
                switch target {
                case .object:
                    ForEach(AccessRuleDraft.generalRights, id: \.mask) { right in
                        Toggle(right.name, isOn: bit(right.mask))
                    }
                case .property:
                    named
                    Toggle("Read", isOn: bit(0x10))
                    Toggle("Write", isOn: bit(0x20))
                case .extendedRight:
                    named
                case .childObjects:
                    named
                    Toggle("Create", isOn: bit(0x1))
                    Toggle("Delete", isOn: bit(0x2))
                case .validatedWrite:
                    named
                }
                if kept != 0 {
                    FormFooter("Also kept, as the rule has them: " + AccessRules.describe(
                        SecurityDescriptor.ACE(type: 0, flags: 0, mask: kept, sid: "S-1-1-0")) { _ in nil }.access.joined(separator: "; ") + ".")
                }
            }
            if let rule {
                Section("In Words") {
                    Text(words(.add(rule)).replacingOccurrences(of: "Add the rule ", with: ""))
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .formStyle(.grouped)
        .toggleStyle(.checkbox)
    }

    /// The attribute, property set, right or class the rule is about, found by name.
    @ViewBuilder
    private var named: some View {
        let all = choices(of: target.kinds)
        let words = find.lowercased().split(separator: " ")
        let shown = all.filter { choice in words.allSatisfy { choice.1.lowercased().contains($0) } }.prefix(300)
        FieldRow(label: "Find") {
            TextField("Find", text: $find, prompt: Text("\(all.count) to choose from"))
                .labelsHidden().textFieldStyle(.roundedBorder).autocorrectionDisabled()
        }
        List(selection: Binding(get: { draft.objectType?.uuidString.lowercased() },
                                set: { key in
                                    draft.objectType = key.flatMap(UUID.init(uuidString:))
                                    if target == .extendedRight { draft.mask = 0x100 }
                                    if target == .validatedWrite { draft.mask = 0x8 }
                                })) {
            ForEach(Array(shown), id: \.0) { key, name in Text(name).tag(Optional(key)) }
            if let chosen = draft.objectType?.uuidString.lowercased(), !shown.contains(where: { $0.0 == chosen }) {
                Text(guidNames[chosen]?.name ?? chosen).tag(Optional(chosen))
            }
        }
        .frame(height: 140)
        .accessibilityLabel("What the rule is about")
    }

    private func bit(_ mask: UInt32) -> Binding<Bool> {
        Binding(get: { draft.mask & mask == mask },
                set: { on in draft.mask = on ? draft.mask | mask : draft.mask & ~mask })
    }

    private func apply() {
        guard let change else { return }
        busy = true
        error = nil
        Task {
            let ok = await session.changePermissions(of: dn, change, words: words(change))
            busy = false
            if ok {
                done()
                dismiss()
            } else {
                error = session.notice?.message ?? "The change was not made."
            }
        }
    }
}

/// Changes an object's owner, shown in words before it is sent.
struct OwnerSheet: View {
    let session: DirectorySession
    let dn: String
    let owner: String
    @Binding var names: [String: PrincipalLabel]
    let done: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var sid = ""
    @State private var reviewing = false
    @State private var busy = false
    @State private var error: String?

    private var change: PermissionChange { .owner(from: owner, to: sid) }
    private var words: String {
        change.words(who: { PrincipalLabel.reviewed($0, names[$0], domainSID: session.domainSID) }, names: { _ in nil })
    }

    var body: some View {
        SheetLayout(title: "Change the Owner", subtitle: dn, width: 520) {
            if reviewing {
                VStack(alignment: .leading, spacing: 12) {
                    Text("This change is sent to the directory:").font(.callout).foregroundStyle(.secondary)
                    Text(words).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    Text("The owner may always read and change the object's permissions. Only the owner changes: the access rules and the audit settings (the SACL) are left alone. Active Directory lets you make only yourself, or a group you belong to, the owner, unless you may restore files and directories. Edit › Undo or Change History takes it back.")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                Form {
                    FieldRow(label: "Now") { Text(PrincipalLabel.reviewed(owner, names[owner], domainSID: session.domainSID)).help(owner) }
                    PrincipalField(session: session, sid: $sid, names: $names)
                }
                .formStyle(.grouped)
                .hugsContent()
            }
        } status: {
            SheetStatus(problem: reviewing ? nil : (sid.isEmpty ? "Choose the new owner." : (sid == owner ? "That is the owner already." : nil)),
                        error: error)
        } buttons: {
            Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
            if reviewing {
                Button("Back") { reviewing = false; error = nil }
                Button("Change Owner") { apply() }.keyboardShortcut(.defaultAction).disabled(busy || !session.canWrite)
            } else {
                Button("Review…") { reviewing = true }.keyboardShortcut(.defaultAction).disabled(sid.isEmpty || sid == owner)
            }
        }
    }

    private func apply() {
        busy = true
        error = nil
        Task {
            let ok = await session.changePermissions(of: dn, change, words: words)
            busy = false
            if ok {
                done()
                dismiss()
            } else {
                error = session.notice?.message ?? "The owner was not changed."
            }
        }
    }
}
