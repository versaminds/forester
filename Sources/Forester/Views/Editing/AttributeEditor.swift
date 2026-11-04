// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import AppKit
import LDAPKit
import SwiftUI
import UniformTypeIdentifiers

/// How an attribute's values are edited, decided from the schema's syntax and
/// what the app knows about well-known attributes.
enum EditorKind: Equatable {
    case text(multiline: Bool)
    case integer
    case boolean
    case distinguishedName
    case generalizedTime
    /// An AD FILETIME the administrator may set (accountExpires): a date or "never".
    case fileTime
    case binary
    case image
    case userAccountControl
    case groupType
    /// A password attribute: changed through the password sheet, not typed here.
    case password
    case readOnly(String)

    static func of(_ attribute: String, schema: LDAPSchema?) -> EditorKind {
        let name = (attribute.split(separator: ";").first.map(String.init) ?? attribute).lowercased()
        switch name {
        case "useraccountcontrol": return .userAccountControl
        case "grouptype": return .groupType
        case "unicodepwd", "userpassword": return .password
        case "ntsecuritydescriptor":
            return .readOnly("Permissions are edited in Active Directory's own tools. Forester changes one thing in them: “User cannot change password”, under Account.")
        case "objectguid", "objectsid", "whencreated", "whenchanged", "usncreated", "usnchanged", "memberof",
             "directreports", "lastlogon", "lastlogontimestamp", "badpwdcount", "badpasswordtime", "logoncount",
             "samaccounttype", "createtimestamp", "modifytimestamp", "creatorsname", "modifiersname", "entryuuid",
             "entrycsn", "structuralobjectclass", "hassubordinates", "subschemasubentry", "entrydn":
            return .readOnly("The server maintains this attribute.")
        case "pwdlastset":
            return .readOnly("Use “User must change password at next sign-in” under Account; AD accepts only 0 and -1 here.")
        case "lockouttime":
            return .readOnly("Use Unlock Account; AD accepts only 0 here.")
        case "accountexpires": return .fileTime
        case "thumbnailphoto", "jpegphoto", "photo": return .image
        case "description", "info", "postaladdress", "streetaddress", "street", "comment": return .text(multiline: true)
        default: break
        }
        if let type = schema?.attributeType(attribute), type.noUserModification {
            return .readOnly("The schema marks this attribute as set by the server only.")
        }
        guard let syntax = schema?.syntax(of: attribute).flatMap(KnownSyntax.init(rawValue:)) else {
            return .text(multiline: false)
        }
        switch syntax {
        case .boolean: return .boolean
        case .dn: return .distinguishedName
        case .integer: return .integer
        case .generalizedTime, .utcTime: return .generalizedTime
        case .jpeg: return .image
        case .octetString, .binary, .certificate, .adSecurityDescriptor: return .binary
        default: return .text(multiline: false)
        }
    }

    var isEditable: Bool {
        switch self {
        case .readOnly, .password: return false
        default: return true
        }
    }
}

/// One value being edited. Text forms are kept as text; bytes as bytes.
struct EditableValue: Identifiable, Equatable {
    let id = UUID()
    var data: Data
    var text: String {
        get { String(decoding: data, as: UTF8.self) }
        set { data = Data(newValue.utf8) }
    }
}

/// Edits every value of one attribute and sends the difference as a single
/// modify: changed values of a single-valued attribute are replaced, values of a
/// multi-valued one are added and deleted individually (so a 3,000-member group
/// is not rewritten to add one member).
struct AttributeEditorSheet: View {
    let session: DirectorySession
    let entry: LDAPEntry
    /// nil: the user picks which attribute to add.
    let initialAttribute: String?
    @Environment(\.dismiss) private var dismiss

    @State private var attribute = ""
    @State private var values: [EditableValue] = []
    @State private var original: [Data] = []
    @State private var saving = false
    @State private var error: String?
    @State private var pickingAttribute: Bool
    @State private var pickingDN: UUID?
    @State private var addingMembers = false

    init(session: DirectorySession, entry: LDAPEntry, attribute: String?) {
        self.session = session
        self.entry = entry
        initialAttribute = attribute
        _pickingAttribute = State(initialValue: attribute == nil)
    }

    private var kind: EditorKind { EditorKind.of(attribute, schema: session.schema) }
    private var singleValued: Bool { session.schema?.isSingleValued(attribute) ?? false }
    private var syntaxLabel: String? {
        session.schema?.syntax(of: attribute).flatMap { session.schema?.syntaxDescription($0) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if pickingAttribute {
                AttributePicker(session: session, entry: entry) { chosen in
                    attribute = chosen
                    // A name typed by hand can be one the entry already has: start
                    // from its values, or saving would replace them all.
                    original = entry.values(chosen)
                    values = original.map { EditableValue(data: $0) }
                    if values.isEmpty || !(session.schema?.isSingleValued(chosen) ?? false) {
                        values.append(EditableValue(data: Data()))
                    }
                    pickingAttribute = false
                }
            } else {
                editor.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            }
            Divider()
            footer
        }
        .frame(width: 600, height: pickingAttribute ? 520 : 460)
        .onAppear {
            guard let initialAttribute else { return }
            attribute = initialAttribute
            original = entry.values(initialAttribute)
            values = original.map { EditableValue(data: $0) }
            if values.isEmpty { values = [EditableValue(data: Data())] }
        }
        .sheet(item: Binding(get: { pickingDN.map(PickRequest.init) }, set: { pickingDN = $0?.id })) { request in
            DNPickerSheet(session: session, allowsMultiple: false,
                          startAt: values.first(where: { $0.id == request.id }).flatMap { $0.text.isEmpty ? nil : $0.text }) { picked in
                if let dn = picked.first, let index = values.firstIndex(where: { $0.id == request.id }) {
                    values[index].text = dn
                }
            }
        }
        .sheet(isPresented: $addingMembers) {
            DNPickerSheet(session: session, allowsMultiple: true) { picked in
                values.removeAll { $0.data.isEmpty }
                for dn in picked where !values.contains(where: { DN.isSame($0.text, dn) }) {
                    values.append(EditableValue(data: Data(dn.utf8)))
                }
            }
        }
    }

    struct PickRequest: Identifiable { let id: UUID }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(pickingAttribute ? "Add Attribute" : attribute).font(.headline)
                Text(DN.displayName(entry.dn)).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if !pickingAttribute {
                if let syntaxLabel { Text(syntaxLabel).font(.caption).foregroundStyle(.secondary) }
                Text(singleValued ? "single value" : "multiple values")
                    .font(.caption)
                    .padding(.horizontal, 6)
                    .background(.quaternary, in: Capsule())
            }
        }
        .padding(14)
    }

    @ViewBuilder
    private var editor: some View {
        switch kind {
        case .readOnly(let reason):
            ContentUnavailableView("Not Editable Here", systemImage: "lock", description: Text(reason))
        case .password:
            ContentUnavailableView("Passwords Have Their Own Sheet", systemImage: "key",
                                   description: Text("Use Reset Password in the toolbar or the Entry menu; it uses the right method for this server."))
        case .userAccountControl:
            FlagEditor(table: ADValues.userAccountControlFlags, value: integerBinding(at: 0), original: originalInteger(at: 0))
        case .groupType:
            GroupTypeEditor(value: integerBinding(at: 0))
        default:
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach($values) { $value in
                        HStack(alignment: kind == .text(multiline: true) ? .top : .center, spacing: 6) {
                            ValueField(kind: kind, value: $value, attribute: attribute) { pickingDN = value.id }
                            if values.count > 1 || !singleValued {
                                Button { values.removeAll { $0.id == value.id } } label: {
                                    Image(systemName: "minus.circle.fill").foregroundStyle(.secondary)
                                }
                                .buttonStyle(.borderless)
                                .help("Remove this value")
                            }
                        }
                    }
                    if !singleValued {
                        HStack(spacing: 16) {
                            Button { values.append(EditableValue(data: Data())) } label: { Label("Add Value", systemImage: "plus.circle") }
                            if kind == .distinguishedName {
                                Button { addingMembers = true } label: { Label("Add from Directory…", systemImage: "person.badge.plus") }
                            }
                        }
                        .buttonStyle(.borderless)
                        .foregroundStyle(.tint)
                        .padding(.top, 2)
                    }
                }
                .padding(14)
            }
        }
    }

    private var footer: some View {
        HStack {
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.callout)
                    .lineLimit(3)
                    .textSelection(.enabled)
            } else if !pickingAttribute, kind.isEditable {
                Text(changeSummary).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Cancel", role: .cancel) { dismiss() }
                .keyboardShortcut(.cancelAction)
            if !pickingAttribute, kind.isEditable {
                Button {
                    save()
                } label: {
                    if saving { ProgressView().controlSize(.small) } else { Text("Save") }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(saving || modifications.isEmpty || validationProblem != nil)
            }
        }
        .padding(14)
    }

    // MARK: Changes

    private var cleaned: [Data] {
        var seen: Set<Data> = []
        return values.map(\.data).filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    private var validationProblem: String? {
        switch kind {
        case .integer, .userAccountControl, .groupType:
            if cleaned.contains(where: { Int64(String(decoding: $0, as: UTF8.self).trimmingCharacters(in: .whitespaces)) == nil }) {
                return "Enter whole numbers."
            }
        case .distinguishedName:
            if cleaned.contains(where: { !String(decoding: $0, as: UTF8.self).contains("=") }) { return "A DN looks like CN=Name,OU=…" }
        default: break
        }
        if singleValued && cleaned.count > 1 { return "This attribute holds a single value." }
        return nil
    }

    private var modifications: [LDAPModification] {
        let new = cleaned
        // A whole-attribute replace for a multi-valued one would also remove
        // values added meanwhile, or ones this account cannot see.
        let knownMultiValued = session.schema?.attributeType(attribute) != nil && !singleValued
        if singleValued || kind == .userAccountControl || kind == .groupType || (original.count <= 1 && !knownMultiValued) {
            if new == original { return [] }
            return new.isEmpty ? [LDAPModification(.delete, attribute)] : [LDAPModification(.replace, attribute, new)]
        }
        let removed = original.filter { !new.contains($0) }
        let added = new.filter { !original.contains($0) }
        var changes: [LDAPModification] = []
        if !removed.isEmpty {
            changes.append(removed.count == original.count && added.isEmpty
                           ? LDAPModification(.delete, attribute) : LDAPModification(.delete, attribute, removed))
        }
        if !added.isEmpty { changes.append(LDAPModification(.add, attribute, added)) }
        return changes
    }

    private var changeSummary: String {
        if let validationProblem { return validationProblem }
        let changes = modifications
        guard !changes.isEmpty else { return "No changes" }
        return changes.map { change in
            switch change.operation {
            case .replace: return "replace"
            case .add: return "add \(change.values.count)"
            case .delete: return change.values.isEmpty ? "remove attribute" : "remove \(change.values.count)"
            case .increment: return "increment"
            }
        }.joined(separator: ", ")
    }

    private func originalInteger(at index: Int) -> Int64 {
        original.indices.contains(index) ? Int64(String(decoding: original[index], as: UTF8.self)) ?? 0 : 0
    }

    private func integerBinding(at index: Int) -> Binding<Int64> {
        Binding(
            get: { values.indices.contains(index) ? Int64(values[index].text) ?? 0 : 0 },
            set: { newValue in
                if values.isEmpty { values = [EditableValue(data: Data())] }
                values[index].text = String(newValue)
            })
    }

    private func save() {
        let changes = modifications
        saving = true
        error = nil
        Task {
            let ok = await session.change("Saved \(attribute).", undo: .values(entry.dn, [attribute])) { try await $0.modify(entry.dn, changes) }
            saving = false
            if ok { dismiss() } else { error = session.notice?.message }
        }
    }
}

/// One value's input, chosen by kind.
struct ValueField: View {
    let kind: EditorKind
    @Binding var value: EditableValue
    let attribute: String
    let pickDN: () -> Void

    var body: some View {
        switch kind {
        case .text(let multiline) where multiline || value.text.count > 80 || value.text.contains("\n"):
            TextEditor(text: $value.text)
                .font(.body)
                .scrollContentBackground(.hidden)
                .padding(.horizontal, 4)
                .padding(.vertical, 5)
                .frame(minHeight: 72, maxHeight: 160)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
                .overlay(RoundedRectangle(cornerRadius: 7).stroke(Color(nsColor: .separatorColor)))
                .accessibilityLabel(attribute)
        case .integer:
            TextField(attribute, text: $value.text, prompt: Text("Number"))
                .labelsHidden().textFieldStyle(.roundedBorder).font(.body.monospacedDigit()).frame(maxWidth: 220)
        case .boolean:
            Picker("", selection: $value.text) {
                Text("TRUE").tag("TRUE")
                Text("FALSE").tag("FALSE")
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .onAppear { if value.text.isEmpty { value.text = "FALSE" } }
        case .distinguishedName:
            HStack(spacing: 6) {
                TextField(attribute, text: $value.text, prompt: Text("CN=…,OU=…,DC=…"))
                    .labelsHidden()
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                Button(action: pickDN) { Image(systemName: "list.bullet.indent") }
                    .buttonStyle(.borderless)
                    .help("Choose from the directory")
                    .accessibilityLabel("Choose from the directory")
            }
        case .generalizedTime:
            GeneralizedTimeField(text: $value.text)
        case .fileTime:
            FileTimeField(text: $value.text)
        case .binary, .image:
            BinaryField(data: $value.data, attribute: attribute, isImage: kind == .image)
        default:
            TextField(attribute, text: $value.text, prompt: Text("Value"))
                .labelsHidden().textFieldStyle(.roundedBorder).autocorrectionDisabled()
        }
    }
}

struct GeneralizedTimeField: View {
    @Binding var text: String

    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(secondsFromGMT: 0)
        f.dateFormat = "yyyyMMddHHmmss'Z'"
        return f
    }()

    var body: some View {
        HStack {
            DatePicker("", selection: Binding(
                get: { ADValues.generalizedTime(text) ?? Date() },
                set: { text = Self.formatter.string(from: $0) }))
                .labelsHidden()
            Text(text.isEmpty ? "not set" : text).font(.caption.monospaced()).foregroundStyle(.secondary)
        }
        .onAppear { if text.isEmpty { text = Self.formatter.string(from: Date()) } }
    }
}

/// accountExpires: a date, or never (0 / 0x7FFFFFFFFFFFFFFF).
struct FileTimeField: View {
    @Binding var text: String

    private var never: Bool {
        guard let raw = Int64(text) else { return true }
        if case .date = ADValues.fileTime(raw) { return false }
        return true
    }

    var body: some View {
        HStack {
            Toggle("Never", isOn: Binding(
                get: { never },
                set: { text = $0 ? "9223372036854775807" : String(ADValues.fileTimeValue(Calendar.current.startOfDay(for: Date().addingTimeInterval(30 * 86400)))) }))
            .toggleStyle(.checkbox)
            if !never {
                DatePicker("Expires at the start of", selection: Binding(
                    get: {
                        if let raw = Int64(text), case .date(let date) = ADValues.fileTime(raw) { return date }
                        return Date()
                    },
                    set: { text = String(ADValues.fileTimeValue($0)) }), displayedComponents: [.date, .hourAndMinute])
            }
        }
    }
}

struct BinaryField: View {
    @Binding var data: Data
    let attribute: String
    let isImage: Bool

    var body: some View {
        HStack(spacing: 10) {
            if isImage, let image = NSImage(data: data) {
                Image(nsImage: image).resizable().aspectRatio(contentMode: .fit).frame(width: 64, height: 64)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(data.isEmpty ? "Empty" : AttributeFormatter.byteCount(data.count))
                if !data.isEmpty, !isImage {
                    Text(AttributeFormatter.hex(data, limit: 24)).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                HStack {
                    Button("Choose File…") { choose() }
                    if !data.isEmpty { Button("Clear") { data = Data() } }
                }
            }
        }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = isImage ? [.jpeg, .png, .image] : [.data]
        panel.message = isImage ? "AD expects thumbnailPhoto as a JPEG under 100 KB." : "Choose the file to store in \(attribute)."
        guard panel.runModal() == .OK, let url = panel.url, let contents = try? Data(contentsOf: url) else { return }
        data = contents
    }
}

/// Checkboxes for a flag word such as userAccountControl.
struct FlagEditor: View {
    let table: [ADValues.Flag]
    @Binding var value: Int64
    /// The value as saved, to say what turning a flag on will do.
    var original: Int64 = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("\(value) (0x\(String(value, radix: 16)))").font(.callout.monospaced()).foregroundStyle(.secondary)
            ScrollView {
                LazyVGrid(columns: [GridItem(.flexible(), alignment: .leading), GridItem(.flexible(), alignment: .leading)], spacing: 6) {
                    ForEach(table, id: \.bit) { flag in
                        Toggle(isOn: Binding(
                            get: { value & flag.bit != 0 },
                            set: { value = $0 ? value | flag.bit : value & ~flag.bit })) {
                            Text(flag.label).foregroundStyle(flag.notable ? .orange : .primary)
                        }
                        .toggleStyle(.checkbox)
                        .help(flag.name)
                    }
                }
            }
            ForEach(table.filter { $0.whenTurnedOn != nil && value & $0.bit != 0 && original & $0.bit == 0 }, id: \.bit) { flag in
                Label("\(flag.label): \(flag.whenTurnedOn ?? "")", systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(14)
    }
}

/// AD groupType as scope plus security/distribution, as rows for a grouped form.
struct GroupTypeRows: View {
    @Binding var value: Int64

    private enum Scope: Int64, CaseIterable { case global = 2, domainLocal = 4, universal = 8 }

    var body: some View {
        FieldRow(label: "Scope") {
            Picker("Scope", selection: Binding(
                get: { Scope.allCases.first { value & $0.rawValue != 0 } ?? .global },
                set: { scope in value = (value & ~0xE) | scope.rawValue })) {
                Text("Global").tag(Scope.global)
                Text("Domain local").tag(Scope.domainLocal)
                Text("Universal").tag(Scope.universal)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
        }
        FieldRow(label: "Type") {
            Picker("Type", selection: Binding(
                get: { value & 0x8000_0000 != 0 || value < 0 },
                set: { secure in
                    let scope = value & 0xF
                    value = secure ? Int64(Int32(bitPattern: UInt32(0x8000_0000) | UInt32(scope))) : scope
                })) {
                Text("Security").tag(true)
                Text("Distribution").tag(false)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
        }
        ValueRow(label: "Result", value: "\(ADValues.groupTypeDescription(value)) (\(value))")
    }
}

/// The group type on its own, for the attribute editor.
struct GroupTypeEditor: View {
    @Binding var value: Int64

    var body: some View {
        Form {
            Section {
                GroupTypeRows(value: $value)
            } footer: {
                FormFooter("AD allows only some scope changes: a global or domain local group becomes universal first, and a group's members must fit its new scope.")
            }
        }
        .formStyle(.grouped)
        .formLabelWidth(56)
    }
}

/// The attributes the entry's object classes allow and it does not have yet.
struct AttributePicker: View {
    let session: DirectorySession
    let entry: LDAPEntry
    let choose: (String) -> Void
    @State private var filter = ""

    private var candidates: [(name: String, required: Bool)] {
        let present = Set(entry.attributes.map { $0.baseName.lowercased() })
        // AD computes exactly what this account may write on this entry.
        let effective = entry.strings("allowedAttributesEffective")
        let allowed: (must: [String], may: [String])
        if !effective.isEmpty {
            allowed = ([], effective)
        } else if let schema = session.schema {
            allowed = schema.allowedAttributes(for: entry.objectClasses)
        } else {
            allowed = ([], [])
        }
        let writable: (String) -> Bool = { name in
            guard let type = session.schema?.attributeType(name) else { return true }
            return !type.noUserModification && !type.isOperational
        }
        return (allowed.must.map { ($0, true) } + allowed.may.map { ($0, false) })
            .filter { !present.contains($0.0.lowercased()) && $0.0.lowercased() != "objectclass" && writable($0.0) }
            .filter { filter.isEmpty || $0.0.localizedCaseInsensitiveContains(filter) }
            .sorted { ($0.1 ? 0 : 1, $0.0.lowercased()) < ($1.1 ? 0 : 1, $1.0.lowercased()) }
    }

    var body: some View {
        VStack(spacing: 0) {
            TextField("Attribute name", text: $filter)
                .textFieldStyle(.roundedBorder)
                .padding(12)
                .onSubmit {
                    if let first = candidates.first { choose(first.name) } else if !filter.isEmpty { choose(filter) }
                }
            if session.schema == nil {
                Text("The server's schema could not be read, so any name can be typed.").font(.caption).foregroundStyle(.secondary)
            }
            List(candidates, id: \.name) { candidate in
                Button {
                    choose(candidate.name)
                } label: {
                    HStack {
                        Text(candidate.name)
                        if candidate.required { Text("required").font(.caption2).foregroundStyle(.orange) }
                        Spacer()
                        if let description = session.schema?.attributeType(candidate.name)?.description {
                            Text(description).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
            .listStyle(.inset)
            if candidates.isEmpty, !filter.isEmpty {
                Button("Use “\(filter)”") { choose(filter) }.padding(8)
            }
        }
    }
}
