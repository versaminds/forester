// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

/// A row in the attribute table: one value, or the group row of a
/// multi-valued attribute, whose values are its children.
struct AttributeRow: Identifiable, Hashable {
    let id: String
    let name: String
    /// nil on the group row of a multi-valued attribute.
    let valueIndex: Int?
    let valueCount: Int
    let value: Data
    let formatted: FormattedValue
    var children: [AttributeRow]?

    var isGroup: Bool { valueIndex == nil }

    var raw: String {
        AttributeFormatter.isBinary(value) ? AttributeFormatter.hex(value, limit: 64) : String(decoding: value, as: UTF8.self)
    }
}

/// Every attribute and value, decoded or raw, filterable, and editable when
/// the connection allows changes.
struct AttributesView: View {
    let session: DirectorySession
    let entry: LDAPEntry
    @State private var filter = ""
    @State private var decoded = true
    @State private var selection: Set<AttributeRow.ID> = []
    @State private var viewing: AttributeRow?
    @State private var editing: EditRequest?
    @State private var confirmingDelete: [AttributeRow] = []

    struct EditRequest: Identifiable {
        let id = UUID()
        /// nil: pick an attribute to add.
        let attribute: String?
    }

    /// Each value formatted once per entry, with the lowercased text the
    /// filter looks in: worked out on every redraw, a group of 50,000 members
    /// made every click and keystroke format 50,000 DNs.
    private final class Prepared {
        struct Attribute {
            let name: String
            let values: [AttributeRow]
            let haystacks: [String]
        }
        var entry: LDAPEntry?
        var attributes: [Attribute] = []
    }
    @State private var prepared = Prepared()

    private func preparedAttributes() -> [Prepared.Attribute] {
        if prepared.entry != entry {
            prepared.entry = entry
            prepared.attributes = entry.attributes
                .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
                .map { attribute in
                    let values = attribute.values.enumerated().map { index, value in
                        AttributeRow(id: "\(attribute.name)#\(index)", name: attribute.name, valueIndex: index,
                                     valueCount: attribute.values.count, value: value,
                                     formatted: AttributeFormatter.format(attribute.name, value))
                    }
                    let haystacks = values.map { row in
                        (row.name + "\n" + row.formatted.text + "\n" + String(decoding: row.value, as: UTF8.self)).lowercased()
                    }
                    return Prepared.Attribute(name: attribute.name, values: values, haystacks: haystacks)
                }
        }
        return prepared.attributes
    }

    private var rows: [AttributeRow] {
        let needle = filter.trimmingCharacters(in: .whitespaces).lowercased()
        return preparedAttributes().compactMap { attribute in
            let values = attribute.values
            let shown = needle.isEmpty ? values : zip(values, attribute.haystacks).filter { $0.1.contains(needle) }.map(\.0)
            guard !shown.isEmpty else { return nil }
            if values.count == 1 { return values[0] }
            let summary = values.prefix(4).map(\.formatted.text).joined(separator: "; ") + (values.count > 4 ? " …" : "")
            return AttributeRow(id: "\(attribute.name)#all", name: attribute.name, valueIndex: nil, valueCount: values.count,
                                value: values[0].value,
                                formatted: FormattedValue(text: summary, kind: values[0].formatted.kind), children: shown)
        }
    }

    private func flat(_ rows: [AttributeRow]) -> [AttributeRow] {
        rows.flatMap { [$0] + ($0.children ?? []) }
    }

    var body: some View {
        let rows = rows
        VStack(spacing: 0) {
            toolbar
            Table(rows, children: \.children, selection: $selection) {
                TableColumn("Attribute") { row in
                    HStack(spacing: 4) {
                        Text(row.name).foregroundStyle(row.isGroup || row.valueCount == 1 ? .primary : .tertiary)
                        if row.isGroup {
                            Text("\(row.valueCount)")
                                .font(.caption2.monospacedDigit())
                                .foregroundStyle(.secondary)
                                .padding(.horizontal, 4)
                                .background(.quaternary, in: Capsule())
                        }
                    }
                    .help(schemaHelp(row.name))
                }
                .width(min: 110, ideal: 180, max: 320)
                TableColumn("Value") { row in valueCell(row) }
            }
            .contextMenu(forSelectionType: AttributeRow.ID.self) { ids in
                menu(for: flat(rows).filter { ids.contains($0.id) })
            } primaryAction: { ids in
                guard let row = flat(rows).first(where: { ids.contains($0.id) }) else { return }
                if session.canWrite, EditorKind.of(row.name, schema: session.schema).isEditable {
                    editing = EditRequest(attribute: row.name)
                } else if !row.isGroup {
                    viewing = row
                }
            }
            .overlay {
                if rows.isEmpty { ContentUnavailableView.search(text: filter) }
            }
            HStack {
                Text("\(entry.attributes.count) attributes, \(entry.attributes.reduce(0) { $0 + $1.values.count }) values")
                Spacer()
                Text(session.canWrite ? "Double-click to edit" : "Double-click to view a value")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(.bar)
        }
        .sheet(item: $viewing) { row in ValueViewer(row: row, dn: entry.dn) }
        .sheet(item: $editing) { request in
            AttributeEditorSheet(session: session, entry: entry, attribute: request.attribute)
        }
        .confirmationDialog(deleteTitle, isPresented: Binding(get: { !confirmingDelete.isEmpty },
                                                               set: { if !$0 { confirmingDelete = [] } })) {
            Button("Delete", role: .destructive) { delete(confirmingDelete) }
        } message: {
            Text("This changes \(DN.displayName(entry.dn)) in the directory and cannot be undone.")
        }
    }

    private var toolbar: some View {
        HStack(spacing: 8) {
            TextField("Filter attributes and values", text: $filter)
                .textFieldStyle(.roundedBorder)
            Toggle("Decode values", isOn: $decoded)
                .toggleStyle(.checkbox)
                .help("Show SIDs, GUIDs, timestamps and flags in readable form")
            if session.canWrite {
                ControlGroup {
                    Button { editing = EditRequest(attribute: nil) } label: { Image(systemName: "plus") }
                        .help("Add an attribute")
                    Button {
                        if let name = selectedRows.first?.name { editing = EditRequest(attribute: name) }
                    } label: { Image(systemName: "pencil") }
                        .help("Edit the selected attribute")
                        .disabled(selectedRows.isEmpty)
                    Button { confirmingDelete = selectedRows } label: { Image(systemName: "minus") }
                        .help("Delete the selected values or attributes")
                        .disabled(selectedRows.isEmpty)
                }
                .fixedSize()
            }
        }
        .padding(10)
    }

    private var selectedRows: [AttributeRow] {
        flat(rows).filter { selection.contains($0.id) }
    }

    private var deleteTitle: String { "Delete \(Self.describe(Self.plan(confirmingDelete)))?" }

    /// What deleting these rows removes: a selected attribute row (or the only
    /// value of one) removes the whole attribute; other rows remove one value.
    static func plan(_ rows: [AttributeRow]) -> (whole: [(name: String, count: Int)], values: [String: [Data]]) {
        var whole: [(name: String, count: Int)] = []
        var values: [String: [Data]] = [:]
        for row in rows where row.isGroup || row.valueCount == 1 {
            if !whole.contains(where: { $0.name == row.name }) { whole.append((row.name, row.valueCount)) }
        }
        for row in rows where !row.isGroup && row.valueCount > 1 && !whole.contains(where: { $0.name == row.name }) {
            values[row.name, default: []].append(row.value)
        }
        return (whole, values)
    }

    /// “member” with all 3,000 values, 2 values of “mail”
    static func describe(_ plan: (whole: [(name: String, count: Int)], values: [String: [Data]])) -> String {
        let attributes = plan.whole.map { $0.count > 1 ? "“\($0.name)” with all \($0.count.formatted()) values" : "the attribute “\($0.name)”" }
        let values = plan.values.sorted { $0.key < $1.key }.map { $0.value.count == 1 ? "a value of “\($0.key)”" : "\($0.value.count) values of “\($0.key)”" }
        let parts = attributes + values
        return parts.count <= 2 ? parts.joined(separator: " and ") : parts.dropLast().joined(separator: ", ") + " and " + parts.last!
    }

    @ViewBuilder
    private func menu(for selected: [AttributeRow]) -> some View {
        if let row = selected.first {
            if !row.isGroup { Button("View Value…") { viewing = row } }
            if session.canWrite, EditorKind.of(row.name, schema: session.schema).isEditable {
                Button("Edit “\(row.name)”…") { editing = EditRequest(attribute: row.name) }
                Button(selected.count > 1 ? "Delete \(selected.count) Values…" : (row.isGroup || row.valueCount == 1 ? "Delete Attribute…" : "Delete Value…"),
                       role: .destructive) { confirmingDelete = selected }
            } else if !session.canWrite {
                Button("Edit “\(row.name)”…") {}.disabled(true)
                Text("Read-only: press ⌥⌘E to allow changes")
            }
            Divider()
            Button(selected.count > 1 ? "Copy Values" : "Copy Value") {
                Pasteboard.copy(selected.flatMap { $0.isGroup ? ($0.children ?? []) : [$0] }
                    .map { decoded ? $0.formatted.text : $0.raw }.joined(separator: "\n"))
            }
            if selected.count == 1, !row.isGroup, row.formatted.text != row.raw {
                Button("Copy Raw Value") { Pasteboard.copy(row.raw) }
            }
            Button("Copy as LDIF") {
                let values = selected.flatMap { $0.isGroup ? ($0.children ?? []) : [$0] }
                let partial = LDAPEntry(dn: entry.dn, attributes: values.map { LDAPAttribute(name: $0.name, values: [$0.value]) })
                Pasteboard.copy(LDIF.entry(partial))
            }
            Button("Copy Attribute Name") { Pasteboard.copy(row.name) }
            if selected.count == 1, !row.isGroup {
                Divider()
                Button("Find Entries with This Value") {
                    session.search.filterText = searchFilter(for: row)
                    session.search.scope = .subtree
                    session.mode = .search
                    session.search.run()
                }
            }
        }
    }

    @ViewBuilder
    private func valueCell(_ row: AttributeRow) -> some View {
        if row.isGroup {
            Text(row.formatted.text).lineLimit(1).foregroundStyle(.secondary)
        } else if decoded, row.formatted.kind == .distinguishedName, let dn = row.formatted.links.first {
            Button { session.open(dn) } label: {
                Text(dn)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .buttonStyle(.link)
            .help("Open \(dn)")
        } else if decoded, row.formatted.kind == .image, let image = NSImage(data: row.value) {
            HStack {
                Image(nsImage: image).resizable().aspectRatio(contentMode: .fit).frame(height: 20)
                Text(row.formatted.text).foregroundStyle(.secondary)
            }
        } else {
            Text(decoded ? row.formatted.text : row.raw)
                .lineLimit(1)
                .truncationMode(.tail)
                .font(Self.isCode(row, decoded: decoded) ? .body.monospaced() : .body)
                .foregroundStyle(row.formatted.kind == .binary ? .secondary : .primary)
                .help(decoded ? (row.formatted.detail ?? row.formatted.text) : row.formatted.text)
        }
    }

    private func schemaHelp(_ name: String) -> String {
        guard let schema = session.schema, let type = schema.attributeType(name) else { return name }
        var parts = [type.names.joined(separator: ", "), type.oid]
        if let syntax = schema.syntax(of: name) { parts.append(schema.syntaxDescription(syntax) ?? syntax) }
        parts.append(type.singleValue ? "single value" : "multiple values")
        if let description = type.description { parts.append(description) }
        return parts.joined(separator: " · ")
    }

    /// Identifiers and bytes read better in a fixed-width face; words and dates do not.
    static func isCode(_ row: AttributeRow, decoded: Bool) -> Bool {
        guard decoded else { return true }
        switch row.formatted.kind {
        case .sid, .guid, .binary: return true
        default: return false
        }
    }

    /// An equality filter for a value, escaped so binary values (SIDs) work.
    private func searchFilter(for row: AttributeRow) -> String {
        let name = row.name.split(separator: ";").first.map(String.init) ?? row.name
        if AttributeFormatter.isBinary(row.value) {
            return "(\(name)=\(LDAPFilter.escapeAll([UInt8](row.value))))"
        }
        return "(\(name)=\(LDAPFilter.escape(String(decoding: row.value, as: UTF8.self))))"
    }

    private func delete(_ rows: [AttributeRow]) {
        let plan = Self.plan(rows)
        var changes = plan.whole.map { LDAPModification(.delete, $0.name) }
        for (name, data) in plan.values {
            changes.append(LDAPModification(.delete, name, data))
        }
        let summary = Self.describe(plan)
        Task {
            let names = Array(Set(changes.map(\.attribute)))
            await session.change("Deleted \(summary).", undo: .values(entry.dn, names)) {
                try await $0.modify(entry.dn, changes)
            }
            selection = []
        }
    }
}

/// A single value in full: text, a hex dump, an image or a certificate.
struct ValueViewer: View {
    let row: AttributeRow
    let dn: String
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text(row.name).font(.headline)
                Text(AttributeFormatter.byteCount(row.value.count)).foregroundStyle(.secondary)
                Spacer()
            }
            if row.formatted.kind != .text && row.formatted.kind != .binary {
                Text(row.formatted.text).textSelection(.enabled)
                if let detail = row.formatted.detail {
                    Text(detail).font(.callout.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            content
            HStack {
                if row.formatted.kind == .certificate {
                    Button("Show Certificate…") { CertificateViewer.show([row.value]) }
                }
                Button("Save…") {
                    let ext = AttributeFormatter.imageType(row.value)?.lowercased() ?? (row.formatted.kind == .certificate ? "cer" : "bin")
                    Exporter.save(row.value, name: "\(DN.displayName(dn))-\(row.name).\(ext)")
                }
                Spacer()
                Button("Copy") {
                    if row.formatted.kind == .image { Pasteboard.copy(image: row.value) } else { Pasteboard.copy(row.raw) }
                }
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(18)
        .frame(width: 620, height: 460)
    }

    @ViewBuilder
    private var content: some View {
        if row.formatted.kind == .image, let image = NSImage(data: row.value) {
            Image(nsImage: image)
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if AttributeFormatter.isBinary(row.value) {
            ScrollView {
                Text(Self.hexDump(row.value))
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(8)
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 6))
        } else {
            ScrollView {
                Text(String(decoding: row.value, as: UTF8.self))
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(8)
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 6))
        }
    }

    /// Offset, sixteen hex bytes, and their printable characters.
    static func hexDump(_ data: Data) -> String {
        let bytes = [UInt8](data.prefix(64 * 1024))
        var lines: [String] = []
        for offset in stride(from: 0, to: bytes.count, by: 16) {
            let chunk = bytes[offset..<min(offset + 16, bytes.count)]
            let hex = chunk.map { String(format: "%02x", $0) }.joined(separator: " ")
            let ascii = String(chunk.map { (0x20...0x7E).contains($0) ? Character(UnicodeScalar($0)) : "." })
            lines.append(String(format: "%08x  ", offset) + hex.padding(toLength: 48, withPad: " ", startingAt: 0) + "  " + ascii)
        }
        if data.count > bytes.count { lines.append("… \(data.count - bytes.count) more bytes") }
        return lines.joined(separator: "\n")
    }
}
