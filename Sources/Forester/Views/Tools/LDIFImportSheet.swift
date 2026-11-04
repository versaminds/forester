// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import AppKit
import LDAPKit
import SwiftUI
import UniformTypeIdentifiers

/// Imports an LDIF file: content records become adds, change records are
/// applied as written. Shows progress and a per-record log.
struct LDIFImportSheet: View {
    let session: DirectorySession
    @Environment(\.dismiss) private var dismiss

    enum ExistingEntries: String, CaseIterable {
        case fail = "Report an error"
        case skip = "Skip them"
        case update = "Replace their attribute values"
    }

    struct FileReference: Identifiable {
        let id = UUID()
        let line: Int
        let reference: String
    }

    struct LogLine: Identifiable {
        let id = UUID()
        let record: LDIFRecord
        let ok: Bool
        let message: String
    }

    @State private var file: URL?
    @State private var text = ""
    /// Files the LDIF's `attr:< file:…` values would read from this Mac.
    @State private var references: [FileReference] = []
    @State private var readReferencedFiles = false
    /// Entries the file would add that exist already, when replacing their values.
    @State private var replacing: [String]?
    @State private var checking = false
    @State private var records: [LDIFRecord] = []
    @State private var parseError: String?
    @State private var continueOnError = true
    @State private var existing: ExistingEntries = .skip
    @State private var writeLog = false
    @State private var log: [LogLine] = []
    @State private var running = false
    @State private var finished = false
    @State private var task: Task<Void, Never>?

    private var done: Int { log.count }
    private var failures: Int { log.filter { !$0.ok }.count }

    var initialFile: URL?
    @State private var dropTargeted = false
    @State private var onlyFailures = false

    private var showsLog: Bool { running || finished }

    private var status: String? {
        if !session.canWrite { return "This connection is read-only. Turn on editing to import." }
        if file == nil { return "Choose an LDIF file, or drop one here." }
        if !references.isEmpty && !readReferencedFiles { return "Allow the files it refers to, or choose another file." }
        return nil
    }

    var body: some View {
        SheetLayout(title: "Import LDIF", subtitle: "Into \(session.profile.displayName)", width: 640, height: showsLog ? 640 : nil) {
            VStack(spacing: 0) {
                Form {
                    Section {
                        FieldRow(label: "File") {
                            HStack {
                                Image(systemName: "doc.text").foregroundStyle(.secondary)
                                Text(file?.lastPathComponent ?? "None chosen")
                                    .foregroundStyle(file == nil ? .secondary : .primary)
                                    .lineLimit(1).truncationMode(.middle)
                                    .help(file?.path ?? "")
                                Spacer()
                                Button(file == nil ? "Choose File…" : "Choose Another…", action: choose).disabled(running || checking)
                            }
                        }
                        if let parseError {
                            Label { Text(parseError).textSelection(.enabled) } icon: {
                                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                            }
                        } else if !records.isEmpty {
                            ValueRow(label: "Contains", value: summary)
                        }
                        if !references.isEmpty {
                            Toggle(isOn: $readReferencedFiles) {
                                Text("Read the \(references.count == 1 ? "file" : "\(references.count) files") it refers to")
                                Text(referencesNote)
                            }
                            .formSwitch("Read the files it refers to", hint: referencesNote)
                            .onChange(of: readReferencedFiles) { _, on in
                                if on, ForesterInfo.fromAppStore, !askForFolder() {
                                    readReferencedFiles = false
                                    return
                                }
                                parse()
                            }
                        }
                    }
                    Section("Options") {
                        Toggle(isOn: $continueOnError) {
                            Text("Continue after an error")
                            Text("Otherwise the import stops at the first record the server refuses.")
                        }
                        .formSwitch("Continue after an error", hint: "Otherwise the import stops at the first record the server refuses.")
                        PickerRow(label: "If an entry exists", selection: $existing) {
                            ForEach(ExistingEntries.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                        }
                        // The sandbox grants the LDIF itself, not its folder;
                        // there Save Log… asks where the log goes.
                        if !ForesterInfo.fromAppStore {
                            Toggle(isOn: $writeLog) {
                                Text("Write a log file next to the LDIF")
                                Text("One line per record, with the server's answer.")
                            }
                            .formSwitch("Write a log file next to the LDIF", hint: "One line per record, with the server's answer.")
                        }
                    }
                }
                .formStyle(.grouped)
                .formLabelWidth(120)
                .hugsContent()
                .disabled(running || checking)
                if showsLog {
                    Divider()
                    VStack(alignment: .leading, spacing: 8) {
                        ProgressView(value: Double(done), total: Double(max(records.count, 1))) {
                            HStack {
                                Text(finished ? "Done: \(done - failures) succeeded, \(failures) failed" : "Importing \(done) of \(records.count)…")
                                Spacer()
                                if failures > 0 {
                                    Toggle("Show only failures", isOn: $onlyFailures).toggleStyle(.checkbox).font(.callout)
                                }
                            }
                        }
                        .padding(.horizontal, 20)
                        .padding(.top, 12)
                        List {
                            ForEach(onlyFailures ? log.filter { !$0.ok } : log) { line in logRow(line) }
                        }
                        .listStyle(.inset(alternatesRowBackgrounds: true))
                    }
                }
            }
            .overlay {
                if dropTargeted {
                    RoundedRectangle(cornerRadius: 10).strokeBorder(Color.accentColor, lineWidth: 3).padding(6)
                }
            }
            .dropDestination(for: URL.self) { urls, _ in
                guard !running, !checking, let url = urls.first else { return false }
                load(url)
                return true
            } isTargeted: { dropTargeted = $0 }
        } status: {
            if checking {
                HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Checking which entries exist…").foregroundStyle(.secondary) }
            } else if let status {
                Text(status).foregroundStyle(.secondary)
            }
        } buttons: {
            if running || checking {
                Button("Stop") { task?.cancel(); checking = false }
            } else {
                if finished, !log.isEmpty {
                    Button("Save Log…", action: saveLogAs)
                }
                Button(finished ? "Close" : "Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                if !finished {
                    Button("Import \(records.count) Record\(records.count == 1 ? "" : "s")", action: checkThenStart)
                        .keyboardShortcut(.defaultAction)
                        .disabled(records.isEmpty || !session.canWrite)
                }
            }
        }
        .onAppear { if let initialFile, file == nil { load(initialFile) } }
        .alert(replacingTitle, isPresented: Binding(get: { replacing != nil }, set: { if !$0 { replacing = nil } })) {
            Button("Replace Values", role: .destructive) { replacing = nil; start() }
            Button("Cancel", role: .cancel) { replacing = nil }
        } message: {
            Text(replacingMessage)
        }
        .onDisappear { task?.cancel() }
    }

    private func logRow(_ line: LogLine) -> some View {
        let color: Color = line.ok ? .secondary : .red
        let outcome = line.message.isEmpty ? "" : ": \(line.message)"
        return HStack(alignment: .top) {
            Image(systemName: line.ok ? "checkmark.circle.fill" : "xmark.octagon.fill")
                .foregroundStyle(line.ok ? Color.green : Color.red)
            VStack(alignment: .leading, spacing: 1) {
                Text("\(Self.verb(line.record)) \(DN.displayName(line.record.dn))").lineLimit(1)
                Text("Line \(line.record.line)\(outcome)").font(.caption).foregroundStyle(color).textSelection(.enabled)
            }
        }
        .help(line.record.dn)
    }

    static func verb(_ record: LDIFRecord) -> String {
        switch record.change {
        case .add: return "Add"
        case .modify: return "Change"
        case .modifyDN(_, _, let superior): return superior == nil ? "Rename" : "Move"
        case .delete: return "Delete"
        }
    }

    private var replacingTitle: String {
        let count = replacing?.count ?? 0
        return count == 1 ? "1 entry exists already" : "\(count) entries exist already"
    }

    private var replacingMessage: String {
        let found = replacing ?? []
        let shown = found.prefix(5).map(DN.displayName).joined(separator: ", ")
        let more = found.count > 5 ? ", and \(found.count - 5) more" : ""
        return "Each attribute in the file replaces all of that attribute's values in \(shown)\(more). Group members and permissions are replaced the same way."
    }

    /// What the file would read and send, so the user can tell a photo from
    /// a private key before allowing it.
    private var referencesNote: String {
        let shown = references.prefix(4).map { "line \($0.line): \($0.reference)" }
        let more = references.count > 4 ? ", and \(references.count - 4) more" : ""
        return "Their contents are sent to the directory: \(shown.joined(separator: "; "))\(more). Only files in the LDIF's folder, up to \(LDIFFileReferences.maxFileBytes >> 20) MB each."
    }

    private var summary: String {
        var adds = 0, modifies = 0, renames = 0, deletes = 0
        for record in records {
            switch record.change {
            case .add: adds += 1
            case .modify: modifies += 1
            case .modifyDN: renames += 1
            case .delete: deletes += 1
            }
        }
        func count(_ n: Int, _ one: String, _ many: String) -> String? { n == 0 ? nil : "\(n) \(n == 1 ? one : many)" }
        let parts = [count(adds, "new entry", "new entries"), count(modifies, "modification", "modifications"),
                     count(renames, "rename or move", "renames or moves"), count(deletes, "deletion", "deletions")].compactMap { $0 }
        return "\(records.count) record\(records.count == 1 ? "" : "s"): " + parts.joined(separator: ", ")
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "ldif") ?? .plainText, .plainText, .text]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        load(url)
    }

    /// The sandbox lets Forester read the LDIF the person chose, not the
    /// files beside it. Choosing its folder in an open panel grants that
    /// folder for as long as Forester runs; nothing else is asked for.
    private func askForFolder() -> Bool {
        guard let folder = file?.deletingLastPathComponent() else { return false }
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.directoryURL = folder
        panel.prompt = "Allow"
        panel.message = "Forester may read only what you choose. Choose the LDIF's folder, \(folder.lastPathComponent), so it can read the files the LDIF refers to."
        guard panel.runModal() == .OK, let chosen = panel.url else { return false }
        // Only a choice that contains the LDIF's folder grants what is read.
        let chosenPath = chosen.standardizedFileURL.path, folderPath = folder.standardizedFileURL.path
        return folderPath == chosenPath || folderPath.hasPrefix(chosenPath.hasSuffix("/") ? chosenPath : chosenPath + "/")
    }

    private func load(_ url: URL) {
        file = url
        log = []
        finished = false
        readReferencedFiles = false
        do {
            text = try String(contentsOf: url, encoding: .utf8)
        } catch {
            text = ""
            references = []
            records = []
            parseError = error.localizedDescription
            return
        }
        references = LDIFParser.fileReferences(in: text).map { FileReference(line: $0.line, reference: $0.reference) }
        parse()
    }

    /// Nothing is read from the Mac's files until the user allows it.
    private func parse() {
        guard let file else { return }
        if !references.isEmpty && !readReferencedFiles {
            records = []
            parseError = nil
            return
        }
        do {
            records = try LDIFParser.parse(text, files: readReferencedFiles ? .within(file.deletingLastPathComponent()) : .refuse)
            parseError = records.isEmpty ? "The file holds no records." : nil
        } catch {
            records = []
            parseError = error.localizedDescription
        }
    }

    /// Replacing values in an entry that exists can change much more than
    /// adding one (a group's members, an entry's permissions), so the user sees
    /// which ones first.
    private func checkThenStart() {
        guard existing == .update else { start(); return }
        let adds = records.compactMap { record -> String? in
            if case .add = record.change { return record.dn }
            return nil
        }
        checking = true
        task = Task {
            var found: [String] = []
            for dn in adds {
                if Task.isCancelled { break }
                let present = try? await session.run { try await $0.read(dn, attributes: ["1.1"]) }
                if present != nil { found.append(dn) }
            }
            checking = false
            guard !Task.isCancelled else { return }
            if found.isEmpty { start() } else { replacing = found }
        }
    }

    private func start() {
        running = true
        log = []
        let records = self.records
        let continueOnError = self.continueOnError
        let existing = self.existing
        task = Task {
            var parents: Set<String> = []
            for record in records {
                if Task.isCancelled { break }
                let outcome = await apply(record, existing: existing)
                log.append(outcome)
                if outcome.ok {
                    parents.insert(DN.parent(record.dn) ?? "")
                    if case .modifyDN(_, _, let superior?) = record.change { parents.insert(superior) }
                }
                if !outcome.ok && !continueOnError { break }
            }
            running = false
            finished = true
            if writeLog, let file { saveLog(next: file) }
            if log.contains(where: \.ok) {
                await session.record("Imported \(log.filter(\.ok).count) of \(records.count) records from \(file?.lastPathComponent ?? "an LDIF file").",
                                     plan: .impossible(dn: "", why: "An import is not undone here. Save its log to see what each record did."),
                                     before: nil, registering: false)
            }
            for parent in parents where session.tree.node(DN.normalized(parent))?.children != nil {
                await session.tree.refresh(DN.normalized(parent))
            }
            session.inspector.reload()
            session.report("Imported \(log.filter(\.ok).count) of \(records.count) records\(failures > 0 ? ", \(failures) failed" : "").",
                           isError: failures > 0)
        }
    }

    private func apply(_ record: LDIFRecord, existing: ExistingEntries) async -> LogLine {
        do {
            switch record.change {
            case .add(let attributes):
                do {
                    try await session.write { try await $0.add(record.dn, attributes: attributes) }
                } catch let error as LDAPError where error.resultCode?.rawValue == 68 && existing != .fail {
                    // AD also answers 68 when another object already has this
                    // sAMAccountName or UPN; only an existing DN is "already there".
                    let present = try? await session.run { try await $0.read(record.dn, attributes: ["1.1"]) }
                    guard present != nil else { throw error }
                    if existing == .skip { return LogLine(record: record, ok: true, message: "already exists, skipped") }
                    let changes = attributes.filter { $0.baseName.caseInsensitiveCompare("objectClass") != .orderedSame }
                        .map { LDAPModification(.replace, $0.name, $0.values) }
                    try await session.write { try await $0.modify(record.dn, changes) }
                    return LogLine(record: record, ok: true, message: "updated")
                }
            case .delete:
                try await session.write { try await $0.delete(record.dn) }
            case .modify(let changes):
                try await session.write { try await $0.modify(record.dn, changes) }
            case .modifyDN(let rdn, let deleteOld, let superior):
                try await session.write { try await $0.modifyDN(record.dn, newRDN: rdn, deleteOldRDN: deleteOld, newSuperior: superior) }
            }
            return LogLine(record: record, ok: true, message: "")
        } catch {
            return LogLine(record: record, ok: false, message: error.localizedDescription)
        }
    }

    private var logText: String {
        let stamp = ISO8601DateFormatter().string(from: Date())
        var text = "# Forester import of \(file?.lastPathComponent ?? "LDIF") into \(session.profile.endpoint), \(stamp)\n"
        for line in log {
            text += "line \(line.record.line)\t\(line.record.summary)\t\(line.record.dn)\t\(line.ok ? "OK" : "FAILED")"
            text += line.message.isEmpty ? "\n" : "\t\(line.message)\n"
        }
        return text
    }

    private func saveLog(next file: URL) {
        let url = file.deletingPathExtension().appendingPathExtension("import-log.txt")
        do {
            try logText.write(to: url, atomically: true, encoding: .utf8)
        } catch {
            session.report("The log could not be written: \(error.localizedDescription)", isError: true)
        }
    }

    private func saveLogAs() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = (file?.deletingPathExtension().lastPathComponent ?? "import") + "-log.txt"
        panel.allowedContentTypes = [.plainText]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try logText.write(to: url, atomically: true, encoding: .utf8)
        } catch {
            session.report("The log could not be written: \(error.localizedDescription)", isError: true)
        }
    }
}

extension DirectorySession {
    /// Exports an entry, its children, or its whole subtree as LDIF, with every
    /// user attribute and ranged values completed.
    func exportLDIF(_ dn: String, scope: LDAPScope) {
        let pageSize = profile.pageSize
        let name = dn.isEmpty ? "rootdse" : DN.displayName(dn)
        report("Exporting \(name)…", isError: false)
        Task {
            do {
                let request = LDAPSearchRequest(base: dn, scope: scope, attributes: ["*"])
                let entries: [LDAPEntry] = try await run { connection in
                    let found = try await connection.pagedSearch(request, pageSize: pageSize).entries
                    var completed: [LDAPEntry] = []
                    for entry in found { completed.append(try await connection.completingRangedAttributes(entry)) }
                    return LDIF.parentsFirst(completed)
                }
                let suffix = scope == .base ? "" : (scope == .oneLevel ? "-children" : "-subtree")
                report("\(entries.count) entries ready.", isError: false)
                Exporter.saveLDIF(entries, suggestedName: name + suffix)
            } catch {
                report(error.localizedDescription, isError: true)
            }
        }
    }
}
