// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

struct SearchView: View {
    let session: DirectorySession
    @Bindable var search: SearchModel
    @State private var building = false

    private var forestWide: Bool { search.wholeForest && session.hasADTools }

    var body: some View {
        VStack(spacing: 0) {
            form
                .padding(12)
            Divider()
            results
        }
    }

    // MARK: Form

    private var form: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Picker("", selection: $building) {
                    Text("Filter").tag(false)
                    Text("Builder").tag(true)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                .help("Type an LDAP filter, or build one from conditions")
                Spacer()
                presetsMenu
            }
            if building {
                FilterBuilder(session: session, filterText: $search.filterText)
                Text(search.filterText).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled).lineLimit(2)
            } else {
                FilterEditor(text: $search.filterText,
                             attributes: session.schema?.attributeNames ?? AttributeField.common,
                             classes: session.schema?.classNames ?? [],
                             invalid: search.filterProblem != nil) { search.run() }
                    .frame(height: 62)
                    .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(search.filterProblem == nil ? Color(nsColor: .separatorColor) : .red.opacity(0.6)))
                    .help("An RFC 4515 filter. Attribute names complete as you type. Return searches; Option-Return starts a new line.")
            }
            if let problem = search.filterProblem, !search.filterText.isEmpty {
                Label(problem, systemImage: "exclamationmark.circle")
                    .font(.caption).foregroundStyle(.red)
            } else if let note = search.presetNote {
                Label(note, systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary)
            }
            HStack(spacing: 6) {
                TextField("Base", text: forestWide ? .constant("") : $search.base,
                          prompt: Text(forestWide ? "Every domain in the forest" : "Base DN"))
                    .font(.callout.monospaced())
                    .textFieldStyle(.roundedBorder)
                    .disabled(forestWide)
                Menu {
                    if let selected = session.selectedDN, !selected.isEmpty {
                        Button("Selected Entry") { search.base = selected }
                        Divider()
                    }
                    ForEach(session.server?.namingContexts ?? [], id: \.self) { context in
                        Button(context) { search.base = context }
                    }
                } label: {
                    // A word rather than a lone chevron: a menu showing only a
                    // symbol is drawn as a smaller icon button, lower than the
                    // field and pop-up beside it.
                    Text("Base")
                }
                .fixedSize()
                .help("Choose the base: the selected entry or a naming context")
                .disabled(forestWide)
            }
            // A DN is long: the base has the row to itself, its scope below it.
            HStack(spacing: 6) {
                Picker("Scope", selection: $search.scope) {
                    ForEach(LDAPScope.allCases, id: \.self) { Text($0.label).tag($0) }
                }
                .labelsHidden()
                .fixedSize()
                .disabled(forestWide)
                if session.hasADTools {
                    Toggle("Whole forest", isOn: $search.wholeForest)
                        .toggleStyle(.checkbox)
                        .fixedSize()
                        .help("Search every domain of the forest through the global catalog, which holds some of each entry's attributes")
                }
                Spacer(minLength: 0)
            }
            HStack(spacing: 6) {
                TextField("Attributes", text: $search.attributesText, prompt: Text("Extra attributes for export, e.g. mail, title, manager"))
                    .font(.callout)
                    .textFieldStyle(.roundedBorder)
                Text("Limit").font(.callout).foregroundStyle(.secondary)
                TextField("Limit", value: $search.limit, format: .number)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 70)
                if search.running || search.lookingInside {
                    Button("Stop") { search.cancel() }
                } else {
                    Button("Search") { search.run() }
                        .keyboardShortcut(.return, modifiers: .command)
                        .buttonStyle(.borderedProminent)
                        .disabled(search.filterProblem != nil)
                }
            }
        }
    }

    private var presetsMenu: some View {
        Menu {
            ForEach(SearchPreset.Group.allCases, id: \.self) { group in
                Section(group.rawValue) {
                    ForEach(SearchPreset.all.filter { $0.group == group }) { preset in
                        Button(preset.title) { search.apply(preset) }
                    }
                }
            }
        } label: {
            Label("Presets", systemImage: "line.3.horizontal.decrease.circle")
        }
        .fixedSize()
        .help("Common searches. Those using userAccountControl bits and AD attributes are for Active Directory.")
    }

    // MARK: Results

    @ViewBuilder
    private var results: some View {
        if let error = search.error {
            ContentUnavailableView {
                Label("Search Failed", systemImage: "exclamationmark.triangle")
            } description: {
                Text(error).textSelection(.enabled)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if (search.running || search.lookingInside) && search.rows.isEmpty {
            VStack(spacing: 8) {
                ProgressView()
                Text(search.lookingInside ? "No names start with that. Looking inside names…"
                     : search.progress > 0 ? "\(search.progress.formatted()) found…" : "Searching…")
                    .font(.callout).foregroundStyle(.secondary).monospacedDigit()
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if !search.hasRun {
            // Filling the pane keeps the search form at the top before the first search.
            ContentUnavailableView("Search the Directory", systemImage: "magnifyingglass",
                                   description: Text("Type an LDAP filter, build one, or pick a preset, then click Search or press ⌘↩."))
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if search.rows.isEmpty {
            ContentUnavailableView("No Matches", systemImage: "magnifyingglass",
                                   description: Text(search.summary.map { "Nothing matched. \($0)." } ?? "Nothing matched."))
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            VStack(spacing: 0) {
                table
                footer
            }
        }
    }

    private var table: some View {
        ResultsTable(session: session, search: search, rows: search.rows,
                     selection: search.selection, sortOrder: search.sortOrder)
            .onChange(of: search.sortOrder) { search.resort() }
            .onChange(of: search.selection) { _, selection in
                if selection.count == 1, let dn = selection.first { session.select(dn) }
            }
    }

    private var footer: some View {
        HStack(spacing: 8) {
            if search.running {
                ProgressView().controlSize(.small)
                Text("\(search.progress.formatted()) found…").monospacedDigit()
            } else if let summary = search.summary {
                Text(summary).monospacedDigit()
            }
            if search.lookingInside {
                ProgressView().controlSize(.small)
                Text("Looking inside names too…").foregroundStyle(.secondary)
            }
            ForEach(search.warnings, id: \.self) { warning in
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .help(warning)
            }
            if let first = search.warnings.first {
                Text(first).lineLimit(1).truncationMode(.tail)
            }
            Spacer()
            Menu {
                Button("CSV…") { Exporter.saveCSV(search.entries, attributes: search.exportAttributes, suggestedName: "search") }
                Button("LDIF, All Attributes…") { search.exportLDIF() }
                Divider()
                Button("Copy DNs") { Pasteboard.copy(search.rows.map(\.id).joined(separator: "\n")) }
            } label: {
                if search.exporting { ProgressView().controlSize(.small) } else { Label("Export", systemImage: "square.and.arrow.up") }
            }
            .fixedSize()
            .disabled(search.entries.isEmpty || search.exporting)
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(.bar)
        .overlay(alignment: .top) { Divider() }
    }
}
