// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

/// Chooses entries by browsing the directory or by finding them by name, and
/// returns their DNs: for DN-valued attributes, adding members, and choosing
/// where to create or move an entry.
struct DNPickerSheet: View {
    let session: DirectorySession
    var allowsMultiple = false
    var containersOnly = false
    var title = "Choose Entries"
    /// Opened in the tree when the picker appears, such as the current container.
    var startAt: String?
    let done: ([String]) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""
    @State private var results: [SearchRow]?
    @State private var selection: Set<String> = []
    @State private var searching = false
    @State private var typedDN = ""
    @State private var problem: String?
    @State private var task: Task<Void, Never>?
    @State private var tree: PickerTree?

    private var heading: String {
        allowsMultiple ? title : (containersOnly ? "Choose a Container" : "Choose an Entry")
    }

    private var chosen: [String] {
        let typed = typedDN.trimmingCharacters(in: .whitespaces)
        return typed.isEmpty ? Array(selection) : [typed]
    }

    var body: some View {
        SheetLayout(title: heading,
                    subtitle: containersOnly ? "Browse to an OU or container, or find it by name." : "Browse the directory, or find entries by name, account or email.",
                    width: 620, height: 540) {
            VStack(spacing: 0) {
                HStack(spacing: 8) {
                    HStack(spacing: 6) {
                        Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                        TextField("Find", text: $query, prompt: Text(containersOnly ? "Find an OU or container" : "Find by name, account or email"))
                            .textFieldStyle(.plain)
                            .onSubmit(find)
                        if searching { ProgressView().controlSize(.small) }
                        if !query.isEmpty {
                            Button { clearSearch() } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }
                                .buttonStyle(.borderless)
                                .help("Clear the search and browse again")
                                .accessibilityLabel("Clear search")
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
                    .overlay(RoundedRectangle(cornerRadius: 7).stroke(Color(nsColor: .separatorColor)))
                    Button("Find", action: find).disabled(query.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 10)
                if let problem {
                    Label(problem, systemImage: "exclamationmark.triangle.fill").font(.callout).foregroundStyle(.red)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 20).padding(.bottom, 6)
                }
                Divider()
                if let results {
                    resultList(results)
                } else if let tree {
                    treeList(tree)
                }
                Divider()
                FieldRow(label: "Or type a DN") {
                    TextField("DN", text: $typedDN, prompt: Text("OU=…,DC=…"))
                        .labelsHidden().textFieldStyle(.roundedBorder).autocorrectionDisabled()
                }
                .formLabelWidth(92)
                .padding(.horizontal, 20)
                .padding(.vertical, 10)
            }
        } status: {
            if !selection.isEmpty, typedDN.isEmpty {
                Text(selection.count == 1 ? DN.canonicalName(selection.first!) : "\(selection.count) chosen")
                    .foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
        } buttons: {
            Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
            Button(allowsMultiple && chosen.count > 1 ? "Choose \(chosen.count)" : "Choose") { finish(chosen) }
                .keyboardShortcut(.defaultAction)
                .disabled(chosen.isEmpty)
        }
        .task {
            let tree = PickerTree(session: session, containersOnly: containersOnly)
            self.tree = tree
            await tree.start(revealing: startAt)
            if let startAt, selection.isEmpty, tree.contains(startAt) { selection = [startAt] }
        }
        .onDisappear { task?.cancel() }
    }

    private func treeList(_ tree: PickerTree) -> some View {
        List(selection: $selection) {
            ForEach(tree.roots) { node in PickerTreeRow(node: node, tree: tree) }
        }
        .listStyle(.inset)
        .contextMenu(forSelectionType: String.self) { _ in } primaryAction: { ids in
            if !allowsMultiple, let id = ids.first { finish([id]) }
        }
        .overlay {
            if let error = tree.error {
                ContentUnavailableView("Cannot Browse", systemImage: "exclamationmark.triangle", description: Text(error))
            }
        }
    }

    private func resultList(_ results: [SearchRow]) -> some View {
        List(results, selection: $selection) { row in
            HStack(spacing: 8) {
                EntryIcon(kind: row.kind, disabled: row.disabled)
                VStack(alignment: .leading, spacing: 1) {
                    Text(row.name)
                    Text(row.location).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Text(row.account).font(.caption).foregroundStyle(.secondary)
            }
            .tag(row.id)
            .help(row.id)
        }
        .listStyle(.inset)
        .contextMenu(forSelectionType: String.self) { _ in } primaryAction: { ids in
            if !allowsMultiple, let id = ids.first { finish([id]) }
        }
        .overlay {
            if results.isEmpty && !searching {
                ContentUnavailableView("Nothing Found", systemImage: "magnifyingglass",
                                       description: Text("No \(containersOnly ? "container" : "entry") matches “\(query)”."))
            }
        }
    }

    private func finish(_ dns: [String]) {
        guard !dns.isEmpty else { return }
        dismiss()
        done(dns)
    }

    private func clearSearch() {
        task?.cancel()
        query = ""
        results = nil
        searching = false
        problem = nil
    }

    private func find() {
        let text = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        task?.cancel()
        searching = true
        problem = nil
        let value = LDAPFilter.escape(text)
        // Names that start with the text first (fast on AD), then, on AD, names
        // that contain it (AD reads every object for that); see SearchModel.nameFilters.
        let filters: [String]
        if containersOnly {
            filters = ["(&\(PickerTree.containerFilter)(|(ou=*\(value)*)(cn=*\(value)*)(name=*\(value)*)))"]
        } else {
            let names = SearchModel.nameFilters(text, activeDirectory: session.isMicrosoft)
            filters = [names.first] + (names.inside.map { [$0] } ?? [])
        }
        let bases = PickerTree.bases(session)
        task = Task {
            var found: [SearchRow] = []
            do {
                for filterText in filters {
                    let filter = try LDAPFilter.parse(filterText)
                    for base in bases {
                        let request = LDAPSearchRequest(base: base, scope: .subtree, filter: filter, attributes: SearchModel.displayAttributes + ObjectKind.disabledAttributes.filter { !SearchModel.displayAttributes.contains($0) })
                        let result = try await session.run { try await $0.pagedSearch(request, pageSize: 200, limit: 200) }
                        let shown = Set(found.map(\.id))
                        found += result.entries.map(SearchRow.init).filter { !shown.contains($0.id) }
                    }
                    guard !Task.isCancelled else { return }
                    // Shown as soon as each search answers; the spinner stays until the last.
                    results = found.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
                }
            } catch {
                // A search replaced by a newer one is not a problem to show.
                guard !Task.isCancelled, !(error is CancellationError) else { return }
                problem = error.localizedDescription
            }
            guard !Task.isCancelled else { return }
            results = found.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
            searching = false
        }
    }
}

/// One entry in the picker's tree. Children are read when it is first opened.
@MainActor @Observable
final class PickerNode: Identifiable {
    let id: String
    let name: String
    let kind: ObjectKind
    let disabled: Bool
    var mayHaveChildren: Bool
    var children: [PickerNode]?
    var isExpanded = false
    var loading = false

    init(dn: String, name: String, kind: ObjectKind, disabled: Bool = false, mayHaveChildren: Bool = true) {
        id = dn
        self.name = name
        self.kind = kind
        self.disabled = disabled
        self.mayHaveChildren = mayHaveChildren
    }
}

/// The directory as the picker shows it: the naming contexts, opened a level at a time.
@MainActor @Observable
final class PickerTree {
    static let containerFilter = "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=domain)(objectClass=domainDNS)(objectClass=builtinDomain)(objectClass=organization))"

    let session: DirectorySession
    let containersOnly: Bool
    var roots: [PickerNode] = []
    var error: String?

    init(session: DirectorySession, containersOnly: Bool) {
        self.session = session
        self.containersOnly = containersOnly
    }

    /// Where browsing and searching start: the default naming context, or every one.
    static func bases(_ session: DirectorySession) -> [String] {
        if !session.profile.baseDN.trimmingCharacters(in: .whitespaces).isEmpty { return [session.profile.baseDN] }
        if let main = session.server?.defaultNamingContext { return [main] }
        return session.server?.namingContexts ?? []
    }

    func start(revealing target: String?) async {
        roots = Self.bases(session).map { PickerNode(dn: $0, name: DN.canonicalName($0), kind: .domain) }
        if let first = roots.first {
            first.isExpanded = true
            await load(first)
        }
        if let target { await reveal(target) }
    }

    func contains(_ dn: String) -> Bool { find(dn, in: roots) != nil }

    private func find(_ dn: String, in nodes: [PickerNode]) -> PickerNode? {
        for node in nodes {
            if DN.isSame(node.id, dn) { return node }
            if let children = node.children, let found = find(dn, in: children) { return found }
        }
        return nil
    }

    /// Opens every container on the way to `dn`.
    func reveal(_ dn: String) async {
        let target = DN.normalized(dn)
        guard var node = roots.first(where: { target.hasSuffix(DN.normalized($0.id)) }) else { return }
        while !DN.isSame(node.id, dn) {
            node.isExpanded = true
            if node.children == nil { await load(node) }
            guard let next = node.children?.first(where: { target.hasSuffix(DN.normalized($0.id)) }) else { return }
            node = next
        }
    }

    func load(_ node: PickerNode) async {
        guard node.children == nil, !node.loading else { return }
        node.loading = true
        defer { node.loading = false }
        do {
            let filter = containersOnly ? try LDAPFilter.parse(Self.containerFilter) : .present("objectClass")
            let request = LDAPSearchRequest(base: node.id, scope: .oneLevel, filter: filter,
                                            attributes: ObjectKind.treeAttributes + ["displayName"])
            let pageSize = session.profile.pageSize
            let result = try await session.run { try await $0.pagedSearch(request, pageSize: pageSize, limit: TreeModel.childLimit) }
            node.children = result.entries.map { entry in
                let kind = ObjectKind.classify(entry)
                let more: Bool
                switch entry.string("hasSubordinates")?.uppercased() {
                case "TRUE": more = true
                case "FALSE": more = false
                default: more = containersOnly ? kind.isContainer : kind.mayHaveChildren
                }
                return PickerNode(dn: entry.dn, name: DN.displayName(entry.dn), kind: kind, disabled: isDisabled(entry), mayHaveChildren: more)
            }
            .sorted {
                if $0.kind.sortRank != $1.kind.sortRank { return $0.kind.sortRank < $1.kind.sortRank }
                return $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
            if node.children?.isEmpty == true { node.mayHaveChildren = false }
        } catch {
            node.children = []
            self.error = error.localizedDescription
        }
    }
}

private struct PickerTreeRow: View {
    @Bindable var node: PickerNode
    let tree: PickerTree

    var body: some View {
        if node.mayHaveChildren {
            DisclosureGroup(isExpanded: $node.isExpanded) {
                if let children = node.children {
                    ForEach(children) { child in PickerTreeRow(node: child, tree: tree) }
                } else {
                    HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Reading…").foregroundStyle(.secondary) }
                }
            } label: {
                label
            }
            .tag(node.id)
            .onChange(of: node.isExpanded) { _, expanded in
                if expanded { Task { await tree.load(node) } }
            }
        } else {
            label.tag(node.id)
        }
    }

    private var label: some View {
        HStack(spacing: 6) {
            EntryIcon(kind: node.kind, disabled: node.disabled)
            Text(node.name).lineLimit(1)
        }
        .help(node.id)
    }
}
