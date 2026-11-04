// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import LDAPKit
import Observation

/// The directory tree, loaded one level at a time as nodes are expanded.
///
/// The outline view (`DirectoryOutline`) shows it. Nodes are plain objects the
/// outline uses as its items; `version` changes whenever their structure does,
/// which is the outline's cue to reload.
@MainActor @Observable
final class TreeModel {
    @MainActor
    final class Node {
        let id: String
        let dn: String
        var name: String
        var kind: ObjectKind
        var disabled = false
        var mayHaveChildren: Bool
        /// Child ids once loaded; nil until then.
        var children: [String]?
        var isExpanded = false
        var isLoading = false
        var error: String?
        /// The container holds more than `childLimit` entries.
        var truncated = false
        var referenceCount = 0

        init(dn: String, name: String, kind: ObjectKind, mayHaveChildren: Bool) {
            id = DN.normalized(dn)
            self.dn = dn
            self.name = name
            self.kind = kind
            self.mayHaveChildren = mayHaveChildren
        }

        var showsDisclosure: Bool {
            if let children { return !children.isEmpty || truncated }
            return mayHaveChildren
        }
    }

    /// More children than this and the tree stops and points at Search.
    static let childLimit = 5000
    static let rootDSEKey = "#rootdse"

    weak var session: DirectorySession?
    @ObservationIgnored private(set) var nodes: [String: Node] = [:]
    private(set) var roots: [String] = []
    /// Bumped on every structural change: children loaded, a node expanded or
    /// collapsed by the model, loading started or finished.
    private(set) var version = 0
    /// Same-value writes are dropped, so the outline syncing its own selection
    /// back does not trigger another update.
    var selection: String? {
        get { selectionStorage }
        set { if newValue != selectionStorage { selectionStorage = newValue } }
    }
    private var selectionStorage: String?
    /// Show only containers (OUs, containers, domains), hiding accounts and
    /// groups: the shape of the directory without its contents.
    private(set) var containersOnly = false

    func setContainersOnly(_ on: Bool) {
        containersOnly = on
        version += 1
    }

    /// Bumped when the view should scroll `scrollTarget` into view.
    private(set) var scrollToken = 0
    private(set) var scrollTarget: String?

    func node(_ id: String) -> Node? { nodes[id] }

    /// Bumped whenever the tree is emptied: a level that finishes loading after
    /// that belongs to the tree that was, not to this one.
    @ObservationIgnored private var epoch = 0

    func clear() {
        epoch += 1
        nodes.removeAll()
        roots.removeAll()
        selection = nil
        version += 1
    }

    func reset(roots dns: [String]) async {
        clear()
        let rootDSE = Node(dn: "", name: "Root DSE", kind: .rootDSE, mayHaveChildren: false)
        rootDSE.children = []
        nodes[Self.rootDSEKey] = rootDSE
        var ids: [String] = []
        for dn in dns {
            let isDomain = DN.components(dn).allSatisfy { DN.rdnAttribute($0)?.lowercased() == "dc" }
            let node = Node(dn: dn, name: Self.rootName(dn), kind: isDomain ? .domain : .container, mayHaveChildren: true)
            nodes[node.id] = node
            ids.append(node.id)
        }
        roots = ids + [Self.rootDSEKey]
        version += 1
        // Refine the guessed icons; a failure here costs nothing but an icon.
        for id in ids {
            guard let node = nodes[id],
                  let entry = try? await session?.run({ try await $0.read(node.dn, attributes: ObjectKind.treeAttributes) })
            else { continue }
            node.kind = ObjectKind.classify(entry)
        }
        version += 1
    }

    static func rootName(_ dn: String) -> String {
        let parts = DN.components(dn)
        if !parts.isEmpty, parts.allSatisfy({ DN.rdnAttribute($0)?.lowercased() == "dc" }) {
            return DN.dnsDomain(dn) ?? dn
        }
        return DN.rdnValue(dn)
    }

    func toggle(_ id: String) {
        guard let node = nodes[id] else { return }
        if node.isExpanded {
            collapse(id)
        } else {
            Task { await expand(id) }
        }
    }

    func collapse(_ id: String) {
        guard let node = nodes[id], node.isExpanded else { return }
        node.isExpanded = false
        version += 1
    }

    func expand(_ id: String) async {
        guard let node = nodes[id], node.showsDisclosure || node.children == nil else { return }
        if !node.isExpanded {
            node.isExpanded = true
            version += 1
        }
        if node.children == nil { await load(node) }
    }

    func refresh(_ id: String) async {
        guard let node = nodes[id] else { return }
        node.children = nil
        node.truncated = false
        node.mayHaveChildren = true
        version += 1
        if node.isExpanded { await load(node) }
    }

    private func load(_ node: Node) async {
        guard let session, !node.isLoading else { return }
        node.isLoading = true
        node.error = nil
        version += 1
        defer {
            node.isLoading = false
            version += 1
        }
        let pageSize = session.profile.pageSize
        let startedIn = epoch
        do {
            let request = LDAPSearchRequest(base: node.dn, scope: .oneLevel,
                                            attributes: ObjectKind.treeAttributes + ["displayName"])
            let result = try await session.run {
                try await $0.pagedSearch(request, pageSize: pageSize, limit: Self.childLimit)
            }
            guard epoch == startedIn else { return }
            var children: [Node] = []
            for entry in result.entries {
                let kind = ObjectKind.classify(entry)
                let id = DN.normalized(entry.dn)
                // An entry cannot be its own child or its parent's: a server
                // answering that way would make the tree endless.
                if id == node.id || node.id.hasSuffix("," + id) { continue }
                let child = nodes[id] ?? Node(dn: entry.dn, name: DN.displayName(entry.dn), kind: kind, mayHaveChildren: true)
                child.kind = kind
                child.disabled = isDisabled(entry)
                if kind == .groupPolicy, let name = entry.string("displayName") { child.name = name }
                switch entry.string("hasSubordinates")?.uppercased() {
                case "TRUE": child.mayHaveChildren = true
                case "FALSE": child.mayHaveChildren = false
                default: child.mayHaveChildren = kind.mayHaveChildren
                }
                nodes[id] = child
                children.append(child)
            }
            children.sort {
                if $0.kind.sortRank != $1.kind.sortRank { return $0.kind.sortRank < $1.kind.sortRank }
                return $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
            node.children = children.map(\.id)
            node.truncated = result.stoppedAtLimit || result.result.code == .sizeLimitExceeded
            node.referenceCount = result.references.count
            if children.isEmpty && !node.truncated {
                node.mayHaveChildren = false
                node.isExpanded = false
            }
        } catch is CancellationError {
            node.isExpanded = false
        } catch {
            node.error = error.localizedDescription
            node.isExpanded = false
        }
    }

    /// Expands the path to `dn`, selects it and scrolls it into view. Returns
    /// false when `dn` is not under any root of this tree.
    @discardableResult
    func reveal(_ dn: String) async -> Bool {
        let target: String
        if dn.isEmpty {
            target = Self.rootDSEKey
        } else {
            let candidates = roots.compactMap { nodes[$0] }.filter { !$0.dn.isEmpty && DN.isWithin(dn, $0.dn) }
            guard let root = candidates.max(by: { DN.components($0.dn).count < DN.components($1.dn).count }) else {
                return false
            }
            for ancestor in DN.path(from: root.dn, to: dn) {
                let id = DN.normalized(ancestor)
                guard nodes[id] != nil else { return false }
                await expand(id)
            }
            target = DN.normalized(dn)
            guard nodes[target] != nil else { return false }
        }
        selection = target
        scrollTarget = target
        scrollToken += 1
        return true
    }
}
