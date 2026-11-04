// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import AppKit
import LDAPKit
import SwiftUI

struct TreeView: View {
    let session: DirectorySession
    let tree: TreeModel

    var body: some View {
        // Reading these here is what makes SwiftUI call updateNSView when they change.
        DirectoryOutline(session: session, tree: tree, version: tree.version,
                         selection: tree.selection, scrollToken: tree.scrollToken)
            .overlay {
                if tree.roots.isEmpty { ProgressView() }
            }
            .safeAreaInset(edge: .top, spacing: 0) {
                if tree.containersOnly {
                    HStack {
                        Text("Showing containers only").font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button("Show All") { tree.setContainersOnly(false) }.controlSize(.small)
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(.bar)
                }
            }
    }
}

/// The directory tree as a native outline view.
///
/// An `NSOutlineView` rather than a SwiftUI `List`: rows have a fixed height, so
/// inserting a thousand children is cheap and never re-enters AppKit's row
/// height cache (which SwiftUI's list does when rows are inserted above the
/// selection), and it brings what Mac users expect from a tree for free:
/// arrow keys, Option-click to expand everything beneath, type-to-select.
struct DirectoryOutline: NSViewRepresentable {
    let session: DirectorySession
    let tree: TreeModel
    let version: Int
    let selection: String?
    let scrollToken: Int

    func makeCoordinator() -> Coordinator {
        Coordinator(session: session, tree: tree)
    }

    func makeNSView(context: Context) -> NSScrollView {
        let outline = NSOutlineView()
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("name"))
        column.resizingMask = .autoresizingMask
        outline.addTableColumn(column)
        outline.outlineTableColumn = column
        outline.headerView = nil
        outline.style = .inset
        outline.rowHeight = 24
        outline.usesAutomaticRowHeights = false
        outline.indentationPerLevel = 14
        outline.autoresizesOutlineColumn = false
        outline.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        outline.allowsMultipleSelection = false
        outline.allowsTypeSelect = true
        outline.backgroundColor = .clear
        outline.dataSource = context.coordinator
        outline.delegate = context.coordinator
        outline.target = context.coordinator
        outline.doubleAction = #selector(Coordinator.doubleClicked(_:))
        let menu = NSMenu()
        menu.delegate = context.coordinator
        outline.menu = menu
        // Drag an entry onto a container to move it there.
        outline.registerForDraggedTypes([.string])
        outline.setDraggingSourceOperationMask(.move, forLocal: true)
        outline.setAccessibilityLabel("Directory tree")

        let scroll = NSScrollView()
        scroll.documentView = outline
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        context.coordinator.outline = outline
        context.coordinator.sync(version: version, selection: selection, scrollToken: scrollToken)
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        // Choosing another connection reuses this view with that connection's
        // tree; its version number says nothing about what the outline shows.
        if context.coordinator.tree !== tree { context.coordinator.forgetShownState() }
        context.coordinator.session = session
        context.coordinator.tree = tree
        context.coordinator.sync(version: version, selection: selection, scrollToken: scrollToken)
    }

    @MainActor
    final class Coordinator: NSObject, NSOutlineViewDataSource, NSOutlineViewDelegate, NSMenuDelegate {
        var session: DirectorySession
        var tree: TreeModel
        weak var outline: NSOutlineView?
        private var shownVersion = -1
        private var shownScrollToken = 0
        /// Set while the coordinator changes the outline itself, so the
        /// delegate callbacks that causes are not mistaken for the user.
        private var syncing = false

        init(session: DirectorySession, tree: TreeModel) {
            self.session = session
            self.tree = tree
        }

        func forgetShownState() {
            shownVersion = -1
            shownScrollToken = -1
        }

        // MARK: Model → view

        func sync(version: Int, selection: String?, scrollToken: Int) {
            guard let outline else { return }
            syncing = true
            defer { syncing = false }
            if version != shownVersion {
                shownVersion = version
                outline.reloadData()
                expandAsInModel(tree.roots, in: outline)
            }
            let shown = (outline.item(atRow: outline.selectedRow) as? TreeModel.Node)?.id
            if shown != selection {
                if let selection, let node = tree.node(selection), case let row = outline.row(forItem: node), row >= 0 {
                    outline.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
                } else {
                    outline.deselectAll(nil)
                }
            }
            if scrollToken != shownScrollToken {
                shownScrollToken = scrollToken
                if let target = tree.scrollTarget, let node = tree.node(target), case let row = outline.row(forItem: node), row >= 0 {
                    scrollToCentre(row, in: outline)
                }
            }
        }

        private func expandAsInModel(_ ids: [String], in outline: NSOutlineView) {
            var visited = Set<String>()
            func expand(_ ids: [String]) {
                for id in ids where visited.insert(id).inserted {
                    guard let node = tree.node(id), node.isExpanded, let children = node.children else { continue }
                    if !outline.isItemExpanded(node) { outline.expandItem(node) }
                    expand(children)
                }
            }
            expand(ids)
        }

        private func scrollToCentre(_ row: Int, in outline: NSOutlineView) {
            guard let clip = outline.enclosingScrollView?.contentView else {
                outline.scrollRowToVisible(row)
                return
            }
            let rect = outline.rect(ofRow: row)
            if clip.documentVisibleRect.contains(rect) { return }
            let y = max(0, rect.midY - clip.bounds.height / 2)
            clip.animator().setBoundsOrigin(NSPoint(x: 0, y: min(y, max(0, outline.frame.height - clip.bounds.height))))
        }

        // MARK: Data source

        private func childIDs(of item: Any?) -> [String] {
            let ids = (item as? TreeModel.Node)?.children ?? (item == nil ? tree.roots : [])
            guard tree.containersOnly else { return ids }
            return ids.filter { id in
                guard let node = tree.node(id) else { return false }
                return node.kind.isContainer || (node.kind == .other && node.mayHaveChildren)
            }
        }

        func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
            childIDs(of: item).count
        }

        func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
            let ids = childIDs(of: item)
            return tree.node(ids[index]) ?? TreeModel.Node(dn: ids[index], name: "?", kind: .other, mayHaveChildren: false)
        }

        func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
            (item as? TreeModel.Node)?.showsDisclosure ?? false
        }

        // MARK: Drag and drop

        func outlineView(_ outlineView: NSOutlineView, pasteboardWriterForItem item: Any) -> NSPasteboardWriting? {
            guard session.canWrite, let node = item as? TreeModel.Node, !node.dn.isEmpty,
                  !tree.roots.contains(node.id) else { return nil }
            return node.dn as NSString
        }

        func outlineView(_ outlineView: NSOutlineView, validateDrop info: NSDraggingInfo, proposedItem item: Any?,
                         proposedChildIndex index: Int) -> NSDragOperation {
            // Only an entry dragged within this tree: text from another app, or
            // a node from a window connected to another directory, is not a DN here.
            guard (info.draggingSource as? NSOutlineView) === outlineView,
                  let target = item as? TreeModel.Node, !target.dn.isEmpty,
                  target.kind.isContainer || target.kind == .other,
                  let dragged = info.draggingPasteboard.string(forType: .string),
                  !DN.isWithin(target.dn, dragged),
                  DN.parent(dragged).map({ !DN.isSame($0, target.dn) }) ?? true else { return [] }
            outlineView.setDropItem(target, dropChildIndex: NSOutlineViewDropOnItemIndex)
            return .move
        }

        func outlineView(_ outlineView: NSOutlineView, acceptDrop info: NSDraggingInfo, item: Any?, childIndex index: Int) -> Bool {
            guard (info.draggingSource as? NSOutlineView) === outlineView,
                  let target = item as? TreeModel.Node, let dragged = info.draggingPasteboard.string(forType: .string) else { return false }
            let alert = NSAlert()
            alert.messageText = "Move “\(DN.displayName(dragged))” to “\(target.name)”?"
            alert.informativeText = "From \(DN.parent(dragged).map(DN.canonicalName) ?? "")\nto \(DN.canonicalName(target.dn))\non \(session.profile.displayName) (\(session.profile.host))"
            alert.addButton(withTitle: "Move")
            alert.addButton(withTitle: "Cancel")
            guard alert.runModal() == .alertFirstButtonReturn else { return false }
            let rdn = DN.rdn(dragged)
            let newDN = "\(rdn),\(target.dn)"
            let oldParent = DN.parent(dragged) ?? ""
            Task { [session] in
                let back = UndoPlan.inverse(dn: newDN, undoneAt: dragged) { try await $0.modifyDN(newDN, newRDN: rdn, deleteOldRDN: true, newSuperior: oldParent) }
                await session.change("Moved to \(DN.canonicalName(target.dn)).", refreshing: [oldParent, target.dn], select: newDN, undo: back) {
                    try await $0.modifyDN(dragged, newRDN: rdn, deleteOldRDN: true, newSuperior: target.dn)
                }
            }
            return true
        }

        // MARK: Delegate

        func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView? {
            guard let node = item as? TreeModel.Node else { return nil }
            let cell = outlineView.makeView(withIdentifier: TreeCell.identifier, owner: nil) as? TreeCell ?? TreeCell()
            cell.configure(node)
            return cell
        }

        func outlineViewItemWillExpand(_ notification: Notification) {
            guard !syncing, let node = notification.userInfo?["NSObject"] as? TreeModel.Node else { return }
            node.isExpanded = true
            if node.children == nil {
                let id = node.id
                Task { await tree.expand(id) }
            }
        }

        func outlineViewItemDidCollapse(_ notification: Notification) {
            guard !syncing, let node = notification.userInfo?["NSObject"] as? TreeModel.Node else { return }
            node.isExpanded = false
        }

        func outlineViewSelectionDidChange(_ notification: Notification) {
            guard !syncing, let outline else { return }
            let node = outline.item(atRow: outline.selectedRow) as? TreeModel.Node
            // Defer the model update past AppKit's own callback.
            DispatchQueue.main.async { [tree, session] in
                tree.selection = node?.id
                if let node { session.select(node.dn) }
            }
        }

        @objc func doubleClicked(_ sender: NSOutlineView) {
            let row = sender.clickedRow
            guard row >= 0, let node = sender.item(atRow: row) as? TreeModel.Node, node.showsDisclosure else { return }
            if sender.isItemExpanded(node) { sender.collapseItem(node) } else { sender.expandItem(node) }
        }

        // MARK: Context menu

        func menuNeedsUpdate(_ menu: NSMenu) {
            menu.removeAllItems()
            guard let outline, outline.clickedRow >= 0,
                  let node = outline.item(atRow: outline.clickedRow) as? TreeModel.Node else { return }
            let expanded = outline.isItemExpanded(node)
            if node.showsDisclosure {
                menu.addItem(ActionMenuItem(expanded ? "Collapse" : "Expand") { [weak outline] in
                    if expanded { outline?.collapseItem(node) } else { outline?.expandItem(node) }
                })
            }
            menu.addItem(ActionMenuItem("Refresh") { [tree] in Task { await tree.refresh(node.id) } })
            menu.addItem(.separator())
            if !node.dn.isEmpty {
                menu.addItem(ActionMenuItem("Search Beneath…") { [session] in session.searchBeneath(node.dn) })
                menu.addItem(.separator())
                if session.canWrite {
                    let parent = node.kind.isContainer ? node.dn : (DN.parent(node.dn) ?? node.dn)
                    menu.addItem(ActionMenuItem("New Entry Here…") { [session] in session.sheet = .newEntry(parent: parent) })
                    if !tree.roots.contains(node.id) {
                        menu.addItem(ActionMenuItem("Rename…") { [session] in session.sheet = .renameMove(dn: node.dn, move: false) })
                        menu.addItem(ActionMenuItem("Move…") { [session] in session.sheet = .renameMove(dn: node.dn, move: true) })
                        menu.addItem(ActionMenuItem("Delete…") { [session] in session.sheet = .delete(dn: node.dn) })
                    }
                    menu.addItem(.separator())
                }
                let export = NSMenuItem(title: "Export as LDIF", action: nil, keyEquivalent: "")
                let submenu = NSMenu()
                submenu.addItem(ActionMenuItem("This Entry…") { [session] in session.exportLDIF(node.dn, scope: .base) })
                submenu.addItem(ActionMenuItem("Its Children…") { [session] in session.exportLDIF(node.dn, scope: .oneLevel) })
                submenu.addItem(ActionMenuItem("The Whole Subtree…") { [session] in session.exportLDIF(node.dn, scope: .subtree) })
                export.submenu = submenu
                menu.addItem(export)
                menu.addItem(.separator())
            }
            menu.addItem(ActionMenuItem("Copy DN") { Pasteboard.copy(node.dn) })
            menu.addItem(ActionMenuItem("Copy Name") { Pasteboard.copy(node.name) })
            if DN.dnsDomain(node.dn) != nil {
                menu.addItem(ActionMenuItem("Copy Canonical Name") { Pasteboard.copy(DN.canonicalName(node.dn)) })
            }
            menu.addItem(.separator())
            let containers = ActionMenuItem("Show Containers Only") { [tree] in tree.setContainersOnly(!tree.containersOnly) }
            containers.state = tree.containersOnly ? .on : .off
            menu.addItem(containers)
        }
    }
}

/// A menu item that runs a closure.
final class ActionMenuItem: NSMenuItem {
    private let handler: () -> Void

    init(_ title: String, handler: @escaping () -> Void) {
        self.handler = handler
        super.init(title: title, action: #selector(run), keyEquivalent: "")
        target = self
    }

    required init(coder: NSCoder) { fatalError("not used") }

    @objc private func run() { handler() }
}

/// One row: icon, name, and when relevant a spinner, a warning, or a note
/// that the container holds more than the tree shows.
final class TreeCell: NSTableCellView {
    static let identifier = NSUserInterfaceItemIdentifier("TreeCell")

    private let icon = NSImageView()
    private let label = NSTextField(labelWithString: "")
    private let spinner = NSProgressIndicator()
    private let warning = NSImageView()
    private let badge = NSTextField(labelWithString: "")

    init() {
        super.init(frame: .zero)
        identifier = Self.identifier
        icon.translatesAutoresizingMaskIntoConstraints = false
        icon.imageScaling = .scaleProportionallyDown
        label.lineBreakMode = .byTruncatingTail
        label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.isDisplayedWhenStopped = false
        warning.image = NSImage(systemSymbolName: "exclamationmark.triangle.fill", accessibilityDescription: "Error")
        warning.contentTintColor = .systemOrange
        badge.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        badge.textColor = .secondaryLabelColor
        let stack = NSStackView(views: [icon, label, badge, warning, spinner])
        stack.orientation = .horizontal
        stack.spacing = 5
        stack.alignment = .centerY
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        textField = label
        imageView = icon
        NSLayoutConstraint.activate([
            icon.widthAnchor.constraint(equalToConstant: 22),
            stack.leadingAnchor.constraint(equalTo: leadingAnchor),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -4),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    @MainActor
    func configure(_ node: TreeModel.Node) {
        let symbol = node.disabled && node.kind == .user ? "person.fill.xmark" : node.kind.symbol
        icon.image = NSImage(systemSymbolName: symbol, accessibilityDescription: node.kind.label)?
            .withSymbolConfiguration(.init(pointSize: 13, weight: .regular))
        icon.contentTintColor = node.disabled ? .secondaryLabelColor : NSColor(node.kind.tint)
        icon.alphaValue = node.disabled && node.kind != .user ? 0.55 : 1
        label.stringValue = node.name
        label.textColor = node.disabled ? .secondaryLabelColor : .labelColor
        badge.stringValue = node.truncated ? "first \(TreeModel.childLimit.formatted())" : ""
        badge.isHidden = !node.truncated
        badge.toolTip = "This container holds more entries than the tree shows. Use Search Beneath to find the rest."
        warning.isHidden = node.error == nil
        warning.toolTip = node.error
        if node.isLoading { spinner.startAnimation(nil) } else { spinner.stopAnimation(nil) }
        toolTip = node.dn.isEmpty ? "Root DSE" : node.dn
        setAccessibilityLabel(node.disabled ? "\(node.name), \(node.kind.label), disabled" : "\(node.name), \(node.kind.label)")
    }
}
