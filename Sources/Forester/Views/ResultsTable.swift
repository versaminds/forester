// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import AppKit
import LDAPKit
import SwiftUI

/// The search results as a native table view.
///
/// An `NSTableView` rather than SwiftUI's `Table`, for the same reasons the
/// tree is an outline view, and one more: every result set a SwiftUI table
/// replaced stayed in memory until the table left the window (19 MB for each
/// search of 50,000 entries). This one shows any number of rows at the cost of
/// the ones in view, and sorting or replacing them is a reload.
struct ResultsTable: NSViewRepresentable {
    let session: DirectorySession
    let search: SearchModel
    // Read here, so SwiftUI calls updateNSView when they change.
    let rows: [SearchRow]
    let selection: Set<SearchRow.ID>
    let sortOrder: [KeyPathComparator<SearchRow>]

    func makeCoordinator() -> Coordinator { Coordinator(session: session, search: search) }

    func makeNSView(context: Context) -> NSScrollView {
        let table = ResultsTableView()
        for column in Column.allCases {
            let tableColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(column.rawValue))
            tableColumn.title = column.title
            tableColumn.minWidth = column.widths.min
            tableColumn.width = column.widths.ideal
            tableColumn.sortDescriptorPrototype = NSSortDescriptor(key: column.rawValue, ascending: true)
            table.addTableColumn(tableColumn)
        }
        table.style = .inset
        table.rowHeight = 24
        table.usesAutomaticRowHeights = false
        table.usesAlternatingRowBackgroundColors = true
        table.allowsMultipleSelection = true
        table.allowsColumnReordering = true
        table.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        table.autosaveName = "SearchResults"
        table.autosaveTableColumns = true
        table.dataSource = context.coordinator
        table.delegate = context.coordinator
        table.target = context.coordinator
        table.doubleAction = #selector(Coordinator.doubleClicked(_:))
        table.onReturn = { [weak coordinator = context.coordinator] in coordinator?.openSelection() }
        let menu = NSMenu()
        menu.delegate = context.coordinator
        table.menu = menu
        table.setAccessibilityLabel("Search results")

        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        context.coordinator.table = table
        context.coordinator.update(rows: rows, selection: selection, sortOrder: sortOrder)
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        context.coordinator.session = session
        context.coordinator.search = search
        context.coordinator.update(rows: rows, selection: selection, sortOrder: sortOrder)
    }

    enum Column: String, CaseIterable {
        case name, kind, account, detail, location

        var title: String {
            switch self {
            case .name: "Name"
            case .kind: "Type"
            case .account: "Account"
            case .detail: "Details"
            case .location: "Location"
            }
        }

        var widths: (min: CGFloat, ideal: CGFloat) {
            switch self {
            case .name: (140, 190)
            case .kind: (50, 70)
            case .account: (60, 100)
            case .detail: (80, 180)
            case .location: (80, 220)
            }
        }

        func comparator(ascending: Bool) -> KeyPathComparator<SearchRow> {
            let order: SortOrder = ascending ? .forward : .reverse
            switch self {
            case .name: return KeyPathComparator(\.name, comparator: .localizedStandard, order: order)
            case .kind: return KeyPathComparator(\.kindLabel, order: order)
            case .account: return KeyPathComparator(\.account, comparator: .localizedStandard, order: order)
            case .detail: return KeyPathComparator(\.detail, comparator: .localizedStandard, order: order)
            case .location: return KeyPathComparator(\.location, comparator: .localizedStandard, order: order)
            }
        }

        init?(_ comparator: KeyPathComparator<SearchRow>) {
            switch comparator.keyPath {
            case \SearchRow.name: self = .name
            case \SearchRow.kindLabel: self = .kind
            case \SearchRow.account: self = .account
            case \SearchRow.detail: self = .detail
            case \SearchRow.location: self = .location
            default: return nil
            }
        }
    }

    @MainActor
    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSMenuDelegate {
        var session: DirectorySession
        var search: SearchModel
        weak var table: NSTableView?
        private var rows: [SearchRow] = []
        private var sortOrder: [KeyPathComparator<SearchRow>] = []
        /// Where each row is, by id, for showing a selection made elsewhere;
        /// built when first needed after the rows change.
        private var index: [SearchRow.ID: Int]?
        /// Set while the coordinator changes the table itself, so the
        /// delegate callbacks that causes are not mistaken for the user.
        private var syncing = false

        init(session: DirectorySession, search: SearchModel) {
            self.session = session
            self.search = search
        }

        // MARK: Model → view

        func update(rows: [SearchRow], selection: Set<SearchRow.ID>, sortOrder: [KeyPathComparator<SearchRow>]) {
            guard let table else { return }
            syncing = true
            defer { syncing = false }
            let descriptors = sortOrder.first.flatMap { comparator in
                Column(comparator).map { [NSSortDescriptor(key: $0.rawValue, ascending: comparator.order == .forward)] }
            } ?? []
            if table.sortDescriptors != descriptors { table.sortDescriptors = descriptors }
            // The same array in the same order is the same rows: replaced, it is
            // a new array; sorted, it may be the same one sorted in place.
            if !Self.same(rows, self.rows) || sortOrder != self.sortOrder {
                self.rows = rows
                self.sortOrder = sortOrder
                index = nil
                table.reloadData()
            }
            let shown = Set(table.selectedRowIndexes.compactMap { $0 < self.rows.count ? self.rows[$0].id : nil })
            if shown != selection {
                if selection.isEmpty {
                    table.deselectAll(nil)
                } else {
                    if index == nil {
                        index = Dictionary(self.rows.enumerated().map { ($0.element.id, $0.offset) }, uniquingKeysWith: { first, _ in first })
                    }
                    let rowsToSelect = IndexSet(selection.compactMap { index?[$0] })
                    table.selectRowIndexes(rowsToSelect, byExtendingSelection: false)
                    if let first = rowsToSelect.first, rowsToSelect.count == 1 { table.scrollRowToVisible(first) }
                }
            }
        }

        private static func same(_ a: [SearchRow], _ b: [SearchRow]) -> Bool {
            a.count == b.count && a.withUnsafeBufferPointer { pa in b.withUnsafeBufferPointer { pa.baseAddress == $0.baseAddress } }
        }

        // MARK: Data source and delegate

        func numberOfRows(in tableView: NSTableView) -> Int { rows.count }

        func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
            guard row < rows.count, let id = tableColumn?.identifier, let column = Column(rawValue: id.rawValue) else { return nil }
            let item = rows[row]
            if column == .name {
                let cell = tableView.makeView(withIdentifier: ResultNameCell.identifier, owner: nil) as? ResultNameCell ?? ResultNameCell()
                cell.configure(item)
                return cell
            }
            let cell = tableView.makeView(withIdentifier: ResultTextCell.identifier, owner: nil) as? ResultTextCell ?? ResultTextCell()
            switch column {
            case .kind: cell.configure(item.kindLabel, secondary: true)
            case .account: cell.configure(item.account, secondary: false)
            case .detail: cell.configure(item.detail, secondary: true)
            case .location: cell.configure(item.location, secondary: true, help: item.location)
            case .name: break
            }
            return cell
        }

        func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
            guard !syncing, let descriptor = tableView.sortDescriptors.first,
                  let column = descriptor.key.flatMap(Column.init(rawValue:)) else { return }
            search.sortOrder = [column.comparator(ascending: descriptor.ascending)]
        }

        func tableViewSelectionDidChange(_ notification: Notification) {
            guard !syncing, let table else { return }
            let ids = Set(table.selectedRowIndexes.compactMap { $0 < rows.count ? rows[$0].id : nil })
            // Past AppKit's own callback, as the tree does.
            DispatchQueue.main.async { [search] in search.selection = ids }
        }

        @objc func doubleClicked(_ sender: NSTableView) {
            let row = sender.clickedRow
            guard row >= 0, row < rows.count else { return }
            session.reveal(rows[row].id)
        }

        func openSelection() {
            guard let table, let row = table.selectedRowIndexes.first, row < rows.count else { return }
            session.reveal(rows[row].id)
        }

        // MARK: Context menu

        /// The rows a menu acts on: the selection when the click was inside it,
        /// otherwise the row clicked, as in the Finder.
        private func clickedIDs() -> [SearchRow.ID] {
            guard let table, table.clickedRow >= 0, table.clickedRow < rows.count else { return [] }
            if table.selectedRowIndexes.contains(table.clickedRow) {
                return table.selectedRowIndexes.compactMap { $0 < rows.count ? rows[$0].id : nil }
            }
            return [rows[table.clickedRow].id]
        }

        func menuNeedsUpdate(_ menu: NSMenu) {
            menu.removeAllItems()
            let ids = clickedIDs()
            guard !ids.isEmpty else { return }
            if ids.count == 1, let dn = ids.first {
                menu.addItem(ActionMenuItem("Show in Tree") { [session] in session.reveal(dn) })
                menu.addItem(ActionMenuItem("Search Beneath…") { [search] in search.base = dn })
                menu.addItem(.separator())
            }
            menu.addItem(ActionMenuItem(ids.count > 1 ? "Copy \(ids.count) DNs" : "Copy DN") {
                Pasteboard.copy(ids.sorted().joined(separator: "\n"))
            })
            menu.addItem(ActionMenuItem("Export Selection as LDIF…") { [search] in search.exportLDIF(only: Set(ids)) })
        }
    }
}

/// Return opens the selected result in the tree, as a double-click does.
final class ResultsTableView: NSTableView {
    var onReturn: (() -> Void)?

    override func keyDown(with event: NSEvent) {
        if event.keyCode == 36 || event.keyCode == 76, event.modifierFlags.intersection([.command, .option, .control, .shift]).isEmpty {
            onReturn?()
        } else {
            super.keyDown(with: event)
        }
    }
}

/// A result's icon and name; its DN as the tooltip.
final class ResultNameCell: NSTableCellView {
    static let identifier = NSUserInterfaceItemIdentifier("ResultNameCell")

    private let icon = NSImageView()
    private let label = NSTextField(labelWithString: "")

    init() {
        super.init(frame: .zero)
        identifier = Self.identifier
        icon.imageScaling = .scaleProportionallyDown
        label.lineBreakMode = .byTruncatingTail
        label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let stack = NSStackView(views: [icon, label])
        stack.orientation = .horizontal
        stack.spacing = 6
        stack.alignment = .centerY
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        textField = label
        imageView = icon
        NSLayoutConstraint.activate([
            icon.widthAnchor.constraint(equalToConstant: 24),
            stack.leadingAnchor.constraint(equalTo: leadingAnchor),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -2),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    @MainActor
    func configure(_ row: SearchRow) {
        let symbol = row.disabled && row.kind == .user ? "person.fill.xmark" : row.kind.symbol
        icon.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?
            .withSymbolConfiguration(.init(pointSize: 13, weight: .regular))
        icon.contentTintColor = row.disabled ? .secondaryLabelColor : NSColor(row.kind.tint)
        icon.alphaValue = row.disabled && row.kind != .user ? 0.5 : 1
        label.stringValue = row.name
        label.textColor = row.disabled ? .secondaryLabelColor : .labelColor
        toolTip = row.id
        setAccessibilityLabel(row.disabled ? "\(row.name), \(row.kind.label), disabled" : "\(row.name), \(row.kind.label)")
    }
}

/// One line of text in a result's column.
final class ResultTextCell: NSTableCellView {
    static let identifier = NSUserInterfaceItemIdentifier("ResultTextCell")

    private let label = NSTextField(labelWithString: "")

    init() {
        super.init(frame: .zero)
        identifier = Self.identifier
        label.lineBreakMode = .byTruncatingTail
        label.translatesAutoresizingMaskIntoConstraints = false
        addSubview(label)
        textField = label
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 2),
            label.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -2),
            label.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    func configure(_ text: String, secondary: Bool, help: String? = nil) {
        label.stringValue = text
        label.textColor = secondary ? .secondaryLabelColor : .labelColor
        toolTip = help
    }
}
