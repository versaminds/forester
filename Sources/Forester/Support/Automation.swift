// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

#if DEBUG
import AppKit
import LDAPKit
import SwiftUI

/// A scripted walk through the app against the test directory, writing a PNG
/// of the window at each step. Debug builds only; started by
///   FORESTER_AUTOMATION=/path/to/output .build/debug/Forester
/// with FORESTER_PROFILE_DIR pointing at a scratch directory, so the
/// user's own saved connections are never touched.
@MainActor
enum Automation {
    static var outputDirectory: URL? {
        ProcessInfo.processInfo.environment["FORESTER_AUTOMATION"].map { URL(fileURLWithPath: $0) }
    }

    static var profileDirectory: URL? {
        ProcessInfo.processInfo.environment["FORESTER_PROFILE_DIR"].map { URL(fileURLWithPath: $0) }
    }

    /// Which parts to run, from FORESTER_AUTOMATION_ONLY (comma-separated):
    /// walkthrough (the main screens and the changes they make), layout (the
    /// toolbar at many window and column sizes), entrysheets (every entry
    /// sheet opened as a click opens it), sheets (every sheet and form, light
    /// and dark) and ui (real clicks and typing through the app's own
    /// controls). All five by default. Also: sample (Try a Sample Directory,
    /// over the internet), marketing (the website's pictures), ad (against
    /// Active Directory) and performance (against a big test directory).
    static var parts: Set<String> {
        let value = ProcessInfo.processInfo.environment["FORESTER_AUTOMATION_ONLY"] ?? "walkthrough,layout,entrysheets,sheets,ui"
        return Set(value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) })
    }

    static func runIfRequested(_ model: AppModel) {
        guard let output = outputDirectory else { return }
        try? FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        Task {
            do {
                try await waitFor("window") { mainWindow() != nil }
                mainWindow()?.setFrame(NSRect(x: 80, y: 80, width: 1440, height: 880), display: true)
                let parts = self.parts
                turnOnAccessibilityTree()
                if parts.contains("walkthrough") { try await walkthrough(model, output: output) }
                if parts.contains("layout") { try await toolbarLayouts(model, output: output) }
                if parts.contains("entrysheets") { try await entrySheets(model, output: output) }
                if parts.contains("sheets") { try await sheetGallery(model, output: output) }
                if parts.contains("ui") { try await UITour.run(model, output: output) }
                if parts.contains("sample") { try await sampleDirectory(model, output: output) }
                if parts.contains("marketing") { try await marketing(model, output: output) }
                if parts.contains("ad") { try await ADChecks.run(model, output: output) }
                if parts.contains("performance") { try await PerformanceChecks.run(model, output: output) }
                // Every window pictured was also read as VoiceOver reads it,
                // by an audit that is first shown to catch an unnamed control.
                try await checkAccessibilityAudit()
                guard accessibilityFindings.isEmpty else {
                    throw AutomationError("controls VoiceOver would announce without a name:\n" + Set(accessibilityFindings).sorted().joined(separator: "\n"))
                }
                log("verified: every control in every window pictured has a name for VoiceOver")
                log("done")
            } catch {
                log("FAILED: \(error)")
                // What the window showed when it failed, and what it had open.
                if let window = mainWindow() {
                    try? write(window, name: "FAILED", output: output)
                    if let session = model.sessions.values.first(where: { $0.phase.isConnected }) {
                        log("at failure: entry \(session.inspector.entry?.dn ?? "none"), membership loading \(session.inspector.membership.loading), tree selection \(session.tree.selection ?? "none")")
                    }
                }
                // Quitting the usual way exits with 0, which would read as a pass.
                fflush(stdout)
                exit(1)
            }
            NSApp.terminate(nil)
        }
    }

    static let base = "DC=corp,DC=example"
    static var testPassword: String { ProcessInfo.processInfo.environment["FORESTER_TEST_PASSWORD"] ?? "" }

    /// The directory the automation runs against: the OpenLDAP test directory
    /// (TestDirectory/start.sh) by default, or with FORESTER_TEST_AD=1 the
    /// Active Directory domain controller from TestDirectory/start-ad.sh.
    struct TestServer {
        let port: Int
        let bindName: String
        let isActiveDirectory: Bool
        let host = "localhost"
        let security = LDAPConnection.Security.startTLS
        /// What every account in the AD directory was given (generate_ldif.py samba).
        static let seededPassword = "Corp-Example-Test-Password-2026!"

        static var current: TestServer {
            ProcessInfo.processInfo.environment["FORESTER_TEST_AD"] == "1"
                ? TestServer(port: 11389, bindName: "Administrator@corp.example", isActiveDirectory: true)
                : TestServer(port: 10389, bindName: "CN=admin,DC=corp,DC=example", isActiveDirectory: false)
        }
    }
    /// The repository, for files the test directory provides (debug builds run from it).
    static var repository: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
    }

    /// The two test connections, saved once.
    static func testProfiles(_ model: AppModel) -> (corp: ConnectionProfile, ldaps: ConnectionProfile) {
        if let corp = model.store.profiles.first(where: { $0.name == "Corp test directory" }),
           let ldaps = model.store.profiles.first(where: { $0.name == "Example.org (LDAPS)" }) {
            return (corp, ldaps)
        }
        var profile = ConnectionProfile()
        profile.name = "Corp test directory"
        let server = TestServer.current
        profile.host = server.host
        profile.port = server.port
        profile.security = server.security
        profile.bindName = server.bindName
        profile.savePassword = false
        var other = ConnectionProfile()
        other.name = "Example.org (LDAPS)"
        other.host = "localhost"
        other.port = 10636
        other.security = .ldaps
        other.authentication = .anonymous
        model.store.save(profile)
        model.store.save(other)
        return (profile, other)
    }

    /// Connects the corp profile, trusting the test CA's certificate when asked.
    static func connectCorp(_ model: AppModel) async throws -> DirectorySession {
        let corp = testProfiles(model).corp
        model.requestedSelection = corp.id
        let session = try require(model.session(for: corp.id))
        if session.phase.isConnected { return session }
        session.connect(password: testPassword)
        try await waitFor("connect outcome") {
            if case .failed = session.phase { return true }
            return session.phase.isConnected || session.pendingTrustFailure != nil
        }
        if session.pendingTrustFailure != nil {
            session.trustPendingCertificate()
            try await waitFor("connected after trust") { session.phase.isConnected }
        }
        if case .failed(let message) = session.phase { throw AutomationError(message) }
        try await waitFor("schema") { session.schema != nil && session.inspector.entry != nil }
        return session
    }

    // MARK: Window layout

    /// The edge between the sidebar and the middle column, found in a picture
    /// of the window at two heights: in the toolbar and below it. They must be
    /// the same line; AppKit's own toolbar background used to start 2 points
    /// early, so the toolbar did not line up with the divider under it.
    static func columnEdges(_ window: NSWindow) throws -> (toolbar: CGFloat, content: CGFloat) {
        func all(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(all) }
        guard let frame = window.contentView?.superview,
              let split = (window.contentView.map(all) ?? []).compactMap({ $0 as? NSSplitView }).first,
              let sidebar = split.arrangedSubviews.first, !sidebar.isHidden else { throw AutomationError("no sidebar") }
        frame.layoutSubtreeIfNeeded()
        guard let rep = frame.bitmapImageRepForCachingDisplay(in: frame.bounds) else { throw AutomationError("no bitmap") }
        frame.cacheDisplay(in: frame.bounds, to: rep)
        let scale = CGFloat(rep.pixelsWide) / frame.bounds.width
        let divider = sidebar.convert(sidebar.bounds, to: nil).maxX
        let toolbarHeight = frame.bounds.height - window.contentLayoutRect.height
        func edge(atPointsFromTop y: CGFloat) -> CGFloat {
            let row = Int(y * scale)
            let startX = Int((divider - 12) * scale)
            guard let base = rep.colorAt(x: startX, y: row) else { return -1 }
            for x in startX..<Int((divider + 12) * scale) {
                guard let color = rep.colorAt(x: x, y: row) else { continue }
                let distance = abs(color.redComponent - base.redComponent) + abs(color.greenComponent - base.greenComponent)
                    + abs(color.blueComponent - base.blueComponent)
                if distance > 0.02 { return CGFloat(x) / scale }
            }
            return -1
        }
        return (edge(atPointsFromTop: toolbarHeight / 2), edge(atPointsFromTop: toolbarHeight + 220))
    }

    // MARK: Toolbar layout

    /// Every control in the toolbar must sit inside its own column. AppKit keeps
    /// the toolbar's parts over their columns only while each fits; otherwise
    /// it moves the toolbar's divider, and a column line runs through a control
    /// (seen with text in the search field and a wide middle column). Tried
    /// with the window at its narrowest, at 1316 and 1800 points, the middle
    /// column as laid out, dragged narrow and dragged wide, the search field
    /// empty and holding text, and a short and a long connection name.
    static func toolbarLayouts(_ model: AppModel, output: URL) async throws {
        let session = try await connectCorp(model)
        let corp = testProfiles(model).corp
        let user = "CN=Pieter Van Damme,OU=Engineering,OU=Users,OU=Corp,\(base)"
        session.mode = .browse
        await session.tree.reveal(user)
        session.open(user)
        try await waitFor("user for the toolbar") { session.inspector.entry.map { DN.isSame($0.dn, user) } == true }
        let window = try require(mainWindow())
        let originalFrame = window.frame
        func rename(_ name: String) {
            model.store.update(corp.id) { $0.name = name }
            if let profile = model.store.profile(corp.id) { session.update(profile) }
        }
        var checked = 0
        for sidebar in [true, false] {
            if !sidebar { try await toggleSidebar(window) }
            for name in [corp.name, "Production directory of the Antwerp and Brussels offices"] {
                rename(name)
                for find in ["", "svc_backup"] {
                    try await setFind(window, find)
                    for width in [0.0, 1316, 1800] {
                        for middle: CGFloat? in [nil, 0, 5000] {
                            window.setFrame(NSRect(x: 40, y: 80, width: max(width, window.minSize.width), height: 760), display: true)
                            try await settle(0.5)
                            if let middle { try await dragMiddleDivider(window, to: middle) }
                            let what = "\(Int(window.frame.width)) wide, middle \(middle.map { $0 == 0 ? "narrowest" : "widest" } ?? "as laid out"), "
                                + (find.isEmpty ? "no search text" : "search text") + (name == corp.name ? "" : ", long name")
                                + (sidebar ? "" : ", sidebar hidden")
                            try verifyToolbarFits(window, what)
                            checked += 1
                            let suffix = (name == corp.name ? "" : "-long-name") + (sidebar ? "" : "-no-sidebar")
                            if width == 1316, middle == 5000, !find.isEmpty { try snapshot("T-toolbar-wide-middle\(suffix)", output) }
                            if width == 0, middle == nil, !find.isEmpty { try snapshot("T-toolbar-narrowest\(suffix)", output) }
                        }
                    }
                }
            }
            if !sidebar { try await toggleSidebar(window) }
        }
        rename(corp.name)
        try await setFind(window, "")
        window.setFrame(originalFrame, display: true)
        try await settle()
        log("verified: every toolbar control stays within its column (\(checked) layouts)")
    }

    /// Hides or shows the sidebar with the toolbar's own sidebar button.
    static func toggleSidebar(_ window: NSWindow) async throws {
        let item = try require(window.toolbar?.items.first { $0.itemIdentifier.rawValue.hasSuffix("toggleSidebar") })
        try await UIDriver.mouseClick(try require(item.view), "the sidebar button")
        try await settle(0.6)
    }

    /// Types into the toolbar's search field, or empties it, without searching.
    static func setFind(_ window: NSWindow, _ text: String) async throws {
        let item = try require(window.toolbar?.items.compactMap { $0 as? NSSearchToolbarItem }.first)
        if !text.isEmpty { item.beginSearchInteraction() }
        try await settle(0.3)
        item.searchField.stringValue = text
        NotificationCenter.default.post(name: NSControl.textDidChangeNotification, object: item.searchField)
        if text.isEmpty { item.endSearchInteraction() }
        window.makeFirstResponder(nil)
        try await settle(0.4)
    }

    /// Drags the divider between the middle column and the detail, the way a
    /// person does: the split view's own tracking loop takes the moves and the
    /// release from the event queue.
    static func dragMiddleDivider(_ window: NSWindow, to target: CGFloat) async throws {
        let split = try require(allViews(window).compactMap { $0 as? NSSplitView }.first)
        let middle = split.arrangedSubviews[1]
        let start = middle.convert(middle.bounds, to: nil).maxX + 0.5
        let y = window.contentLayoutRect.midY
        func event(_ type: NSEvent.EventType, _ x: CGFloat) -> NSEvent? {
            NSEvent.mouseEvent(with: type, location: NSPoint(x: x, y: y), modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                               windowNumber: window.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)
        }
        for step in 1...10 {
            if let e = event(.leftMouseDragged, start + (target - start) * CGFloat(step) / 10) { NSApp.postEvent(e, atStart: false) }
        }
        if let up = event(.leftMouseUp, target) { NSApp.postEvent(up, atStart: false) }
        if let down = event(.leftMouseDown, start) { NSApp.sendEvent(down) }
        try await settle(0.5)
    }

    static func allViews(_ window: NSWindow) -> [NSView] {
        func all(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(all) }
        return (window.contentView?.superview ?? window.contentView).map(all) ?? []
    }

    /// Fails when a toolbar control or the title crosses a column line, or the
    /// toolbar's own divider is not over the column line.
    static func verifyToolbarFits(_ window: NSWindow, _ what: String) throws {
        let views = allViews(window)
        let split = try require(views.compactMap { $0 as? NSSplitView }.first)
        let dividers = split.arrangedSubviews.filter { !$0.isHidden }.map { $0.convert($0.bounds, to: nil).maxX }.dropLast()
        if ProcessInfo.processInfo.environment["FORESTER_LAYOUT_LOG"] == "1" {
            let items = (split.delegate as? NSSplitViewController)?.splitViewItems.map { "min \($0.minimumThickness) max \($0.maximumThickness) hold \($0.holdingPriority.rawValue)" } ?? []
            log("layout \(what): columns \(split.arrangedSubviews.map { Int($0.frame.width) }) minSize \(window.minSize) contentMin \(window.contentMinSize) items \(items)")
        }
        func name(_ view: NSView) -> String { String(describing: type(of: view)) }
        func frame(_ view: NSView) -> NSRect { view.convert(view.bounds, to: nil) }
        let toolbarBottom = window.contentLayoutRect.maxY
        let separators = views.filter { name($0) == "NSSeparatorToolbarItemView" && !$0.isHiddenOrHasHiddenAncestor }
        func dump() {
            for view in views where !view.isHiddenOrHasHiddenAncestor && frame(view).minY >= toolbarBottom - 1
                && ((name(view).hasPrefix("NSToolbar") && name(view).hasSuffix("Viewer")) || view is NSTextField) {
                let label = ([view] + view.subviews).compactMap { ($0 as? NSTextField)?.stringValue ?? ($0 as? NSButton)?.title }.first ?? ""
                log("  \(name(view)) \(Int(frame(view).minX))–\(Int(frame(view).maxX)) '\(label)'")
            }
        }
        if ProcessInfo.processInfo.environment["FORESTER_LAYOUT_LOG"] == "1" { log("layout dump \(what)"); dump() }
        // macOS 26 draws the tracking separator of a glass toolbar right of
        // the split view's divider it follows: 2 points with the sidebar
        // shown, 6 with it hidden (seen on GitHub's macOS 26 runners; macOS 27
        // lines them up). AppKit places it, not the app, so up to 8 points is
        // allowed there and nowhere else, and each gap is logged.
        let os = ProcessInfo.processInfo.operatingSystemVersion.majorVersion
        let tolerance: CGFloat = ToolbarFit.glass && os == 26 ? 8 : 1
        for separator in separators {
            let x = frame(separator).minX
            if let gap = dividers.map({ abs($0 - x) }).min(), gap > 1, gap <= tolerance {
                log("noted: macOS \(os) draws the toolbar's divider \(gap) points from the column line (\(what))")
            }
            guard dividers.contains(where: { abs($0 - x) <= tolerance }) else {
                dump()
                throw AutomationError("check failed: the toolbar's divider is at \(x), the column line at \(dividers.map { "\($0)" }.joined(separator: ", ")) (\(what))")
            }
        }
        let controls = views.filter { view in
            !view.isHiddenOrHasHiddenAncestor && frame(view).width > 2 && frame(view).minY >= toolbarBottom - 1
                && ((name(view).hasPrefix("NSToolbar") && name(view).hasSuffix("Viewer") && !separators.contains { $0.isDescendant(of: view) })
                    || (view is NSTextField && !((view as? NSTextField)?.stringValue.isEmpty ?? true)))
        }
        guard controls.count > 4 else { throw AutomationError("check failed: no toolbar controls found (\(what))") }
        for control in controls {
            let r = frame(control)
            if let line = dividers.first(where: { r.minX < $0 - 0.5 && r.maxX > $0 + 0.5 }) {
                dump()
                let label = ([control] + control.subviews).compactMap { ($0 as? NSTextField)?.stringValue ?? ($0 as? NSButton)?.title }.first ?? name(control)
                throw AutomationError("check failed: '\(label)' (\(Int(r.minX))–\(Int(r.maxX))) crosses the column line at \(line) (\(what))")
            }
        }
    }

    static func verifyColumnEdges(_ what: String) throws {
        // Since macOS 26 the toolbar is glass over the columns, so there is no
        // toolbar background to line up, and drawing the view hierarchy (all
        // this measures) leaves the glass out. The toolbar checks measure the
        // controls themselves either way.
        guard !ToolbarFit.glass else {
            log("skipped: the toolbar meets the sidebar divider (\(what)): the toolbar is glass")
            return
        }
        let window = try require(mainWindow())
        let edges = try columnEdges(window)
        guard edges.toolbar >= 0, abs(edges.toolbar - edges.content) < 0.5 else {
            throw AutomationError("check failed: the toolbar meets the sidebar divider (\(what)): toolbar edge at \(edges.toolbar), column edge at \(edges.content)")
        }
        log("verified: the toolbar meets the sidebar divider (\(what))")
    }

    // MARK: Every sheet

    /// Every sheet an entry can open, opened the way a click opens it: through
    /// the session's sheet and SwiftUI's own presentation, which sizes the
    /// sheet to its content. Each must appear, keep the app answering, and
    /// close again.
    static func entrySheets(_ model: AppModel, output: URL) async throws {
        let session = try await connectCorp(model)
        let user = "CN=Pieter Van Damme,OU=Engineering,OU=Users,OU=Corp,\(base)"
        let pieter = try require(try await session.run { try await $0.read(user, attributes: ["*", "+"]) })
        let sheets: [(String, DirectorySession.EntrySheet)] = [
            ("password", .password(pieter)),
            ("new-entry", .newEntry(parent: "OU=Engineering,OU=Users,OU=Corp,\(base)")),
            ("duplicate", .duplicate(pieter)),
            ("rename", .renameMove(dn: user, move: false)),
            ("move", .renameMove(dn: user, move: true)),
            ("delete", .delete(dn: user)),
            ("account-status", .accountStatus(pieter)),
            ("import", .importLDIF(nil)),
            ("history", .history),
        ]
        let window = try require(mainWindow())
        for (name, sheet) in sheets {
            session.sheet = sheet
            try await waitFor("sheet \(name)") { window.attachedSheet != nil }
            try await settle(1.0)
            let shown = try require(window.attachedSheet)
            guard shown.frame.height > 80, shown.frame.height < window.frame.height else {
                throw AutomationError("check failed: the \(name) sheet is \(Int(shown.frame.height)) points tall")
            }
            try write(shown, name: "E-\(name)", output: output)
            session.sheet = nil
            try await waitFor("sheet \(name) closed") { window.attachedSheet == nil }
        }
        log("verified: every entry sheet opens the way a click opens it, keeps the app answering, and closes")
    }

    /// Every sheet and form, presented as a real sheet on the main window so it
    /// has the size it has for a person, in light mode and then dark.
    static func sheetGallery(_ model: AppModel, output: URL) async throws {
        let session = try await connectCorp(model)
        let user = "CN=Pieter Van Damme,OU=Engineering,OU=Users,OU=Corp,\(base)"
        let group = "CN=GG-Engineering,OU=Groups,OU=Corp,\(base)"
        let pieter = try require(try await session.run { try await $0.read(user, attributes: ["*", "+"]) })
        let groupEntry = try require(try await session.run { try await $0.read(group, attributes: ["*", "+"]) })
        let sample = repository.appendingPathComponent("TestDirectory/sample-import.ldif")
        let corp = testProfiles(model).corp

        for dark in [false, true] {
            NSApp.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            let suffix = dark ? "-dark" : ""
            func show<V: View>(_ name: String, wait: Double = 0.8, _ view: V) async throws {
                try await presentSheet("S-\(name)\(suffix)", wait: wait, view)
            }
            try await show("profile-new", ProfileEditor(profile: ConnectionProfile()) { _, _ in })
            try await show("profile-edit", ProfileEditor(profile: model.store.profile(corp.id) ?? corp) { _, _ in })
            try await show("new-ad-user", NewEntrySheet(session: session, parentDN: "OU=Engineering,OU=Users,OU=Corp,\(base)"))
            try await show("password-reset", PasswordSheet(session: session, entry: pieter))
            try await show("import-loaded", LDIFImportSheet(session: session, initialFile: sample))
            try await show("edit-description", AttributeEditorSheet(session: session, entry: pieter, attribute: "description"))
            session.open(user)
            await session.tree.reveal(user)
            session.inspector.tab = .overview
            try await settle(1.2)
            try snapshot("S-main-window\(suffix)", output)
            ForesterInfo.showAboutPanel()
            try await settle(0.8)
            if let about = NSApp.windows.first(where: { $0.isVisible && $0 !== mainWindow() && $0.sheetParent == nil && $0.frame.width < 600 }) {
                try write(about, name: "S-about\(suffix)", output: output)
                about.close()
            }
            if dark { continue }
            try await show("password-prompt", PasswordPrompt(session: session, message: "Bind failed: Invalid credentials (49)."))
            try await show("go-to-dn", GoToDNSheet(session: session))
            try await show("settings", SettingsView().environment(model))
            try await show("dn-picker", wait: 1.5, DNPickerSheet(session: session, containersOnly: true, startAt: "OU=Engineering,OU=Users,OU=Corp,\(base)") { _ in })
            try await show("new-ad-group", NewEntrySheet(session: session, parentDN: "OU=Groups,OU=Corp,\(base)", initialTemplate: .adGroup))
            try await show("new-ou", NewEntrySheet(session: session, parentDN: "OU=Corp,\(base)", initialTemplate: .organizationalUnit))
            try await show("new-computer", NewEntrySheet(session: session, parentDN: "OU=Servers,OU=Corp,\(base)", initialTemplate: .adComputer))
            try await show("new-custom", NewEntrySheet(session: session, parentDN: "OU=Corp,\(base)", initialTemplate: .custom))
            try await show("duplicate", NewEntrySheet(session: session, parentDN: DN.parent(user) ?? "", source: pieter))
            try await show("rename", RenameMoveSheet(session: session, dn: user))
            try await show("move", RenameMoveSheet(session: session, dn: user, startWithMove: true))
            try await show("delete-one", wait: 1.2, DeleteEntrySheet(session: session, dn: user))
            try await show("import-empty", LDIFImportSheet(session: session))
            try await show("account-status", wait: 4, AccountStatusSheet(session: session, entry: pieter))
            try await show("edit-title", AttributeEditorSheet(session: session, entry: pieter, attribute: "title"))
            try await show("edit-manager", AttributeEditorSheet(session: session, entry: pieter, attribute: "manager"))
            try await show("edit-expires", AttributeEditorSheet(session: session, entry: pieter, attribute: "accountExpires"))
            try await show("edit-photo", AttributeEditorSheet(session: session, entry: pieter, attribute: "thumbnailPhoto"))
            try await show("edit-readonly", AttributeEditorSheet(session: session, entry: pieter, attribute: "objectSid"))
            try await show("edit-group-type", AttributeEditorSheet(session: session, entry: groupEntry, attribute: "groupType"))
            try await show("edit-members", AttributeEditorSheet(session: session, entry: groupEntry, attribute: "member"))
            try await show("add-attribute", AttributeEditorSheet(session: session, entry: pieter, attribute: nil))
            if let photo = pieter.attribute("thumbnailPhoto")?.values.first {
                try await show("view-photo", ValueViewer(row: AttributeRow(id: "p", name: "thumbnailPhoto", valueIndex: 0, valueCount: 1, value: photo,
                                                                         formatted: AttributeFormatter.format("thumbnailPhoto", photo)), dn: user))
            }
            if let sid = pieter.attribute("objectSid")?.values.first {
                try await show("view-sid", ValueViewer(row: AttributeRow(id: "s", name: "objectSid", valueIndex: 0, valueCount: 1, value: sid,
                                                                       formatted: AttributeFormatter.format("objectSid", sid)), dn: user))
            }
        }
        NSApp.appearance = nil
    }

    // MARK: Sample directory

    /// The way in before there is a directory of one's own: from an empty
    /// sidebar, Try a Sample Directory adds Forum Systems' public test server
    /// once and opens it, read-only and without signing in. It needs the
    /// internet, so it is not part of the default run:
    /// FORESTER_AUTOMATION_ONLY=sample, with a FORESTER_PROFILE_DIR that
    /// holds no connections.
    static func sampleDirectory(_ model: AppModel, output: URL) async throws {
        guard model.store.profiles.isEmpty else {
            throw AutomationError("the sample part starts with no connections: point FORESTER_PROFILE_DIR at an empty folder")
        }
        let window = try require(mainWindow())
        try await settle()
        try snapshot("S-no-connections", output)
        try UIDriver.click(try UIDriver.button("Try a Sample Directory", in: window), "Try a Sample Directory")
        try await waitFor("the sample directory added") { model.store.profiles.count == 1 }
        let profile = model.store.profiles[0]
        guard profile.isSample, profile.readOnly, profile.authentication == .anonymous, !profile.savePassword else {
            throw AutomationError("check failed: the sample directory was added as \(profile.endpoint), read-only \(profile.readOnly), \(profile.authentication)")
        }
        let session = try require(model.session(for: profile.id))
        try await waitFor("the sample directory connected", timeout: 30) {
            if case .failed = session.phase { return true }
            return session.phase.isConnected
        }
        if case .failed(let message) = session.phase { throw AutomationError("the sample directory did not connect: \(message)") }
        try await waitFor("the sample directory's entries") { session.inspector.entry != nil && !session.tree.roots.isEmpty }
        try await settle()
        try snapshot("S-sample-directory", output)
        // Asking again opens the same connection rather than adding another.
        model.trySampleDirectory()
        try await settle()
        guard model.store.profiles.count == 1 else { throw AutomationError("check failed: a second Try a Sample Directory added another connection") }
        log("verified: Try a Sample Directory adds the public test directory once and opens it read-only, without signing in")
    }

    // MARK: Website and App Store pictures

    /// Pictures for the website and the App Store: the main window at 1440 by
    /// 900 points, which is 2880 by 1800 pixels, one of the App Store's Mac
    /// sizes; a few sheets and the domain information window. Light and dark.
    /// Not part of the default run: FORESTER_AUTOMATION_ONLY=marketing.
    static func marketing(_ model: AppModel, output: URL) async throws {
        let session = try await connectCorp(model)
        let (corp, other) = testProfiles(model)
        func rename(_ id: UUID, _ name: String) {
            model.store.update(id) { $0.name = name }
            if let profile = model.store.profile(id) { model.existingSession(id)?.update(profile) }
        }
        rename(corp.id, "corp.example")
        rename(other.id, "Example.org")
        defer {
            rename(corp.id, corp.name)
            rename(other.id, other.name)
            session.setReadOnly(true)
            NSApp.appearance = nil
        }
        let window = try require(mainWindow())
        window.setFrame(NSRect(x: 60, y: 60, width: 1440, height: 900), display: true)
        try await settle(0.5)
        if let split = allViews(window).compactMap({ $0 as? NSSplitView }).first {
            split.setPosition(240, ofDividerAt: 0)
            split.setPosition(240 + 1 + 450, ofDividerAt: 1)
        }
        let pieter = "CN=Pieter Van Damme,OU=Engineering,OU=Users,OU=Corp,\(base)"
        let svcSQL = "CN=svc_sql,OU=Service Accounts,OU=Corp,\(base)"
        let vpn = "CN=DL-VPN-Users,OU=Groups,OU=Corp,\(base)"
        func open(_ dn: String, tab: InspectorModel.Tab) async throws {
            session.mode = .browse
            await session.tree.reveal(dn)
            session.open(dn)
            try await waitFor("\(dn) for the pictures") {
                session.inspector.entry.map { DN.isSame($0.dn, dn) } == true && !session.inspector.membership.loading
            }
            session.inspector.tab = tab
            if tab == .membership {
                session.inspector.membership.loadNested()
                try await waitFor("nested members for the pictures") { session.inspector.membership.nested != nil }
            }
        }
        func both(_ name: String, _ shoot: (String) async throws -> Void) async throws {
            for dark in [false, true] {
                NSApp.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
                _ = await UIDriver.bringForward(window)
                try await settle(1.0)
                try await shoot("M-\(name)-\(dark ? "dark" : "light")")
            }
        }

        // Read-only first, for the part about safety; then with changes allowed,
        // so controls are drawn as a person who edits sees them.
        session.setReadOnly(true)
        try await open(pieter, tab: .overview)
        try await both("read-only") { try snapshot($0, output) }
        session.setReadOnly(false)
        try await both("overview") { try snapshot($0, output) }
        try await open(svcSQL, tab: .overview)
        try await both("service-account") { try snapshot($0, output) }
        try await open(pieter, tab: .attributes)
        try await both("attributes") { try snapshot($0, output) }
        try await open(vpn, tab: .membership)
        try await both("membership") { try snapshot($0, output) }

        session.mode = .search
        session.search.base = base
        if let preset = SearchPreset.all.first(where: { $0.title == "Password never expires" }) {
            session.search.apply(preset)
        }
        try await waitFor("search for the pictures") { !session.search.running && session.search.hasRun }
        if let row = session.search.rows.first(where: { DN.isSame($0.id, svcSQL) }) ?? session.search.rows.first {
            session.search.selection = [row.id]
            session.select(row.id)
        }
        try await waitFor("search selection for the pictures") { session.inspector.entry != nil }
        session.inspector.tab = .overview
        try await both("search") { try snapshot($0, output) }
        session.mode = .browse

        let group = "CN=GG-Engineering,OU=Groups,OU=Corp,\(base)"
        let groupEntry = try require(try await session.run { try await $0.read(group, attributes: ["*", "+"]) })
        let pieterEntry = try require(try await session.run { try await $0.read(pieter, attributes: ["*", "+"]) })
        let sample = repository.appendingPathComponent("TestDirectory/sample-import.ldif")
        try await both("edit-members") { name in
            try await presentSheet(name, wait: 1.0, AttributeEditorSheet(session: session, entry: groupEntry, attribute: "member"))
        }
        try await both("password") { name in
            try await presentSheet(name, wait: 0.8, PasswordSheet(session: session, entry: pieterEntry))
        }
        try await both("import") { name in
            try await presentSheet(name, wait: 0.8, LDIFImportSheet(session: session, initialFile: sample))
        }
        try await both("domain") { name in
            try await snapshotHostedAsync(name, size: NSSize(width: 980, height: 760), wait: 3, DomainInfoView(session: session))
        }
        log("marketing pictures written")
    }

    /// Shows a view the way SwiftUI shows a sheet: in a window sized to the
    /// view, attached to the main window.
    static func presentSheet<V: View>(_ name: String, wait: Double, _ view: V) async throws {
        guard let main = mainWindow() else { throw AutomationError("no window for \(name)") }
        // Sized once to what the content needs. Letting the controller keep
        // the sheet at its preferred size, as this did, loops forever in
        // AppKit's constraint pass with a grouped form or a toggle in the
        // sheet when linked with the macOS 27 SDK; SwiftUI's own sheets, which
        // the app uses, do not.
        let controller = NSHostingController(rootView: view)
        controller.sizingOptions = []
        let sheet = NSWindow(contentViewController: controller)
        sheet.setContentSize(controller.view.fittingSize)
        sheet.isReleasedWhenClosed = false // ARC owns it; AppKit releasing it too is a double free
        main.beginSheet(sheet, completionHandler: nil)
        try await settle(wait)
        try write(sheet, name: name, output: outputDirectory!)
        main.endSheet(sheet)
        sheet.orderOut(nil)
    }

    static func log(_ message: String) {
        let stamp = Date().formatted(.dateTime.hour().minute().second().secondFraction(.fractional(3)))
        FileHandle.standardError.write(Data("[automation] \(stamp) \(message)\n".utf8))
    }

    /// Each read of a saved password can make macOS ask for the Mac's
    /// password, so a password is read from the keychain once per run, saying
    /// whether one is saved reads none, and an unchanged one is not written
    /// again. And a password is only handed out for the connection it was
    /// saved for. Uses a throwaway item in the login keychain, removed afterwards.
    static func checkKeychainReads() throws {
        var profile = ConnectionProfile()
        profile.host = "keychain-check.example"
        profile.bindName = "cn=check"
        let id = profile.id
        defer { Keychain.deletePassword(for: id) }
        Keychain.setPassword("automation-\(id.uuidString.prefix(8))", for: profile)
        Keychain.forgetKnown() // as after quitting and opening the app again
        Keychain.reads = 0
        Keychain.writes = 0
        guard Keychain.hasPassword(for: id), Keychain.reads == 0 else {
            throw AutomationError("check failed: saying a password is saved read it from the keychain (\(Keychain.reads) reads)")
        }
        let first = Keychain.password(for: profile).password
        let second = Keychain.password(for: profile).password
        guard let first, first == second, Keychain.reads == 1 else {
            throw AutomationError("check failed: a saved password was read from the keychain \(Keychain.reads) times, not once")
        }
        Keychain.setPassword(first, for: profile)
        guard Keychain.writes == 0 else { throw AutomationError("check failed: an unchanged password was written to the keychain again") }
        let changes: [(String, (inout ConnectionProfile) -> Void)] = [
            ("another server", { $0.host = "elsewhere.example" }),
            ("another port", { $0.port = 1389 }),
            ("no encryption", { $0.security = .none }),
            ("another user", { $0.bindName = "cn=someone else" }),
            ("any certificate accepted", { $0.trust.trustAnyCertificate = true }),
        ]
        for (what, change) in changes {
            var changed = profile
            change(&changed)
            guard Keychain.password(for: changed) == .savedForAnotherConnection else {
                throw AutomationError("check failed: the saved password was handed out for \(what)")
            }
        }
        var renamed = profile
        renamed.name = "Renamed"
        renamed.host = "KEYCHAIN-check.example"
        guard Keychain.password(for: renamed).password == first else {
            throw AutomationError("check failed: renaming a connection lost its saved password")
        }
        Keychain.deletePassword(for: id)
        Keychain.forgetKnown()
        guard !Keychain.hasPassword(for: id), Keychain.password(for: profile) == .none else {
            throw AutomationError("check failed: a deleted password is still found")
        }
        log("verified: a saved password is read once per run, not to show that one is saved, and only for the connection it was saved for")
    }

    /// An accessibility answer, asked through Objective-C: SwiftUI's elements
    /// answer the accessibility methods without adopting the protocol in
    /// Swift's eyes.
    static func axObject(_ element: AnyObject, _ method: String) -> AnyObject? {
        let selector = NSSelectorFromString(method)
        guard let element = element as? NSObject, element.responds(to: selector) else { return nil }
        return element.perform(selector)?.takeUnretainedValue()
    }

    /// A text answer, kept only if it is text: some elements answer a text
    /// method with another kind of object, and calling the method as one that
    /// returns a String raises an Objective-C exception while bridging it.
    /// Inside a task that exception is swallowed by AppKit and leaves the main
    /// thread's executor state behind, which crashed the app moments later in
    /// unrelated code.
    static func axText(_ element: AnyObject, _ method: String) -> String {
        let value = axObject(element, method)
        let string = (value as? NSString).map(String.init) ?? (value as? NSAttributedString)?.string ?? ""
        return string.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// What VoiceOver would announce without a name: every control in the
    /// window's accessibility tree with no label, title, help or placeholder.
    static func controls(_ window: NSWindow) -> (named: [String], unnamed: [String]) {
        let controls: Set<String> = ["AXButton", "AXCheckBox", "AXPopUpButton", "AXMenuButton", "AXRadioButton", "AXTextField",
                                     "AXSlider", "AXLink", "AXComboBox", "AXIncrementor", "AXDisclosureTriangle", "AXTextArea"]
        // Announced by what they are: the window's own buttons and a scroll bar's parts.
        let announcedByRole: Set<String> = ["AXCloseButton", "AXMinimizeButton", "AXZoomButton", "AXFullScreenButton",
                                            "AXIncrementArrow", "AXDecrementArrow", "AXIncrementPage", "AXDecrementPage"]
        var unnamed: [String] = []
        var named: [String] = []
        var seen = Set<ObjectIdentifier>()
        let object = axObject, text = axText
        func walk(_ element: AnyObject, path: String, depth: Int) {
            guard depth < 80, seen.insert(ObjectIdentifier(element)).inserted else { return }
            let role = text(element, "accessibilityRole")
            let subrole = text(element, "accessibilitySubrole")
            let hidden = element.isAccessibilityElement?() == false
            // A label element linked to the control is read with it.
            let linked = object(element, "accessibilityTitleUIElement").map { title -> String in
                let label = text(title, "accessibilityLabel")
                return label.isEmpty ? text(title, "accessibilityTitle") : label
            } ?? ""
            // Text shown for reading is announced by what it says.
            let content = role == "AXTextArea" && (element as? NSTextView)?.isEditable == false ? "text" : ""
            let name = [text(element, "accessibilityLabel"), text(element, "accessibilityTitle"), text(element, "accessibilityHelp"),
                        text(element, "accessibilityPlaceholderValue"), linked, content].first { !$0.isEmpty } ?? ""
            if controls.contains(role), !hidden, !announcedByRole.contains(subrole) {
                if name.isEmpty {
                    unnamed.append("\(role) in \(path)")
                } else {
                    named.append("\(role): \(name)")
                }
            }
            let here = name.isEmpty ? role : name
            for child in (object(element, "accessibilityChildren") as? [AnyObject] ?? []) {
                walk(child as AnyObject, path: depth < 1 ? here : path + " › " + here, depth: depth + 1)
            }
        }
        if let frame = window.contentView?.superview ?? window.contentView { walk(frame, path: window.title, depth: 0) }
        return (named, unnamed)
    }

    static func audit(_ window: NSWindow, _ what: String) {
        let (named, missing) = controls(window)
        accessibilityFindings += missing.map { "\(what): \($0)" }
        log("accessibility (\(what)): \(named.count) named, \(missing.count) unnamed control\(missing.count == 1 ? "" : "s")")
        for item in Set(missing).sorted() { log("  unnamed: \(item)") }
        // FORESTER_A11Y_NAMES=1 lists every name too, to read them for sense.
        if ProcessInfo.processInfo.environment["FORESTER_A11Y_NAMES"] != nil { for item in named { log("  named: \(item)") } }
    }

    static var accessibilityFindings: [String] = []

    /// The audit sees SwiftUI's controls and catches an unnamed one: a button
    /// showing only a shape, which nothing names (a symbol is named after itself).
    /// SwiftUI makes accessibility elements for what it draws only while an
    /// assistive app is asking: these are the attributes such an app sets.
    static func turnOnAccessibilityTree() {
        for attribute in ["AXEnhancedUserInterface", "AXManualAccessibility"] {
            // The informal setter, reached by name: there is no protocol method for an arbitrary attribute.
            _ = NSApp.perform(NSSelectorFromString("accessibilitySetValue:forAttribute:"), with: NSNumber(value: true), with: attribute)
        }
    }

    static func checkAccessibilityAudit() async throws {
        turnOnAccessibilityTree()
        let view = VStack {
            Button {} label: { Circle().frame(width: 12, height: 12) }
            Button("Named") {}
        }
        .padding(40)
        .frame(width: 240, height: 160)
        // As a sheet, the way the gallery shows sheets, so it is drawn like them.
        guard let main = mainWindow() else { throw AutomationError("no window for the accessibility check") }
        let controller = NSHostingController(rootView: view)
        controller.sizingOptions = [.preferredContentSize]
        let window = NSWindow(contentViewController: controller)
        window.isReleasedWhenClosed = false
        main.beginSheet(window, completionHandler: nil)
        defer {
            main.endSheet(window)
            window.orderOut(nil)
        }
        // SwiftUI makes accessibility elements for what it draws itself once
        // they are first asked for, a moment later.
        _ = controls(window)
        try await settle(2)
        let (named, unnamed) = controls(window)
        guard unnamed.count == 1, named.contains("AXButton: Named") else {
            throw AutomationError("check failed: the accessibility audit did not find the unnamed button (named \(named), unnamed \(unnamed))")
        }
        log("verified: the accessibility audit finds an unnamed control and accepts a named one")
    }

    /// Updates come only from a build that names the feed and its key: this
    /// one names neither, so it has no updater and no update menu. (The
    /// release build's feed and signature are checked by make-release.sh.)
    static func checkUpdateRules() throws {
        #if !APP_STORE
        Updates.start()
        guard !Updates.isAvailable else { throw AutomationError("check failed: a build without a feed and key started an updater") }
        log("verified: a build without an update feed and key has no updater")
        #endif
    }

    static func walkthrough(_ model: AppModel, output: URL) async throws {
        let password = testPassword
        try checkCarryOver()
        try checkKeychainReads()
        try checkUpdateRules()
        let (profile, other) = testProfiles(model)
        model.requestedSelection = profile.id
        try await settle()
        try snapshot("01-not-connected", output)

        let session = try require(model.session(for: profile.id))
        session.connect(password: password)
        try await waitFor("connect outcome") {
            if case .failed = session.phase { return true }
            return session.phase.isConnected || session.pendingTrustFailure != nil
        }
        if session.pendingTrustFailure != nil {
            try await settle()
            try snapshotSheet("02-certificate-prompt", output)
            session.trustPendingCertificate()
            try await waitFor("connected after trust") { session.phase.isConnected }
        }
        if case .failed(let message) = session.phase { throw AutomationError(message) }
        try await waitFor("domain loaded") { session.inspector.entry != nil }
        try await settle()
        try snapshot("03-domain", output)
        try verifyColumnEdges("browsing")
        try verifyToolbarFits(try require(mainWindow()), "browsing")
        log("verified: every toolbar control stays within its column (browsing)")

        // Help › Copy Diagnostics says what a problem report needs, and none
        // of the host, the user or the password.
        session.report("Example failure", isError: true)
        session.report("Could not connect to \(session.profile.host):\(session.profile.port) as \(session.profile.bindName)", isError: true)
        let diagnostics = Diagnostics.text(model, session: session)
        guard diagnostics.contains("Server: OpenLDAP"), diagnostics.contains("Example failure"), diagnostics.contains("‹host›"),
              !diagnostics.contains(session.profile.host), !diagnostics.localizedCaseInsensitiveContains(session.profile.bindName),
              !diagnostics.contains(testPassword) else {
            throw AutomationError("check failed: diagnostics leave out the host, user and password, and say what the server is:\n\(diagnostics)")
        }
        log("verified: diagnostics name the server and errors, never the host, the user or the password")
        // The made-up failures would otherwise show in the next pictures.
        session.notice = nil

        let user = "CN=Jens Mertens,OU=IT Operations,OU=Users,OU=Corp,\(base)"
        let target = try await firstUser(session, in: "OU=Engineering,OU=Users,OU=Corp,\(base)") ?? user
        await session.tree.reveal(target)
        session.open(target)
        try await waitFor("user loaded") { session.inspector.entry.map { DN.isSame($0.dn, target) } == true && !session.inspector.membership.loading }
        try await settle()
        try snapshot("04-user-overview", output)

        session.inspector.tab = .attributes
        try await settle()
        try snapshot("05-user-attributes", output)

        session.inspector.tab = .membership
        session.inspector.membership.loadNested()
        try await waitFor("nested groups") { session.inspector.membership.nested != nil }
        try await settle()
        try snapshot("06-user-membership", output)

        let group = "CN=DL-VPN-Users,OU=Groups,OU=Corp,\(base)"
        await session.tree.reveal(group)
        session.open(group)
        try await waitFor("group loaded") { session.inspector.entry.map { DN.isSame($0.dn, group) } == true && !session.inspector.membership.loading }
        session.inspector.membership.loadNested()
        try await waitFor("nested members") { session.inspector.membership.nested != nil }
        try await settle()
        try snapshot("07-group-membership", output)

        session.inspector.tab = .overview
        let dc = "CN=LEGACY01,OU=Servers,OU=Corp,\(base)"
        await session.tree.reveal(dc)
        session.open(dc)
        try await waitFor("computer loaded") { session.inspector.entry.map { DN.isSame($0.dn, dc) } == true }
        try await settle()
        try snapshot("08-computer", output)

        session.mode = .search
        session.search.base = base
        if let preset = SearchPreset.all.first(where: { $0.title == "Password never expires" }) {
            session.search.apply(preset)
        }
        try await waitFor("search") { !session.search.running && session.search.hasRun }
        if let first = session.search.rows.first?.id {
            session.search.selection = [first]
            session.select(first)
        }
        try await waitFor("search selection") { session.inspector.entry != nil }
        try await settle()
        try snapshot("09-search-preset", output)

        session.search.quickFind("bulk01")
        try await waitFor("quick find") { !session.search.running && session.search.hasRun }
        try await settle()
        try snapshot("10-quick-find", output)

        session.search.filterText = "(&(objectClass=user)(sAMAccountName=bulk*)"
        try await settle()
        try snapshot("11-filter-error", output)

        session.search.filterText = "(objectClass=user)"
        session.search.base = "OU=Bulk Import,OU=Corp,\(base)"
        session.search.scope = .oneLevel
        session.search.run()
        try await waitFor("paged search") { !session.search.running }
        try await settle()
        try snapshot("12-paged-search", output)
        try verifyColumnEdges("searching")
        try verifyToolbarFits(try require(mainWindow()), "searching")
        log("verified: every toolbar control stays within its column (searching)")

        session.mode = .browse
        await session.tree.reveal("OU=Bulk Import,OU=Corp,\(base)")
        session.open("OU=Bulk Import,OU=Corp,\(base)")
        try await settle()
        try snapshot("13-large-ou", output)

        session.tree.selection = TreeModel.rootDSEKey
        session.select("")
        try await waitFor("root DSE") { session.inspector.entry?.dn == "" }
        try await settle()
        try snapshot("14-root-dse", output)

        NSApp.appearance = NSAppearance(named: .aqua)
        let gpo = "OU=Workstations,OU=Corp,\(base)"
        await session.tree.reveal(gpo)
        session.open(gpo)
        try await waitFor("OU") { session.inspector.entry.map { DN.isSame($0.dn, gpo) } == true }
        try await settle()
        try snapshot("15-light-ou", output)
        session.open(target)
        try await waitFor("user again") { session.inspector.entry.map { DN.isSame($0.dn, target) } == true && !session.inspector.membership.loading }
        try await settle()
        try snapshot("16-light-user", output)
        NSApp.appearance = nil

        try await editingWalkthrough(session, base: base, user: target, output: output)
        try await staleResultChecks(session, base: base, user: target)

        // A second profile with LDAPS and an unknown CA: the trust prompt.
        model.requestedSelection = other.id
        let ldaps = try require(model.session(for: other.id))
        ldaps.connect()
        try await waitFor("trust prompt") { ldaps.pendingTrustFailure != nil || ldaps.phase.isConnected }
        try await settle(1.5)
        try snapshotSheet("17-trust-prompt", output)
        ldaps.pendingTrustFailure = nil
        try await settle()
        try snapshot("18-trust-declined", output)

        // Both connected, switching between them shows each one's own tree.
        ldaps.connect()
        try await waitFor("trust prompt again") { ldaps.pendingTrustFailure != nil || ldaps.phase.isConnected }
        if ldaps.pendingTrustFailure != nil { ldaps.trustPendingCertificate(once: true) }
        try await waitFor("LDAPS connected") { ldaps.phase.isConnected && ldaps.inspector.entry != nil }
        // Connected afresh, both trees have gone through the same steps and so
        // carry the same change count: the case where the outline used to keep
        // showing the other connection's tree.
        session.disconnect()
        session.connect(password: password)
        try await waitFor("corp connected again") { session.phase.isConnected && session.inspector.entry != nil }
        model.requestedSelection = other.id
        try await settle(1.5)
        // Both reach the same test server, so the trees look alike: what is
        // checked is that the outline shows the selected connection's own nodes.
        func showing(_ shown: DirectorySession) -> Bool {
            guard let node = firstTreeNode() else { return false }
            return shown.tree.node(node.id) === node
        }
        try verify("the tree shows the selected connection's nodes", showing(ldaps))
        model.requestedSelection = profile.id
        try await settle(1.5)
        try verify("switching connections shows the other connection's nodes", showing(session))
        model.requestedSelection = other.id
        try await settle(1.5)
        try verify("and switching back shows the first one's again", showing(ldaps))
        ldaps.disconnect()
        session.disconnect()
    }

    /// Connections saved under the former name are copied over, and a file
    /// already in the new place is never overwritten. Runs on scratch folders.
    static func checkCarryOver() throws {
        let scratch = FileManager.default.temporaryDirectory.appendingPathComponent("forester-carry-over-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: scratch) }
        let old = scratch.appendingPathComponent(ProfileStore.formerFolderName)
        let new = scratch.appendingPathComponent(ProfileStore.folderName)
        try FileManager.default.createDirectory(at: old, withIntermediateDirectories: true)
        try Data("[\"old\"]".utf8).write(to: old.appendingPathComponent("connections.json"))
        ProfileStore.carryOver(from: old, to: new)
        let copied = try? String(contentsOf: new.appendingPathComponent("connections.json"), encoding: .utf8)
        try Data("[\"newer\"]".utf8).write(to: new.appendingPathComponent("connections.json"))
        ProfileStore.carryOver(from: old, to: new)
        let kept = try? String(contentsOf: new.appendingPathComponent("connections.json"), encoding: .utf8)
        let original = try? String(contentsOf: old.appendingPathComponent("connections.json"), encoding: .utf8)
        try verify("connections saved as LDAP Explorer are carried over, without overwriting or removing anything",
                   copied == "[\"old\"]" && kept == "[\"newer\"]" && original == "[\"old\"]")
    }

    static func verify(_ what: String, _ condition: Bool) throws {
        guard condition else { throw AutomationError("check failed: \(what)") }
        log("verified: \(what)")
    }

    /// The first item the tree's outline shows.
    static func firstTreeNode() -> TreeModel.Node? {
        func all(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(all) }
        guard let outline = (mainWindow()?.contentView.map(all) ?? []).compactMap({ $0 as? NSOutlineView })
            .first(where: { $0.numberOfRows > 0 }) else { return nil }
        return outline.item(atRow: 0) as? TreeModel.Node
    }

    /// Results of slow work must not land on what the user moved on to.
    static func staleResultChecks(_ session: DirectorySession, base: String, user: String) async throws {
        // Nested groups asked for on one entry are not shown on the next.
        session.mode = .browse
        session.open(user)
        try await waitFor("user for nested") { session.inspector.entry.map { DN.isSame($0.dn, user) } == true && !session.inspector.membership.loading }
        session.inspector.membership.loadNested()
        let other = "CN=GG-SRE,OU=Groups,OU=Corp,\(base)"
        session.open(other)
        try await waitFor("next entry") { session.inspector.entry.map { DN.isSame($0.dn, other) } == true }
        try await settle(2)
        try verify("nested groups of the previous entry are not shown on the next", session.inspector.membership.nested == nil)

        // A search replaced by a new one does not mark the new one stopped.
        session.mode = .search
        session.search.base = "OU=Bulk Import,OU=Corp,\(base)"
        session.search.scope = .oneLevel
        session.search.filterText = "(objectClass=user)"
        session.search.run()
        try await settle(0.05)
        session.search.base = "OU=Corp,\(base)"
        session.search.scope = .subtree
        session.search.run()
        try await settle(0.03)
        try verify("re-running a search keeps it running, not \"Stopped.\"", session.search.running && session.search.summary != "Stopped.")
        try await waitFor("second search") { !session.search.running }
        try verify("the results are the second search's", session.search.summary != "Stopped." && session.search.rows.count > 1_500)
        session.mode = .browse
    }

    /// The editing features, each change read back from the server to prove it
    /// happened, and each new sheet and tool window photographed.
    static func editingWalkthrough(_ session: DirectorySession, base: String, user: String, output: URL) async throws {
        func read(_ dn: String, _ attributes: [String] = ["*"]) async throws -> LDAPEntry? {
            try await session.run { try await $0.read(dn, attributes: attributes) }
        }
        func expect(_ what: String, _ condition: Bool) throws {
            guard condition else { throw AutomationError("check failed: \(what)") }
            log("verified: \(what)")
        }

        // Read-only is the default: a change is refused before it is sent.
        try expect("new profiles are read-only", session.profile.readOnly)
        let refused = await session.change("should not happen") { try await $0.modify(user, [.replace("description", ["x"])]) }
        try expect("a change is refused while read-only", !refused)
        // The refusal's notice would otherwise show in the next pictures.
        session.notice = nil
        session.setReadOnly(false)
        session.open(user)
        try await waitFor("user with editing") { session.inspector.entry.map { DN.isSame($0.dn, user) } == true }
        session.inspector.tab = .overview
        try await settle(1.2)
        try snapshot("19-editing-overview", output)

        // Attribute editing: the editor sheet, then the change it makes.
        let entry = try require(session.inspector.entry)
        try snapshotHosted("20-attribute-editor", size: NSSize(width: 600, height: 460),
                           AttributeEditorSheet(session: session, entry: entry, attribute: "description"))
        try snapshotHosted("21-attribute-picker", size: NSSize(width: 600, height: 520),
                           AttributeEditorSheet(session: session, entry: entry, attribute: nil))
        try snapshotHosted("22-uac-editor", size: NSSize(width: 600, height: 460),
                           AttributeEditorSheet(session: session, entry: entry, attribute: "userAccountControl"))
        await session.change("Saved description.") { try await $0.modify(user, [.replace("description", ["Edited by the walkthrough"])]) }
        try expect("description saved", try await read(user)?.string("description") == "Edited by the walkthrough")
        session.inspector.tab = .attributes
        try await settle(1.2)
        try snapshot("23-attributes-editable", output)

        // Account actions.
        let current = try require(try await read(user, ["*", "+"]))
        await AccountActions.setEnabled(false, current, session: session)
        try expect("account disabled", (try await read(user)?.int("userAccountControl") ?? 0) & 2 != 0)
        let disabled = try require(try await read(user, ["*", "+"]))
        await AccountActions.setEnabled(true, disabled, session: session)
        try expect("account enabled", (try await read(user)?.int("userAccountControl") ?? 2) & 2 == 0)
        let locked = "CN=Thomas Wouters,OU=Sales,OU=Users,OU=Corp,\(base)"
        if let lockedEntry = try await read(locked, ["*", "+"]) {
            await AccountActions.unlock(lockedEntry, session: session)
            try expect("account unlocked", try await read(locked)?.int("lockoutTime") == 0)
        }
        let service = "CN=svc_backup,OU=Service Accounts,OU=Corp,\(base)"
        let serviceEntry = try require(try await read(service, ["*"]))
        _ = await AccountActions.setCannotChangePassword(false, serviceEntry, session: session)
        try expect("user may change password",
                   try await AccountActions.readSecurityDescriptor(service, session: session)?.userCannotChangePassword == false)
        _ = await AccountActions.setCannotChangePassword(true, serviceEntry, session: session)
        try expect("user cannot change password again",
                   try await AccountActions.readSecurityDescriptor(service, session: session)?.userCannotChangePassword == true)
        await AccountActions.setMustChangePassword(true, current, session: session)
        try expect("must change password", try await read(user)?.int("pwdLastSet") == 0)
        session.open(user)
        try await waitFor("user reloaded") { session.inspector.entry.map { DN.isSame($0.dn, user) } == true }
        session.inspector.tab = .overview
        try await settle(1.2)
        try snapshot("24-account-panel", output)

        // Entry management: create, rename, move, delete.
        let ou = "OU=Walkthrough,OU=Corp,\(base)"
        try? await session.run { try await $0.deleteSubtree(ou, useTreeDelete: false) }
        session.sheet = .newEntry(parent: "OU=Corp,\(base)")
        try await settle(1.2)
        try snapshotSheet("25-new-entry", output)
        session.sheet = nil
        try await settle()
        await session.change("Created Walkthrough.", refreshing: ["OU=Corp,\(base)"], select: ou) {
            try await $0.add(ou, attributes: [LDAPAttribute(name: "objectClass", values: [Data("top".utf8), Data("organizationalUnit".utf8)]),
                                              LDAPAttribute(name: "ou", values: [Data("Walkthrough".utf8)])])
        }
        let created = "CN=New Person,\(ou)"
        await session.change("Created New Person.", refreshing: [ou], select: created) {
            try await $0.add(created, attributes: [
                LDAPAttribute(name: "objectClass", values: ["top", "person", "organizationalPerson", "user"].map { Data($0.utf8) }),
                LDAPAttribute(name: "cn", values: [Data("New Person".utf8)]), LDAPAttribute(name: "sn", values: [Data("Person".utf8)]),
                LDAPAttribute(name: "sAMAccountName", values: [Data("new.person".utf8)]),
                LDAPAttribute(name: "userAccountControl", values: [Data("546".utf8)]),
            ])
        }
        try expect("entry created", try await read(created) != nil)
        try await settle(1.0)
        try snapshot("26-created-in-tree", output)
        session.sheet = .duplicate(try require(try await read(user, ["*", "+"])))
        try await settle(1.2)
        try snapshotSheet("27-duplicate", output)
        session.sheet = .renameMove(dn: created, move: false)
        try await settle(1.0)
        try snapshotSheet("28-rename-move", output)
        session.sheet = nil
        try await settle()
        let renamed = "CN=Renamed Person,\(ou)"
        await session.change("Renamed.", refreshing: [ou], select: renamed) { try await $0.modifyDN(created, newRDN: "CN=Renamed Person") }
        let renamedEntry = try await read(renamed)
        let oldEntry = try await read(created)
        try expect("entry renamed", renamedEntry != nil && oldEntry == nil)
        let moved = "CN=Renamed Person,OU=Disabled Users,OU=Corp,\(base)"
        await session.change("Moved.", refreshing: [ou, "OU=Disabled Users,OU=Corp,\(base)"], select: moved) {
            try await $0.modifyDN(renamed, newRDN: "CN=Renamed Person", newSuperior: "OU=Disabled Users,OU=Corp,\(base)")
        }
        try expect("entry moved", try await read(moved) != nil)
        await session.change("Moved back.", refreshing: [ou, "OU=Disabled Users,OU=Corp,\(base)"], select: renamed) {
            try await $0.modifyDN(moved, newRDN: "CN=Renamed Person", newSuperior: ou)
        }
        session.sheet = .delete(dn: ou)
        try await settle(1.5)
        try snapshotSheet("29-delete-subtree", output)
        session.sheet = nil
        try await settle()
        await session.change("Deleted Walkthrough.", refreshing: ["OU=Corp,\(base)"], select: "OU=Corp,\(base)") {
            try await $0.deleteSubtree(ou, useTreeDelete: false)
        }
        try expect("subtree deleted", try await read(ou) == nil)
        try await undoChecks(session, base: base, user: user)

        // Passwords, LDIF import, account status.
        session.sheet = .password(try require(try await read(user, ["*", "+"])))
        try await settle(1.0)
        try snapshotSheet("30-password", output)
        session.sheet = .importLDIF(nil)
        try await settle(1.0)
        try snapshotSheet("31-ldif-import", output)
        session.sheet = .accountStatus(try require(try await read(user, ["*", "+"])))
        try await settle(4)
        try snapshotSheet("32-account-status", output)
        session.sheet = nil
        try await settle()

        // Replication metadata and a dynamic group.
        session.open(user)
        try await waitFor("user for replication") { session.inspector.entry.map { DN.isSame($0.dn, user) } == true }
        session.inspector.tab = .replication
        try await settle(1.5)
        try snapshot("33-replication", output)
        let dynamic = "CN=DYN-Engineering,OU=Groups,OU=Corp,\(base)"
        await session.tree.reveal(dynamic)
        session.open(dynamic)
        session.inspector.tab = .membership
        try await waitFor("dynamic group") { session.inspector.membership.dynamic != nil }
        try await settle(1.2)
        try snapshot("34-dynamic-group", output)

        // Search builder and the containers-only tree.
        session.mode = .search
        try await settle(1.0)
        try snapshot("35-search-form", output)
        session.mode = .browse
        session.tree.setContainersOnly(true)
        try await settle(1.0)
        try snapshot("36-containers-only", output)
        session.tree.setContainersOnly(false)

        // Tool windows.
        try await waitFor("schema loaded") { session.schema != nil }
        try await snapshotHostedAsync("37-domain-info", size: NSSize(width: 980, height: 1100), wait: 3, DomainInfoView(session: session))
        try await snapshotHostedAsync("38-server-monitor", size: NSSize(width: 980, height: 720), wait: 2, ServerMonitorView(session: session))
        try await snapshotHostedAsync("39-schema", size: NSSize(width: 980, height: 720), wait: 1, SchemaBrowserView(session: session, initialSelection: "user"))
        session.setReadOnly(true)
    }

    /// Changes are taken back with Edit › Undo and from the change history:
    /// a value comes back, Redo makes the change again, only the values a
    /// change added leave a list, a change someone else overwrote is undone
    /// only when asked to, a rename goes back, and what cannot be undone says why.
    static func undoChecks(_ session: DirectorySession, base: String, user: String) async throws {
        func read(_ dn: String, _ attributes: [String] = ["*"]) async throws -> LDAPEntry? {
            try await session.run { try await $0.read(dn, attributes: attributes) }
        }
        func expect(_ what: String, _ condition: Bool) throws {
            guard condition else { throw AutomationError("check failed: \(what)") }
            log("verified: \(what)")
        }
        let undoManager = UndoManager()
        let previousManager = session.undoManager
        session.undoManager = undoManager
        defer { session.undoManager = previousManager }

        // A value, with Edit › Undo and Redo.
        let before = try await read(user)?.string("description")
        await session.change("Saved description.", undo: .values(user, ["description"])) {
            try await $0.modify(user, [.replace("description", ["Changed to be undone"])])
        }
        try expect("Edit › Undo is offered for the change", undoManager.canUndo && undoManager.undoActionName == "Saved description")
        session.notice = nil
        undoManager.undo()
        try await waitFor("description undone") { session.notice?.message.hasPrefix("Undid") == true }
        try expect("undo puts the earlier value back", try await read(user)?.string("description") == before)
        try expect("Edit › Redo is offered after undoing", undoManager.canRedo)
        session.notice = nil
        undoManager.redo()
        try await waitFor("description redone") { session.notice?.message.hasPrefix("Redid") == true }
        try expect("redo makes the change again", try await read(user)?.string("description") == "Changed to be undone")
        try expect("a redo is listed as one", session.history.first?.summary == "Redid: Saved description.")

        // A list: only what the change added goes, and someone else's
        // addition meanwhile stops a plain undo but survives a forced one.
        let groups = try await session.run {
            try await $0.pagedSearch(LDAPSearchRequest(base: base, scope: .subtree, filter: try LDAPFilter.parse("(&(objectClass=group)(member=*))"),
                                                       attributes: ["member"]), limit: 1)
        }
        let group = try require(groups.entries.first?.dn)
        let membersBefore = Set(try await session.run { try await $0.completingRangedAttributes(try await $0.read(group, attributes: ["member"])!) }.values("member"))
        let other = "CN=svc_backup,OU=Service Accounts,OU=Corp,\(base)"
        await session.change("Added to group.", undo: .values(group, ["member"])) {
            try await $0.modify(group, [.add("member", [user])])
        }
        let added = try require(session.history.first)
        try await session.run { try await $0.modify(group, [.add("member", [other])]) }
        try expect("a change someone else overwrote is not undone without asking", await session.undo(added.id) == nil)
        _ = await session.undo(added.id, force: true)
        let membersAfter = try await session.run { try await $0.completingRangedAttributes(try await $0.read(group, attributes: ["member"])!) }.values("member")
        // The server spells a DN its own way, so they are compared as DNs.
        let afterDNs = membersAfter.map { String(decoding: $0, as: UTF8.self) }
        try expect("undoing removes only the member the change added",
                   !afterDNs.contains { DN.isSame($0, user) } && afterDNs.contains { DN.isSame($0, other) }
                       && membersBefore.isSubset(of: Set(membersAfter)))
        try await session.run { try await $0.modify(group, [.delete("member", [other])]) }

        // A rename goes back.
        let ou = "OU=Undo Checks,OU=Corp,\(base)"
        try? await session.run { try await $0.deleteSubtree(ou, useTreeDelete: false) }
        try await session.run {
            try await $0.add(ou, attributes: [LDAPAttribute(name: "objectClass", values: [Data("top".utf8), Data("organizationalUnit".utf8)]),
                                              LDAPAttribute(name: "ou", values: [Data("Undo Checks".utf8)])])
        }
        let renamed = "OU=Undo Checks Renamed,OU=Corp,\(base)"
        var renamedOU = renamed
        await session.change("Renamed.", undo: .inverse(dn: renamed, undoneAt: ou) {
            try await $0.modifyDN(renamed, newRDN: "OU=Undo Checks", deleteOldRDN: true)
        }) { try await $0.modifyDN(ou, newRDN: "OU=Undo Checks Renamed") }
        _ = await session.undo(try require(session.history.first).id)
        let back = try await read(ou)
        let gone = try await read(renamed)
        try expect("undoing a rename brings the old name back", back != nil && gone == nil)
        _ = await session.undo(try require(session.history.first).id)
        let again = try await read(renamed)
        try expect("undoing that undo renames it again", again != nil)
        // An entry someone changed since is not renamed back without asking.
        let renameAgain = try require(session.history.first)
        try await session.run { try await $0.modify(renamed, [.replace("description", ["changed by someone else"])]) }
        try expect("a change someone made since stops an undo until confirmed", await session.undo(renameAgain.id) == nil)
        _ = await session.undo(renameAgain.id, force: true)
        let forcedBack = try await read(ou)
        try expect("…and confirmed, it goes ahead", forcedBack != nil)
        renamedOU = ou
        try? await session.run { try await $0.deleteSubtree(renamedOU, useTreeDelete: false) }

        // A change whose details are not kept (a new user's password) is
        // undone, and not redone.
        let secretOU = "OU=Undo Secret,OU=Corp,\(base)"
        try? await session.run { try await $0.delete(secretOU) }
        await session.change("Created.", undo: .inverse(dn: secretOU, keepsChange: false) { try await $0.delete(secretOU) }) {
            try await $0.add(secretOU, attributes: [LDAPAttribute(name: "objectClass", values: [Data("top".utf8), Data("organizationalUnit".utf8)]),
                                                    LDAPAttribute(name: "ou", values: [Data("Undo Secret".utf8)])])
        }
        _ = await session.undo(try require(session.history.first).id)
        let secretGone = try await read(secretOU)
        let undoneCreate = try require(session.history.first)
        try expect("a creation whose details are not kept is undone, and cannot be redone",
                   secretGone == nil && !undoneCreate.canUndo && undoneCreate.notUndoable?.contains("not kept") == true)

        // A value whose spelling changed only in case comes back: the server
        // takes "a@x" and "A@x" for the same mail address.
        _ = try await session.run { try await $0.modify(user, [.replace("mail", ["First.Mail@corp.example", "second.mail@corp.example"])]) }
        await session.change("Saved mail.", undo: .values(user, ["mail"])) {
            try await $0.modify(user, [.replace("mail", ["first.mail@corp.example", "Second.Mail@corp.example"])])
        }
        let caseOnly = await session.undo(try require(session.history.first).id)
        let mailBack = Set(try await read(user)?.strings("mail") ?? [])
        try expect("undoing a change of case in a list puts the old spelling back",
                   caseOnly != nil && mailBack == ["First.Mail@corp.example", "second.mail@corp.example"])

        // What cannot be undone says why, and is not offered.
        let entry = try require(try await read(user, ["*", "+"]))
        await AccountActions.unlock(entry, session: session)
        let unlock = try require(session.history.first)
        try expect("an unlock is listed as not undoable, with the reason", !unlock.canUndo && unlock.notUndoable?.isEmpty == false)
        try snapshotHosted("39b-change-history", size: NSSize(width: 640, height: 460), ChangeHistorySheet(session: session))
    }

    /// Renders a view in a window of its own (sheets the walkthrough cannot open by clicking).
    static func snapshotHosted<V: View>(_ name: String, size: NSSize, _ view: V) throws {
        let window = NSWindow(contentRect: NSRect(origin: .zero, size: size), styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false // ARC owns it; AppKit releasing it too is a double free
        window.contentView = NSHostingView(rootView: view.frame(width: size.width, height: size.height))
        window.layoutIfNeeded()
        try write(window, name: name, output: outputDirectory!)
        window.close()
    }

    static func snapshotHostedAsync<V: View>(_ name: String, size: NSSize, wait: Double, _ view: V) async throws {
        let window = NSWindow(contentRect: NSRect(origin: NSPoint(x: 120, y: 120), size: size), styleMask: [.titled, .resizable],
                              backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false // ARC owns it; AppKit releasing it too is a double free
        window.contentView = NSHostingView(rootView: view.frame(width: size.width, height: size.height))
        window.orderFront(nil)
        try await settle(wait)
        try write(window, name: name, output: outputDirectory!)
        window.close()
    }

    static func firstUser(_ session: DirectorySession, in ou: String) async throws -> String? {
        let result = try await session.run {
            try await $0.search(LDAPSearchRequest(base: ou, scope: .oneLevel, filter: try LDAPFilter.parse("(title=Head of*)"),
                                                  attributes: ["1.1"]))
        }
        return result.entries.first?.dn
    }

    // MARK: Plumbing

    struct AutomationError: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }

    static func require<T>(_ value: T?) throws -> T {
        guard let value else { throw AutomationError("missing value") }
        return value
    }

    static func waitFor(_ what: String, timeout: TimeInterval = 20, _ condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            if Date() > deadline { throw AutomationError("timed out waiting for \(what)") }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        log("ok: \(what)")
    }

    static func settle(_ seconds: Double = 0.8) async throws {
        try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
    }

    static func mainWindow() -> NSWindow? {
        NSApp.windows.first { $0.isVisible && $0.sheetParent == nil && $0.frame.width > 500 }
    }

    static func snapshot(_ name: String, _ output: URL) throws {
        guard let window = mainWindow() else { throw AutomationError("no window for \(name)") }
        try write(window, name: name, output: output)
    }

    static func snapshotSheet(_ name: String, _ output: URL) throws {
        guard let sheet = mainWindow()?.attachedSheet else { throw AutomationError("no sheet for \(name)") }
        try write(sheet, name: name, output: output)
    }

    /// Renders the window's own view hierarchy, title bar and toolbar included.
    /// This reads only the app's own views, so it needs no screen-recording permission.
    /// FORESTER_SCREEN_CAPTURE=1 takes each picture from the screen instead of
    /// drawing the view hierarchy, which leaves out the glass of macOS 26 and
    /// later: what the App Store screenshots need. It needs the Screen
    /// Recording permission of whatever started the app (a terminal).
    static let capturesScreen = ProcessInfo.processInfo.environment["FORESTER_SCREEN_CAPTURE"] == "1"

    static func write(_ window: NSWindow, name: String, output: URL) throws {
        audit(window, name)
        let file = output.appendingPathComponent("\(name).png")
        // A window never put on screen (a sheet pictured on its own) has no
        // pixels to capture, and no glass to lose by drawing it.
        if capturesScreen, window.isVisible, window.occlusionState.contains(.visible) {
            // Pictured as a person sees it while using it: in front and key.
            // Started from a terminal, the app loses the front now and then,
            // and an inactive window is drawn grey. macOS lets it come back
            // only while nobody is busy in another app, so it keeps asking
            // for a while, and a picture taken without the front says so.
            func inFront() -> Bool { NSApp.isActive && (window.isKeyWindow || window.attachedSheet?.isKeyWindow == true) }
            let deadline = Date().addingTimeInterval(20)
            while !inFront(), Date() < deadline {
                NSApp.activate(ignoringOtherApps: true)
                (window.sheetParent ?? window).orderFront(nil)
                window.makeKey()
                RunLoop.current.run(until: Date().addingTimeInterval(0.5))
            }
            if !inFront() { log("inactive: \(name) was taken while another app was in front") }
            let capture = Process()
            capture.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
            capture.arguments = ["-x", "-o", "-l", String(window.windowNumber), file.path]
            try capture.run()
            capture.waitUntilExit()
            guard capture.terminationStatus == 0, FileManager.default.fileExists(atPath: file.path) else {
                throw AutomationError("the screen could not be captured: give the terminal the Screen Recording permission")
            }
            log("snapshot \(name)")
            return
        }
        guard let view = window.contentView?.superview ?? window.contentView else { throw AutomationError("no view") }
        view.layoutSubtreeIfNeeded()
        guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { throw AutomationError("no bitmap") }
        view.cacheDisplay(in: view.bounds, to: rep)
        guard let png = rep.representation(using: .png, properties: [:]) else { throw AutomationError("no png") }
        try png.write(to: file)
        log("snapshot \(name)")
    }
}
#endif
