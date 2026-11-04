// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

#if DEBUG
import AppKit
import LDAPKit
import SwiftUI

/// Drives the app through its own controls, the way a person would: commands
/// are chosen from the menu bar, text is typed key by key into fields, pop-up
/// menus are set, Return and Escape press a sheet's default and cancel
/// buttons, and toolbar items are clicked.
///
/// Text fields, pop-ups and switches are found as the AppKit views SwiftUI puts
/// on screen, by their prompt, value or title. Buttons and checkboxes are
/// found in the accessibility tree, by their title: linked with the macOS 26
/// SDK or later, SwiftUI draws them itself and they are no longer NSButtons.
@MainActor
enum UIDriver {
    struct NotFound: Error, CustomStringConvertible {
        let description: String
    }

    // MARK: Finding

    static func views(in window: NSWindow) -> [NSView] {
        func all(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(all) }
        return (window.contentView?.superview ?? window.contentView).map(all) ?? []
    }

    /// Top to bottom, then left to right, as a person reads the window.
    static func onScreenOrder(_ a: NSView, _ b: NSView) -> Bool {
        let (ra, rb) = (a.convert(a.bounds, to: nil), b.convert(b.bounds, to: nil))
        if abs(ra.midY - rb.midY) > 4 { return ra.midY > rb.midY }
        return ra.minX < rb.minX
    }

    static func visible(_ view: NSView) -> Bool {
        !view.isHiddenOrHasHiddenAncestor && view.window != nil && view.visibleRect.width > 1
    }

    /// Editable fields, including those scrolled out of view (typing scrolls to them).
    static func textFields(in window: NSWindow) -> [NSTextField] {
        views(in: window).compactMap { $0 as? NSTextField }
            .filter { $0.isEditable && !$0.isHiddenOrHasHiddenAncestor }
            .sorted(by: onScreenOrder)
    }

    static func field(prompt: String, in window: NSWindow) throws -> NSTextField {
        guard let field = textFields(in: window).first(where: { $0.placeholderString == prompt }) else {
            throw NotFound(description: "no field with the prompt “\(prompt)”\n\(describe(window))")
        }
        return field
    }

    /// A field with this prompt or value, given a moment to appear: a sheet's
    /// fields are filled in just after it is first drawn.
    static func waitForField(prompt: String? = nil, value: String? = nil, in window: NSWindow) async throws -> NSTextField {
        let deadline = Date().addingTimeInterval(3)
        while true {
            if let prompt, let found = try? field(prompt: prompt, in: window) { return found }
            if let value, let found = try? field(value: value, in: window) { return found }
            if Date() > deadline {
                if let prompt { return try field(prompt: prompt, in: window) }
                return try field(value: value ?? "", in: window)
            }
            try await Automation.settle(0.1)
        }
    }

    static func field(value: String, in window: NSWindow) throws -> NSTextField {
        guard let field = textFields(in: window).first(where: { $0.stringValue == value }) else {
            throw NotFound(description: "no field holding “\(value)”\n\(describe(window))")
        }
        return field
    }

    static func secureFields(in window: NSWindow) -> [NSTextField] {
        textFields(in: window).filter { $0 is NSSecureTextField || String(describing: Swift.type(of: $0)).contains("Secure") }
    }

    static func popUp(showing title: String, in window: NSWindow) throws -> NSPopUpButton {
        guard let popUp = views(in: window).compactMap({ $0 as? NSPopUpButton }).first(where: { $0.titleOfSelectedItem == title && visible($0) }) else {
            throw NotFound(description: "no pop-up showing “\(title)”\n\(describe(window))")
        }
        return popUp
    }

    /// A button or checkbox as VoiceOver finds it.
    struct Control {
        let element: AnyObject
        let role: String
        let title: String
        /// In screen coordinates.
        let frame: NSRect
        let enabled: Bool
        /// A checkbox's state.
        let isOn: Bool
    }

    /// Buttons and checkboxes in the window's accessibility tree, toolbar
    /// included, in on-screen order. The window's own close, minimise and zoom
    /// buttons are left out, and so is anything scrolled out of the window,
    /// which the tree also holds.
    static func controls(in window: NSWindow) -> [Control] {
        Automation.turnOnAccessibilityTree()
        let windowButtons: Set<String> = ["AXCloseButton", "AXMinimizeButton", "AXZoomButton", "AXFullScreenButton"]
        var found: [Control] = []
        var seen = Set<ObjectIdentifier>()
        func walk(_ element: AnyObject, depth: Int) {
            guard depth < 80, seen.insert(ObjectIdentifier(element)).inserted else { return }
            let role = Automation.axText(element, "accessibilityRole")
            if role == "AXButton" || role == "AXCheckBox", !windowButtons.contains(Automation.axText(element, "accessibilitySubrole")),
               element.isAccessibilityElement?() != false {
                let title = [Automation.axText(element, "accessibilityLabel"), Automation.axText(element, "accessibilityTitle")]
                    .first { !$0.isEmpty } ?? ""
                let frame = element.accessibilityFrame?() ?? .zero
                if frame.width > 1, window.frame.contains(NSPoint(x: frame.midX, y: frame.midY)) {
                    let isOn = (Automation.axObject(element, "accessibilityValue") as? NSNumber)?.boolValue ?? false
                    found.append(Control(element: element, role: role, title: title, frame: frame,
                                         enabled: element.isAccessibilityEnabled?() ?? true, isOn: isOn))
                }
            }
            for child in Automation.axObject(element, "accessibilityChildren") as? [AnyObject] ?? [] { walk(child, depth: depth + 1) }
        }
        if let root = window.contentView?.superview ?? window.contentView { walk(root, depth: 0) }
        return found.sorted {
            if abs($0.frame.midY - $1.frame.midY) > 4 { return $0.frame.midY > $1.frame.midY }
            return $0.frame.minX < $1.frame.minX
        }
    }

    static func buttons(in window: NSWindow) -> [Control] { controls(in: window).filter { $0.role == "AXButton" } }

    static func button(_ title: String, in window: NSWindow) throws -> Control {
        guard let button = buttons(in: window).first(where: { $0.title == title }) else {
            throw NotFound(description: "no button “\(title)”\n\(describe(window))")
        }
        return button
    }

    /// The buttons along the bottom edge of a sheet, left to right.
    static func bottomBar(in window: NSWindow) -> [Control] {
        buttons(in: window).filter { $0.frame.midY - window.frame.minY < 60 }
    }

    /// The button Return presses: by the Mac's layout, the last one on the
    /// sheet's bottom edge, when Return is what it answers to.
    static func defaultButton(in window: NSWindow) -> Control? {
        bottomBar(in: window).last { ["Cancel", "Close", "Stop"].contains($0.title) == false }
    }

    static func switches(in window: NSWindow) -> [NSSwitch] {
        views(in: window).compactMap { $0 as? NSSwitch }.filter { visible($0) }.sorted(by: onScreenOrder)
    }

    /// Checkboxes in on-screen order.
    static func checkboxes(in window: NSWindow) -> [Control] {
        controls(in: window).filter { $0.role == "AXCheckBox" }
    }

    static func textView(in window: NSWindow) -> NSTextView? {
        views(in: window).compactMap { $0 as? NSTextView }.first { $0.isEditable && !$0.isFieldEditor && visible($0) }
    }

    /// The controls a window shows, for working out why something was not found.
    static func describe(_ window: NSWindow) -> String {
        let fields = views(in: window).compactMap { view -> String? in
            let kind = String(describing: Swift.type(of: view))
            switch view {
            case let popUp as NSPopUpButton: return "  pop-up \(kind) “\(popUp.titleOfSelectedItem ?? "")”"
            case let field as NSTextField where field.isEditable && visible(field):
                return "  field \(kind) “\(field.stringValue.prefix(40))” prompt “\(field.placeholderString ?? "")”"
            default: return nil
            }
        }
        let controls = controls(in: window).map { "  \($0.role) “\($0.title)” enabled \($0.enabled)\($0.role == "AXCheckBox" ? " on \($0.isOn)" : "")" }
        return (fields + controls).joined(separator: "\n")
    }

    // MARK: Acting

    /// Presses a button or checkbox as VoiceOver does.
    static func click(_ control: Control, _ name: String) throws {
        guard control.enabled else { throw NotFound(description: "“\(name)” is disabled") }
        guard control.element.accessibilityPerformPress?() == true else { throw NotFound(description: "“\(name)” did not take the press") }
        Automation.log("clicked \(name)")
    }

    /// A mouse click at the middle of a view, delivered to its window as a real
    /// click is (the release is queued first, for controls that track the mouse).
    static func mouseClick(_ view: NSView, _ name: String) async throws {
        guard let window = view.window else { throw NotFound(description: "\(name) is not in a window") }
        view.scrollToVisible(view.bounds)
        let rect = view.convert(view.bounds, to: nil)
        let point = NSPoint(x: rect.midX, y: rect.midY)
        func event(_ type: NSEvent.EventType) -> NSEvent? {
            NSEvent.mouseEvent(with: type, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                               windowNumber: window.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: type == .leftMouseDown ? 1 : 0)
        }
        guard let down = event(.leftMouseDown), let up = event(.leftMouseUp) else { throw NotFound(description: "no mouse event") }
        NSApp.postEvent(up, atStart: false)
        window.sendEvent(down)
        try await Automation.settle(0.3)
        Automation.log("clicked \(name) with the mouse")
    }

    /// Puts the caret in a field, selects what it holds and types over it, then
    /// checks the field holds exactly that. Keys queued while macOS has put
    /// another app in front are dropped; they are then typed straight to the
    /// window, and the log says so.
    static func type(_ text: String, into field: NSTextField, _ name: String) async throws {
        guard let window = field.window else { throw NotFound(description: "\(name) is not in a window") }
        field.scrollToVisible(field.bounds)
        try await Automation.settle(0.1)
        for attempt in 0..<2 {
            window.makeFirstResponder(field)
            try await Automation.settle(0.1)
            field.currentEditor()?.selectAll(nil)
            await type(text, in: window, direct: attempt > 0)
            let shown = field.currentEditor()?.string ?? field.stringValue
            if shown == text {
                Automation.log("typed into \(name)")
                return
            }
            Automation.log("\(name) holds “\(shown)” after typing (app in front: \(NSApp.isActive)); typing again")
        }
        throw NotFound(description: "typing into \(name) did not arrive")
    }

    static func type(_ text: String, into view: NSTextView, _ name: String) async throws {
        guard let window = view.window else { throw NotFound(description: "\(name) is not in a window") }
        for attempt in 0..<2 {
            window.makeFirstResponder(view)
            view.selectAll(nil)
            await type(text, in: window, direct: attempt > 0)
            if view.string == text {
                Automation.log("typed into \(name)")
                return
            }
            Automation.log("\(name) holds “\(view.string)” after typing (app in front: \(NSApp.isActive)); typing again")
        }
        throw NotFound(description: "typing into \(name) did not arrive")
    }

    static func type(_ text: String, in window: NSWindow, direct: Bool = false) async {
        for character in text {
            key(String(character), code: 0, in: window, direct: direct)
            try? await Automation.settle(0.01) // let the run loop take each key, as typing would
        }
        try? await Automation.settle(0.2)
    }

    static func key(_ characters: String, code: UInt16, modifiers: NSEvent.ModifierFlags = [], in window: NSWindow, direct: Bool = false) {
        for type in [NSEvent.EventType.keyDown, .keyUp] {
            guard let event = NSEvent.keyEvent(with: type, location: .zero, modifierFlags: modifiers,
                                               timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: window.windowNumber,
                                               context: nil, characters: characters, charactersIgnoringModifiers: characters,
                                               isARepeat: false, keyCode: code) else { continue }
            // Into the event queue when this window has the keyboard, so the
            // app reads it exactly as it reads typing (completion looks at the
            // current event); straight to the window otherwise.
            if !direct && NSApp.isActive && NSApp.keyWindow === window {
                NSApp.postEvent(event, atStart: false)
            } else {
                window.sendEvent(event)
            }
        }
    }

    /// Return or Escape: offered to the window's key equivalents first, which
    /// is how AppKit gives them to a default or cancel button, then typed.
    static func press(_ characters: String, code: UInt16, in window: NSWindow) async {
        if let event = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [],
                                        timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: window.windowNumber,
                                        context: nil, characters: characters, charactersIgnoringModifiers: characters,
                                        isARepeat: false, keyCode: code),
           window.performKeyEquivalent(with: event) {
        } else {
            key(characters, code: code, in: window)
        }
        try? await Automation.settle(0.3)
    }

    static func pressReturn(in window: NSWindow) async {
        await press("\r", code: 36, in: window)
        Automation.log("pressed Return")
    }

    static func pressEscape(in window: NSWindow) async {
        await press("\u{1b}", code: 53, in: window)
        Automation.log("pressed Escape")
    }

    /// Asks macOS to bring the app forward; it may refuse while the person is
    /// busy in another app.
    static func bringForward(_ window: NSWindow, seconds: Double = 3) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while !NSApp.isActive && Date() < deadline {
            NSRunningApplication.current.activate(options: [.activateAllWindows])
            NSApp.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            try? await Automation.settle(0.3)
        }
        return NSApp.isActive
    }

    static func choose(_ popUp: NSPopUpButton, item: String) throws {
        guard popUp.indexOfItem(withTitle: item) >= 0 else { throw NotFound(description: "no item “\(item)” in the pop-up") }
        popUp.selectItem(withTitle: item)
        if let action = popUp.action { NSApp.sendAction(action, to: popUp.target, from: popUp) }
        Automation.log("chose \(item)")
    }

    // MARK: Menus

    /// Finds a menu item, opening each menu on the way as clicking the menu
    /// bar would: SwiftUI fills a menu's items when it opens.
    static func menuItem(_ path: [String]) -> NSMenuItem? {
        var menu = NSApp.mainMenu
        var item: NSMenuItem?
        for title in path {
            if let menu {
                menu.delegate?.menuNeedsUpdate?(menu)
                menu.delegate?.menuWillOpen?(menu)
                menu.update()
                menu.delegate?.menuDidClose?(menu)
            }
            item = menu?.items.first { $0.title == title }
            menu = item?.submenu
        }
        if let menu = item?.menu {
            menu.delegate?.menuNeedsUpdate?(menu)
            menu.update()
        }
        return item
    }

    /// Chooses a menu command, waiting a moment for SwiftUI to enable it (menu
    /// state follows the focused window and is updated after it changes).
    /// Menu commands follow the focused window, so they are unavailable while
    /// the app is in the background; `orElse` then runs the same action and
    /// the log says the menu itself was not exercised.
    static var menusSkipped: [String] = []

    static func choose(_ path: [String], orElse fallback: (() -> Void)? = nil) async throws {
        let name = path.joined(separator: " › ")
        if !NSApp.isActive, let window = Automation.mainWindow(), !(await bringForward(window)), let fallback {
            fallback()
            menusSkipped.append(name)
            Automation.log("app in the background: did \(name) without the menu")
            try await Automation.settle(0.3)
            return
        }
        let deadline = Date().addingTimeInterval(4)
        while true {
            if let item = menuItem(path), let menu = item.menu, item.isEnabled {
                menu.performActionForItem(at: menu.index(of: item))
                Automation.log("chose \(name)")
                try await Automation.settle(0.2)
                return
            }
            if Date() > deadline {
                let state = menuItem(path).map { "enabled \($0.isEnabled)" } ?? "missing"
                throw NotFound(description: "menu item \(name) is not available (\(state))")
            }
            try await Automation.settle(0.2)
        }
    }

    static func menuTitle(startingWith prefix: String, in menuTitle: String) -> String? {
        menuItem([menuTitle])?.submenu?.items.first { $0.title.hasPrefix(prefix) }?.title
    }
}

/// A scripted session through the app's own controls, checking each result on
/// the server: add a connection by typing it in, test it, trust the
/// certificate, connect, find an entry, allow changes, rename, create a user,
/// reset a password, disable and enable it, delete it, import LDIF, delete a
/// subtree, and search with completion.
@MainActor
enum UITour {
    typealias D = UIDriver

    static func run(_ model: AppModel, output: URL) async throws {
        let base = Automation.base
        func log(_ text: String) { Automation.log(text) }
        func expect(_ what: String, _ condition: Bool) throws {
            guard condition else { throw Automation.AutomationError("UI check failed: \(what)") }
            log("verified (UI): \(what)")
        }
        func shot(_ name: String) throws { try Automation.snapshot("U-\(name)", output) }
        func sheetShot(_ name: String) throws { try Automation.snapshotSheet("U-\(name)", output) }
        func waitForSheet(_ what: String) async throws -> NSWindow {
            try await Automation.waitFor("sheet: \(what)") { Automation.mainWindow()?.attachedSheet != nil }
            try await Automation.settle(0.7)
            let sheet = try Automation.require(Automation.mainWindow()?.attachedSheet)
            sheet.makeKey()
            return sheet
        }
        func waitForNoSheet(_ what: String, timeout: TimeInterval = 20) async throws {
            try await Automation.waitFor("closed: \(what)", timeout: timeout) { Automation.mainWindow()?.attachedSheet == nil }
            try await Automation.settle(0.5)
        }

        // Start from nothing: no saved connections, the app in front.
        for profile in model.store.profiles { model.delete(profile.id) }
        let window = try Automation.require(Automation.mainWindow())
        // macOS lets an app come forward only when the person is not busy in
        // another one, so keep asking for a while.
        for _ in 0..<40 where !NSApp.isActive {
            NSRunningApplication.current.activate(options: [.activateAllWindows])
            NSApp.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            try await Automation.settle(0.5)
        }
        guard NSApp.isActive else {
            throw Automation.AutomationError("the UI tour needs Forester in front; macOS kept another app active")
        }
        try await Automation.settle(0.5)
        try shot("01-no-connections")
        try expect("the Help menu links to the Forester and VersaMinds websites",
                   D.menuItem(["Help", "Forester Website"]) != nil && D.menuItem(["Help", "VersaMinds Website"]) != nil
                   && NSApp.mainMenu?.items.first?.submenu?.items.contains(where: { $0.title == "About Forester" }) == true)

        // A new connection, typed in.
        try await D.choose(["File", "New Connection…"])
        let editor = try await waitForSheet("new connection")
        try await D.type("Corp (typed in)", into: try await D.waitForField(prompt: "Corp domain", in: editor), "Name")
        let server = Automation.TestServer.current
        try await D.type(server.host, into: try D.field(prompt: "dc01.corp.example", in: editor), "Host")
        try await D.type(String(server.port), into: try await D.waitForField(value: "389", in: editor), "Port")
        try await D.type(server.bindName, into: try D.field(prompt: "user@corp.example, CORP\\user or a DN", in: editor), "User")
        try await D.type(Automation.testPassword, into: try D.field(prompt: "Asked when you connect", in: editor), "Password")
        // Keep the test password out of the login keychain.
        let remember = try Automation.require(D.switches(in: editor).first)
        try expect("Remember the password starts on", remember.state == .on)
        remember.performClick(nil)
        try sheetShot("02-connection-typed")

        let bar = D.bottomBar(in: editor).map(\.title)
        try expect("the editor's buttons are Test Connection, Cancel and Add", bar == ["Test Connection", "Cancel", "Add"])
        try D.click(try D.button("Test Connection", in: editor), "Test Connection")
        try await Automation.waitFor("certificate question") { (try? D.button("Trust This Certificate", in: editor)) != nil }
        try await Automation.settle(0.4)
        try sheetShot("03-connection-untrusted")
        try D.click(try D.button("Trust This Certificate", in: editor), "Trust This Certificate")
        try await Automation.settle(2.5)
        try sheetShot("04-connection-tested")
        await D.pressReturn(in: editor)
        try await waitForNoSheet("connection editor")
        let profile = try Automation.require(model.store.profiles.first { $0.name == "Corp (typed in)" })
        try expect("the typed connection was saved, read-only, with the certificate trusted",
                   profile.host == server.host && profile.port == server.port && profile.bindName == server.bindName
                   && profile.readOnly && !profile.trust.pinnedFingerprints.isEmpty && !profile.savePassword)

        // Connect with the menu command.
        try await D.choose(["Directory", "Connect"]) { model.session(for: profile.id)?.connect() }
        let session = try Automation.require(model.session(for: profile.id))
        try await Automation.waitFor("connected") { session.phase.isConnected && session.inspector.entry != nil }
        try await Automation.waitFor("schema") { session.schema != nil }
        try await Automation.settle(1)
        try shot("05-connected")
        try expect("connected read-only with the password typed in the editor", session.phase.isConnected && !session.canWrite)
        // Leftovers of an interrupted run would make the steps below fail for the wrong reason.
        let pieterRenamed = "CN=Pieter Van Damme (renamed),OU=Engineering,OU=Users,OU=Corp,\(base)"
        _ = try? await session.run { connection in
            try? await connection.delete("CN=Ui Tester,OU=Engineering,OU=Users,OU=Corp,\(base)")
            try? await connection.deleteSubtree("OU=Imported,OU=Corp,\(base)", useTreeDelete: false)
            if (try? await connection.read(pieterRenamed, attributes: ["1.1"])) != nil {
                try? await connection.modifyDN(pieterRenamed, newRDN: "CN=Pieter Van Damme")
            }
        }

        // Go to an entry by typing its DN.
        let pieter = "CN=Pieter Van Damme,OU=Engineering,OU=Users,OU=Corp,\(base)"
        var goToSheet = true
        try await D.choose(["Directory", "Go to DN…"]) { goToSheet = false; session.open(pieter) }
        if goToSheet {
            let goTo = try await waitForSheet("go to DN")
            try await D.type(pieter, into: try await D.waitForField(prompt: "CN=Jane Doe,OU=Users,DC=corp,DC=example", in: goTo), "DN")
            await D.pressReturn(in: goTo)
            try await waitForNoSheet("go to DN")
        }
        try await Automation.waitFor("Pieter shown") { session.inspector.entry.map { DN.isSame($0.dn, pieter) } == true }

        // Allow changes with the toolbar's Read-only button.
        let readOnly = try Automation.require(D.controls(in: window).first { $0.title == "Read-only" })
        try expect("the toolbar says Read-only, as a toggle that is off", readOnly.role == "AXCheckBox" && !readOnly.isOn)
        try D.click(readOnly, "Read-only in the toolbar")
        try await Automation.waitFor("editing on") { session.canWrite }
        try await Automation.settle(0.8)
        try shot("06-editing-on")

        // Rename through the Entry menu, then back.
        try await D.choose(["Entry", "Rename…"]) { if let dn = session.selectedDN { session.sheet = .renameMove(dn: dn, move: false) } }
        var rename = try await waitForSheet("rename")
        try await D.type("Pieter Van Damme (renamed)", into: try await D.waitForField(value: "Pieter Van Damme", in: rename), "Name")
        try sheetShot("07-rename-typed")
        await D.pressReturn(in: rename)
        try await waitForNoSheet("rename")
        let renamed = "CN=Pieter Van Damme (renamed),OU=Engineering,OU=Users,OU=Corp,\(base)"
        let renamedEntry = try await read(session, renamed)
        let oldEntry = try await read(session, pieter)
        try expect("renamed on the server", renamedEntry != nil && oldEntry == nil)
        try await Automation.waitFor("renamed entry shown") { session.inspector.entry.map { DN.isSame($0.dn, renamed) } == true }
        try await D.choose(["Entry", "Rename…"]) { if let dn = session.selectedDN { session.sheet = .renameMove(dn: dn, move: false) } }
        rename = try await waitForSheet("rename back")
        try await D.type("Pieter Van Damme", into: try await D.waitForField(value: "Pieter Van Damme (renamed)", in: rename), "Name")
        await D.pressReturn(in: rename)
        try await waitForNoSheet("rename back")
        let back = try await read(session, pieter)
        try expect("renamed back", back != nil)

        // A new user, typed in, next to Pieter.
        try await Automation.waitFor("Pieter selected again") { session.inspector.entry.map { DN.isSame($0.dn, pieter) } == true }
        try await D.choose(["Entry", "New Entry…"]) { if let parent = session.newEntryParent { session.sheet = .newEntry(parent: parent) } }
        let create = try await waitForSheet("new entry")
        try expect("Create waits for a name", D.defaultButton(in: create)?.enabled == false)
        try await D.type("Ui Tester", into: try await D.waitForField(prompt: "Jane Doe", in: create), "Name")
        try await D.type("Ui", into: try D.field(prompt: "First name", in: create), "givenName")
        try await D.type("Tester", into: try D.field(prompt: "Last name", in: create), "sn")
        let passwords = D.secureFields(in: create)
        try expect("the form asks for a password twice", passwords.count == 2)
        try await D.type("Correct-Horse-42", into: passwords[0], "Password")
        try await D.type("Correct-Horse-41", into: passwords[1], "Confirm")
        try expect("Create waits while the passwords differ", D.defaultButton(in: create)?.enabled == false)
        try await D.type("Correct-Horse-42", into: passwords[1], "Confirm")
        try sheetShot("08-new-user-typed")
        await D.pressReturn(in: create)
        try await waitForNoSheet("new entry")
        let tester = "CN=Ui Tester,OU=Engineering,OU=Users,OU=Corp,\(base)"
        let created = try await read(session, tester)
        try expect("the new user exists, with its account names filled in from the name",
                   created?.string("sAMAccountName") == "ui.tester" && created?.string("userPrincipalName") == "ui.tester@corp.example"
                   && created?.string("displayName") == "Ui Tester" && created?.string("sn") == "Tester")
        // AD never returns a password, so there the password is checked by
        // signing in with it: AD answers "must change" only to the right one.
        let storedPassword = server.isActiveDirectory
            ? try await signIn(session, tester, "Correct-Horse-42") == .mustChange
            : created?.attribute("unicodePwd") != nil
        try expect("it was created enabled, with its password, which must be changed",
                   storedPassword && created?.int("pwdLastSet") == 0 && (created?.int("userAccountControl") ?? 2) & 2 == 0)

        // Reset its password with a generated one.
        try await Automation.waitFor("new user selected") { session.inspector.entry.map { DN.isSame($0.dn, tester) } == true }
        try await D.choose(["Entry", "Reset Password…"]) { if let entry = session.inspector.entry { session.sheet = .password(entry) } }
        let password = try await waitForSheet("reset password")
        try expect("Reset waits for a password", D.defaultButton(in: password)?.enabled == false)
        try D.click(try D.button("Generate a Strong Password", in: password), "Generate a Strong Password")
        try await Automation.settle(0.4)
        // Generate shows the password, so it is in a plain field now: 20 characters.
        let generated = (D.textFields(in: password) + D.secureFields(in: password)).map(\.stringValue).first { $0.count == 20 } ?? ""
        try sheetShot("09-password-generated")
        await D.pressReturn(in: password)
        try await waitForNoSheet("reset password")
        let after = try await read(session, tester)
        if server.isActiveDirectory {
            // AD accepts the previous password for another hour, so the proof is
            // the generated one, which never existed before, working.
            let new = try await signIn(session, tester, generated)
            try expect("the password was replaced: the generated one works", !generated.isEmpty && new == .mustChange)
        } else {
            try expect("the password was replaced", after?.values("unicodePwd").first != created?.values("unicodePwd").first)
        }

        // Disable and enable it with the Account panel's checkbox.
        session.inspector.tab = .overview
        try await Automation.settle(1.2)
        var enabled = try Automation.require(D.checkboxes(in: window).first { $0.title == "Account enabled" })
        try expect("Account enabled is ticked", enabled.isOn)
        try D.click(enabled, "Account enabled")
        try await Automation.waitFor("disabled") { (session.inspector.entry?.int("userAccountControl") ?? 0) & 2 != 0 }
        let disabledEntry = try await read(session, tester)
        try expect("unticking it disabled the account", (disabledEntry?.int("userAccountControl") ?? 0) & 2 != 0)
        try await Automation.settle(0.8)
        try shot("10-account-disabled")
        enabled = try Automation.require(D.checkboxes(in: window).first { $0.title == "Account enabled" })
        try expect("the checkbox shows the account disabled", !enabled.isOn)
        try D.click(enabled, "Account enabled")
        try await Automation.waitFor("enabled") { (session.inspector.entry?.int("userAccountControl") ?? 2) & 2 == 0 }

        // Requiring a smart card costs the account its password in AD, so it asks first.
        try await Automation.settle(0.8)
        let uacBefore = try await read(session, tester)?.int("userAccountControl")
        let smartCard = try Automation.require(D.checkboxes(in: window).first { $0.title.hasPrefix("Smart card is required") })
        try D.click(smartCard, "Smart card is required")
        let question = try await waitForSheet("smart card question")
        let words = D.views(in: question).compactMap { ($0 as? NSTextField)?.stringValue }.joined(separator: " ")
        try sheetShot("10b-smart-card-question")
        await D.pressEscape(in: question)
        try await waitForNoSheet("smart card question")
        let uacAfter = try await read(session, tester)?.int("userAccountControl")
        try expect("ticking \"Smart card is required\" first asks, saying the password will be replaced; Cancel changes nothing",
                   words.contains("replaces the account's password") && uacBefore == uacAfter && (uacAfter ?? 0) & 0x40000 == 0)

        // Delete it.
        try await D.choose(["Entry", "Delete…"]) { if let dn = session.selectedDN { session.sheet = .delete(dn: dn) } }
        let delete = try await waitForSheet("delete")
        try await Automation.waitFor("counted") { D.defaultButton(in: delete)?.enabled == true }
        await D.pressReturn(in: delete)
        try await waitForNoSheet("delete")
        let gone = try await read(session, tester)
        try expect("the user is gone", gone == nil)

        // Import the sample LDIF (handed to the sheet as a dropped file would
        // be: the open panel runs in another process).
        var sample = Automation.repository.appendingPathComponent("TestDirectory/sample-import.ldif")
        // In the App Store sandbox the app reads only files the person chose and
        // its own container, so scripts/automation-sandboxed.sh hands the sample
        // over in the environment, and it goes into the container first.
        if let text = ProcessInfo.processInfo.environment["FORESTER_SAMPLE_LDIF"] {
            sample = FileManager.default.temporaryDirectory.appendingPathComponent("sample-import.ldif")
            try text.write(to: sample, atomically: true, encoding: .utf8)
        }
        session.sheet = .importLDIF(sample)
        let importer = try await waitForSheet("import")
        await D.pressReturn(in: importer)
        try await Automation.waitFor("import done", timeout: 30) { (try? D.button("Close", in: importer)) != nil }
        try await Automation.settle(0.8)
        try sheetShot("11-import-done")
        let imported = "OU=Imported,OU=Corp,\(base)"
        let importedOU = try await read(session, imported)
        let hopper = try await read(session, "CN=Grace Hopper Import,\(imported)")
        let legacy = try await read(session, "CN=GG-Empty-Legacy,OU=Groups,OU=Corp,\(base)")
        try expect("the import added, renamed and deleted as the file says", importedOU != nil && hopper != nil && legacy == nil)
        await D.pressEscape(in: importer)
        try await waitForNoSheet("import")

        // Delete the imported OU, typing its name to confirm.
        await session.tree.reveal(imported)
        session.open(imported)
        try await Automation.waitFor("Imported selected") { session.inspector.entry.map { DN.isSame($0.dn, imported) } == true }
        try await D.choose(["Entry", "Delete…"]) { if let dn = session.selectedDN { session.sheet = .delete(dn: dn) } }
        let deleteAll = try await waitForSheet("delete subtree")
        try await Automation.waitFor("count") { (try? D.field(prompt: "Type Imported to confirm", in: deleteAll)) != nil }
        try expect("Delete All waits for the name", D.defaultButton(in: deleteAll)?.enabled == false)
        try await D.type("Imported", into: try D.field(prompt: "Type Imported to confirm", in: deleteAll), "confirmation")
        try sheetShot("12-delete-confirmed")
        await D.pressReturn(in: deleteAll)
        try await waitForNoSheet("delete subtree", timeout: 30)
        let importedGone = try await read(session, imported)
        try expect("the imported OU and everything in it are gone", importedGone == nil)

        // Search: completion of attribute names, then a typed filter.
        try await D.choose(["Directory", "Search"]) { session.mode = .search }
        try await Automation.settle(0.8)
        let filter = try Automation.require(D.textView(in: window))
        let front = await D.bringForward(window)
        log("before typing the filter: app active \(front), key window is main \(NSApp.keyWindow === window)")
        try await D.type("(sAMAccountNa", into: filter, "the filter")
        try await Automation.settle(0.8)
        let stillFront = NSApp.isActive && NSApp.keyWindow === window && filter.string == "(sAMAccountNa"
        let completing = NSApp.windows.contains { $0.isVisible && $0 !== window && $0.attachedSheet == nil && $0.frame.width < 600 }
        log(completing ? "completion list shown" : "completion list not shown: \(NSApp.windows.filter(\.isVisible).map(\.className))")
        if completing { try shot("13-completion") }
        if front && stillFront {
            try expect("typing an attribute name offers completions", completing)
        } else {
            log("completion not checked: macOS put another app in front while typing (app in front: \(NSApp.isActive)), and completion follows real key events")
        }
        await D.pressEscape(in: window)
        try await D.type("(sAMAccountName=pvandamme)", into: filter, "the filter")
        await D.pressReturn(in: window)
        try await Automation.waitFor("search ran") { !session.search.running && session.search.hasRun }
        try await Automation.settle(0.8)
        try shot("14-search-typed")
        try expect("the typed filter found Pieter", session.search.rows.map(\.id).contains { DN.isSame($0, pieter) })

        // Read-only again from the Entry menu.
        let title = D.menuTitle(startingWith: "Make Connection Read-Only", in: "Entry") ?? "Make Connection Read-Only"
        try await D.choose(["Entry", title]) { session.setReadOnly(true) }
        try await Automation.waitFor("read-only again") { !session.canWrite }
        try expect("the menu made the connection read-only", session.profile.readOnly)
        if !D.menusSkipped.isEmpty {
            log("note: the app was in the background for \(D.menusSkipped.count) menu command(s), done directly: \(D.menusSkipped.joined(separator: "; "))")
        }
        session.disconnect()
    }

    static func read(_ session: DirectorySession, _ dn: String) async throws -> LDAPEntry? {
        try await session.run { try await $0.read(dn, attributes: ["*"]) }
    }

    enum SignIn: Equatable { case success, mustChange, wrongPassword, disabled, lockedOut, other(String) }

    /// Signs in as `dn` on a connection of its own, the way a person would, and
    /// says how AD answered (its "data 773" and the like, as Forester words them).
    static func signIn(_ session: DirectorySession, _ dn: String, _ password: String) async throws -> SignIn {
        let connection = LDAPConnection(session.profile.options)
        defer { Task { await connection.close() } }
        try await connection.open()
        do {
            try await connection.bind(dn: dn, password: password)
            return .success
        } catch {
            let message = error.localizedDescription
            if message.contains("must be changed") { return .mustChange }
            if message.contains("name or password is wrong") { return .wrongPassword }
            if message.contains("is disabled") { return .disabled }
            if message.contains("locked out") { return .lockedOut }
            return .other(message)
        }
    }
}
#endif
