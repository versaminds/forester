// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import AppKit
import LDAPKit
import SwiftUI

@main
struct ForesterApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup("Forester", id: "main") {
            ContentView()
                .environment(model)
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                    model.store.reloadIfChanged()
                }
        }
        .defaultSize(width: 1320, height: 820)
        .commands { AppCommands(model: model) }

        WindowGroup("Tool", for: ToolWindowID.self) { $id in
            if let id {
                ToolWindowContent(id: id).environment(model)
            }
        }
        .defaultSize(width: 980, height: 720)

        Settings {
            SettingsView().environment(model)
        }
    }
}

/// App preferences: where connections are kept, and update checks.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var checksAutomatically = false

    var body: some View {
        Form {
            Section {
                if !ForesterInfo.fromAppStore {
                    Toggle("Keep connections in iCloud Drive", isOn: Binding(
                        get: { model.store.inICloudDrive }, set: { model.store.setICloudDrive($0) }))
                        .formSwitch("Keep connections in iCloud Drive")
                        .disabled(ProfileStore.iCloudDriveRoot == nil)
                    Text(ProfileStore.iCloudDriveRoot == nil
                         ? "iCloud Drive is off on this Mac. Turn it on in System Settings › Apple Account › iCloud."
                         : "Your connections appear on every Mac that keeps them in iCloud Drive. Passwords stay in each Mac's keychain; they are not synced.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                LabeledContent("Stored in") {
                    Button(model.store.url.deletingLastPathComponent().path.replacingOccurrences(of: NSHomeDirectory(), with: "~")) {
                        NSWorkspace.shared.activateFileViewerSelecting([model.store.url])
                    }
                    .buttonStyle(.link)
                }
            } header: {
                Text("Connections")
            }
            #if !APP_STORE
            if Updates.isAvailable {
                Section {
                    Toggle("Check for updates automatically", isOn: $checksAutomatically)
                        .formSwitch("Check for updates automatically")
                        .onChange(of: checksAutomatically) { _, on in Updates.checksAutomatically = on }
                    Text("Forester reads the list of releases on forester.versaminds.live once a day and offers a new version when there is one. Every update is checked against VersaMinds' signature before it is installed. Nothing about you or your directories is sent. Off, it only checks when you choose Forester › Check for Updates.")
                        .font(.caption).foregroundStyle(.secondary)
                } header: {
                    Text("Updates")
                }
            }
            #endif
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .padding(.vertical, 10)
        #if !APP_STORE
        .onAppear { checksAutomatically = Updates.checksAutomatically }
        #endif
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Launched as a bare executable (swift run) there is no bundle to make
        // it a regular app; a built .app does not need this.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        #if DEBUG
        if ProcessInfo.processInfo.environment["FORESTER_AUTOMATION"] != nil { return }
        #endif
        #if !APP_STORE
        Updates.start()
        #endif
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

/// Saved profiles and the sessions opened from them, shared by all windows.
@MainActor @Observable
final class AppModel {
    #if DEBUG
    let store = ProfileStore(directory: Automation.profileDirectory)
    #else
    let store = ProfileStore()
    #endif
    /// Set to move a window's sidebar selection from outside the view
    /// (opening another domain of the forest, automation). Every setting is a
    /// new request, so asking again for the connection asked for last time
    /// moves the selection back to it when the person has since chosen another.
    var requestedSelection: UUID? {
        get { selectionRequest?.id }
        set { selectionRequest = newValue.map { SelectionRequest(id: $0) } }
    }
    private(set) var selectionRequest: SelectionRequest?

    struct SelectionRequest: Equatable {
        let id: UUID
        let token = UUID()
    }
    /// Not observed: sessions are created lazily from view bodies, and each
    /// session is itself observable, which is what views care about.
    @ObservationIgnored private(set) var sessions: [UUID: DirectorySession] = [:]

    init() {
        store.onReload = { [weak self] in self?.syncSessions() }
    }

    func existingSession(_ id: UUID) -> DirectorySession? { sessions[id] }

    func session(for id: UUID?) -> DirectorySession? {
        guard let id, let profile = store.profile(id) else { return nil }
        if let existing = sessions[id] { return existing }
        let session = DirectorySession(profile: profile)
        // Only what the session itself changes is written back; the rest of
        // the profile stays as saved, even if it changed on disk meanwhile.
        session.onReadOnlyChange = { [weak self, weak session] readOnly in
            guard let self else { return }
            self.store.update(id) { $0.readOnly = readOnly }
            if let current = self.store.profile(id), current != session?.profile { session?.update(current) }
        }
        session.onPinCertificate = { [weak self, weak session] fingerprint, host, port in
            guard let self else { return }
            self.store.update(id) {
                guard $0.options.host == host, $0.options.port == port, !$0.trust.pinnedFingerprints.contains(fingerprint) else { return }
                $0.trust.pinnedFingerprints.append(fingerprint)
            }
            if let current = self.store.profile(id), current != session?.profile { session?.update(current) }
        }
        sessions[id] = session
        return session
    }

    /// Open sessions take profiles changed on disk (another Mac, an import);
    /// a session whose profile is gone is closed.
    private func syncSessions() {
        for (id, session) in sessions {
            if let profile = store.profile(id) {
                if profile != session.profile { session.update(profile) }
            } else {
                session.disconnect()
                sessions[id] = nil
            }
        }
    }

    /// Opens another domain of the forest: the saved connection to it with the
    /// same user if there is one, otherwise a new one (read-only, trusting no
    /// certificate beyond this Mac's). Only a domain the forest itself lists
    /// is opened, and the password typed for this connection is lent to it
    /// only over an encrypted connection.
    func openDomain(_ dnsName: String, from session: DirectorySession, select dn: String? = nil) async {
        let host = dnsName.lowercased()
        let domains = await session.forestDomains()
        // A name from directory data is opened only when the forest lists it.
        guard let listed = domains.first(where: { $0.dnsName.lowercased() == host }) else {
            session.report("\(dnsName) is not a domain of this forest, so Forester does not connect to it from here.", isError: true)
            return
        }
        var profile: ConnectionProfile
        if let existing = store.profiles.first(where: {
            $0.host.lowercased() == host && $0.bindName.caseInsensitiveCompare(session.profile.bindName) == .orderedSame
        }) {
            profile = existing
        } else {
            profile = ConnectionProfile()
            profile.name = dnsName
            profile.host = dnsName
            profile.port = session.profile.port
            profile.security = session.profile.security
            profile.authentication = session.profile.authentication
            profile.bindName = session.profile.bindName
            profile.savePassword = session.profile.savePassword
            profile.pageSize = session.profile.pageSize
            profile.timeoutSeconds = session.profile.timeoutSeconds
            profile.baseDN = listed.dn
            store.save(profile)
        }
        guard let other = self.session(for: profile.id) else { return }
        session.lendPassword(to: other)
        requestedSelection = profile.id
        if !other.phase.isConnected { other.connect() }
        if let dn {
            for _ in 0..<100 where !other.phase.isConnected { try? await Task.sleep(nanoseconds: 100_000_000) }
            if other.phase.isConnected { other.open(dn); await other.tree.reveal(dn) }
        }
    }

    func save(_ profile: ConnectionProfile, password: String?) {
        store.save(profile)
        if profile.authentication == .simple, let password, !password.isEmpty {
            if profile.savePassword { Keychain.setPassword(password, for: profile) }
        }
        if !profile.savePassword || profile.authentication != .simple {
            Keychain.deletePassword(for: profile.id)
        }
        if let session = sessions[profile.id] {
            session.update(profile)
            if let password, !password.isEmpty { session.usePassword(password) }
        } else if profile.authentication == .simple, let password, !password.isEmpty, !profile.savePassword {
            // A password typed into a new connection is used until the app
            // quits even when it is not remembered, rather than asked again.
            session(for: profile.id)?.usePassword(password)
        }
    }

    func delete(_ id: UUID) {
        sessions[id]?.disconnect()
        sessions[id] = nil
        store.delete(id)
    }
}

// MARK: Menu commands

struct FocusedSessionKey: FocusedValueKey {
    typealias Value = DirectorySession
}

struct NewConnectionActionKey: FocusedValueKey {
    typealias Value = () -> Void
}

struct GoToDNActionKey: FocusedValueKey {
    typealias Value = () -> Void
}

extension FocusedValues {
    var session: DirectorySession? {
        get { self[FocusedSessionKey.self] }
        set { self[FocusedSessionKey.self] = newValue }
    }

    var newConnection: (() -> Void)? {
        get { self[NewConnectionActionKey.self] }
        set { self[NewConnectionActionKey.self] = newValue }
    }

    var goToDN: (() -> Void)? {
        get { self[GoToDNActionKey.self] }
        set { self[GoToDNActionKey.self] = newValue }
    }
}

struct AppCommands: Commands {
    let model: AppModel
    @FocusedValue(\.session) private var session
    @FocusedValue(\.newConnection) private var newConnection
    @FocusedValue(\.goToDN) private var goToDN
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(replacing: .appInfo) {
            Button("About Forester") { ForesterInfo.showAboutPanel() }
            #if !APP_STORE
            if Updates.isAvailable {
                Button("Check for Updates…") { Updates.checkNow() }
            }
            #endif
        }

        CommandGroup(replacing: .help) {
            Button("Forester Website") { NSWorkspace.shared.open(ForesterInfo.website) }
            Button("Copy Diagnostics") { Diagnostics.copy(model, session: session) }
            Button("VersaMinds Website") { NSWorkspace.shared.open(ForesterInfo.companyWebsite) }
            Divider()
            Button("License") { NSWorkspace.shared.open(ForesterInfo.licenseURL) }
        }

        CommandGroup(replacing: .newItem) {
            Button("New Connection…") { newConnection?() }
                .keyboardShortcut("n")
                .disabled(newConnection == nil)
            Button("New Window") { openWindow(id: "main") }
                .keyboardShortcut("n", modifiers: [.command, .shift])
        }

        CommandMenu("Directory") {
            if let session, session.phase.isConnected {
                Button("Disconnect") { session.disconnect() }
            } else {
                Button("Connect") { session?.connect() }
                    .keyboardShortcut("k")
                    .disabled(session == nil)
            }
            Divider()
            Button("Browse") { session?.mode = .browse }
                .keyboardShortcut("1")
                .disabled(session?.phase.isConnected != true)
            Button("Search") { session?.mode = .search }
                .keyboardShortcut("2")
                .disabled(session?.phase.isConnected != true)
            Divider()
            Button("Refresh Entry") { session?.inspector.reload() }
                .keyboardShortcut("r")
                .disabled(session?.selectedDN == nil)
            Button("Go to DN…") { goToDN?() }
                .keyboardShortcut("g", modifiers: [.command, .shift])
                .disabled(goToDN == nil || session?.phase.isConnected != true)
            Button("Show in Tree") { if let dn = session?.selectedDN { session?.reveal(dn) } }
                .keyboardShortcut("l")
                .disabled(session?.selectedDN == nil)
            Button("Copy DN") {
                if let dn = session?.selectedDN { Pasteboard.copy(dn) }
            }
            .keyboardShortcut("c", modifiers: [.command, .shift])
            .disabled(session?.selectedDN == nil)
        }

        CommandMenu("Entry") {
            let entry = session?.inspector.entry
            let dn = session?.selectedDN ?? ""
            let canChange = entry != nil && session?.canChangeEntry(dn) == true
            Button(session?.profile.readOnly == false ? "Make Connection Read-Only" : "Allow Changes to This Directory") {
                if let session { session.setReadOnly(!session.profile.readOnly) }
            }
            .keyboardShortcut("e", modifiers: [.command, .option])
            .disabled(session?.phase.isConnected != true)
            Divider()
            Button("New Entry…") { if let parent = session?.newEntryParent { session?.sheet = .newEntry(parent: parent) } }
                .keyboardShortcut("n", modifiers: [.command, .control])
                .disabled(session?.canWrite != true)
            Button("Duplicate…") { if let entry { session?.sheet = .duplicate(entry) } }
                .keyboardShortcut("d")
                .disabled(!canChange)
            Button("Rename…") { session?.sheet = .renameMove(dn: dn, move: false) }
                .keyboardShortcut("r", modifiers: [.command, .shift])
                .disabled(!canChange)
            Button("Move…") { session?.sheet = .renameMove(dn: dn, move: true) }
                .keyboardShortcut("m", modifiers: [.command, .shift])
                .disabled(!canChange)
            Button("Delete…") { session?.sheet = .delete(dn: dn) }
                .disabled(!canChange)
            Button("Change History…") { session?.sheet = .history }
                .disabled(session?.phase.isConnected != true)
            Divider()
            if let session, let entry, let method = AccountLockMethod.method(for: entry, session: session) {
                let disabled = method.isDisabled(entry)
                Button(disabled ? "Enable Account" : "Disable Account") {
                    Task { await AccountActions.setEnabled(disabled, entry, session: session) }
                }
                .keyboardShortcut("e", modifiers: [.command, .shift])
                .disabled(!session.canWrite)
                Button("Reset Password…") { session.sheet = .password(entry) }
                    .keyboardShortcut("p", modifiers: [.command, .shift])
                    .disabled(!session.canWrite)
                Button("Unlock Account") { Task { await AccountActions.unlock(entry, session: session) } }
                    .disabled(!session.canWrite || !AccountActions.isLocked(entry))
                if session.hasADTools {
                    Button("Account Status on Each DC…") { session.sheet = .accountStatus(entry) }
                }
            } else {
                Button("Enable or Disable Account") {}.disabled(true)
                Button("Reset Password…") {}.disabled(true)
            }
        }

        CommandMenu("Tools") {
            let connected = session?.phase.isConnected == true
            Button("Domain Information") {
                if let session { openWindow(value: ToolWindowID(profile: session.id, tool: .domainInfo)) }
            }
            .keyboardShortcut("i", modifiers: [.command, .shift])
            .disabled(!connected || session?.hasADTools != true)
            Button("Server Monitor") {
                if let session { openWindow(value: ToolWindowID(profile: session.id, tool: .serverMonitor)) }
            }
            .keyboardShortcut("m", modifiers: [.command, .control])
            .disabled(!connected)
            Button("Schema") {
                if let session { openWindow(value: ToolWindowID(profile: session.id, tool: .schema)) }
            }
            .keyboardShortcut("s", modifiers: [.command, .option])
            .disabled(!connected)
            Divider()
            Button("Import LDIF…") { session?.sheet = .importLDIF(nil) }
                .keyboardShortcut("o", modifiers: [.command, .shift])
                .disabled(session?.canWrite != true)
            Button("Export Subtree as LDIF…") { if let dn = session?.selectedDN { session?.exportLDIF(dn, scope: .subtree) } }
                .disabled(session?.selectedDN == nil)
            Divider()
            Button(session?.tree.containersOnly == true ? "Show All Entries in Tree" : "Show Only Containers in Tree") {
                if let tree = session?.tree { tree.setContainersOnly(!tree.containersOnly) }
            }
            .disabled(!connected)
        }

        CommandGroup(before: .toolbar) {
            Button("Back") { session?.goBack() }
                .keyboardShortcut("[")
                .disabled(session?.canGoBack != true)
            Button("Forward") { session?.goForward() }
                .keyboardShortcut("]")
                .disabled(session?.canGoForward != true)
            Divider()
        }
    }
}

enum Pasteboard {
    static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    static func copy(image data: Data) {
        guard let image = NSImage(data: data) else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.writeObjects([image])
    }
}
