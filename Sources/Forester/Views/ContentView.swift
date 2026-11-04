// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

struct ContentView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.undoManager) private var undoManager
    @SceneStorage("selectedProfile") private var storedSelection = ""
    @State private var selection: UUID?
    @State private var editing: ConnectionProfile?
    @State private var showingGoTo = false
    @State private var columnVisibility = NavigationSplitViewVisibility.all
    @State private var middleWidth: CGFloat = 440

    private var session: DirectorySession? { model.session(for: selection) }
    private var sidebarShown: Bool { columnVisibility != .doubleColumn && columnVisibility != .detailOnly }
    private var titleRoom: CGFloat { ToolbarFit.titleRoom(column: middleWidth, sidebarShown: sidebarShown) }
    private var title: String { ToolbarFit.title(session?.profile.displayName ?? "Forester", room: titleRoom) }
    private var subtitle: String {
        ToolbarFit.subtitle(session?.phase.isConnected == true ? (session?.server?.kind.label ?? "") : "", room: titleRoom)
    }

    var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            SidebarView(selection: $selection, editing: $editing)
                .navigationSplitViewColumnWidth(min: 190, ideal: 230, max: 340)
        } content: {
            Group {
                if let session {
                    BrowserColumn(session: session, editing: $editing)
                } else {
                    NoConnectionView(hasProfiles: !model.store.profiles.isEmpty) { editing = ConnectionProfile() }
                }
            }
            .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { middleWidth = $0 }
            // Inside the width: outside it, it hid the column's width from
            // the split view, which fell back to a 200-point minimum.
            .navigationSplitViewColumnWidth(min: ToolbarFit.contentMinimum(sidebarShown: sidebarShown), ideal: 440, max: 900)
            .overlay(alignment: .top) { Divider() }
        } detail: {
            Group {
                if let session, session.phase.isConnected {
                    InspectorView(session: session)
                } else {
                    ContentUnavailableView("No Entry Selected", systemImage: "sidebar.right",
                                           description: Text("Connect to a directory and choose an entry."))
                        // The whole column, so the line below puts itself under the toolbar.
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .navigationSplitViewColumnWidth(min: ToolbarFit.detailMinimum, ideal: 720)
            .overlay(alignment: .top) { Divider() }
        }
        // AppKit draws the middle column's toolbar background 3 points wider than
        // the column, over the sidebar's edge, so it never lined up with the
        // divider below it. Without it the toolbar shows each column's own
        // background, and the line under the toolbar is drawn inside each
        // column (above), so both meet the column edges exactly.
        .toolbarBackground(.hidden, for: .windowToolbar)
        .navigationTitle(title)
        .navigationSubtitle(subtitle)
        .sheet(item: $editing) { profile in
            ProfileEditor(profile: profile) { saved, password in
                model.save(saved, password: password)
                selection = saved.id
            }
        }
        .sheet(isPresented: $showingGoTo) {
            if let session { GoToDNSheet(session: session) }
        }
        .modifier(EntrySheetHost(session: session))
        .focusedSceneValue(\.session, session)
        .focusedSceneValue(\.newConnection, { editing = ConnectionProfile() })
        .focusedSceneValue(\.goToDN, { showingGoTo = true })
        .onAppear {
            if selection == nil, let id = UUID(uuidString: storedSelection), model.store.profile(id) != nil {
                selection = id
            } else if selection == nil {
                selection = model.store.profiles.first?.id
            }
        }
        .onChange(of: selection) { old, new in
            storedSelection = new?.uuidString ?? ""
            // The window has one Undo for whichever directory it shows: a
            // directory left behind takes its changes off it, so Edit › Undo
            // never reverses a change in a directory that is not on screen.
            // They stay in its Change History, which names the directory.
            if let old, old != new, let left = model.session(for: old) {
                undoManager?.removeAllActions(withTarget: left)
                left.undoManager = nil
            }
        }
        .onChange(of: model.selectionRequest) { _, new in if let new { selection = new.id } }
        #if DEBUG
        .task { ContentView.startAutomationOnce(model) }
        #endif
    }
}

#if DEBUG
extension ContentView {
    @MainActor private static var automationStarted = false

    @MainActor static func startAutomationOnce(_ model: AppModel) {
        guard !automationStarted else { return }
        automationStarted = true
        Automation.runIfRequested(model)
    }
}
#endif

struct NoConnectionView: View {
    let hasProfiles: Bool
    let add: () -> Void

    var body: some View {
        ContentUnavailableView {
            Label(hasProfiles ? "Choose a Connection" : "No Connections", systemImage: "server.rack")
        } description: {
            Text(hasProfiles ? "Pick a server in the sidebar." : "Add an LDAP server or Active Directory domain controller to start browsing.")
        } actions: {
            Button("New Connection…", action: add)
                .buttonStyle(.borderedProminent)
        }
    }
}

/// The middle column: connect screen until connected, then the tree or search.
struct BrowserColumn: View {
    @Environment(AppModel.self) private var model
    @Environment(\.undoManager) private var undoManager
    @Bindable var session: DirectorySession
    @Binding var editing: ConnectionProfile?
    @State private var quickFind = ""
    @State private var showingServerInfo = false

    var body: some View {
        Group {
            if session.phase.isConnected {
                VStack(spacing: 0) {
                    switch session.mode {
                    case .browse: TreeView(session: session, tree: session.tree)
                    case .search: SearchView(session: session, search: session.search)
                    }
                    StatusBar(session: session)
                }
                .searchable(text: $quickFind, placement: .toolbar, prompt: session.isMicrosoft ? "Find (name, account, mail…)" : "Find by name")
                .onSubmit(of: .search) { session.search.quickFind(quickFind) }
                .toolbar {
                    // In this column's part of the toolbar, not centred over the
                    // window: it switches what this column shows.
                    ToolbarItem {
                        Picker("Mode", selection: $session.mode) {
                            ForEach(DirectorySession.Mode.allCases, id: \.self) { mode in
                                Text(mode.label).tag(mode)
                            }
                        }
                        .pickerStyle(.segmented)
                        .help("Browse the tree (⌘1) or search with a filter (⌘2)")
                    }
                    ToolbarItem {
                        Button { showingServerInfo = true } label: { Label("Server Info", systemImage: "info.circle") }
                            .help("What the server reports about itself")
                    }
                }
                .sheet(isPresented: $showingServerInfo) { ServerInfoView(session: session) }
                .task(id: session.id) { session.undoManager = undoManager }
            } else {
                ConnectView(session: session) { editing = model.store.profile(session.profile.id) ?? session.profile }
            }
        }
        .sheet(item: $session.passwordRequest) { request in
            PasswordPrompt(session: session, message: request.message)
        }
        .sheet(item: Binding(get: { session.pendingTrustFailure.map(TrustFailureItem.init) },
                             set: { if $0 == nil { session.pendingTrustFailure = nil } })) { item in
            CertificateTrustSheet(failure: item.failure, host: session.profile.host,
                                  trust: { session.trustPendingCertificate() },
                                  trustOnce: { session.trustPendingCertificate(once: true) },
                                  cancel: { session.pendingTrustFailure = nil })
        }
    }
}

struct TrustFailureItem: Identifiable {
    let failure: CertificateTrustFailure
    var id: String { failure.sha256Fingerprint }
}

struct StatusBar: View {
    let session: DirectorySession
    private var unchecked: Bool { session.profile.trust.trustAnyCertificate }

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: session.isSecure ? "lock.fill" : "lock.open")
                .foregroundStyle(session.isSecure && !unchecked ? Color.green : Color.orange)
                .help(session.isSecure ? (unchecked ? "The connection is encrypted, but the server's certificate is not checked: anyone on the network path could be in between."
                                                    : "The connection is encrypted with TLS.") : "The connection is not encrypted.")
            // Shortened from the end: the server, host and encryption come
            // first and stay readable, and the whole line is in the tooltip.
            Text(session.statusLine)
                .lineLimit(1)
                .truncationMode(.tail)
                .help(session.statusLine)
            Spacer()
            if !session.history.isEmpty {
                Button {
                    session.sheet = .history
                } label: {
                    Label("\(session.history.count) change\(session.history.count == 1 ? "" : "s")", systemImage: "clock.arrow.circlepath")
                }
                .buttonStyle(.borderless)
                .help("Changes made in this window, and undoing them")
            }
            Label(session.profile.readOnly ? "Read-only" : "Editing",
                  systemImage: session.profile.readOnly ? "lock" : "pencil")
                .foregroundStyle(session.profile.readOnly ? Color.secondary : Color.orange)
                .help(session.profile.readOnly ? "No changes are sent to this directory." : "Changes are sent to this directory.")
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(.bar)
        .overlay(alignment: .top) { Divider() }
    }
}

/// Shown for a profile that is not connected: what it points at, and Connect.
struct ConnectView: View {
    let session: DirectorySession
    let edit: () -> Void

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "server.rack")
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(.secondary)
            VStack(spacing: 4) {
                Text(session.profile.displayName).font(.title2.weight(.semibold))
                Text(session.profile.endpoint).font(.callout.monospaced()).foregroundStyle(.secondary)
                    .textSelection(.enabled)
                Text(session.profile.authentication == .simple ? session.profile.bindName : session.profile.authentication.label)
                    .font(.callout).foregroundStyle(.secondary)
            }
            if case .failed(let message) = session.phase {
                Label {
                    Text(message).textSelection(.enabled)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
                .font(.callout)
                .frame(maxWidth: 380)
                .padding(10)
                .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
            }
            if session.profile.security == .none || session.profile.trust.trustAnyCertificate {
                Text(session.profile.security == .none
                     ? "This connection is not encrypted; the password and everything read travel in clear text."
                     : "This connection accepts any certificate, so it cannot tell the real server from someone in between.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 360)
            }
            HStack {
                Button("Edit…", action: edit)
                Button {
                    session.connect()
                } label: {
                    if session.phase == .connecting {
                        ProgressView().controlSize(.small).frame(width: 60)
                    } else {
                        Text("Connect").frame(width: 60)
                    }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(session.phase == .connecting || session.profile.host.isEmpty)
            }
        }
        .padding(30)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct PasswordPrompt: View {
    let session: DirectorySession
    let message: String?
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Password for \(session.profile.displayName)").font(.headline)
            Text(session.profile.bindName).font(.callout.monospaced()).foregroundStyle(.secondary)
            if let message {
                Text(message).font(.callout).foregroundStyle(.red)
            }
            SecureField("Password", text: $password)
                .textFieldStyle(.roundedBorder)
                .onSubmit(submit)
            Text(session.profile.savePassword ? "The password will be saved in your keychain." : "The password is kept only until you quit.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Connect", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(password.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 380)
    }

    private func submit() {
        guard !password.isEmpty else { return }
        dismiss()
        session.connect(password: password)
    }
}

struct GoToDNSheet: View {
    let session: DirectorySession
    @Environment(\.dismiss) private var dismiss
    @State private var dn = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Go to DN").font(.headline)
            TextField("CN=Jane Doe,OU=Users,DC=corp,DC=example", text: $dn)
                .textFieldStyle(.roundedBorder)
                .font(.body.monospaced())
                .onSubmit(go)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Go", action: go).keyboardShortcut(.defaultAction).disabled(dn.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 520)
        .onAppear { dn = session.selectedDN ?? "" }
    }

    private func go() {
        let target = dn.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty else { return }
        dismiss()
        session.open(target)
        session.reveal(target)
    }
}
