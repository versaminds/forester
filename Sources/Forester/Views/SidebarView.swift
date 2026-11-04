// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import AppKit
import LDAPKit
import SwiftUI

struct SidebarView: View {
    @Environment(AppModel.self) private var model
    @Binding var selection: UUID?
    @Binding var editing: ConnectionProfile?
    @State private var confirmingDelete: ConnectionProfile?

    var body: some View {
        List(selection: $selection) {
            Section("Connections") {
                ForEach(model.store.profiles) { profile in
                    ProfileRow(profile: profile, session: model.existingSession(profile.id))
                        .tag(profile.id)
                }
                .onMove { model.store.move(from: $0, to: $1) }
            }
        }
        .listStyle(.sidebar)
        .contextMenu(forSelectionType: UUID.self) { ids in
            if let id = ids.first, let profile = model.store.profile(id) {
                let session = model.existingSession(id)
                if session?.phase.isConnected == true {
                    Button("Disconnect") { session?.disconnect() }
                } else {
                    Button("Connect") { selection = id; model.session(for: id)?.connect() }
                }
                Divider()
                Button("Edit…") { editing = profile }
                Button("Duplicate") { selection = model.store.duplicate(id)?.id }
                Button("Copy URL") { Pasteboard.copy(profile.endpoint) }
                Divider()
                Button("Delete…", role: .destructive) { confirmingDelete = profile }
            }
        } primaryAction: { ids in
            guard let id = ids.first, let session = model.session(for: id) else { return }
            if !session.phase.isConnected { session.connect() }
        }
        .safeAreaInset(edge: .bottom) {
            HStack(spacing: 2) {
                Button { editing = ConnectionProfile() } label: { Image(systemName: "plus").frame(width: 22, height: 22) }
                    .help("New connection")
                Button {
                    if let profile = model.store.profile(selection) { confirmingDelete = profile }
                } label: { Image(systemName: "minus").frame(width: 22, height: 22) }
                    .help("Delete the selected connection")
                    .disabled(selection == nil)
                Spacer()
                Menu {
                    Button("Import Connections…") { importConnections() }
                    Button("Export Selected Connection…") {
                        if let profile = model.store.profile(selection) { exportConnections([profile]) }
                    }
                    .disabled(selection == nil)
                    Button("Export All Connections…") { exportConnections(model.store.profiles) }
                        .disabled(model.store.profiles.isEmpty)
                    Divider()
                    SettingsLink { Text("Keep Connections in iCloud Drive…") }
                } label: { Image(systemName: "ellipsis.circle").frame(width: 22, height: 22) }
                    .menuIndicator(.hidden)
                    .fixedSize()
                    .help("Import, export and sync connections")
                Button {
                    if let profile = model.store.profile(selection) { editing = profile }
                } label: { Image(systemName: "slider.horizontal.3").frame(width: 22, height: 22) }
                    .help("Edit the selected connection")
                    .disabled(selection == nil)
            }
            .buttonStyle(.borderless)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
        }
        .overlay {
            if let error = model.store.loadError {
                Text(error).font(.caption).foregroundStyle(.red).padding()
            }
        }
        .confirmationDialog("Delete “\(confirmingDelete?.displayName ?? "")”?", isPresented: Binding(
            get: { confirmingDelete != nil }, set: { if !$0 { confirmingDelete = nil } }), presenting: confirmingDelete
        ) { profile in
            Button("Delete", role: .destructive) {
                if selection == profile.id { selection = nil }
                model.delete(profile.id)
            }
        } message: { _ in
            Text("The saved password is removed from the keychain too.")
        }
    }
}

extension SidebarView {
    func exportConnections(_ profiles: [ConnectionProfile]) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = profiles.count == 1 ? "\(profiles[0].displayName).forester" : "Forester Connections.forester"
        panel.message = "Passwords are not included."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try model.store.export(profiles, to: url) } catch { NSAlert(error: error).runModal() }
    }

    func importConnections() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.message = "Choose connection files exported from Forester (.forester), or from LDAP Explorer before it was renamed (.ldapconnections)."
        guard panel.runModal() == .OK else { return }
        for url in panel.urls {
            do { try model.store.importProfiles(from: url) } catch {
                let alert = NSAlert()
                alert.messageText = "“\(url.lastPathComponent)” could not be imported."
                alert.informativeText = error.localizedDescription
                alert.runModal()
            }
        }
    }
}

private struct ProfileRow: View {
    let profile: ConnectionProfile
    let session: DirectorySession?

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "server.rack")
                .foregroundStyle(.secondary)
                .overlay(alignment: .bottomTrailing) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 7, height: 7)
                        .overlay(Circle().stroke(.background, lineWidth: 1.5))
                        .offset(x: 3, y: 2)
                }
            VStack(alignment: .leading, spacing: 1) {
                Text(profile.displayName).lineLimit(1)
                Text(profile.host.isEmpty ? "No host" : "\(profile.host):\(String(profile.port))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .help(session?.statusLine ?? profile.endpoint)
    }

    private var statusColor: Color {
        switch session?.phase {
        case .connected?: return .green
        case .connecting?: return .yellow
        case .failed?: return .red
        default: return .clear
        }
    }
}
