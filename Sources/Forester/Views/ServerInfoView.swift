// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

struct ServerInfoView: View {
    let session: DirectorySession
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                if let server = session.server {
                    ServerInfoContent(session: session, server: server)
                        .padding(20)
                }
            }
            Divider()
            HStack {
                Button("Show Root DSE Attributes") {
                    dismiss()
                    session.mode = .browse
                    session.tree.selection = TreeModel.rootDSEKey
                    session.select("")
                    session.inspector.tab = .attributes
                }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(14)
        }
        .frame(width: 560, height: 620)
    }
}

/// What the root DSE says, in words: shared by the sheet and the Root DSE entry.
struct ServerInfoContent: View {
    let session: DirectorySession
    let server: ServerInfo

    var body: some View {
        let root = server.rootDSE
        VStack(alignment: .leading, spacing: 18) {
            group("Server") {
                row("Type", server.kind.label)
                row("Host", server.dnsHostName ?? session.profile.host)
                row("Vendor", root.string("vendorName"))
                row("Version", root.string("vendorVersion"))
                row("Domain functional level", server.domainFunctionality.map(ADValues.functionalLevelName))
                row("Forest functional level", server.forestFunctionality.map(ADValues.functionalLevelName))
                row("DC functional level", root.int("domainControllerFunctionality").map { ADValues.functionalLevelName(Int($0)) })
                row("Global catalog", root.string("isGlobalCatalogReady").map { $0.uppercased() == "TRUE" ? "Yes" : "No" })
                row("Server time", root.string("currentTime").flatMap(ADValues.generalizedTime).map { AttributeFormatter.dateText($0) })
                row("LDAP versions", root.strings("supportedLDAPVersion").joined(separator: ", "))
            }
            group("This connection") {
                row("Endpoint", session.profile.endpoint)
                row("Encryption", session.isSecure ? "TLS (\(session.profile.security.label))" : "None")
                row("Bound as", session.identity.map { $0.replacingOccurrences(of: "dn:", with: "").replacingOccurrences(of: "u:", with: "") })
                row("Paged results", server.supportsPaging ? "Supported" : "Not supported")
                row("StartTLS", server.supportsStartTLS ? "Supported" : "Not advertised")
            }
            group("Naming contexts") {
                ForEach(server.namingContexts, id: \.self) { context in
                    HStack {
                        Button(context) { session.open(context) }
                            .buttonStyle(.link)
                        if context == server.defaultNamingContext {
                            Text("default").font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            oidList("Capabilities", root.strings("supportedCapabilities"))
            oidList("Controls", root.strings("supportedControl"))
            oidList("Extended operations", root.strings("supportedExtension"))
            oidList("Features", root.strings("supportedFeatures"))
            let mechanisms = root.strings("supportedSASLMechanisms")
            if !mechanisms.isEmpty {
                group("SASL mechanisms") { Text(mechanisms.joined(separator: ", ")).textSelection(.enabled) }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func group<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            Grid(alignment: .topLeading, horizontalSpacing: 14, verticalSpacing: 5) { content() }
                .font(.callout)
        }
    }

    @ViewBuilder
    private func row(_ label: String, _ value: String?) -> some View {
        if let value, !value.isEmpty {
            GridRow {
                Text(label).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                Text(value).textSelection(.enabled)
            }
        }
    }

    @ViewBuilder
    private func oidList(_ title: String, _ oids: [String]) -> some View {
        if !oids.isEmpty {
            group(title) {
                ForEach(oids.sorted { (KnownOIDs.name($0) ?? "~\($0)") < (KnownOIDs.name($1) ?? "~\($1)") }, id: \.self) { oid in
                    GridRow {
                        Text(KnownOIDs.name(oid) ?? "Unknown").foregroundStyle(KnownOIDs.name(oid) == nil ? .secondary : .primary)
                        Text(oid).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
            }
        }
    }
}
