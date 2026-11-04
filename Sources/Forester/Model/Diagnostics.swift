// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import AppKit
import LDAPKit

/// Help › Copy Diagnostics: what someone answering a problem report needs to
/// know (versions, the kind of server and how the connection is made), and
/// no passwords or directory contents. Recent errors are included with this
/// connection's host and user replaced; they can still name entries or other
/// servers, so the person reads it before sending it anywhere.
@MainActor
enum Diagnostics {
    static func text(_ model: AppModel, session: DirectorySession?) -> String {
        var lines = ["Forester \(ForesterInfo.version)\(ForesterInfo.fromAppStore ? " (Mac App Store)" : "")"]
        let os = ProcessInfo.processInfo.operatingSystemVersion
        lines.append("macOS \(os.majorVersion).\(os.minorVersion).\(os.patchVersion), \(architecture)")
        lines.append("Saved connections: \(model.store.profiles.count)\(model.store.inICloudDrive ? ", kept in iCloud Drive" : "")")
        guard let session else {
            lines.append("No connection selected.")
            return lines.joined(separator: "\n")
        }
        let profile = session.profile
        lines.append("")
        lines.append("Connection: \(ProfileEditor.securityLabel(profile.security)), \(profile.authentication.label.lowercased()), \(profile.readOnly ? "read-only" : "editing on")\(profile.trust.trustAnyCertificate ? ", accepts any certificate" : "")\(profile.trust.pinnedFingerprints.isEmpty ? "" : ", \(profile.trust.pinnedFingerprints.count) trusted certificate(s)")")
        switch session.phase {
        case .idle: lines.append("State: not connected")
        case .connecting: lines.append("State: connecting")
        case .failed: lines.append("State: failed (see the errors below)")
        case .connected: lines.append("State: connected, \(session.isSecure ? "encrypted" : "not encrypted")")
        }
        if let server = session.server {
            var facts = ["Server: \(server.kind.label)"]
            if let vendor = server.vendorVersion { facts.append(vendor) }
            if let level = server.domainFunctionality { facts.append("domain level \(ADValues.functionalLevelName(level))") }
            if let level = server.forestFunctionality { facts.append("forest level \(ADValues.functionalLevelName(level))") }
            if session.hasADTools { facts.append(session.isGlobalCatalog ? "global catalog" : "not a global catalog") }
            facts.append(server.supportsPaging ? "paging" : "no paging")
            lines.append(facts.joined(separator: ", "))
            lines.append("Schema: \(session.schema == nil ? "not read" : "read")")
        }
        let errors = session.recentErrors.map { ($0.0, redact($0.1, profile: profile, server: session.server)) }
        lines.append("")
        if errors.isEmpty {
            lines.append("No errors since connecting.")
        } else {
            lines.append("Recent errors, newest first (this connection's host and user are replaced; other names can remain, so read before sending):")
            for (date, message) in errors.reversed() {
                lines.append("- \(date.formatted(date: .omitted, time: .standard)) \(message)")
            }
        }
        return lines.joined(separator: "\n")
    }

    /// The connection's host, its server's own name, the domain and the user,
    /// replaced wherever an error repeats them.
    static func redact(_ message: String, profile: ConnectionProfile, server: ServerInfo?) -> String {
        var text = message
        var replacements: [(String, String)] = []
        let user = profile.bindName.trimmingCharacters(in: .whitespaces)
        if !user.isEmpty {
            replacements.append((user, "‹user›"))
            // The name alone, as Kerberos and AD's messages give it.
            let bare = user.split(separator: "\\").last.map(String.init)?.split(separator: "@").first.map(String.init) ?? user
            if bare.count > 2 { replacements.append((bare, "‹user›")) }
        }
        for host in [profile.host, server?.dnsHostName, server?.domainDNSName].compactMap({ $0 }) where host.count > 2 {
            replacements.append((host, "‹host›"))
        }
        // Longest first, so a host is not half replaced by its domain.
        for (name, placeholder) in replacements.sorted(by: { $0.0.count > $1.0.count }) {
            text = text.replacingOccurrences(of: name, with: placeholder, options: .caseInsensitive)
        }
        // A Kerberos connection has no user name of its own: the user is
        // whoever holds the ticket, and Kerberos messages name them as a
        // principal, user@REALM, the realm in capitals.
        text = text.replacingOccurrences(of: #"[A-Za-z0-9._$/-]+@(‹host›|[A-Z][A-Z0-9-]*(\.[A-Z0-9-]+)+)"#,
                                         with: "‹user›@‹realm›", options: .regularExpression)
        return text
    }

    /// Apple silicon, Intel, or Intel code translated by Rosetta.
    static var architecture: String {
        #if arch(arm64)
        return "Apple silicon"
        #else
        var translated: Int32 = 0
        var size = MemoryLayout<Int32>.size
        let isTranslated = sysctlbyname("sysctl.proc_translated", &translated, &size, nil, 0) == 0 && translated == 1
        return isTranslated ? "Intel build under Rosetta" : "Intel"
        #endif
    }

    static func copy(_ model: AppModel, session: DirectorySession?) {
        Pasteboard.copy(text(model, session: session))
        let alert = NSAlert()
        alert.messageText = "Diagnostics copied"
        alert.informativeText = "Versions, the kind of server and how this connection is made, without passwords, and with this connection's host and user replaced. Recent errors are included and can still name entries or other servers: read it before you paste it into an issue."
        alert.runModal()
    }
}
