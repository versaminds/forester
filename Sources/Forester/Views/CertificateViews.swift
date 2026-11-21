// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SecurityInterface
import SwiftUI

/// The system certificate viewer, the same panel Keychain Access shows.
enum CertificateViewer {
    @MainActor
    static func show(_ chain: [Data]) {
        let certificates = chain.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard !certificates.isEmpty else { return }
        let panel = SFCertificatePanel.shared()
        panel?.setDefaultButtonTitle("Close")
        panel?.runModal(forCertificates: certificates, showGroup: true)
    }
}

struct CertificateTrustSheet: View {
    let failure: CertificateTrustFailure
    let host: String
    let trust: () -> Void
    var trustOnce: (() -> Void)?
    let cancel: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "exclamationmark.shield.fill")
                    .font(.system(size: 36))
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 6) {
                    Text("This Mac does not trust the certificate of “\(host)”").font(.headline)
                    Text(failure.reason).font(.callout).foregroundStyle(.secondary)
                }
            }
            Grid(alignment: .leading, verticalSpacing: 6) {
                GridRow {
                    Text("Issued to").foregroundStyle(.secondary)
                    Text(failure.subject).textSelection(.enabled)
                }
                GridRow(alignment: .top) {
                    Text("SHA-256").foregroundStyle(.secondary)
                    Text(failure.sha256Fingerprint).font(.caption.monospaced()).textSelection(.enabled)
                }
            }
            .font(.callout)
            Text(Self.explanation)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Show Certificate…") { CertificateViewer.show(failure.chain) }
                Spacer()
                // Return and Escape both decline: trusting takes a click, so
                // a key pressed out of habit never accepts a certificate.
                Button("Cancel", role: .cancel) { dismiss(); cancel() }
                    .keyboardShortcut(.defaultAction)
                if let trustOnce {
                    Button("Trust Once") { dismiss(); trustOnce() }
                        .help("Connect without remembering the certificate: it is forgotten when you disconnect.")
                }
                Button("Always Trust") { dismiss(); trust() }
                    .help("Pin this certificate to the connection; it can be forgotten in the connection's settings.")
            }
        }
        .padding(20)
        .frame(width: 520)
        .background {
            Button("Cancel") { dismiss(); cancel() }
                .keyboardShortcut(.cancelAction)
                .opacity(0)
                .accessibilityHidden(true)
        }
    }

    /// Trust Once lasts until the connection is closed: disconnecting,
    /// changing its server, or quitting.
    static let explanation = "Directory servers often use a certificate from the organisation's own CA. Compare the fingerprint with what your administrator expects before trusting it. Trusting pins this certificate to this connection only (Trust Once forgets it when you disconnect); installing the organisation's root CA in Keychain Access trusts all of its servers."
}
