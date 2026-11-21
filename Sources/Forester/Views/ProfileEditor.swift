// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

struct ProfileEditor: View {
    let onSave: (ConnectionProfile, String?) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var draft: ConnectionProfile
    @State private var password = ""
    @State private var testState: TestState = .idle
    @State private var testTask: Task<Void, Never>?
    @State private var hasSavedPassword = false
    @State private var revealPassword = false
    /// Certificates trusted with Test Connection while editing.
    @State private var pinnedHere: [String] = []
    private let original: ConnectionProfile
    private let isNew: Bool

    enum TestState: Equatable {
        case idle, running
        case success(String)
        case failure(String)
        case untrusted(CertificateTrustFailure)
    }

    init(profile: ConnectionProfile, onSave: @escaping (ConnectionProfile, String?) -> Void) {
        self.onSave = onSave
        _draft = State(initialValue: profile)
        original = profile
        isNew = profile.host.isEmpty && profile.name.isEmpty
    }

    private var hostIsEmpty: Bool { draft.host.trimmingCharacters(in: .whitespaces).isEmpty }
    private var portIsValid: Bool { ConnectionProfile.portRange.contains(draft.port) }
    /// Kerberos over TLS binds the ticket to the server's certificate, which
    /// means nothing with any certificate accepted (see `LDAPConnection.bindKerberos`).
    private var kerberosWithAnyCertificate: Bool {
        draft.authentication == .kerberos && draft.security != .none && draft.trust.trustAnyCertificate
    }
    /// A certificate is shown in the TLS handshake, so it needs TLS, and one chosen.
    private var certificateIncomplete: Bool {
        draft.authentication == .certificate && (draft.security == .none || draft.clientCertificate.isEmpty)
    }
    /// The keychain's certificates with a private key, read when the sheet opens.
    @State private var certificates: [ClientCertificates.Choice] = []

    /// The saved password was saved for other server, user or security
    /// settings than these, so it is not used with them (see `Keychain`).
    private var savedPasswordDoesNotApply: Bool {
        hasSavedPassword && Keychain.connection(of: draft) != Keychain.connection(of: original)
    }

    private var serverChanged: Bool {
        draft.host.trimmingCharacters(in: .whitespaces).lowercased() != original.host.trimmingCharacters(in: .whitespaces).lowercased()
            || draft.port != original.port
    }

    /// Certificates trusted for the server as it was are not trusted for another one.
    private var effectivePins: [String] {
        serverChanged ? draft.trust.pinnedFingerprints.filter(pinnedHere.contains) : draft.trust.pinnedFingerprints
    }

    var body: some View {
        SheetLayout(title: isNew ? "New Connection" : "Edit Connection",
                    subtitle: isNew ? "A directory server to browse. Nothing is changed in it unless you allow changes." : nil,
                    width: 560, height: 680) {
            VStack(spacing: 0) {
                form
                if testState != .idle {
                    Divider()
                    testResult
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 12)
                        .background(.background.secondary)
                }
            }
        } status: {
            Button {
                runTest()
            } label: {
                if testState == .running {
                    HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Testing…") }
                } else {
                    Text("Test Connection")
                }
            }
            .disabled(hostIsEmpty || testState == .running)
            .help("Connects, signs in and reads the server's information, without saving.")
        } buttons: {
            Button("Cancel", role: .cancel) { testTask?.cancel(); dismiss() }
                .keyboardShortcut(.cancelAction)
            Button(isNew ? "Add" : "Save") {
                testTask?.cancel()
                var saved = draft
                saved.trust.pinnedFingerprints = effectivePins
                saved.host = saved.host.trimmingCharacters(in: .whitespaces)
                saved.name = saved.name.trimmingCharacters(in: .whitespaces)
                onSave(saved, password.isEmpty ? nil : password)
                dismiss()
            }
            .keyboardShortcut(.defaultAction)
            .disabled(hostIsEmpty || !portIsValid || kerberosWithAnyCertificate || certificateIncomplete)
        }
        .onAppear {
            hasSavedPassword = !isNew && Keychain.hasPassword(for: draft.id)
            if draft.authentication == .certificate { certificates = ClientCertificates.all() }
        }
        .onChange(of: draft.authentication) { _, new in
            if new == .certificate, certificates.isEmpty { certificates = ClientCertificates.all() }
        }
    }

    private var form: some View {
        Form {
            Section {
                TextFieldRow(label: "Name", text: $draft.name, prompt: draft.host.isEmpty ? "Corp domain" : draft.host,
                             help: "How the connection is listed in the sidebar.")
            }
            Section("Server") {
                TextFieldRow(label: "Host", text: $draft.host, prompt: "dc01.corp.example",
                             help: "A domain controller or directory server, or the domain name itself.")
                PickerRow(label: "Security", selection: $draft.security) {
                    ForEach(LDAPConnection.Security.allCases, id: \.self) { Text(Self.securityLabel($0)).tag($0) }
                }
                .onChange(of: draft.security) { old, new in
                    if draft.port == old.defaultPort { draft.port = new.defaultPort }
                }
                FieldRow(label: "Port") {
                    TextField("Port", value: $draft.port, format: .number.grouping(.never))
                        .labelsHidden()
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 80)
                    if !portIsValid {
                        Text("Between 1 and 65535").font(.callout).foregroundStyle(.red)
                    }
                }
                if draft.security == .none {
                    Label("Passwords and directory data travel unencrypted, and Active Directory refuses a password sign-in over plain LDAP when signing is required.",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                }
            }
            Section("Sign In") {
                PickerRow(label: "Sign in", selection: $draft.authentication) {
                    ForEach(ConnectionProfile.Authentication.allCases, id: \.self) { Text($0.label).tag($0) }
                }
                if draft.authentication.usesPassword {
                    TextFieldRow(label: "User", text: $draft.bindName,
                                 prompt: draft.authentication == .scram ? "The user name the server knows" : "user@corp.example, CORP\\user or a DN")
                    PasswordFieldRow(label: "Password", text: $password,
                                     prompt: savedPasswordDoesNotApply ? "Enter it again for these settings"
                                         : (hasSavedPassword ? "Saved in the keychain" : "Asked when you connect"),
                                     reveal: $revealPassword)
                    Toggle("Remember the password in the keychain", isOn: $draft.savePassword)
                        .formSwitch("Remember the password in the keychain")
                    if draft.authentication == .scram {
                        FormFooter("SCRAM-SHA-256: the password proves itself without being sent, and the server proves it knows it too. Over TLS the sign-in is bound to the connection when the server can check that. The server must offer SCRAM-SHA-256; Active Directory does not.")
                    }
                } else if draft.authentication == .kerberos {
                    FormFooter("Signs in with the Kerberos ticket this Mac already has, from Ticket Viewer, kinit or your organisation's single sign-on. No password is typed or kept. Use the domain controller's full DNS name as the host."
                               + (draft.security == .none
                                  ? " Without StartTLS or LDAPS, Kerberos encrypts the connection itself; a server that does not agree to that is not used."
                                  : ""))
                } else if draft.authentication == .certificate {
                    certificatePicker
                }
            }
            Section {
                TextFieldRow(label: "Base DN", text: $draft.baseDN, prompt: "Found automatically",
                             help: "Where browsing starts. Leave empty to start from every naming context the server offers.")
            } header: {
                Text("Browsing")
            }
            Section {
                Toggle(isOn: $draft.readOnly) {
                    Text("Read-only")
                    Text("Nothing is sent to the directory. Turn off to edit entries, reset passwords and import LDIF.")
                }
                .formSwitch("Read-only", hint: "Nothing is sent to the directory. Turn off to edit entries, reset passwords and import LDIF.")
            }
            Section("Advanced") {
                NumberFieldRow(label: "Page size", value: $draft.pageSize, range: 50...5000, step: 50, unit: "entries")
                NumberFieldRow(label: "Timeout", value: $draft.timeoutSeconds, range: 5...300, step: 5, unit: "seconds")
                if !effectivePins.isEmpty {
                    FieldRow(label: "Trusted") {
                        HStack(alignment: .firstTextBaseline) {
                            VStack(alignment: .leading, spacing: 2) {
                                ForEach(effectivePins, id: \.self) { fingerprint in
                                    Text(fingerprint.prefix(29) + "…").font(.callout.monospaced()).foregroundStyle(.secondary)
                                        .help("SHA-256 \(fingerprint)")
                                }
                            }
                            Spacer()
                            Button("Forget") { draft.trust.pinnedFingerprints = []; pinnedHere = [] }
                                .help("Ask again before trusting this server's certificate.")
                        }
                    }
                }
                Toggle(isOn: $draft.trust.trustAnyCertificate) {
                    Text("Accept any certificate")
                    Text(anyCertificateNote)
                }
                .formSwitch("Accept any certificate", hint: anyCertificateNote)
            }
        }
        .formStyle(.grouped)
        .formLabelWidth(84)
    }

    /// A certificate with its private key from the keychain, shown to the
    /// server in the TLS handshake (SASL EXTERNAL).
    @ViewBuilder
    private var certificatePicker: some View {
        let chosenIsMissing = !draft.clientCertificate.isEmpty
            && !certificates.contains { TrustPolicyFingerprint.same($0.id, draft.clientCertificate) }
        PickerRow(label: "Certificate", selection: Binding(
            get: { certificates.first { TrustPolicyFingerprint.same($0.id, draft.clientCertificate) }?.id ?? draft.clientCertificate },
            set: { draft.clientCertificate = $0 })) {
            if draft.clientCertificate.isEmpty { Text("Choose…").tag("") }
            if chosenIsMissing { Text("Not in the keychain").tag(draft.clientCertificate) }
            ForEach(certificates) { choice in
                Text(choice.name).tag(choice.id).help("SHA-256 \(choice.id)")
            }
        }
        if draft.security == .none {
            FormFooter("A certificate is shown in the TLS handshake: choose StartTLS or LDAPS.")
        } else if certificates.isEmpty {
            FormFooter("The keychain holds no certificate with its private key. Import yours (a .p12 file) into Keychain Access, then open this again.")
        } else {
            FormFooter("Signs in as the account the server maps this certificate to (SASL EXTERNAL). No password is typed or kept. macOS asks before Forester first uses the certificate's key.")
        }
    }

    private var anyCertificateNote: String {
        if draft.authentication != .kerberos || draft.security == .none { return "Only for a lab: anyone on the network path could read the password." }
        return draft.trust.trustAnyCertificate
            ? "Turn this off to sign in with Kerberos: a ticket must be bound to a certificate this Mac trusts."
            : "Not with Kerberos: a ticket must be bound to a certificate this Mac trusts."
    }

    static func securityLabel(_ security: LDAPConnection.Security) -> String {
        switch security {
        case .none: return "None (plain LDAP)"
        case .startTLS: return "StartTLS"
        case .ldaps: return "LDAPS"
        }
    }

    @ViewBuilder
    private var testResult: some View {
        switch testState {
        case .idle:
            EmptyView()
        case .running:
            HStack(spacing: 8) { ProgressView().controlSize(.small); Text("Connecting to \(draft.host)…").foregroundStyle(.secondary) }
        case .success(let text):
            Label { Text(text).textSelection(.enabled) } icon: { Image(systemName: "checkmark.circle.fill").foregroundStyle(.green) }
        case .failure(let text):
            Label { Text(text).textSelection(.enabled) } icon: { Image(systemName: "xmark.octagon.fill").foregroundStyle(.red) }
        case .untrusted(let failure):
            VStack(alignment: .leading, spacing: 8) {
                Label { Text("This Mac does not trust the certificate of “\(failure.subject)”. \(failure.reason)") } icon: {
                    Image(systemName: "exclamationmark.shield.fill").foregroundStyle(.orange)
                }
                Text("SHA-256 \(failure.sha256Fingerprint)").font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                HStack {
                    Button("Show Certificate…") { CertificateViewer.show(failure.chain) }
                    Button("Trust This Certificate") {
                        draft.trust.pinnedFingerprints.append(failure.sha256Fingerprint)
                        pinnedHere.append(failure.sha256Fingerprint)
                        runTest()
                    }
                    .help("Pin this certificate to the connection and test again.")
                }
            }
        }
    }

    private func runTest() {
        testTask?.cancel()
        testState = .running
        var profile = draft
        profile.trust.pinnedFingerprints = effectivePins
        let typed = password
        // Never sent to settings it was not saved for.
        let saved = typed.isEmpty && !savedPasswordDoesNotApply && hasSavedPassword ? Keychain.password(for: original).password : nil
        var options = profile.options
        if profile.authentication == .certificate {
            options.clientIdentity = certificates.first { TrustPolicyFingerprint.same($0.id, profile.clientCertificate) }?.identity
        }
        testTask = Task {
            let connection = LDAPConnection(options)
            defer { Task { await connection.close() } }
            do {
                try await connection.open()
                let typedOrSaved = typed.isEmpty ? (saved ?? "") : typed
                switch profile.authentication {
                case .simple: try await connection.bind(dn: profile.bindName, password: typedOrSaved)
                case .scram: try await connection.bindSCRAM(user: profile.bindName, password: typedOrSaved)
                case .kerberos: try await connection.bindKerberos()
                case .certificate: try await connection.bindExternal()
                case .anonymous: break
                }
                let info = ServerInfo(rootDSE: try await connection.rootDSE())
                let who = try? await connection.whoAmI()
                let (secure, sealed) = (await connection.isSecure, await connection.isSealed)
                let kerberosServer = await connection.kerberosServer
                guard !Task.isCancelled else { return }
                var text = "Connected to \(info.kind.label)"
                if let host = info.dnsHostName { text += " (\(host))" }
                text += sealed ? ", encrypted by Kerberos" : (secure ? " over TLS" : ", unencrypted")
                // Without TLS, the name Kerberos authenticated is what says who the server is.
                if let kerberosServer { text += ", Kerberos server \(kerberosServer)" }
                if let who, who != "anonymous" { text += ", bound as \(who.replacingOccurrences(of: "dn:", with: ""))" }
                if let context = info.defaultNamingContext { text += ". Default naming context \(context)." }
                testState = .success(text)
            } catch LDAPError.untrustedCertificate(let failure) {
                testState = .untrusted(failure)
            } catch {
                guard !Task.isCancelled else { return }
                testState = .failure(error.localizedDescription)
            }
        }
    }
}
