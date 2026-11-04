// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import Security
import SwiftUI

/// How a directory records that an account is disabled.
enum AccountLockMethod {
    /// AD: bit 0x2 of userAccountControl.
    case userAccountControl
    /// 389 Directory Server and FreeIPA (and OpenLDAP sites that adopt it).
    case nsAccountLock
    /// eDirectory.
    case loginDisabled
    /// OpenLDAP's password policy overlay: a lock time of 000001010000Z is permanent.
    case pwdAccountLockedTime

    @MainActor
    static func method(for entry: LDAPEntry, session: DirectorySession) -> AccountLockMethod? {
        if entry.attribute("userAccountControl") != nil { return .userAccountControl }
        let kind = ObjectKind.classify(entry)
        guard [.user, .computer, .serviceAccount].contains(kind) else { return nil }
        if session.server?.kind == .eDirectory { return .loginDisabled }
        if entry.attribute("nsAccountLock") != nil || session.server?.kind == .the389DirectoryServer { return .nsAccountLock }
        if let schema = session.schema {
            if schema.attributeType("nsAccountLock") != nil,
               schema.allowedAttributes(for: entry.objectClasses).may.contains(where: { $0.caseInsensitiveCompare("nsAccountLock") == .orderedSame }) {
                return .nsAccountLock
            }
            if schema.attributeType("pwdAccountLockedTime") != nil { return .pwdAccountLockedTime }
        }
        return nil
    }

    func isDisabled(_ entry: LDAPEntry) -> Bool {
        switch self {
        case .userAccountControl: return (entry.int("userAccountControl") ?? 0) & 0x2 != 0
        case .nsAccountLock: return entry.string("nsAccountLock")?.uppercased() == "TRUE"
        case .loginDisabled: return entry.string("loginDisabled")?.uppercased() == "TRUE"
        case .pwdAccountLockedTime: return entry.string("pwdAccountLockedTime") == "000001010000Z"
        }
    }

    func changes(enabling: Bool, _ entry: LDAPEntry) -> [LDAPModification] {
        switch self {
        case .userAccountControl:
            let uac = entry.int("userAccountControl") ?? 512
            return [.replace("userAccountControl", [String(enabling ? uac & ~0x2 : uac | 0x2)])]
        case .nsAccountLock:
            return enabling ? (entry.attribute("nsAccountLock") != nil ? [.delete("nsAccountLock")] : [])
                : [.replace("nsAccountLock", ["TRUE"])]
        case .loginDisabled:
            return [.replace("loginDisabled", [enabling ? "FALSE" : "TRUE"])]
        case .pwdAccountLockedTime:
            return enabling ? (entry.attribute("pwdAccountLockedTime") != nil ? [.delete("pwdAccountLockedTime")] : [])
                : [.replace("pwdAccountLockedTime", ["000001010000Z"])]
        }
    }
}

@MainActor
enum AccountActions {
    static let passwordNotRequired: Int64 = 0x20

    /// userAccountControl as the server has it now. Changes start from this,
    /// not from the copy shown, which may be older than another change.
    static func currentUAC(_ dn: String, on connection: LDAPConnection) async throws -> Int64 {
        try await connection.read(dn, attributes: ["userAccountControl"])?.int("userAccountControl") ?? 512
    }

    static func setEnabled(_ enabled: Bool, _ entry: LDAPEntry, session: DirectorySession) async {
        guard let method = AccountLockMethod.method(for: entry, session: session) else {
            session.report("This directory has no account-disable attribute Forester knows.", isError: true)
            return
        }
        let name = DN.displayName(entry.dn)
        let refreshing = DN.parent(entry.dn).map { [$0] } ?? []
        guard method == .userAccountControl else {
            let changes = method.changes(enabling: enabled, entry)
            await session.change(enabled ? "Enabled \(name)." : "Disabled \(name).", refreshing: refreshing,
                                 undo: .values(entry.dn, Array(Set(changes.map(\.attribute))))) {
                try await $0.modify(entry.dn, changes)
            }
            return
        }
        let ok = await session.change(enabled ? "Enabled \(name)." : "Disabled \(name).", refreshing: refreshing,
                                      undo: .values(entry.dn, ["userAccountControl"])) { connection in
            let uac = try await currentUAC(entry.dn, on: connection)
            // An enabled account must have a password: "password not required"
            // (left by creating it without one) goes when it is enabled.
            let value = enabled ? uac & ~0x2 & ~passwordNotRequired : uac | 0x2
            try await connection.modify(entry.dn, [.replace("userAccountControl", [String(value)])])
        }
        if !ok, enabled, let message = session.notice?.message,
           message.contains("(19)") || message.contains("(53)") || message.localizedCaseInsensitiveContains("0000052D") {
            session.report("\(name) has no password AD accepts yet. Reset the password first, then enable the account. (\(message))", isError: true)
        }
    }

    /// AD: a lockout ends when lockoutTime is set to 0. With OpenLDAP's
    /// password policy, deleting pwdAccountLockedTime does it.
    static func unlock(_ entry: LDAPEntry, session: DirectorySession) async {
        let changes: [LDAPModification] = entry.attribute("lockoutTime") != nil || session.hasADTools
            ? [.replace("lockoutTime", ["0"])] : [.delete("pwdAccountLockedTime")]
        await session.change("Unlocked \(DN.displayName(entry.dn)).",
                             undo: .impossible(dn: entry.dn, why: "A lockout is not put back: the account locks again after enough wrong passwords.")) {
            try await $0.modify(entry.dn, changes)
        }
    }

    static func isLocked(_ entry: LDAPEntry) -> Bool {
        let computed = entry.int("msDS-User-Account-Control-Computed") ?? 0
        if computed & 0x10 != 0 { return true }
        if entry.attribute("msDS-User-Account-Control-Computed") == nil, (entry.int("lockoutTime") ?? 0) > 0 { return true }
        if let locked = entry.string("pwdAccountLockedTime"), locked != "000001010000Z" { return true }
        return false
    }

    static func setFlag(_ bit: Int64, on: Bool, _ entry: LDAPEntry, session: DirectorySession, label: String) async {
        await session.change("\(label): \(on ? "on" : "off").", undo: .values(entry.dn, ["userAccountControl"])) { connection in
            let uac = try await currentUAC(entry.dn, on: connection)
            let value = on ? uac | bit : uac & ~bit
            try await connection.modify(entry.dn, [.replace("userAccountControl", [String(value)])])
        }
    }

    /// pwdLastSet 0 forces a change at next sign-in; -1 clears that (AD then
    /// stores the current time).
    static func setMustChangePassword(_ on: Bool, _ entry: LDAPEntry, session: DirectorySession) async {
        // AD accepts only 0 and -1 here, so the earlier date cannot be put back:
        // undoing turning it off asks for a change again, and undoing turning
        // it on starts the password's age today.
        let back = UndoPlan.inverse(dn: entry.dn) { try await $0.modify(entry.dn, [.replace("pwdLastSet", [on ? "-1" : "0"])]) }
        await session.change(on ? "The password must be changed at next sign-in." : "No password change required.", undo: back) {
            try await $0.modify(entry.dn, [.replace("pwdLastSet", [on ? "0" : "-1"])])
        }
    }

    /// Reads the DACL (only the DACL: reading the SACL needs a privilege most
    /// administrators lack).
    static func readSecurityDescriptor(_ dn: String, session: DirectorySession) async throws -> SecurityDescriptor? {
        let entry = try await session.run {
            try await $0.read(dn, attributes: ["nTSecurityDescriptor"], controls: [.sdFlags(4)])
        }
        guard let data = entry?.values("nTSecurityDescriptor").first else { return nil }
        return try SecurityDescriptor(data: data)
    }

    static func setCannotChangePassword(_ on: Bool, _ entry: LDAPEntry, session: DirectorySession) async -> Bool {
        do {
            guard var descriptor = try await readSecurityDescriptor(entry.dn, session: session) else {
                session.report("The account's security descriptor could not be read.", isError: true)
                return false
            }
            descriptor.setUserCannotChangePassword(on)
            let data = try descriptor.encoded()
            return await session.change(on ? "The user can no longer change the password." : "The user may change the password.",
                                        undo: .values(entry.dn, ["nTSecurityDescriptor"], controls: [.sdFlags(4)])) {
                try await $0.modify(entry.dn, [LDAPModification(.replace, "nTSecurityDescriptor", [data])], controls: [.sdFlags(4)])
            }
        } catch {
            session.report(error.localizedDescription, isError: true)
            return false
        }
    }
}

/// Account controls on a user's or computer's Overview: what is set, and,
/// when editing is on, switches to change it.
struct AccountPanel: View {
    let session: DirectorySession
    let entry: LDAPEntry
    @State private var cannotChange: Bool?
    @State private var resettingPassword = false
    /// A flag that weakens or replaces something, waiting for the user to agree.
    @State private var confirming: Int64?
    @State private var busy = false

    private var method: AccountLockMethod? { AccountLockMethod.method(for: entry, session: session) }
    private var uac: Int64 { entry.int("userAccountControl") ?? 0 }
    private var isAD: Bool { entry.attribute("userAccountControl") != nil }
    private var writable: Bool { session.canWrite && !busy }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Account").font(.headline)
                Spacer()
                if AccountActions.isLocked(entry) {
                    Button("Unlock") { run { await AccountActions.unlock(entry, session: session) } }
                        .disabled(!writable)
                }
                Button("Reset Password…") { resettingPassword = true }
                    .disabled(!session.canWrite)
            }
            if let method {
                toggle("Account enabled", isOn: !method.isDisabled(entry)) { on in
                    await AccountActions.setEnabled(on, entry, session: session)
                }
            }
            if isAD {
                toggle("User must change password at next sign-in", isOn: entry.int("pwdLastSet") == 0) { on in
                    await AccountActions.setMustChangePassword(on, entry, session: session)
                }
                if let cannotChange {
                    toggle("User cannot change password", isOn: cannotChange) { on in
                        if await AccountActions.setCannotChangePassword(on, entry, session: session) { self.cannotChange = on }
                    }
                }
                flag(0x10000, "Password never expires")
                flag(Self.smartCard, "Smart card is required for interactive sign-in")
                flag(0x100000, "Account is sensitive and cannot be delegated")
                flag(Self.noPreAuthentication, "Do not require Kerberos pre-authentication")
            }
            if !session.canWrite {
                Text("Read-only. Click Read-only in the toolbar, or press ⌥⌘E, to change these.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
        .task(id: entry.dn) {
            guard isAD else { return }
            cannotChange = (try? await AccountActions.readSecurityDescriptor(entry.dn, session: session))??.userCannotChangePassword
        }
        .sheet(isPresented: $resettingPassword) { PasswordSheet(session: session, entry: entry) }
        .alert(confirming == Self.smartCard ? "Require a smart card for \(DN.displayName(entry.dn))?"
                   : "Stop requiring Kerberos pre-authentication for \(DN.displayName(entry.dn))?",
               isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } })) {
            Button(confirming == Self.smartCard ? "Require Smart Card" : "Stop Requiring It", role: .destructive) {
                guard let bit = confirming else { return }
                let label = bit == Self.smartCard ? "Smart card required" : "Kerberos pre-authentication not required"
                run { await AccountActions.setFlag(bit, on: true, entry, session: session, label: label) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(confirming == Self.smartCard ? ADValues.smartCardRequiredNote
                 : "Anyone on the network can then ask a domain controller for data encrypted with this account's password and try to crack it offline. Only for a service that cannot do pre-authentication.")
        }
    }

    private static let smartCard: Int64 = 0x40000
    private static let noPreAuthentication: Int64 = 0x400000

    private func flag(_ bit: Int64, _ label: String) -> some View {
        toggle(label, isOn: uac & bit != 0) { on in
            // AD replaces the password when a smart card becomes required, which
            // cannot be undone, and no pre-authentication exposes the password
            // to offline cracking: ask first.
            if on && (bit == Self.smartCard || bit == Self.noPreAuthentication) {
                confirming = bit
                return
            }
            await AccountActions.setFlag(bit, on: on, entry, session: session, label: label)
        }
    }

    private func toggle(_ label: String, isOn: Bool, action: @escaping (Bool) async -> Void) -> some View {
        Toggle(label, isOn: Binding(get: { isOn }, set: { value in run { await action(value) } }))
            .toggleStyle(.checkbox)
            .disabled(!writable)
    }

    private func run(_ work: @escaping () async -> Void) {
        busy = true
        Task {
            await work()
            busy = false
        }
    }
}

/// Resets a password (as an administrator) or changes it (knowing the old one),
/// with the method the server needs.
struct PasswordSheet: View {
    let session: DirectorySession
    let entry: LDAPEntry
    @Environment(\.dismiss) private var dismiss
    @State private var changeOwn = false
    @State private var current = ""
    @State private var password = ""
    @State private var confirm = ""
    @State private var reveal = false
    @State private var mustChange = true
    @State private var unlock = true
    @State private var saving = false
    @State private var error: String?
    @State private var sendUnencrypted = false

    enum Method {
        case unicodePwd, passwordModify, userPassword

        var label: String {
            switch self {
            case .unicodePwd: return "Active Directory (unicodePwd)"
            case .passwordModify: return "Password Modify extended operation (RFC 3062)"
            case .userPassword: return "Replacing userPassword"
            }
        }
    }

    private var isAD: Bool { session.hasADTools && entry.attribute("userAccountControl") != nil }

    private var method: Method {
        if isAD { return .unicodePwd }
        if session.server?.kind == .eDirectory { return .userPassword }
        return session.server?.supportsPasswordModify == true ? .passwordModify : .userPassword
    }

    private var problem: String? {
        if method == .unicodePwd && !session.isSecure { return "AD accepts a new password only over an encrypted connection (StartTLS or LDAPS)." }
        if !session.isSecure && !sendUnencrypted { return "This connection is not encrypted: the new password would travel in clear text." }
        if changeOwn && current.isEmpty { return "Enter the current password." }
        if password.isEmpty { return "Enter a new password." }
        if password != confirm { return "The passwords do not match." }
        return nil
    }

    var body: some View {
        SheetLayout(title: changeOwn ? "Change Password" : "Reset Password", subtitle: DN.displayName(entry.dn), width: 540) {
            Form {
                Section {
                    Picker("", selection: $changeOwn) {
                        Text("Reset as administrator").tag(false)
                        Text("Change, knowing the current one").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                }
                Section {
                    if changeOwn {
                        PasswordFieldRow(label: "Current", text: $current, reveal: $reveal, showsRevealButton: false)
                    }
                    PasswordFieldRow(label: "New", text: $password, reveal: $reveal)
                    PasswordFieldRow(label: "Confirm", text: $confirm, reveal: $reveal, showsRevealButton: false)
                    FieldRow(label: "") {
                        Button {
                            password = Self.generate()
                            confirm = password
                            reveal = true
                        } label: {
                            Label("Generate a Strong Password", systemImage: "wand.and.stars")
                        }
                        .help("20 random characters from all four kinds, without look-alikes such as 0 and O.")
                    }
                }
                if isAD && !changeOwn {
                    Section {
                        Toggle("User must change password at next sign-in", isOn: $mustChange)
                            .formSwitch("User must change password at next sign-in")
                        if AccountActions.isLocked(entry) { Toggle("Unlock the account", isOn: $unlock).formSwitch("Unlock the account") }
                    }
                }
                Section {
                    ValueRow(label: "Method", value: method.label)
                    if !session.isSecure && method != .unicodePwd {
                        Toggle("Send it unencrypted anyway", isOn: $sendUnencrypted)
                            .formSwitch("Send it unencrypted anyway")
                    }
                } footer: {
                    if method == .userPassword {
                        FormFooter("The value is stored as given unless the server hashes it on write; many OpenLDAP servers do, with a password policy or the password-hash setting.")
                    }
                }
            }
            .formStyle(.grouped)
            .formLabelWidth(64)
            .hugsContent()
        } status: {
            SheetStatus(problem: problem, error: error)
        } buttons: {
            Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
            Button(changeOwn ? "Change Password" : "Reset Password") { save() }
                .keyboardShortcut(.defaultAction)
                .disabled(saving || problem != nil)
        }
    }

    private func save() {
        saving = true
        error = nil
        let dn = entry.dn
        let method = self.method
        let (old, new, own, forceChange, doUnlock) = (current, password, changeOwn, mustChange, unlock && AccountActions.isLocked(entry))
        Task {
            let ok = await session.change(own ? "Password changed." : "Password reset.",
                                          undo: .impossible(dn: dn, why: "A password cannot be read back, so it cannot be put back.")) { connection in
                switch method {
                case .unicodePwd:
                    if own {
                        try await connection.modify(dn, [LDAPModification(.delete, "unicodePwd", [ADValues.unicodePwd(old)]),
                                                         LDAPModification(.add, "unicodePwd", [ADValues.unicodePwd(new)])])
                    } else {
                        var changes = [LDAPModification(.replace, "unicodePwd", [ADValues.unicodePwd(new)])]
                        if forceChange { changes.append(.replace("pwdLastSet", ["0"])) }
                        if doUnlock { changes.append(.replace("lockoutTime", ["0"])) }
                        // The account has a password now; "password not required" goes.
                        let uac = try await AccountActions.currentUAC(dn, on: connection)
                        if uac & AccountActions.passwordNotRequired != 0 {
                            changes.append(.replace("userAccountControl", [String(uac & ~AccountActions.passwordNotRequired)]))
                        }
                        try await connection.modify(dn, changes)
                    }
                case .passwordModify:
                    try await connection.passwordModify(user: dn, oldPassword: own ? old : nil, newPassword: new)
                case .userPassword:
                    if own {
                        try await connection.modify(dn, [.delete("userPassword", [old]), .add("userPassword", [new])])
                    } else {
                        try await connection.modify(dn, [.replace("userPassword", [new])])
                    }
                }
            }
            saving = false
            if ok { dismiss() } else { error = session.notice?.message }
        }
    }

    /// 20 characters from all four classes, without look-alikes (0/O, 1/l/I).
    static func generate() -> String {
        let sets = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!@#$%*-_=+?"].map(Array.init)
        let all = sets.flatMap { $0 }
        // The system's cryptographic generator, without modulo bias.
        var generator = SystemRandomNumberGenerator()
        func random(_ upper: Int) -> Int { Int.random(in: 0..<upper, using: &generator) }
        var characters = sets.map { $0[random($0.count)] }
        while characters.count < 20 { characters.append(all[random(all.count)]) }
        for index in characters.indices.reversed() { characters.swapAt(index, random(index + 1)) }
        return String(characters)
    }
}
