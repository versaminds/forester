// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import LDAPKit
import Observation

/// Everything about one open connection: its state, the tree, the search, and
/// what the inspector is showing. One per profile, shared by every window.
@MainActor @Observable
final class DirectorySession: Identifiable {
    enum Phase: Equatable {
        case idle, connecting, connected
        case failed(String)

        var isConnected: Bool { self == .connected }
    }

    enum Mode: String, CaseIterable {
        case browse, search
        var label: String { self == .browse ? "Browse" : "Search" }
    }

    let id: UUID
    private(set) var profile: ConnectionProfile
    private(set) var phase: Phase = .idle
    var mode: Mode = .browse
    private(set) var server: ServerInfo?
    private(set) var identity: String?
    private(set) var isSecure = false
    /// `S-1-5-21-…` of the domain, read from the domain object, for resolving
    /// primary groups (stored as a bare RID).
    private(set) var domainSID: String?
    /// The domain object is a domainDNS: AD data, even if the server is not AD
    /// (Samba, or the test directory). Turns on the Active Directory tools.
    private(set) var domainLooksLikeAD = false
    /// The server's schema, read in the background after connecting.
    private(set) var schema: LDAPSchema?
    /// A short message about the last change, shown at the bottom of the window.
    var notice: Notice?
    /// The last errors reported, oldest first, for Help › Copy Diagnostics.
    @ObservationIgnored private(set) var recentErrors: [(Date, String)] = []
    /// Changes made in this window, newest first, each with its way back.
    var history: [ChangeRecord] = []
    /// The window's, so Edit › Undo takes directory changes back too.
    @ObservationIgnored weak var undoManager: UndoManager?
    /// What GUIDs in permissions stand for, read once per connection.
    @ObservationIgnored var guidNames: [String: SchemaGUIDName]?
    /// The forest's domains, read once per connection.
    @ObservationIgnored var cachedForestDomains: [ForestDomain]?
    /// The global catalog, for searches of the whole forest.
    @ObservationIgnored var globalCatalogConnection: LDAPConnection?
    /// Names found for SIDs in permissions.
    @ObservationIgnored var sidNames: [String: (name: String, dn: String?)] = [:]
    /// The editing sheet to show, from whichever place asked for it: the
    /// inspector's toolbar, the tree's menu, or the menu bar.
    var sheet: EntrySheet?

    enum EntrySheet: Identifiable {
        case newEntry(parent: String)
        case duplicate(LDAPEntry)
        case renameMove(dn: String, move: Bool)
        case delete(dn: String)
        case password(LDAPEntry)
        case accountStatus(LDAPEntry)
        /// With a file when one was dropped on the window.
        case importLDIF(URL?)
        case history

        var id: String {
            switch self {
            case .newEntry(let parent): return "new|\(parent)"
            case .duplicate(let entry): return "dup|\(entry.dn)"
            case .renameMove(let dn, let move): return "mv|\(dn)|\(move)"
            case .delete(let dn): return "del|\(dn)"
            case .password(let entry): return "pw|\(entry.dn)"
            case .accountStatus(let entry): return "st|\(entry.dn)"
            case .importLDIF: return "import"
            case .history: return "history"
            }
        }
    }

    /// Where a new entry goes: the selected container, or the selected entry's parent.
    var newEntryParent: String? {
        guard let dn = selectedDN, !dn.isEmpty else { return server?.defaultNamingContext }
        let kind = inspector.entry.map(ObjectKind.classify) ?? .other
        return kind.isContainer ? dn : (DN.parent(dn) ?? dn)
    }

    struct Notice: Identifiable, Equatable {
        let id = UUID()
        var message: String
        var isError: Bool
    }

    /// A certificate the system refused, waiting for the user to decide.
    var pendingTrustFailure: CertificateTrustFailure?
    /// The profile binds with a password and none is known; the UI asks.
    var passwordRequest: PasswordRequest?

    struct PasswordRequest: Identifiable, Equatable {
        let id = UUID()
        var message: String?
    }

    let tree: TreeModel
    let search: SearchModel
    let inspector: InspectorModel

    private(set) var selectedDN: String?
    private var backStack: [String] = []
    private var forwardStack: [String] = []
    var canGoBack: Bool { !backStack.isEmpty }
    var canGoForward: Bool { !forwardStack.isEmpty }

    @ObservationIgnored private var connection: LDAPConnection?
    @ObservationIgnored private var password: String?
    @ObservationIgnored private var connectTask: Task<Void, Never>?
    @ObservationIgnored private var reconnectTask: Task<LDAPConnection, Error>?
    /// The user turned editing on or off; the app remembers it.
    @ObservationIgnored var onReadOnlyChange: ((Bool) -> Void)?
    /// The user chose to always trust a certificate, presented by this host and port.
    @ObservationIgnored var onPinCertificate: ((_ fingerprint: String, _ host: String, _ port: Int) -> Void)?
    /// Certificates trusted until disconnecting ("Trust Once"), for this
    /// profile's server only: forgotten when it changes.
    @ObservationIgnored private var trustedOnce: [String] = []
    /// The server that presented `pendingTrustFailure`'s certificate.
    @ObservationIgnored private var pendingTrustEndpoint: (host: String, port: Int)?
    @ObservationIgnored private var noticeTask: Task<Void, Never>?

    init(profile: ConnectionProfile) {
        id = profile.id
        self.profile = profile
        tree = TreeModel()
        search = SearchModel()
        inspector = InspectorModel()
        tree.session = self
        search.session = self
        inspector.session = self
    }

    var isMicrosoft: Bool { server?.kind.isMicrosoft ?? false }

    /// The Active Directory tools apply: domain information, password
    /// policies, account status across DCs, replication metadata.
    var hasADTools: Bool { isMicrosoft || domainLooksLikeAD }

    /// Changes may be made: connected, and the profile is not read-only.
    var canWrite: Bool { phase.isConnected && !profile.readOnly }

    /// The entry may be renamed, moved, duplicated or deleted: not the root
    /// DSE, and not the top of a naming context, whose deletion would take
    /// the whole directory with it.
    func canChangeEntry(_ dn: String) -> Bool {
        guard canWrite, !dn.isEmpty else { return false }
        let id = DN.normalized(dn)
        return !tree.roots.contains(id) && !(server?.namingContexts ?? []).contains { DN.normalized($0) == id }
    }

    var statusLine: String {
        switch phase {
        case .idle: return "Not connected"
        case .connecting: return "Connecting to \(profile.host)…"
        case .failed(let message): return message
        case .connected:
            var parts = [server?.kind.label ?? "LDAP", profile.host]
            parts.append(isSecure ? (profile.trust.trustAnyCertificate ? "TLS, certificate not checked" : "TLS") : "unencrypted")
            if let identity { parts.append(identity == "anonymous" ? "anonymous" : identity.replacingOccurrences(of: "dn:", with: "")) }
            return parts.joined(separator: " · ")
        }
    }

    // MARK: Connecting

    func connect(password supplied: String? = nil) {
        connectTask?.cancel()
        connectTask = Task { await performConnect(supplied) }
    }

    /// Bumped by every connect and disconnect. Work started for an earlier
    /// connection checks it and stops rather than bringing that connection
    /// back after the user disconnected or connected anew.
    @ObservationIgnored private var generation = 0
    var connectionGeneration: Int { generation }

    func disconnect() {
        generation += 1
        connectTask?.cancel()
        reconnectTask?.cancel()
        reconnectTask = nil
        trustedOnce = []
        pendingTrustFailure = nil
        // Edit › Undo needs the connection; the history stays to read.
        undoManager?.removeAllActions(withTarget: self)
        let old = connection
        let catalog = globalCatalogConnection
        connection = nil
        globalCatalogConnection = nil
        Task {
            await old?.close()
            await catalog?.close()
        }
        phase = .idle
        server = nil
        identity = nil
        isSecure = false
        schema = nil
        domainLooksLikeAD = false
        domainSID = nil
        guidNames = nil
        sidNames = [:]
        cachedForestDomains = nil
        tree.clear()
        search.clear()
        inspector.clear()
        selectedDN = nil
        backStack.removeAll()
        forwardStack.removeAll()
    }

    /// Takes edits from the profile editor. Anything that changes where or how
    /// to connect drops the connection, since it no longer matches the profile.
    func update(_ newProfile: ConnectionProfile) {
        let reconnectNeeded = newProfile.options.host != profile.options.host || newProfile.port != profile.port
            || newProfile.security != profile.security || newProfile.authentication != profile.authentication
            || newProfile.bindName != profile.bindName || newProfile.baseDN != profile.baseDN
            || newProfile.trust != profile.trust
        let serverChanged = newProfile.options.host.lowercased() != profile.options.host.lowercased()
            || newProfile.port != profile.port || newProfile.security != profile.security
        let identityChanged = newProfile.bindName != profile.bindName || newProfile.authentication != profile.authentication
        profile = newProfile
        if serverChanged {
            trustedOnce = []
            pendingTrustFailure = nil
        }
        // Changes made on one server, or as one user, are not undone on or as
        // another: the history starts again.
        if serverChanged || identityChanged {
            history.removeAll()
            undoManager?.removeAllActions(withTarget: self)
        }
        if reconnectNeeded {
            password = nil
            if phase != .idle { disconnect() }
        }
    }

    /// Hands this connection's password to a connection to another domain of
    /// the same forest, for the same user, so it is not asked for again. Only
    /// over encryption the other connection checks: it must not send it in
    /// clear text, nor to whoever answers with any certificate. A saved
    /// connection that accepts any certificate asks for it, as the keychain
    /// keeps a password apart for such a connection.
    func lendPassword(to other: DirectorySession) {
        guard let password, other.profile.authentication == .simple, other.profile.security != .none,
              !other.profile.trust.trustAnyCertificate,
              other.profile.bindName.caseInsensitiveCompare(profile.bindName) == .orderedSame else { return }
        other.usePassword(password)
    }

    /// A password typed in the profile editor replaces the remembered one for
    /// the next connect or reconnect.
    func usePassword(_ newPassword: String) {
        password = newPassword
    }

    /// The user looked at the certificate and chose to trust it: for this
    /// session only (`once`), or pinned to the profile.
    func trustPendingCertificate(once: Bool = false) {
        guard let failure = pendingTrustFailure else { return }
        pendingTrustFailure = nil
        // Only for the server that presented it, if the profile changed meanwhile.
        guard let endpoint = pendingTrustEndpoint, endpoint.host == profile.options.host, endpoint.port == profile.options.port else { return }
        if once {
            trustedOnce.append(failure.sha256Fingerprint)
        } else {
            if !profile.trust.pinnedFingerprints.contains(failure.sha256Fingerprint) {
                profile.trust.pinnedFingerprints.append(failure.sha256Fingerprint)
            }
            onPinCertificate?(failure.sha256Fingerprint, endpoint.host, endpoint.port)
        }
        connect()
    }

    /// Turns editing on or off for this profile, and remembers it.
    func setReadOnly(_ readOnly: Bool) {
        guard profile.readOnly != readOnly else { return }
        profile.readOnly = readOnly
        onReadOnlyChange?(readOnly)
    }

    private func performConnect(_ supplied: String?) async {
        if profile.authentication == .simple {
            if let supplied {
                password = supplied
            } else if password == nil, profile.savePassword {
                switch Keychain.password(for: profile) {
                case .found(let saved):
                    password = saved
                case .savedForAnotherConnection:
                    // The server, user or security changed since: the password
                    // is not sent anywhere it was not saved for.
                    passwordRequest = PasswordRequest(message: "The saved password belongs to this connection's earlier server, user or security settings. Enter it again to use it here.")
                    return
                case .none:
                    break
                }
            }
            guard let password, !password.isEmpty else {
                passwordRequest = PasswordRequest()
                return
            }
        }
        generation += 1
        let mine = generation
        /// False once the user disconnected or connected again meanwhile.
        func current() -> Bool { generation == mine && !Task.isCancelled }
        if let old = connection { await old.close() }
        connection = nil
        phase = .connecting
        domainSID = nil
        domainLooksLikeAD = false
        do {
            let fresh = try await openConnection()
            let root = try await fresh.rootDSE()
            guard current() else { await fresh.close(); return }
            let info = ServerInfo(rootDSE: root)
            let secure = await fresh.isSecure
            var who = try? await fresh.whoAmI()
            if profile.authentication == .simple, who == nil || who == "anonymous" {
                who = profile.bindName
            }
            var sid: String?
            var looksLikeAD = false
            if let base = info.defaultNamingContext,
               let domain = try? await fresh.read(base, attributes: ["objectSid", "objectClass"]) {
                sid = domain.values("objectSid").first.flatMap(ADValues.sidString)
                looksLikeAD = domain.hasObjectClass("domainDNS")
            }
            guard current() else { await fresh.close(); return }
            connection = fresh
            server = info
            isSecure = secure
            identity = who
            domainSID = sid
            domainLooksLikeAD = looksLikeAD
            schema = nil
            Task { [weak self] in
                let loaded = try? await fresh.schema(rootDSE: root)
                guard let self, self.generation == mine else { return }
                self.schema = loaded
            }
            if supplied != nil, profile.savePassword, let password {
                Keychain.setPassword(password, for: profile)
            }
            phase = .connected
            let roots = rootDNs(info)
            await tree.reset(roots: roots)
            search.prepare(base: roots.first ?? "")
            if let first = roots.first {
                await tree.expand(DN.normalized(first))
                guard current() else { return }
                tree.selection = DN.normalized(first)
                select(first, recordHistory: false)
            }
        } catch is CancellationError {
            if generation == mine { phase = .idle }
        } catch where generation != mine {
            // Disconnected or connected again meanwhile: this attempt's outcome no longer matters.
        } catch LDAPError.untrustedCertificate(let failure) {
            pendingTrustEndpoint = (profile.options.host, profile.options.port)
            pendingTrustFailure = failure
            phase = .failed("The server's certificate is not trusted.")
        } catch let error as LDAPError where error.resultCode == .invalidCredentials {
            password = nil
            phase = .failed(error.localizedDescription)
            if profile.authentication == .simple {
                passwordRequest = PasswordRequest(message: error.localizedDescription)
            }
        } catch {
            phase = .failed(error.localizedDescription)
        }
        if case .failed(let message) = phase { remember(message) }
    }

    /// Signs a fresh connection in the way the profile says.
    private func signIn(_ connection: LDAPConnection) async throws {
        switch profile.authentication {
        case .simple: try await connection.bind(dn: profile.bindName, password: password ?? "")
        case .kerberos: try await connection.bindKerberos()
        case .anonymous: break
        }
    }

    private func openConnection() async throws -> LDAPConnection {
        var options = profile.options
        options.trust.pinnedFingerprints += trustedOnce
        let fresh = LDAPConnection(options)
        do {
            try await fresh.open()
            try await signIn(fresh)
        } catch {
            await fresh.close()
            throw error
        }
        return fresh
    }

    /// A separate connection to another server (another domain controller)
    /// with this profile's credentials. The caller closes it.
    ///
    /// The host comes from directory data, so the password goes there only
    /// encrypted, and only to a server whose certificate this Mac trusts: the
    /// certificates trusted for this profile's own server are not carried over.
    func openConnection(to host: String, port: Int? = nil, timeout: TimeInterval) async throws -> LDAPConnection {
        guard profile.security != .none || profile.authentication != .simple else {
            throw LDAPError.connectionFailed("Not contacted: this connection is not encrypted, so signing in there would send the password in clear text.")
        }
        var options = profile.options
        options.host = host
        if let port { options.port = port }
        options.timeout = timeout
        if host.caseInsensitiveCompare(profile.options.host) == .orderedSame {
            options.trust.pinnedFingerprints += trustedOnce
        } else {
            options.trust = TrustPolicy()
        }
        let other = LDAPConnection(options)
        do {
            try await other.open()
            try await signIn(other)
        } catch {
            await other.close()
            throw error
        }
        return other
    }

    /// The configured base, or every naming context with the default first.
    private func rootDNs(_ info: ServerInfo) -> [String] {
        let base = profile.baseDN.trimmingCharacters(in: .whitespaces)
        if !base.isEmpty { return [base] }
        var contexts = info.namingContexts
        if let preferred = info.defaultNamingContext,
           let index = contexts.firstIndex(where: { DN.isSame($0, preferred) }) {
            contexts.insert(contexts.remove(at: index), at: 0)
        }
        return contexts
    }

    // MARK: Running requests

    /// Runs `body` on the connection. If the connection turns out to be gone
    /// (AD drops idle connections after 15 minutes; a VPN reconnects), opens a
    /// new one and tries once more.
    func run<T>(_ body: (LDAPConnection) async throws -> T, replayAfterLoss: Bool = true) async throws -> T {
        guard phase == .connected, let current = connection else { throw LDAPError.notConnected }
        let mine = generation
        do {
            let result = try await body(current)
            lastExchange = Date()
            return result
        } catch let error as LDAPError where error.isConnectionLoss {
            // Closed by Disconnect (or a new connect), not lost: do not reopen it.
            guard generation == mine, phase == .connected else { throw LDAPError.notConnected }
            let fresh = try await reconnect(replacing: current, generation: mine)
            // A change is sent again only if it never left: otherwise the server
            // may have made it, and an increment or a password change would
            // happen twice, or fail for having happened.
            guard replayAfterLoss || error == .notConnected else { throw WriteInterruptedError() }
            let result = try await body(fresh)
            lastExchange = Date()
            return result
        }
    }

    /// When the connection last answered.
    @ObservationIgnored private var lastExchange = Date.distantPast

    struct WriteInterruptedError: LocalizedError {
        var errorDescription: String? {
            "The connection was lost while the change was being sent, so it may or may not have been made. Forester has reconnected; check the entry before trying again."
        }
    }

    private func reconnect(replacing old: LDAPConnection, generation mine: Int) async throws -> LDAPConnection {
        if let connection, connection !== old, await connection.isAlive { return connection }
        if let reconnectTask { return try await reconnectTask.value }
        let task = Task { try await openConnection() }
        reconnectTask = task
        defer { if generation == mine { reconnectTask = nil } }
        do {
            let fresh = try await task.value
            guard generation == mine, phase == .connected else {
                await fresh.close()
                throw LDAPError.notConnected
            }
            connection = fresh
            return fresh
        } catch {
            if generation == mine, !(error is CancellationError) { phase = .failed(error.localizedDescription) }
            throw error
        }
    }

    // MARK: Changing the directory

    struct ReadOnlyError: LocalizedError {
        var errorDescription: String? {
            "This connection is read-only. Click Read-only in the toolbar (or press ⌥⌘E) to allow changes."
        }
    }

    /// Runs a change on the connection, refusing when the profile is read-only.
    func write<T>(_ body: (LDAPConnection) async throws -> T) async throws -> T {
        guard !profile.readOnly else { throw ReadOnlyError() }
        // A server closes a connection left idle (Active Directory after 15
        // minutes), which the app learns only by using it. A read first finds
        // that out and reconnects, so the change goes over a connection that
        // just answered, and is not sent twice.
        if Date().timeIntervalSince(lastExchange) > 30 {
            _ = try? await run { try await $0.read("", attributes: ["1.1"]) }
        }
        return try await run(body, replayAfterLoss: false)
    }

    /// Makes a change and reports it: `done` on success, the server's reason on
    /// failure. Reloads the entry being shown, refreshes the listed tree
    /// containers, and opens `select` afterwards. Returns whether it worked, so
    /// a sheet can close only on success.
    ///
    /// `undo` says how to take the change back; the change history and
    /// Edit › Undo use it.
    @discardableResult
    func change(_ done: String, refreshing containers: [String] = [], select target: String? = nil,
                undo plan: UndoPlan? = nil, registersUndo: Bool = true,
                _ body: @escaping (LDAPConnection) async throws -> Void) async -> Bool {
        var failure: Error?
        var before: LDAPEntry??
        if case .attributes(let dn, let names, let controls)? = plan, !profile.readOnly {
            before = await snapshot(dn, names, controls: controls)
        }
        do {
            try await write(body)
        } catch {
            failure = error
        }
        if failure == nil {
            await record(done, plan: plan ?? .impossible(dn: selectedDN ?? "", why: "This change cannot be undone here."),
                         before: before, registering: registersUndo, change: body)
        }
        if let failure {
            report(failure.localizedDescription, isError: true)
            // Part of it may have happened (a subtree delete stopped at a
            // protected child), so the tree must not keep showing what is gone.
            guard !(failure is ReadOnlyError), phase == .connected else { return false }
        } else {
            report(done, isError: false)
        }
        for container in containers {
            let key = container.isEmpty ? TreeModel.rootDSEKey : DN.normalized(container)
            if tree.node(key)?.children != nil { await tree.refresh(key) }
        }
        if failure != nil {
            inspector.reload()
            return false
        }
        if let target {
            open(target)
            await tree.reveal(target)
        } else {
            inspector.reload()
        }
        return true
    }

    private func remember(_ error: String) {
        recentErrors.append((Date(), error))
        if recentErrors.count > 20 { recentErrors.removeFirst(recentErrors.count - 20) }
    }

    func report(_ message: String, isError: Bool) {
        if isError { remember(message) }
        noticeTask?.cancel()
        notice = Notice(message: message, isError: isError)
        let id = notice?.id
        noticeTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: isError ? 9_000_000_000 : 4_000_000_000)
            guard !Task.isCancelled, self?.notice?.id == id else { return }
            self?.notice = nil
        }
    }

    // MARK: Navigation

    func select(_ dn: String?, recordHistory: Bool = true) {
        guard dn != selectedDN || inspector.entry == nil else { return }
        if recordHistory, let current = selectedDN, current != dn {
            backStack.append(current)
            forwardStack.removeAll()
        }
        selectedDN = dn
        inspector.load(dn)
    }

    /// Opens an entry from a link: shows it in the inspector and highlights it
    /// in the tree if the tree has it loaded.
    func open(_ dn: String) {
        select(dn)
        let key = DN.normalized(dn)
        if tree.node(key) != nil { tree.selection = key }
    }

    func goBack() {
        guard let previous = backStack.popLast() else { return }
        if let current = selectedDN { forwardStack.append(current) }
        selectedDN = previous
        inspector.load(previous)
        syncTreeSelection()
    }

    func goForward() {
        guard let next = forwardStack.popLast() else { return }
        if let current = selectedDN { backStack.append(current) }
        selectedDN = next
        inspector.load(next)
        syncTreeSelection()
    }

    func reveal(_ dn: String) {
        mode = .browse
        Task { await tree.reveal(dn) }
    }

    func searchBeneath(_ dn: String) {
        search.base = dn
        mode = .search
    }

    private func syncTreeSelection() {
        guard let selectedDN else { return }
        let key = DN.normalized(selectedDN)
        tree.selection = tree.node(key) != nil ? key : nil
    }
}
