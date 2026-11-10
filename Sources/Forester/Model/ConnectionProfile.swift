// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import LDAPKit
import Observation
import Security

/// A saved server: where it is, how to secure the connection, and how to bind.
struct ConnectionProfile: Codable, Identifiable, Hashable {
    enum Authentication: String, Codable, CaseIterable {
        case anonymous, simple, kerberos

        var label: String {
            switch self {
            case .anonymous: return "Anonymous"
            case .simple: return "Name and password"
            case .kerberos: return "Kerberos ticket"
            }
        }
    }

    var id = UUID()
    var name = ""
    var host = ""
    var port = 389
    var security: LDAPConnection.Security = .startTLS
    var authentication: Authentication = .simple
    /// A DN, or for Active Directory `user@domain` or `DOMAIN\user`.
    var bindName = ""
    var savePassword = true
    /// Where browsing starts. Empty means the server's naming contexts.
    var baseDN = ""
    var pageSize = 500
    var timeoutSeconds = 30
    var trust = TrustPolicy()
    /// No changes are sent to the directory while this is on. On by default, so
    /// a new connection to a production directory cannot be changed by accident.
    var readOnly = true

    init() {}

    var displayName: String { name.isEmpty ? (host.isEmpty ? "New connection" : host) : name }

    /// Forum Systems' public LDAP test server: a few people and groups that
    /// anyone may read, so Forester can be tried before there is a directory
    /// of one's own to point it at. It offers no TLS; nothing is sent to it
    /// but anonymous searches.
    static let sampleHost = "ldap.forumsys.com"

    static var sample: ConnectionProfile {
        var profile = ConnectionProfile()
        profile.name = "Sample directory"
        profile.host = sampleHost
        profile.port = 389
        profile.security = .none
        profile.authentication = .anonymous
        profile.savePassword = false
        profile.baseDN = "dc=example,dc=com"
        return profile
    }

    var isSample: Bool { host.caseInsensitiveCompare(Self.sampleHost) == .orderedSame }

    var endpoint: String {
        let scheme = security == .ldaps ? "ldaps" : "ldap"
        return "\(scheme)://\(host):\(port)"
    }

    static let portRange = 1...65535
    static let pageSizeRange = 50...5000
    static let timeoutRange = 5...300

    var options: LDAPConnection.Options {
        LDAPConnection.Options(host: host.trimmingCharacters(in: .whitespaces),
                               port: Self.portRange.contains(port) ? port : security.defaultPort, security: security,
                               timeout: TimeInterval(timeoutSeconds.clamped(to: Self.timeoutRange)), trust: trust)
    }

    // Decoding tolerates fields added in later versions being absent.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        host = try c.decodeIfPresent(String.self, forKey: .host) ?? ""
        port = try c.decodeIfPresent(Int.self, forKey: .port) ?? 389
        security = try c.decodeIfPresent(LDAPConnection.Security.self, forKey: .security) ?? .startTLS
        authentication = try c.decodeIfPresent(Authentication.self, forKey: .authentication) ?? .simple
        bindName = try c.decodeIfPresent(String.self, forKey: .bindName) ?? ""
        savePassword = try c.decodeIfPresent(Bool.self, forKey: .savePassword) ?? true
        baseDN = try c.decodeIfPresent(String.self, forKey: .baseDN) ?? ""
        // A file can come from anywhere: numbers are kept to what the editor allows.
        if !Self.portRange.contains(port) { port = security.defaultPort }
        pageSize = (try c.decodeIfPresent(Int.self, forKey: .pageSize) ?? 500).clamped(to: Self.pageSizeRange)
        timeoutSeconds = (try c.decodeIfPresent(Int.self, forKey: .timeoutSeconds) ?? 30).clamped(to: Self.timeoutRange)
        trust = try c.decodeIfPresent(TrustPolicy.self, forKey: .trust) ?? TrustPolicy()
        // Profiles saved before editing existed were made for a read-only app.
        readOnly = try c.decodeIfPresent(Bool.self, forKey: .readOnly) ?? true
    }
}

/// Saved profiles, kept as JSON in Application Support, or in iCloud Drive so
/// they follow the user to their other Macs. Passwords are never in this file;
/// they live in each Mac's keychain.
@MainActor @Observable
final class ProfileStore {
    private(set) var profiles: [ConnectionProfile] = []
    private(set) var loadError: String?
    private(set) var url: URL
    private(set) var inICloudDrive: Bool

    @ObservationIgnored private let fixedDirectory: URL?
    @ObservationIgnored private var loadedModification: Date?
    /// Called after the list was re-read from disk or replaced by an import,
    /// so open sessions can take the new versions.
    @ObservationIgnored var onReload: (() -> Void)?
    static let iCloudKey = "connectionsInICloudDrive"
    static let folderName = "Forester"
    /// What the app was called before it was Forester; its saved connections,
    /// iCloud setting and keychain passwords are carried over once.
    static let formerFolderName = "LDAP Explorer"
    static let formerBundleIdentifier = "live.versaminds.LDAPExplorer"

    static var localDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent(folderName, isDirectory: true)
    }

    /// iCloud Drive's folder, when the user has iCloud Drive turned on. Never
    /// for the App Store build: the sandbox keeps it out of iCloud Drive's folder.
    static var iCloudDriveRoot: URL? {
        guard !ForesterInfo.fromAppStore else { return nil }
        let root = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Mobile Documents/com~apple~CloudDocs", isDirectory: true)
        return FileManager.default.fileExists(atPath: root.path) ? root : nil
    }

    init(directory: URL? = nil) {
        fixedDirectory = directory
        // The App Store build never had the former name, and its sandbox could
        // not read that name's folders anyway.
        if directory == nil, !ForesterInfo.fromAppStore { Self.carryOverFromFormerName() }
        let wantsICloud = directory == nil && UserDefaults.standard.bool(forKey: Self.iCloudKey) && Self.iCloudDriveRoot != nil
        inICloudDrive = wantsICloud
        url = Self.location(directory: directory, iCloud: wantsICloud)
        load()
    }

    private static func location(directory: URL?, iCloud: Bool) -> URL {
        let base = directory ?? (iCloud ? iCloudDriveRoot!.appendingPathComponent(folderName, isDirectory: true) : localDirectory)
        return base.appendingPathComponent("connections.json")
    }

    /// Copies connections saved under the former name to Forester's folders,
    /// locally and in iCloud Drive, and the iCloud Drive setting. The old files
    /// are left as they were, so nothing is lost if this goes wrong.
    static func carryOverFromFormerName(fileManager: FileManager = .default) {
        let defaults = UserDefaults.standard
        if defaults.object(forKey: iCloudKey) == nil,
           let former = UserDefaults(suiteName: formerBundleIdentifier), former.object(forKey: iCloudKey) != nil {
            defaults.set(former.bool(forKey: iCloudKey), forKey: iCloudKey)
        }
        let applicationSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        var places = [applicationSupport]
        // iCloud Drive only for someone who kept their connections there:
        // looking inside it can make macOS ask for permission.
        if UserDefaults(suiteName: formerBundleIdentifier)?.bool(forKey: iCloudKey) == true, let iCloud = iCloudDriveRoot {
            places.append(iCloud)
        }
        for place in places {
            carryOver(from: place.appendingPathComponent(formerFolderName, isDirectory: true),
                      to: place.appendingPathComponent(folderName, isDirectory: true), fileManager: fileManager)
        }
    }

    /// connections.json from one folder to another, unless the new one has its own.
    static func carryOver(from old: URL, to new: URL, fileManager: FileManager = .default) {
        let source = old.appendingPathComponent("connections.json")
        let destination = new.appendingPathComponent("connections.json")
        guard fileManager.fileExists(atPath: source.path), !fileManager.fileExists(atPath: destination.path) else { return }
        try? fileManager.createDirectory(at: new, withIntermediateDirectories: true)
        try? fileManager.copyItem(at: source, to: destination)
    }

    /// Moves the connections file into or out of iCloud Drive. Connections
    /// already there (from another Mac) are kept and merged with these.
    func setICloudDrive(_ on: Bool) {
        guard fixedDirectory == nil, on != inICloudDrive, !on || Self.iCloudDriveRoot != nil else { return }
        reloadIfChanged()
        let current = profiles
        UserDefaults.standard.set(on, forKey: Self.iCloudKey)
        inICloudDrive = on
        url = Self.location(directory: nil, iCloud: on)
        if on {
            // Other Macs' connections already in iCloud Drive join this Mac's.
            profiles = []
            load()
            let incoming = profiles
            profiles = current + incoming.filter { other in !current.contains { $0.id == other.id } }
        } else {
            // The local file was not kept up to date meanwhile: the list as it
            // is now is the one to keep, not the older copy.
            profiles = current
        }
        persist()
        onReload?()
    }

    /// Picks up changes another Mac made through iCloud Drive. Saved
    /// passwords stay where they are: a connection missing from the file may
    /// only be a sync conflict, and a changed one no longer gets its password
    /// (see `Keychain`). Deleting a connection here deletes its password.
    @discardableResult
    func reloadIfChanged() -> Bool {
        let modified = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.modificationDate] as? Date
        guard modified != nil, modified != loadedModification else { return false }
        load()
        onReload?()
        return true
    }

    /// Changes one profile as it is now on disk: a session that turns editing
    /// on, or pins a certificate, must not write back an older copy of the rest.
    func update(_ id: UUID, _ change: (inout ConnectionProfile) -> Void) {
        reloadIfChanged()
        guard let index = profiles.firstIndex(where: { $0.id == id }) else { return }
        change(&profiles[index])
        persist()
    }

    /// Writes the chosen profiles to a file another Mac or colleague can
    /// import. Passwords are not included.
    func export(_ chosen: [ConnectionProfile], to destination: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(chosen).write(to: destination, options: .atomic)
    }

    /// Adds profiles from an exported file. A profile already here (same id)
    /// is replaced by the imported one. Returns how many were imported.
    ///
    /// A connection file can come from anyone, so what it carries is not taken
    /// on trust: an imported connection is read-only, and trusts no certificate
    /// the user has not approved here (no pins, no "accept any"). A saved
    /// password stays with the connection it was saved for (see `Keychain`).
    @discardableResult
    func importProfiles(from source: URL) throws -> Int {
        let data = try Data(contentsOf: source)
        let imported: [ConnectionProfile]
        if let list = try? JSONDecoder().decode([ConnectionProfile].self, from: data) {
            imported = list
        } else {
            imported = [try JSONDecoder().decode(ConnectionProfile.self, from: data)]
        }
        reloadIfChanged()
        for var profile in imported {
            profile.readOnly = true
            profile.trust = TrustPolicy()
            if let index = profiles.firstIndex(where: { $0.id == profile.id }) {
                profiles[index] = profile
            } else {
                profiles.append(profile)
            }
        }
        persist()
        onReload?()
        return imported.count
    }

    func profile(_ id: UUID?) -> ConnectionProfile? {
        profiles.first { $0.id == id }
    }

    func save(_ profile: ConnectionProfile) {
        reloadIfChanged()
        if let index = profiles.firstIndex(where: { $0.id == profile.id }) {
            profiles[index] = profile
        } else {
            profiles.append(profile)
        }
        persist()
    }

    func delete(_ id: UUID) {
        reloadIfChanged()
        profiles.removeAll { $0.id == id }
        Keychain.deletePassword(for: id)
        persist()
    }

    func duplicate(_ id: UUID) -> ConnectionProfile? {
        guard var copy = profile(id) else { return nil }
        let original = copy.id
        copy.id = UUID()
        copy.name = "\(copy.displayName) copy"
        if let source = profile(original), let password = Keychain.password(for: source).password {
            Keychain.setPassword(password, for: copy)
        }
        save(copy)
        return copy
    }

    func move(from source: IndexSet, to destination: Int) {
        // Offsets refer to the list on screen; if the file changed meanwhile they
        // may not, so the move waits for the next one.
        guard !reloadIfChanged() else { return }
        profiles.move(fromOffsets: source, toOffset: destination)
        persist()
    }

    private func load() {
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        do {
            // Coordinated, so a file iCloud Drive has evicted is downloaded first.
            var coordinationError: NSError?
            var data: Data?
            var readError: Error?
            NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &coordinationError) { readURL in
                do { data = try Data(contentsOf: readURL) } catch { readError = error }
            }
            if let error = coordinationError ?? readError { throw error }
            profiles = try JSONDecoder().decode([ConnectionProfile].self, from: data ?? Data())
            loadedModification = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.modificationDate] as? Date
            loadError = nil
        } catch {
            // Keep the unreadable file rather than overwrite it on the next save.
            let backup = url.deletingPathExtension().appendingPathExtension("unreadable.json")
            try? FileManager.default.removeItem(at: backup)
            try? FileManager.default.copyItem(at: url, to: backup)
            loadError = "Saved connections could not be read (\(error.localizedDescription)). A copy was kept as \(backup.lastPathComponent)."
        }
    }

    private func persist() {
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(profiles)
            var coordinationError: NSError?
            var writeError: Error?
            NSFileCoordinator().coordinate(writingItemAt: url, options: .forReplacing, error: &coordinationError) { writeURL in
                do { try data.write(to: writeURL, options: .atomic) } catch { writeError = error }
            }
            if let error = coordinationError ?? writeError { throw error }
            loadedModification = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.modificationDate] as? Date
        } catch {
            loadError = "Connections could not be saved: \(error.localizedDescription)"
        }
    }
}

/// Bind passwords, one generic-password item per profile, each tied to the
/// connection it was saved for.
///
/// The tie is what keeps the password safe from the profiles file: anything
/// that can change that file (another process, a synced copy, an imported
/// connection) could otherwise point a profile at another server and have the
/// saved password sent there, without ever touching the keychain. So each item
/// records the server, port, encryption, sign-in name and certificate checking
/// it was saved with, and is handed out only while the profile still matches.
/// Otherwise the user is asked for the password again.
///
/// Reading an item can make macOS ask for the Mac's password: twice when the
/// app's signature has changed since the item was saved (once to let this copy
/// of the app read it, once for the item's partition list), which an app
/// signed ad hoc does with every build. So each password is read from the
/// keychain at most once while the app runs, saying whether one is saved
/// does not read it, and an unchanged password is not written again.
enum Keychain {
    static let service = "Forester"
    /// Passwords saved before the app was renamed; each moves to `service`
    /// the first time it is needed.
    static let formerService = "LDAP Explorer"

    enum Lookup: Equatable {
        case found(String)
        /// A password is saved, but for a different server or setting.
        case savedForAnotherConnection
        case none

        var password: String? {
            if case .found(let password) = self { return password }
            return nil
        }
    }

    /// What a password is saved for. Pinned certificates are not part of it:
    /// the user pins them while connecting, and a pin alone is no use to anyone
    /// who cannot also intercept the real server's traffic.
    static func connection(of profile: ConnectionProfile) -> Data {
        let parts = ["forester-1", profile.host.trimmingCharacters(in: .whitespaces).lowercased(), String(profile.port),
                     profile.security.rawValue, profile.bindName.trimmingCharacters(in: .whitespaces).lowercased(),
                     profile.trust.trustAnyCertificate ? "any-certificate" : "checked-certificate"]
        return Data(parts.joined(separator: "\n").utf8)
    }

    private struct Saved: Equatable {
        var password: String
        /// nil for an item saved before passwords were tied to a connection.
        var connection: Data?
    }

    private static let lock = NSLock()
    nonisolated(unsafe) private static var known: [UUID: Saved] = [:]
    #if DEBUG
    /// Passwords read from and written to the keychain itself (automation checks these).
    nonisolated(unsafe) static var reads = 0
    nonisolated(unsafe) static var writes = 0
    static func forgetKnown() { lock.withLock { known.removeAll() } }
    #endif

    private static func query(_ id: UUID, service: String = service) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: id.uuidString]
    }

    private static func read(_ id: UUID, service: String) -> Saved? {
        #if DEBUG
        reads += 1
        #endif
        var q = query(id, service: service)
        q[kSecReturnData as String] = true
        q[kSecReturnAttributes as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess, let found = item as? [String: Any],
              let data = found[kSecValueData as String] as? Data, let password = String(data: data, encoding: .utf8) else { return nil }
        return Saved(password: password, connection: found[kSecAttrGeneric as String] as? Data)
    }

    /// Whether an item exists, from its attributes alone: they are not
    /// encrypted, so this never asks for a password.
    private static func exists(_ id: UUID, service: String) -> Bool {
        var q = query(id, service: service)
        q[kSecReturnAttributes as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess
    }

    static func hasPassword(for id: UUID) -> Bool {
        if lock.withLock({ known[id] }) != nil { return true }
        return exists(id, service: service) || exists(id, service: formerService)
    }

    /// The password saved for this profile, if the profile still describes the
    /// connection it was saved for.
    static func password(for profile: ConnectionProfile) -> Lookup {
        let id = profile.id
        let expected = connection(of: profile)
        var saved: Saved
        if let cached = lock.withLock({ known[id] }) {
            saved = cached
        } else if let found = read(id, service: service) {
            saved = found
        } else if let former = read(id, service: formerService) {
            // From before the rename, and from before passwords were tied to a
            // connection: tied now, to this one.
            setPassword(former.password, for: profile)
            if read(id, service: service)?.password == former.password { SecItemDelete(query(id, service: formerService) as CFDictionary) }
            saved = Saved(password: former.password, connection: expected)
        } else {
            return .none
        }
        if saved.connection == nil {
            // Saved before passwords were tied to a connection: tie it to this one.
            SecItemUpdate(query(id) as CFDictionary, [kSecAttrGeneric as String: expected] as CFDictionary)
            saved.connection = expected
        }
        lock.withLock { known[id] = saved }
        return saved.connection == expected ? .found(saved.password) : .savedForAnotherConnection
    }

    /// Saves the password for this profile's connection. False when the
    /// keychain refused it (the user denied access, or the keychain is locked):
    /// the password is then asked for again next time.
    @discardableResult
    static func setPassword(_ password: String, for profile: ConnectionProfile) -> Bool {
        let id = profile.id
        let saved = Saved(password: password, connection: connection(of: profile))
        if lock.withLock({ known[id] }) == saved { return true }
        #if DEBUG
        writes += 1
        #endif
        let data = Data(password.utf8)
        var status = SecItemUpdate(query(id) as CFDictionary,
                                   [kSecValueData as String: data, kSecAttrGeneric as String: saved.connection!] as CFDictionary)
        if status == errSecItemNotFound {
            var q = query(id)
            q[kSecValueData as String] = data
            q[kSecAttrGeneric as String] = saved.connection
            q[kSecAttrLabel as String] = "Forester bind password"
            status = SecItemAdd(q as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            lock.withLock { known[id] = nil }
            return false
        }
        lock.withLock { known[id] = saved }
        return true
    }

    static func deletePassword(for id: UUID) {
        lock.withLock { known[id] = nil }
        SecItemDelete(query(id) as CFDictionary)
        SecItemDelete(query(id, service: formerService) as CFDictionary)
    }
}

extension Comparable {
    func clamped(to range: ClosedRange<Self>) -> Self { min(max(self, range.lowerBound), range.upperBound) }
}
