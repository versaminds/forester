// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import LDAPKit
import Observation
import Security

/// A saved server: where it is, how to secure the connection, and how to bind.
struct ConnectionProfile: Codable, Identifiable, Hashable {
    enum Authentication: String, Codable, CaseIterable {
        case anonymous, simple, scram, kerberos, certificate

        var label: String {
            switch self {
            case .anonymous: return "Anonymous"
            case .simple: return "Name and password"
            case .scram: return "Name and password (SCRAM)"
            case .kerberos: return "Kerberos ticket"
            case .certificate: return "Certificate"
            }
        }

        /// A password is typed, remembered in the keychain and asked for.
        var usesPassword: Bool { self == .simple || self == .scram }
    }

    var id = UUID()
    var name = ""
    var host = ""
    var port = 389
    var security: LDAPConnection.Security = .startTLS
    var authentication: Authentication = .simple
    /// A DN, or for Active Directory `user@domain` or `DOMAIN\user`; for
    /// SCRAM, the user name the server knows.
    var bindName = ""
    /// The SHA-256 of the keychain certificate a certificate sign-in shows.
    /// The certificate and its key stay in the keychain.
    var clientCertificate = ""
    var savePassword = true
    /// Where browsing starts. Empty means the server's naming contexts.
    var baseDN = ""
    var pageSize = 500
    var timeoutSeconds = 30
    var trust = TrustPolicy()
    /// No changes are sent to the directory while this is on. On by default, so
    /// a new connection to a production directory cannot be changed by accident.
    var readOnly = true
    /// The server and security `clientCertificate` was chosen for, on this
    /// Mac (`certificateBinding`); never read from the connections file.
    var clientCertificateFor = ""

    init() {}

    /// What a profile file holds. `clientCertificateFor` is this Mac's alone.
    enum CodingKeys: String, CodingKey {
        case id, name, host, port, security, authentication, bindName, clientCertificate, savePassword, baseDN
        case pageSize, timeoutSeconds, trust, readOnly
    }

    /// The server, port, security and certificate checking a client
    /// certificate is chosen for: changed, it is chosen again.
    var certificateBinding: String {
        [host.trimmingCharacters(in: .whitespaces).lowercased(), String(port), security.rawValue,
         trust.trustAnyCertificate ? "any-certificate" : "checked-certificate"].joined(separator: "\n")
    }

    /// A connection to `host` that signs in as `other` does: the same kind of
    /// sign-in, user and certificate. A certificate sign-in has no user name,
    /// so the name alone would match any of them.
    func signsIn(to host: String, as other: ConnectionProfile) -> Bool {
        self.host.trimmingCharacters(in: .whitespaces).lowercased() == host.lowercased()
            && authentication == other.authentication
            && bindName.caseInsensitiveCompare(other.bindName) == .orderedSame
            && clientCertificate == other.clientCertificate
    }

    /// The certificates trusted for a connection this profile's settings make
    /// to another server, or another port of its own (the global catalog,
    /// other domain controllers, another domain of the forest): the system's,
    /// and for its own host the certificates pinned for it, never "accept any".
    /// The password, or the client certificate, goes there with them.
    func trustForOtherConnection(to otherHost: String, trustedOnce: [String]) -> TrustPolicy {
        guard otherHost.caseInsensitiveCompare(options.host) == .orderedSame else { return TrustPolicy() }
        return TrustPolicy(pinnedFingerprints: trust.pinnedFingerprints + trustedOnce)
    }

    /// The chosen certificate is shown only to what it was chosen for.
    var certificateIsBoundHere: Bool { !clientCertificate.isEmpty && clientCertificateFor == certificateBinding }

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

    /// What could happen to a password typed for this connection, in words;
    /// nil when it goes only encrypted to a certificate that is checked.
    var passwordExposure: String? {
        guard authentication.usesPassword else { return nil }
        if security == .none {
            return authentication == .scram
                ? "Not encrypted: the password is not sent, but everything read travels in clear text."
                : "Not encrypted: the password is sent in clear text."
        }
        if trust.trustAnyCertificate {
            return "Any certificate is accepted: whoever is between this Mac and the server could read the password."
        }
        return nil
    }

    /// What travels readable on a connection without TLS, in words; nil with TLS.
    var plainConnectionNote: String? {
        guard security == .none else { return nil }
        switch authentication {
        case .kerberos: return "Without TLS, Kerberos encrypts this connection itself, and Forester connects only if the server agrees to that."
        case .scram: return "This connection is not encrypted: the password is not sent, but everything read travels in clear text."
        case .simple: return "This connection is not encrypted; the password and everything read travel in clear text."
        case .anonymous, .certificate: return "This connection is not encrypted; everything read travels in clear text."
        }
    }

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
        clientCertificate = try c.decodeIfPresent(String.self, forKey: .clientCertificate) ?? ""
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
        let modified = Self.modification(url), laterModified = Self.modification(laterURL)
        guard (modified != nil && modified != loadedModification) || laterModified != laterModification else { return false }
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
    /// Nor does it replace a connection here: one with the same id comes in as
    /// a connection of its own, unless it is the same one, which is left as it
    /// is. Returns how many were added.
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
        var added = 0
        for var profile in imported {
            profile = Self.asImported(profile)
            if let existing = profiles.first(where: { $0.id == profile.id }) {
                guard Self.asImported(existing) != profile else { continue }
                profile.id = UUID()
            }
            profiles.append(profile)
            added += 1
        }
        persist()
        onReload?()
        return added
    }

    /// What an imported connection may carry: no certificate trusted, no
    /// client certificate chosen (which of this Mac's certificates to show a
    /// server is chosen here, not by whoever wrote the file), and read-only.
    static func asImported(_ profile: ConnectionProfile) -> ConnectionProfile {
        var profile = profile
        profile.readOnly = true
        profile.trust = TrustPolicy()
        profile.clientCertificate = ""
        profile.clientCertificateFor = ""
        return profile
    }

    func profile(_ id: UUID?) -> ConnectionProfile? {
        profiles.first { $0.id == id }
    }

    /// `choosingCertificate`: the person chose the client certificate for
    /// the profile as it is now (in the connection editor), so it is shown
    /// to this server, port and security from now on.
    func save(_ profile: ConnectionProfile, choosingCertificate: Bool = false) {
        reloadIfChanged()
        var profile = profile
        if choosingCertificate {
            profile.clientCertificateFor = profile.clientCertificate.isEmpty ? "" : profile.certificateBinding
        }
        if let index = profiles.firstIndex(where: { $0.id == profile.id }) {
            profiles[index] = profile
        } else {
            profiles.append(profile)
        }
        persist()
    }

    // MARK: This Mac's own decisions
    //
    // Which certificates are trusted for a connection, whether changes are
    // allowed, and which client certificate it shows are decided on this
    // Mac and kept here, never taken from the connections file: anything
    // that can write that file (another process, a synced copy) could
    // otherwise pin its own certificate and catch the saved password, allow
    // changes, or pick one of this Mac's certificates to show.

    struct LocalSettings: Codable, Equatable {
        var pinnedFingerprints: [String] = []
        var trustAnyCertificate = false
        var readOnly = true
        var clientCertificate = ""
        var clientCertificateFor = ""

        init() {}

        init(_ profile: ConnectionProfile) {
            pinnedFingerprints = profile.trust.pinnedFingerprints
            trustAnyCertificate = profile.trust.trustAnyCertificate
            readOnly = profile.readOnly
            clientCertificate = profile.clientCertificate
            clientCertificateFor = profile.clientCertificateFor
        }

        func apply(to profile: inout ConnectionProfile) {
            profile.trust = TrustPolicy(pinnedFingerprints: pinnedFingerprints, trustAnyCertificate: trustAnyCertificate)
            profile.readOnly = readOnly
            profile.clientCertificate = clientCertificate
            profile.clientCertificateFor = clientCertificateFor
        }
    }

    /// Beside the local connections file, also when the connections are in
    /// iCloud Drive: these do not follow the user to another Mac.
    private var settingsURL: URL {
        (fixedDirectory ?? Self.localDirectory).appendingPathComponent("connection-settings.json")
    }
    @ObservationIgnored private var localSettings: [UUID: LocalSettings] = [:]
    @ObservationIgnored private var localSettingsLoaded = false

    /// Gives each profile this Mac's settings for it. The first time (this
    /// Mac had no settings yet, as on the first start of this version), they
    /// are taken from the file as this Mac last saved it; a connection that
    /// arrives later (from another Mac) starts read-only, trusting no
    /// certificate beyond the system's and showing none of this Mac's.
    private func applyLocalSettings(_ loaded: [ConnectionProfile]) -> [ConnectionProfile] {
        if !localSettingsLoaded {
            localSettingsLoaded = true
            if let data = try? Data(contentsOf: settingsURL), let saved = try? JSONDecoder().decode([UUID: LocalSettings].self, from: data) {
                localSettings = saved
            } else {
                for profile in loaded {
                    var settings = LocalSettings(profile)
                    // Bound to what it was set up for, as the person last saw it.
                    if !settings.clientCertificate.isEmpty { settings.clientCertificateFor = profile.certificateBinding }
                    localSettings[profile.id] = settings
                }
                saveLocalSettings()
            }
        }
        var added = false
        let applied = loaded.map { profile -> ConnectionProfile in
            var profile = profile
            if localSettings[profile.id] == nil {
                localSettings[profile.id] = LocalSettings()
                added = true
            }
            localSettings[profile.id]?.apply(to: &profile)
            return profile
        }
        if added { saveLocalSettings() }
        return applied
    }

    private func saveLocalSettings() {
        do {
            try FileManager.default.createDirectory(at: settingsURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(localSettings).write(to: settingsURL, options: .atomic)
        } catch {
            loadError = "This Mac's connection settings could not be saved: \(error.localizedDescription)"
        }
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

    // MARK: Two files, for Forester 1.1
    //
    // Forester 1.1 reads connections.json as a whole: one connection signing
    // in a way it does not know makes it set the file aside, and its next
    // save writes its own list over it, in iCloud Drive on every Mac. So
    // connections that sign in a way 1.1 does not know (SCRAM, a certificate,
    // and whatever comes later) live in a file of their own beside it, which
    // 1.1 never opens. 1.1 reads and writes the connections it knows; the
    // others, and the order of all of them, stay as they are.

    /// Beside connections.json; 1.1 does not know it is there.
    static let laterFileName = "connections-1.2.json"
    private var laterURL: URL { url.deletingLastPathComponent().appendingPathComponent(Self.laterFileName) }
    @ObservationIgnored private var laterModification: Date?
    /// Entries of the later file this version cannot read (written by a
    /// newer one), kept as they are and written back with the rest.
    @ObservationIgnored private var unreadableLater: [JSONValue] = []
    /// The later file could not be read at all: it is not written over.
    @ObservationIgnored private var laterUnreadable = false

    /// What the later file holds: its connections, and every connection's
    /// place in the list, since 1.1 keeps the order of only its own.
    private struct LaterFile: Codable {
        var order: [UUID]
        var profiles: [JSONValue]
    }

    private static func modification(_ url: URL) -> Date? {
        (try? FileManager.default.attributesOfItem(atPath: url.path))?[.modificationDate] as? Date
    }

    /// Coordinated, so a file iCloud Drive has evicted is downloaded first.
    private static func coordinatedRead(_ url: URL) throws -> Data {
        var coordinationError: NSError?
        var data: Data?
        var readError: Error?
        NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &coordinationError) { readURL in
            do { data = try Data(contentsOf: readURL) } catch { readError = error }
        }
        if let error = coordinationError ?? readError { throw error }
        return data ?? Data()
    }

    private static func coordinatedWrite(_ data: Data, to url: URL) throws {
        var coordinationError: NSError?
        var writeError: Error?
        NSFileCoordinator().coordinate(writingItemAt: url, options: .forReplacing, error: &coordinationError) { writeURL in
            do { try data.write(to: writeURL, options: .atomic) } catch { writeError = error }
        }
        if let error = coordinationError ?? writeError { throw error }
    }

    /// The connections 1.1 knows and the later ones, in the order last saved.
    private func merged(_ known: [ConnectionProfile]) -> [ConnectionProfile] {
        guard FileManager.default.fileExists(atPath: laterURL.path) else {
            unreadableLater = []
            laterUnreadable = false
            laterModification = nil
            return known
        }
        do {
            let later = try JSONDecoder().decode(LaterFile.self, from: try Self.coordinatedRead(laterURL))
            laterModification = Self.modification(laterURL)
            laterUnreadable = false
            var readable: [ConnectionProfile] = []
            unreadableLater = []
            for entry in later.profiles {
                if let profile = try? JSONDecoder().decode(ConnectionProfile.self, from: JSONEncoder().encode(entry)) {
                    readable.append(profile)
                } else {
                    unreadableLater.append(entry)
                }
            }
            // A connection in both (1.1 wrote back an old copy of one since
            // changed to a later kind of sign-in): the later one is the newer.
            let all = known.filter { profile in !readable.contains { $0.id == profile.id } } + readable
            let place = Dictionary(later.order.enumerated().map { ($1, $0) }, uniquingKeysWith: { first, _ in first })
            // Those the order does not name (added by 1.1 since) go last.
            return all.enumerated().sorted { a, b in
                (place[a.element.id] ?? Int.max, a.offset) < (place[b.element.id] ?? Int.max, b.offset)
            }.map(\.element)
        } catch {
            laterUnreadable = true
            loadError = "Connections saved by a newer Forester could not be read (\(error.localizedDescription)); \(Self.laterFileName) is left as it is."
            return known
        }
    }

    private func load() {
        guard FileManager.default.fileExists(atPath: url.path) else {
            profiles = applyLocalSettings(merged([]))
            return
        }
        do {
            let known = try JSONDecoder().decode([ConnectionProfile].self, from: try Self.coordinatedRead(url))
            loadedModification = Self.modification(url)
            loadError = nil
            unsavedUnreadable = false
            profiles = applyLocalSettings(merged(known))
        } catch {
            // The next save replaces the file (and, in iCloud Drive, every
            // Mac's copy), so each unreadable version is kept first, under a
            // name of its own: a newer Forester elsewhere may have written it.
            let modified = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.modificationDate] as? Date
            if modified == nil || modified != backedUpModification {
                let stamp = ISO8601DateFormatter.string(from: Date(), timeZone: .current, formatOptions: [.withFullDate, .withTime])
                    .replacingOccurrences(of: ":", with: "")
                let backup = url.deletingPathExtension().appendingPathExtension("unreadable-\(stamp).json")
                if (try? FileManager.default.copyItem(at: url, to: backup)) != nil {
                    backedUpModification = modified
                    unsavedUnreadable = false
                    loadError = "Saved connections could not be read (\(error.localizedDescription)). A copy was kept as \(backup.lastPathComponent)."
                } else {
                    unsavedUnreadable = true
                    loadError = "Saved connections could not be read (\(error.localizedDescription)), and no copy could be made, so changes are not saved over them."
                }
            }
        }
    }

    /// The last version that could not be read, already kept as a copy.
    @ObservationIgnored private var backedUpModification: Date?
    /// The file could be neither read nor copied: saving would lose it.
    @ObservationIgnored private var unsavedUnreadable = false

    private func persist() {
        // This Mac's settings are those of the profiles as they are here.
        localSettings = Dictionary(profiles.map { ($0.id, LocalSettings($0)) }, uniquingKeysWith: { first, _ in first })
        localSettingsLoaded = true
        saveLocalSettings()
        guard !unsavedUnreadable else { return }
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let known = profiles.filter(\.authentication.isKnownToVersion11)
            let later = profiles.filter { !$0.authentication.isKnownToVersion11 }
            try Self.coordinatedWrite(try encoder.encode(known), to: url)
            loadedModification = Self.modification(url)
            if !laterUnreadable, !later.isEmpty || !unreadableLater.isEmpty || FileManager.default.fileExists(atPath: laterURL.path) {
                let entries = try later.map { try JSONDecoder().decode(JSONValue.self, from: encoder.encode($0)) } + unreadableLater
                try Self.coordinatedWrite(try encoder.encode(LaterFile(order: profiles.map(\.id), profiles: entries)), to: laterURL)
                laterModification = Self.modification(laterURL)
            }
        } catch {
            loadError = "Connections could not be saved: \(error.localizedDescription)"
        }
    }
}

extension ConnectionProfile.Authentication {
    /// Forester 1.1 reads a connection signing in this way; one it does not
    /// is kept in the later file (see `ProfileStore`).
    var isKnownToVersion11: Bool { self == .anonymous || self == .simple || self == .kerberos }
}

/// Any JSON, kept as it was read: connections a newer Forester wrote, which
/// this one cannot read but must not lose.
indirect enum JSONValue: Codable, Hashable {
    case null, bool(Bool), number(Double), string(String), array([JSONValue]), object([String: JSONValue])

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let value = try? c.decode(Bool.self) { self = .bool(value) }
        else if let value = try? c.decode(Double.self) { self = .number(value) }
        else if let value = try? c.decode(String.self) { self = .string(value) }
        else if let value = try? c.decode([JSONValue].self) { self = .array(value) }
        else { self = .object(try c.decode([String: JSONValue].self)) }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let value): try c.encode(value)
        case .number(let value): try c.encode(value)
        case .string(let value): try c.encode(value)
        case .array(let value): try c.encode(value)
        case .object(let value): try c.encode(value)
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
        var parts = ["forester-1", profile.host.trimmingCharacters(in: .whitespaces).lowercased(), String(profile.port),
                     profile.security.rawValue, profile.bindName.trimmingCharacters(in: .whitespaces).lowercased(),
                     profile.trust.trustAnyCertificate ? "any-certificate" : "checked-certificate"]
        // SCRAM never sends the password; a simple bind does. A password saved
        // for one is not handed to the other, which could send it in the clear.
        if profile.authentication == .scram { parts.append("scram") }
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
            saved = Saved(password: former.password, connection: nil)
        } else {
            return .none
        }
        // Saved under the former name or before passwords were tied to a
        // connection, it says nothing about the server it was meant for: the
        // profile could have been changed since. It is asked for again, then
        // saved tied to this connection, rather than sent where it now points.
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

/// Certificates with a private key in the keychain (identities), for signing
/// in with a certificate. Listing them reads only certificates; macOS asks
/// before the key is first used to sign in.
enum ClientCertificates {
    struct Choice: Identifiable, Hashable {
        let identity: ClientIdentity
        let name: String
        var id: String { identity.sha256Fingerprint }
    }

    static func all() -> [Choice] {
        let query: [String: Any] = [kSecClass as String: kSecClassIdentity, kSecReturnRef as String: true,
                                    kSecMatchLimit as String: kSecMatchLimitAll]
        var found: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &found) == errSecSuccess,
              let identities = found as? [SecIdentity] else { return [] }
        var seen = Set<String>()
        return identities.compactMap { secIdentity -> Choice? in
            guard let identity = ClientIdentity(secIdentity), seen.insert(identity.sha256Fingerprint).inserted,
                  let certificate = SecCertificateCreateWithData(nil, identity.certificate as CFData) else { return nil }
            return Choice(identity: identity, name: SecCertificateCopySubjectSummary(certificate) as String? ?? identity.sha256Fingerprint)
        }
        .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// The certificate a profile names, if it is still in the keychain.
    static func identity(_ fingerprint: String) -> ClientIdentity? {
        guard !fingerprint.isEmpty else { return nil }
        return all().first { TrustPolicyFingerprint.same($0.id, fingerprint) }?.identity
    }
}

/// Fingerprints compared as the transport compares pins: hex digits only.
enum TrustPolicyFingerprint {
    static func same(_ a: String, _ b: String) -> Bool {
        a.lowercased().filter(\.isHexDigit) == b.lowercased().filter(\.isHexDigit)
    }
}

extension Comparable {
    func clamped(to range: ClosedRange<Self>) -> Self { min(max(self, range.lowerBound), range.upperBound) }
}
