// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import LDAPKit

/// A domain of the Active Directory forest, from its cross-reference in the
/// configuration partition.
struct ForestDomain: Identifiable, Hashable {
    let dn: String
    let dnsName: String
    let netbiosName: String?
    var id: String { dn }
}

extension DirectorySession {
    /// This connection's server holds the entry: it is in one of the naming
    /// contexts the server serves. Another domain's entries are reached by
    /// connecting to that domain.
    ///
    /// A child domain's names end in its parent's (DC=child,DC=corp,DC=example
    /// is beneath DC=corp,DC=example), so lying beneath a naming context is
    /// not enough: a DC= part right beneath it starts a domain of its own.
    func holdsEntry(_ dn: String) -> Bool {
        if dn.isEmpty { return true }
        let containing = (server?.namingContexts ?? []).filter { DN.isWithin(dn, $0) }
        guard let context = containing.max(by: { DN.components($0).count < DN.components($1).count }) else { return false }
        let parts = DN.components(dn)
        let depth = parts.count - DN.components(context).count
        guard depth > 0 else { return true }
        return DN.rdnAttribute(parts[depth - 1])?.lowercased() != "dc"
    }

    /// The domain of the forest an entry belongs to, when this connection's
    /// server does not hold it (a search of the whole forest finds such
    /// entries). nil for a domain the forest does not list: its name comes
    /// from a DN, and nothing is opened for it.
    func otherDomain(of dn: String) async -> ForestDomain? {
        guard hasADTools, !holdsEntry(dn), let dns = DN.dnsDomain(dn)?.lowercased() else { return nil }
        return await forestDomains().first { $0.dnsName.lowercased() == dns }
    }

    /// Every domain of the forest. Directory data, but written only by the
    /// forest's own administrators.
    func forestDomains() async -> [ForestDomain] {
        if let cachedForestDomains { return cachedForestDomains }
        guard let configuration = server?.configurationNamingContext,
              let filter = try? LDAPFilter.parse("(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))") else { return [] }
        let request = LDAPSearchRequest(base: "CN=Partitions,\(configuration)", scope: .oneLevel, filter: filter,
                                        attributes: ["nCName", "dnsRoot", "nETBIOSName"])
        guard let found = (try? await run({ try await $0.pagedSearch(request, pageSize: 500) }))?.entries else { return [] }
        let domains = found.compactMap { entry -> ForestDomain? in
            guard let dn = entry.string("nCName"), let dns = entry.string("dnsRoot") else { return nil }
            return ForestDomain(dn: dn, dnsName: dns, netbiosName: entry.string("nETBIOSName"))
        }
        .sorted { $0.dnsName.localizedStandardCompare($1.dnsName) == .orderedAscending }
        cachedForestDomains = domains
        return domains
    }

    /// The server is a global catalog: it answers searches of the whole forest.
    var isGlobalCatalog: Bool {
        server?.rootDSE.string("isGlobalCatalogReady")?.uppercased() == "TRUE"
    }

    /// 3269 over TLS from the first byte, 3268 otherwise (with StartTLS when
    /// the connection uses it).
    var globalCatalogPort: Int {
        #if DEBUG
        if let port = ProcessInfo.processInfo.environment["FORESTER_TEST_GC_PORT"].flatMap(Int.init) { return port }
        #endif
        return profile.security == .ldaps ? 3269 : 3268
    }

    /// Runs on the global catalog, opening it again once if it was lost
    /// (a search is safe to repeat).
    func runOnGlobalCatalog<T>(_ body: (LDAPConnection) async throws -> T) async throws -> T {
        let catalog = try await globalCatalog()
        do {
            return try await body(catalog)
        } catch let error as LDAPError where error.isConnectionLoss {
            globalCatalogConnection = nil
            Task { await catalog.close() }
            return try await body(try await globalCatalog())
        }
    }

    /// A connection to this server's global catalog, opened on first use and
    /// kept until disconnecting. Signed in like the connection itself.
    func globalCatalog() async throws -> LDAPConnection {
        if let existing = globalCatalogConnection, await existing.isAlive { return existing }
        guard isGlobalCatalog else { throw ForestError.notGlobalCatalog(profile.host) }
        let started = connectionGeneration
        let connection = try await openConnection(to: profile.options.host, port: globalCatalogPort, timeout: TimeInterval(profile.timeoutSeconds))
        // Disconnected, or connected elsewhere, while it opened: not kept.
        guard connectionGeneration == started, phase.isConnected else {
            await connection.close()
            throw LDAPError.notConnected
        }
        globalCatalogConnection = connection
        return connection
    }
}

enum ForestError: LocalizedError {
    case notGlobalCatalog(String)
    var errorDescription: String? {
        switch self {
        case .notGlobalCatalog(let host):
            return "\(host) is not a global catalog, so it cannot search the whole forest. Connect to one that is: Domain Information lists them."
        }
    }
}
