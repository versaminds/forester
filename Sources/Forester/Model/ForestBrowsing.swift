// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import LDAPKit

/// Another domain of the forest, browsed in this window beside the
/// connection's own: one more root in the tree, read and changed over a
/// connection to that domain made with this connection's sign-in.
struct BrowsedDomain: Identifiable {
    let domain: ForestDomain
    var connection: LDAPConnection?
    /// Why the connection could not be made, or was lost and not made again.
    var failure: String?
    /// The naming contexts its server holds, from its root DSE.
    var held: [String] = []
    /// `S-1-5-21-…` of the domain, for its accounts' primary groups.
    var domainSID: String?

    var id: String { DN.normalized(domain.dn) }
    var isOpen: Bool { connection != nil }
}

extension DirectorySession {
    /// The browsed domain whose tree `dn` is in.
    func browsedDomain(containing dn: String) -> BrowsedDomain? {
        browsedDomains.filter { DN.isWithin(dn, $0.domain.dn) }
            .max { DN.components($0.domain.dn).count < DN.components($1.domain.dn).count }
    }

    /// The root of the domain `dn` is in: a browsed domain's, or this
    /// connection's own default naming context.
    func domainRoot(for dn: String) -> String? {
        browsedDomain(containing: dn)?.domain.dn ?? server?.defaultNamingContext
    }

    /// The SID of the domain `dn` is in.
    func domainSID(for dn: String) -> String? {
        if let browsed = browsedDomain(containing: dn) { return browsed.domainSID }
        return domainSID
    }

    /// Where searches and pickers may start: the server's naming contexts and
    /// the browsed domains.
    var browsableRoots: [String] {
        (server?.namingContexts ?? []) + browsedDomains.map(\.domain.dn)
    }

    /// Domains of the forest that could be browsed here: listed, not this
    /// connection's own, and not browsed already. From the list read when
    /// connecting.
    var domainsToBrowse: [ForestDomain] {
        (cachedForestDomains ?? []).filter { domain in
            !holdsEntry(domain.dn) && !browsedDomains.contains { DN.isSame($0.domain.dn, domain.dn) }
        }
    }

    /// Adds another domain of the forest to this window's tree, over a
    /// connection of its own: to the domain's DNS name, with this
    /// connection's port, security and sign-in. A password goes there only
    /// over TLS to a certificate this Mac trusts (`openConnection(to:)`).
    /// Only a domain the forest lists is added.
    func browse(_ domain: ForestDomain) async {
        guard phase.isConnected, hasADTools else { return }
        let listed = await forestDomains()
        guard let listedDomain = listed.first(where: { DN.isSame($0.dn, domain.dn) }) else {
            report("\(domain.dnsName) is not a domain of this forest, so Forester does not connect to it from here.", isError: true)
            return
        }
        guard !holdsEntry(listedDomain.dn) else { return }
        guard !browsedDomains.contains(where: { DN.isSame($0.domain.dn, listedDomain.dn) }) else {
            reveal(listedDomain.dn)
            return
        }
        let started = connectionGeneration
        browsedDomains.append(BrowsedDomain(domain: listedDomain))
        tree.addRoot(listedDomain.dn)
        tree.setLoading(DN.normalized(listedDomain.dn), true)
        await open(listedDomain, generation: started)
        tree.setLoading(DN.normalized(listedDomain.dn), false)
        guard connectionGeneration == started else { return }
        if browsedDomain(containing: listedDomain.dn)?.isOpen == true {
            await tree.expand(DN.normalized(listedDomain.dn))
        }
    }

    /// Opens (or opens again) a browsed domain's connection, and routes to it.
    private func open(_ domain: ForestDomain, generation started: Int) async {
        let (host, port) = Self.endpoint(of: domain, port: profile.port)
        var opened: LDAPConnection?
        var failure: String?
        var held: [String] = []
        var sid: String?
        do {
            let connection = try await openConnection(to: host, port: port, timeout: TimeInterval(profile.timeoutSeconds))
            held = ServerInfo(rootDSE: try await connection.rootDSE()).namingContexts
            sid = (try? await connection.read(domain.dn, attributes: ["objectSid"]))??.values("objectSid").first.flatMap(ADValues.sidString)
            opened = connection
        } catch {
            failure = error.localizedDescription
        }
        // Disconnected, or the domain taken out of the tree, meanwhile.
        guard connectionGeneration == started, let index = browsedDomains.firstIndex(where: { DN.isSame($0.domain.dn, domain.dn) }) else {
            if let opened { await opened.close() }
            return
        }
        browsedDomains[index].connection = opened
        browsedDomains[index].failure = failure
        browsedDomains[index].held = held
        if let sid { browsedDomains[index].domainSID = sid }
        tree.setError(DN.normalized(domain.dn), failure.map { "\(domain.dnsName) could not be opened: \($0)" })
        await installRoutes()
    }

    /// Takes a browsed domain out of the tree and closes its connection.
    func stopBrowsing(_ rootDN: String) async {
        guard let index = browsedDomains.firstIndex(where: { DN.isSame($0.domain.dn, rootDN) }) else { return }
        let removed = browsedDomains.remove(at: index)
        await installRoutes()
        if let selectedDN, DN.isWithin(selectedDN, removed.domain.dn) { select(nil) }
        if search.base.isEmpty == false, DN.isWithin(search.base, removed.domain.dn) {
            search.base = server?.defaultNamingContext ?? ""
        }
        tree.removeRoot(DN.normalized(removed.domain.dn))
        await removed.connection?.close()
    }

    /// Opens again the browsed domains whose connection was lost (a domain
    /// controller closes one left idle).
    func reopenLostDomains() async {
        let started = connectionGeneration
        for browsed in browsedDomains {
            guard let connection = browsed.connection, !(await connection.isAlive) else { continue }
            await open(browsed.domain, generation: started)
            await connection.close()
        }
    }

    /// Gives this connection, and each browsed domain's, the routes that send
    /// every request about a DN to the connection of the domain holding it.
    /// `home` routes a connection not yet in use (one just reopened).
    func installRoutes(home: LDAPConnection? = nil) async {
        guard hasADTools, let server, let home = home ?? connection else { return }
        let forest = await forestDomains()
        let homeHeld = server.namingContexts
        func route(_ domain: ForestDomain, from held: [String]) -> ForestRoutes.Domain? {
            guard !held.contains(where: { DN.isSame($0, domain.dn) }) else { return nil }
            if homeHeld.contains(where: { DN.isSame($0, domain.dn) }) {
                return ForestRoutes.Domain(root: domain.dn, dnsName: domain.dnsName, connection: home)
            }
            let browsed = browsedDomains.first { DN.isSame($0.domain.dn, domain.dn) }
            return ForestRoutes.Domain(root: domain.dn, dnsName: domain.dnsName, connection: browsed?.connection,
                                       failure: browsed?.failure)
        }
        await home.setRoutes(ForestRoutes(held: homeHeld, domains: forest.compactMap { route($0, from: homeHeld) }))
        for browsed in browsedDomains {
            guard let connection = browsed.connection else { continue }
            await connection.setRoutes(ForestRoutes(held: browsed.held, domains: forest.compactMap { route($0, from: browsed.held) }))
        }
    }

    /// Where a domain's controllers answer: its DNS name, which names them all.
    /// A debug build may point a name elsewhere for the test forest of
    /// TestDirectory/start.sh, which has no DNS of its own:
    /// FORESTER_TEST_DOMAIN_HOSTS="child.corp.example=localhost:10489".
    static func endpoint(of domain: ForestDomain, port: Int) -> (host: String, port: Int) {
        #if DEBUG
        if let mapped = testDomainHosts[domain.dnsName.lowercased()] { return mapped }
        #endif
        return (domain.dnsName, port)
    }

    #if DEBUG
    static var testDomainHosts: [String: (host: String, port: Int)] {
        let text = ProcessInfo.processInfo.environment["FORESTER_TEST_DOMAIN_HOSTS"] ?? ""
        var hosts: [String: (host: String, port: Int)] = [:]
        for item in text.split(separator: ",") {
            let parts = item.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let target = parts[1].split(separator: ":")
            guard target.count == 2, let port = Int(target[1]) else { continue }
            hosts[parts[0].trimmingCharacters(in: .whitespaces).lowercased()] = (String(target[0]), port)
        }
        return hosts
    }
    #endif
}
