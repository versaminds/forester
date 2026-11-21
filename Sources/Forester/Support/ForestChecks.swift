// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

#if DEBUG
import AppKit
import LDAPKit

/// Browsing another domain of the forest in the same window, against the
/// test forest of TestDirectory/start.sh: corp.example, and its child domain
/// child.corp.example on a slapd of its own, reached through
/// FORESTER_TEST_DOMAIN_HOSTS (scripts/automation.sh sets it). Through the
/// functions the app's controls call, each result read back from the server.
///   FORESTER_AUTOMATION_ONLY=forest
@MainActor
enum ForestChecks {
    static let child = "DC=child,DC=corp,DC=example"
    static let lieve = "CN=Lieve Peeters,OU=Staff,DC=child,DC=corp,DC=example"
    static let readers = "CN=UG-Forest-Readers,CN=Users,DC=corp,DC=example"
    static let childPort = 10489

    static func run(_ model: AppModel, output: URL) async throws {
        setenv("FORESTER_TEST_DOMAIN_HOSTS", "child.corp.example=localhost:\(childPort)", 0)
        let session = try await Automation.connectCorp(model)
        func expect(_ what: String, _ condition: Bool) throws {
            guard condition else { throw Automation.AutomationError("check failed (forest): \(what)") }
            Automation.log("verified (forest): \(what)")
        }
        /// The child domain's server itself, to read back what was changed.
        func direct() async throws -> LDAPConnection {
            let connection = LDAPConnection(.init(host: "localhost", port: childPort, security: .none, timeout: 10))
            try await connection.open()
            return connection
        }

        let domains = await session.forestDomains()
        try expect("the forest lists both domains, and the child one can be browsed here",
                   Set(domains.map(\.dnsName)) == ["corp.example", "child.corp.example"]
                       && session.domainsToBrowse.map(\.dnsName) == ["child.corp.example"])
        // Before it is browsed, its entries are neither read from this server nor shown.
        session.open(lieve)
        try await Automation.waitFor("other domain noticed") { session.inspector.error != nil }
        try expect("before it is browsed, an entry of the child domain is offered, not read",
                   session.inspector.otherDomain == "child.corp.example" && session.inspector.entry == nil)

        let domain = try Automation.require(session.domainsToBrowse.first)
        await session.browse(domain)
        let rootID = DN.normalized(child)
        try expect("browsed, the child domain is one more root of the tree, open and without an error",
                   session.tree.roots.contains(rootID) && session.browsedDomain(containing: lieve)?.isOpen == true
                       && session.tree.node(rootID)?.error == nil && session.tree.roots.last == TreeModel.rootDSEKey)
        try await Automation.waitFor("child root expanded") { session.tree.node(rootID)?.children != nil }
        let children = session.tree.node(rootID)?.children ?? []
        try expect("its root lists its own containers", children.contains(DN.normalized("OU=Staff,\(child)")))
        try expect("it is not this connection's entry to rename or delete", !session.canChangeEntry(child))

        session.open(lieve)
        try await Automation.waitFor("Lieve shown") { session.inspector.entry.map { DN.isSame($0.dn, lieve) } == true }
        try expect("an entry of the child domain is read and shown", session.inspector.entry?.string("cn") == "Lieve Peeters")
        session.inspector.tab = .membership
        try await Automation.waitFor("membership read") { !session.inspector.membership.loading }
        try expect("its primary group is found in its own domain",
                   session.inspector.membership.error == nil
                       && session.inspector.membership.primaryGroupIsInChildDomain(child))
        let permissions = try await session.permissions(of: lieve)
        try expect("its permissions are read from its domain", !permissions.rules.isEmpty)

        // Read-only holds for the other domain too.
        session.setReadOnly(true)
        let refused = await session.change("Should not happen.") { try await $0.modify(lieve, [.replace("description", ["refused"])]) }
        let server = try await direct()
        let untouched = try await server.read(lieve, attributes: ["description"])?.string("description")
        try expect("read-only, no change is sent to the other domain", !refused && untouched != "refused")

        session.setReadOnly(false)
        let note = "Written from the parent's window"
        let changed = await session.change("Description saved.", undo: .values(lieve, ["description"])) {
            try await $0.modify(lieve, [.replace("description", [note])])
        }
        let written = try await server.read(lieve, attributes: ["description"])?.string("description")
        try expect("a change goes to the child domain's server", changed && written == note)
        _ = await session.undo(try Automation.require(session.history.first).id)
        let undone = try await server.read(lieve, attributes: ["description"])?.string("description")
        try expect("Change History undoes it there", undone == untouched)

        // Search, and what an export reads, beneath the other domain's root.
        session.search.base = child
        session.search.scope = .subtree
        session.search.filterText = "(objectClass=user)"
        session.search.wholeForest = false
        session.search.run()
        try await Automation.waitFor("search beneath the child domain") { !session.search.running }
        try expect("a search beneath the child domain finds its three people",
                   session.search.error == nil && Set(session.search.rows.map(\.name)) == ["Lieve Peeters", "Jef Claes", "Mira Janssens"])
        let exported = try await session.run { try await $0.pagedSearch(LDAPSearchRequest(base: child, scope: .subtree, attributes: ["*"]), pageSize: 200) }
        try expect("an export of its subtree reads every entry of it", exported.entries.count == 8)

        // A group of corp.example with a member from each domain.
        session.open(readers)
        // The entry is read again when opened; its members are worked out from
        // that read, so the wait is for it as well.
        try await Automation.waitFor("group shown") {
            session.inspector.entry.map { DN.isSame($0.dn, readers) } == true && !session.inspector.loading
        }
        session.inspector.tab = .membership
        try await Automation.waitFor("members read") { !session.inspector.membership.loading }
        let members = session.inspector.membership.members
        try expect("a group's member from the child domain is read from there, named and known as a user",
                   members.contains { DN.isSame($0.dn, lieve) && $0.kind == .user }
                       && members.contains { DN.isSame($0.dn, pieter) })

        // Stop browsing: the root goes, the connection closes, and the
        // entries are no longer read.
        let connection = session.browsedDomain(containing: lieve)?.connection
        await session.stopBrowsing(child)
        let closed = await connection?.isAlive == false
        session.open(lieve)
        try await Automation.waitFor("refused again") { session.inspector.error != nil }
        try expect("taken out of the tree, its root and connection are gone and its entries no longer read",
                   !session.tree.roots.contains(rootID) && closed && session.inspector.entry == nil)

        // A domain whose controllers do not answer shows that on its own root;
        // the rest of the window carries on.
        setenv("FORESTER_TEST_DOMAIN_HOSTS", "child.corp.example=localhost:1", 1)
        await session.browse(domain)
        let stillReads = try await session.run { try await $0.read(readers, attributes: ["cn"]) } != nil
        try expect("a domain that cannot be reached shows why on its root, and nothing else breaks",
                   session.tree.node(rootID)?.error != nil && session.browsedDomain(containing: lieve)?.isOpen == false && stillReads)
        await session.stopBrowsing(child)
        setenv("FORESTER_TEST_DOMAIN_HOSTS", "child.corp.example=localhost:\(childPort),corp.example=localhost:\(corpPort)", 1)
        await server.close()

        // Its connection lost, requests that all find it so at once wait for
        // one new connection: none more is signed in and left open.
        await session.browse(domain)
        let lost = try Automation.require(session.browsedDomain(containing: lieve)?.connection)
        await lost.close()
        let openedBefore = session.browsedConnectionsOpened
        let reads = await withTaskGroup(of: Bool.self) { group -> [Bool] in
            for _ in 0..<5 {
                group.addTask { @MainActor in (try? await session.run { try await $0.read(lieve, attributes: ["cn"]) }) != nil }
            }
            var results: [Bool] = []
            for await result in group { results.append(result) }
            return results
        }
        let reopened = session.browsedDomain(containing: lieve)?.connection
        let reopenedAlive = await reopened?.isAlive == true
        try expect("a lost connection to it is opened again once for every request that found it lost",
                   reads.allSatisfy { $0 } && session.browsedConnectionsOpened == openedBefore + 1 && reopened !== lost && reopenedAlive)
        await session.stopBrowsing(child)
        session.setReadOnly(true)

        try await childBrowsesParent(model, corpSession: session, expect: expect)
    }

    static let corpPort = 10389
    static let pieter = "CN=Pieter Van Damme,OU=Engineering,OU=Users,OU=Corp,DC=corp,DC=example"

    /// Connected to the child domain, browsing its parent: the parent's root
    /// contains every DN of the child's, yet the child's own entries stay its
    /// own, and taking the parent out leaves the child's tree.
    static func childBrowsesParent(_ model: AppModel, corpSession: DirectorySession,
                                   expect: (String, Bool) throws -> Void) async throws {
        var profile = corpSession.profile
        profile.id = UUID()
        profile.name = "Child test domain"
        profile.port = childPort
        profile.readOnly = true
        model.store.save(profile)
        let session = try Automation.require(model.session(for: profile.id))
        session.connect(password: Automation.testPassword)
        try await Automation.waitFor("child domain connected") {
            if case .failed = session.phase { return true }
            return session.phase.isConnected || session.pendingTrustFailure != nil
        }
        if session.pendingTrustFailure != nil {
            session.trustPendingCertificate()
            try await Automation.waitFor("child domain connected after trust") { session.phase.isConnected }
        }
        if case .failed(let message) = session.phase { throw Automation.AutomationError(message) }
        let parent = try Automation.require(session.domainsToBrowse.first { $0.dnsName == "corp.example" })
        try expect("from the child domain, its parent is offered to browse, and a crossRef pointing elsewhere is not",
                   session.domainsToBrowse.map(\.dnsName) == ["corp.example"])
        await session.browse(parent)
        let childRoot = DN.normalized(child), parentRoot = DN.normalized("DC=corp,DC=example")
        try expect("the parent is one more root, open",
                   session.tree.roots.contains(parentRoot) && session.browsedDomain(containing: pieter)?.isOpen == true)
        try expect("the child's own entries and the configuration stay the child's, the parent's go to the parent",
                   session.browsedDomain(containing: lieve) == nil && session.domainRoot(for: lieve).map(DN.normalized) == childRoot
                       && session.domainSID(for: lieve) == session.domainSID
                       && session.browsedDomain(containing: "CN=Partitions,CN=Configuration,DC=corp,DC=example") == nil
                       && session.domainRoot(for: pieter).map(DN.normalized) == parentRoot)
        session.open(lieve)
        try await Automation.waitFor("Lieve shown from her own domain") {
            session.inspector.entry.map { DN.isSame($0.dn, lieve) } == true && !session.inspector.loading
        }
        session.inspector.tab = .membership
        try await Automation.waitFor("membership read") { !session.inspector.membership.loading }
        try expect("her primary group is her own domain's, not the parent's",
                   session.inspector.membership.primaryGroupIsInChildDomain(child))
        await session.tree.expand(childRoot)
        try await Automation.waitFor("child root expanded") { session.tree.node(childRoot)?.children != nil }
        let staff = DN.normalized("OU=Staff,\(child)")
        await session.stopBrowsing("DC=corp,DC=example")
        try expect("taking the parent out leaves the child's own tree and the entry shown",
                   !session.tree.roots.contains(parentRoot) && session.tree.roots.contains(childRoot)
                       && session.tree.node(staff) != nil && session.tree.node(childRoot) != nil
                       && session.selectedDN.map { DN.isSame($0, lieve) } == true)
        session.disconnect()
        model.delete(profile.id)
        model.requestedSelection = corpSession.id
    }
}

extension MembershipModel {
    /// The primary group shown is the domain's own: its DN is in that domain.
    func primaryGroupIsInChildDomain(_ domain: String) -> Bool {
        memberOf.contains { $0.note == "Primary group" && DN.isWithin($0.dn, domain) }
    }
}
#endif
