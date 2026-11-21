// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import Testing
@testable import LDAPKit

/// Which connection answers for a DN when two domains of a forest are
/// browsed in one window. No server needed.
@Suite struct ForestRoutesTests {
    static let corp = "DC=corp,DC=example", child = "DC=child,DC=corp,DC=example"
    static let held = [corp, "CN=Configuration,DC=corp,DC=example", "CN=Schema,CN=Configuration,DC=corp,DC=example",
                       "DC=DomainDnsZones,DC=corp,DC=example"]
    static let childConnection = LDAPConnection(.init(host: "child.example", port: 389, security: .none))

    static func isHere(_ route: ForestRoutes.Route) -> Bool { if case .here = route { return true }; return false }
    static func goesTo(_ route: ForestRoutes.Route) -> LDAPConnection? { if case .connection(let c) = route { return c }; return nil }
    static func refusal(_ route: ForestRoutes.Route) -> String? { if case .refused(let why) = route { return why }; return nil }

    @Test func thisDomainsEntriesStayHere() {
        let routes = ForestRoutes(held: Self.held, domains: [.init(root: Self.child, dnsName: "child.corp.example", connection: Self.childConnection)])
        for dn in ["", Self.corp, "CN=Pieter Van Damme,OU=Users,OU=Corp,DC=corp,DC=example",
                   "CN=Partitions,CN=Configuration,DC=corp,DC=example",
                   "DC=host,DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example",
                   "dc=corp,dc=example", "CN=x,CN=MicrosoftDNS,CN=System,DC=corp,DC=example",
                   // Not of any domain this forest lists: asked as before.
                   "CN=x,DC=elsewhere,DC=com"] {
            #expect(Self.isHere(routes.route(dn)), "\(dn)")
        }
    }

    @Test func aBrowsedDomainsEntriesGoToItsConnection() {
        let routes = ForestRoutes(held: Self.held, domains: [.init(root: Self.child, dnsName: "child.corp.example", connection: Self.childConnection)])
        for dn in [Self.child, "CN=Lieve Peeters,OU=Staff,DC=child,DC=corp,DC=example", "cn=lieve peeters,ou=staff,dc=child,dc=corp,dc=example"] {
            #expect(Self.goesTo(routes.route(dn)) === Self.childConnection, "\(dn)")
        }
    }

    /// Never sent where it does not belong: a domain listed but not open, one
    /// that failed, and a child domain the forest does not even list.
    @Test func anotherDomainsEntriesAreRefusedUnlessOpen() throws {
        let closed = ForestRoutes(held: Self.held, domains: [.init(root: Self.child, dnsName: "child.corp.example")])
        #expect(Self.refusal(closed.route("CN=Lieve,DC=child,DC=corp,DC=example"))?.contains("not open in this window") == true)
        let failed = ForestRoutes(held: Self.held, domains: [.init(root: Self.child, dnsName: "child.corp.example", failure: "refused")])
        #expect(Self.refusal(failed.route("CN=Lieve,DC=child,DC=corp,DC=example"))?.contains("could not be opened: refused") == true)
        let unlisted = ForestRoutes(held: Self.held, domains: [])
        let why = try #require(Self.refusal(unlisted.route("CN=Someone,OU=Users,DC=other,DC=corp,DC=example")))
        #expect(why.contains("other.corp.example"), "\(why)")
        #expect(!unlisted.holds("DC=other,DC=corp,DC=example"))
        #expect(unlisted.holds("CN=Users,DC=corp,DC=example"))
    }

    /// From the child domain's connection: its own entries and the forest's
    /// configuration (every domain controller holds it) are its own; the
    /// parent's entries go back to the parent's connection.
    @Test func fromTheChildTheParentsEntriesGoToTheParent() {
        let parent = LDAPConnection(.init(host: "corp.example", port: 389, security: .none))
        let routes = ForestRoutes(held: [Self.child, "CN=Configuration,DC=corp,DC=example"],
                                  domains: [.init(root: Self.corp, dnsName: "corp.example", connection: parent)])
        #expect(Self.isHere(routes.route("CN=Lieve,OU=Staff,DC=child,DC=corp,DC=example")))
        #expect(Self.isHere(routes.route("CN=Partitions,CN=Configuration,DC=corp,DC=example")))
        #expect(Self.goesTo(routes.route("CN=Pieter,OU=Users,DC=corp,DC=example")) === parent)
        // A grandchild beneath the child is a domain of its own again.
        #expect(Self.refusal(routes.route("CN=x,DC=grand,DC=child,DC=corp,DC=example")) != nil)
    }

    /// Connected to the child domain and browsing its parent, whose root
    /// contains every DN of the child's: which domain holds a DN follows the
    /// child's own naming contexts first, as requests are routed.
    @Test func browsingAnAncestorLeavesThisDomainsEntriesHere() {
        let parent = LDAPConnection(.init(host: "corp.example", port: 389, security: .none))
        let childHeld = [Self.child, "CN=Configuration,DC=corp,DC=example", "CN=Schema,CN=Configuration,DC=corp,DC=example"]
        let routes = ForestRoutes(held: childHeld, domains: [.init(root: Self.corp, dnsName: "corp.example", connection: parent)])
        for own in [Self.child, "CN=Lieve,OU=Staff,DC=child,DC=corp,DC=example", "CN=Partitions,CN=Configuration,DC=corp,DC=example",
                    "CN=user,CN=Schema,CN=Configuration,DC=corp,DC=example"] {
            #expect(routes.domain(holding: own) == nil, "\(own)")
            #expect(Self.isHere(routes.route(own)), "\(own)")
        }
        #expect(routes.domain(holding: "CN=Pieter,OU=Users,DC=corp,DC=example")?.root == Self.corp)
        #expect(Self.goesTo(routes.route(Self.corp)) === parent)
    }

    /// <GUID=…> and <SID=…> do not say where an entry is: with other domains
    /// about they are refused; dc written as domainComponent or its OID is dc.
    @Test func entriesNamedOtherwiseAreNotSentAstray() {
        let routes = ForestRoutes(held: Self.held, domains: [.init(root: Self.child, dnsName: "child.corp.example", connection: Self.childConnection)])
        for named in ["<GUID=bf967aba-0de6-11d0-a285-00aa003049e2>", " <SID=S-1-5-21-1-2-3-500>", "<WKGUID=a9d1ca15768811d1aded00c04fd8d5cd,DC=corp,DC=example>"] {
            #expect(Self.refusal(routes.route(named))?.contains("GUID or SID") == true, "\(named)")
            #expect(routes.domain(holding: named) == nil)
        }
        #expect(Self.isHere(ForestRoutes(held: Self.held, domains: []).route("<GUID=bf967aba-0de6-11d0-a285-00aa003049e2>")))
        for spelled in ["CN=Lieve,domainComponent=child,DC=corp,DC=example", "CN=Lieve,0.9.2342.19200300.100.1.25=child,DC=corp,DC=example",
                        "CN=Lieve,OID.0.9.2342.19200300.100.1.25=child,dc=corp,dc=example"] {
            #expect(Self.goesTo(routes.route(spelled)) === Self.childConnection, "\(spelled)")
        }
        let unlisted = ForestRoutes(held: Self.held, domains: [])
        #expect(Self.refusal(unlisted.route("CN=x,0.9.2342.19200300.100.1.25=other,DC=corp,DC=example")) != nil)
        #expect(DN.isSame("domainComponent=corp,DC=example", "dc=corp,dc=example"))
        #expect(DN.dnsDomain("0.9.2342.19200300.100.1.25=child,dc=corp,dc=example") == "child.corp.example")
    }

    /// In a tree of several roots, one beneath another, a node belongs to
    /// the deepest root above it: taking the outer one out leaves the inner.
    @Test func aNodeBelongsToItsDeepestRoot() {
        let roots = [Self.child, "CN=Configuration,DC=corp,DC=example", Self.corp]
        #expect(DN.deepestRoot(of: "CN=Lieve,OU=Staff,DC=child,DC=corp,DC=example", in: roots) == Self.child)
        #expect(DN.deepestRoot(of: "CN=Partitions,CN=Configuration,DC=corp,DC=example", in: roots) == "CN=Configuration,DC=corp,DC=example")
        #expect(DN.deepestRoot(of: "CN=Pieter,OU=Users,DC=corp,DC=example", in: roots) == Self.corp)
        #expect(DN.deepestRoot(of: "dc=example,dc=org", in: roots) == nil)
    }

    /// A crossRef is a domain only when its DNS name is the one its naming
    /// context spells: the DNS name is where Forester would connect.
    @Test func aCrossRefPointingElsewhereIsNoDomain() {
        #expect(ForestRoutes.isConsistent(nCName: "DC=child,DC=corp,DC=example", dnsRoot: "Child.Corp.Example"))
        #expect(!ForestRoutes.isConsistent(nCName: "DC=elsewhere,DC=corp,DC=example", dnsRoot: "attacker.example"))
        #expect(!ForestRoutes.isConsistent(nCName: "CN=Configuration,DC=corp,DC=example", dnsRoot: "corp.example"))
        #expect(!ForestRoutes.isConsistent(nCName: "", dnsRoot: ""))
    }

    /// The connection refuses before anything is sent: an unopened connection
    /// would otherwise say it is not connected.
    @Test func aConnectionRefusesBeforeSending() async throws {
        let home = LDAPConnection(.init(host: "corp.example", port: 389, security: .none))
        await home.setRoutes(ForestRoutes(held: Self.held, domains: [.init(root: Self.child, dnsName: "child.corp.example")]))
        let lieve = "CN=Lieve,OU=Staff,DC=child,DC=corp,DC=example"
        func refused(_ body: () async throws -> Void) async -> Bool {
            do { try await body(); return false } catch let error as LDAPError {
                if case .otherDomain = error { return true }
                return false
            } catch { return false }
        }
        #expect(await refused { _ = try await home.read(lieve) })
        #expect(await refused { try await home.modify(lieve, [.replace("description", ["x"])]) })
        #expect(await refused { try await home.add(lieve, attributes: []) })
        #expect(await refused { try await home.delete(lieve) })
        #expect(await refused { _ = try await home.passwordModify(user: lieve, oldPassword: nil, newPassword: "x") })
        #expect(await refused { _ = try await home.pagedSearch(LDAPSearchRequest(base: Self.child, scope: .subtree)) })
        // A move between domains is refused even with both open.
        await home.setRoutes(ForestRoutes(held: Self.held, domains: [.init(root: Self.child, dnsName: "child.corp.example", connection: Self.childConnection)]))
        #expect(await refused { try await home.modifyDN("CN=Pieter,OU=Users,DC=corp,DC=example", newRDN: "CN=Pieter", newSuperior: "OU=Staff,DC=child,DC=corp,DC=example") })
        // This domain's own entries are still asked here (and, unopened, fail so).
        await #expect(throws: LDAPError.notConnected) { _ = try await home.read("CN=Pieter,OU=Users,DC=corp,DC=example") }
    }
}

/// Two domains of one forest, browsed over two connections, against the
/// test directory of TestDirectory/start.sh: corp.example on 10389, and
/// its child domain child.corp.example served by a slapd of its own on 10489.
@Suite(.enabled(if: ProcessInfo.processInfo.environment["FORESTER_TEST_SERVER"] == "1"), .serialized)
struct ForestIntegrationTests {
    static let corp = "DC=corp,DC=example", child = "DC=child,DC=corp,DC=example"
    static let lieve = "CN=Lieve Peeters,OU=Staff,DC=child,DC=corp,DC=example"

    static func open(_ port: Int) async throws -> LDAPConnection {
        let connection = LDAPConnection(.init(host: "localhost", port: port, security: .startTLS, timeout: 10,
                                              trust: TrustPolicy(trustAnyCertificate: true)))
        try await connection.open()
        try await connection.bind(dn: "CN=admin,DC=corp,DC=example", password: "secret")
        return connection
    }

    /// The home connection, routed, and the child domain's, as the app sets them up.
    static func forest() async throws -> (home: LDAPConnection, child: LDAPConnection, homeWire: WireLog, childWire: WireLog) {
        let home = try await open(10389), child = try await open(10489)
        let homeHeld = ServerInfo(rootDSE: try await home.rootDSE()).namingContexts
        let childHeld = ServerInfo(rootDSE: try await child.rootDSE()).namingContexts
        await home.setRoutes(ForestRoutes(held: homeHeld, domains: [.init(root: Self.child, dnsName: "child.corp.example", connection: child)]))
        await child.setRoutes(ForestRoutes(held: childHeld, domains: [.init(root: corp, dnsName: "corp.example", connection: home)]))
        let homeWire = WireLog(), childWire = WireLog()
        await home.observeReceivedBytes { homeWire.append($0) }
        await child.observeReceivedBytes { childWire.append($0) }
        return (home, child, homeWire, childWire)
    }

    /// The forest's configuration lists both domains, as the app reads them,
    /// from either domain's server; a crossRef whose DNS name is not the one
    /// its naming context spells (written to send a sign-in elsewhere) is
    /// listed by the server but not taken for a domain.
    @Test(arguments: [10389, 10489])
    func theForestListsBothDomains(_ port: Int) async throws {
        let home = try await Self.open(port)
        let filter = try LDAPFilter.parse("(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))")
        let found = try await home.pagedSearch(LDAPSearchRequest(base: "CN=Partitions,CN=Configuration,\(Self.corp)", scope: .oneLevel,
                                                                 filter: filter, attributes: ["nCName", "dnsRoot"]))
        await home.close()
        #expect(Set(found.entries.compactMap { $0.string("dnsRoot") }) == ["corp.example", "child.corp.example", "attacker.example"])
        let domains = found.entries.filter {
            ForestRoutes.isConsistent(nCName: $0.string("nCName") ?? "", dnsRoot: $0.string("dnsRoot") ?? "")
        }
        #expect(Set(domains.compactMap { $0.string("dnsRoot") }) == ["corp.example", "child.corp.example"])
    }

    /// Connected to the child domain and browsing its parent: the child's own
    /// entries and the forest's configuration (which its server holds too)
    /// are its own, although the parent's root contains them; the parent's
    /// entries go to the parent's server.
    @Test func fromTheChildTheParentIsBrowsed() async throws {
        let child = try await Self.open(10489), parent = try await Self.open(10389)
        let held = ServerInfo(rootDSE: try await child.rootDSE()).namingContexts
        #expect(held.contains { DN.isSame($0, "CN=Configuration,\(Self.corp)") })
        let routes = ForestRoutes(held: held, domains: [.init(root: Self.corp, dnsName: "corp.example", connection: parent)])
        await child.setRoutes(routes)
        let childWire = WireLog(), parentWire = WireLog()
        await child.observeReceivedBytes { childWire.append($0) }
        await parent.observeReceivedBytes { parentWire.append($0) }
        #expect(routes.domain(holding: Self.lieve) == nil)
        #expect(routes.domain(holding: "CN=Partitions,CN=Configuration,\(Self.corp)") == nil)
        #expect(routes.domain(holding: "CN=Pieter Van Damme,OU=Engineering,OU=Users,OU=Corp,\(Self.corp)")?.root == Self.corp)
        #expect(try await child.read(Self.lieve, attributes: ["cn"])?.string("cn") == "Lieve Peeters")
        let partitions = try await child.read("CN=Partitions,CN=Configuration,\(Self.corp)", attributes: ["cn"])
        #expect(partitions != nil)
        #expect(parentWire.bytes.isEmpty, "the parent's server was asked about the child's own entries")
        let pieter = try await child.read("CN=Pieter Van Damme,OU=Engineering,OU=Users,OU=Corp,\(Self.corp)", attributes: ["cn"])
        #expect(pieter?.string("cn") == "Pieter Van Damme")
        #expect(!parentWire.bytes.isEmpty)
        await child.close()
        await parent.close()
    }

    /// Asked of the home connection, the child domain's entries are read,
    /// searched, paged and changed on the child's server, and nothing about
    /// them crosses the home connection.
    @Test func theChildDomainIsReadAndChangedOverItsOwnConnection() async throws {
        let (home, child, homeWire, childWire) = try await Self.forest()
        let homeBefore = homeWire.bytes.count, childBefore = childWire.bytes.count
        let entry = try #require(try await home.read(Self.lieve, attributes: ["cn", "objectSid"]))
        #expect(entry.string("cn") == "Lieve Peeters")
        let staff = try await home.pagedSearch(LDAPSearchRequest(base: Self.child, scope: .subtree, filter: .equality("objectClass", "user"),
                                                                attributes: ["cn"]), pageSize: 2)
        #expect(Set(staff.entries.compactMap { $0.string("cn") }) == ["Lieve Peeters", "Jef Claes", "Mira Janssens"])
        let note = "Changed through the parent's connection \(UInt32.random(in: 0..<1_000_000))"
        try await home.modify(Self.lieve, [.replace("description", [note])])
        #expect(homeWire.bytes.count == homeBefore, "the parent's server was asked about the child domain")
        #expect(childWire.bytes.count > childBefore)
        // Read straight from the child's server: the change is there.
        let direct = try await Self.open(10489)
        #expect(try await direct.read(Self.lieve, attributes: ["description"])?.string("description") == note)
        try await home.modify(Self.lieve, [.delete("description")])
        // Added, renamed within the child domain, and deleted, over the parent's connection.
        let temp = "CN=Forest Temp \(UInt32.random(in: 0..<1_000_000)),OU=Staff,\(Self.child)"
        try await home.add(temp, attributes: [LDAPAttribute(name: "objectClass", values: [Data("container".utf8)]),
                                              LDAPAttribute(name: "cn", values: [Data(DN.rdnValue(temp).utf8)])])
        let renamed = "CN=Forest Renamed \(UInt32.random(in: 0..<1_000_000)),OU=Staff,\(Self.child)"
        try await home.modifyDN(temp, newRDN: DN.rdn(renamed))
        #expect(try await direct.read(renamed) != nil)
        try await home.delete(renamed)
        #expect(try await direct.read(renamed) == nil)
        #expect(homeWire.bytes.count == homeBefore)
        for connection in [home, child, direct] { await connection.close() }
    }

    /// A corp.example group holding a member from each domain: the members
    /// are read together, each from its own domain's server.
    @Test func aGroupsMembersFromBothDomainsAreRead() async throws {
        let (home, child, _, _) = try await Self.forest()
        let group = try #require(try await home.read("CN=UG-Forest-Readers,CN=Users,\(Self.corp)", attributes: ["member"]))
        let members = group.strings("member")
        #expect(members.contains { DN.isSame($0, Self.lieve) })
        let read = try await home.readEach(members, attributes: ["cn"])
        #expect(Set(read.compactMap { $0.string("cn") }) == ["Pieter Van Damme", "Lieve Peeters"])
        // And from the child's side, the parent's entries go to the parent.
        #expect(try await child.read("CN=Pieter Van Damme,OU=Engineering,OU=Users,OU=Corp,\(Self.corp)", attributes: ["cn"])?.string("cn") == "Pieter Van Damme")
        await home.close()
        await child.close()
    }

    /// Without the child domain open, its entries are refused, and the
    /// parent's server never hears of them; moving between domains is refused.
    @Test func withoutTheChildOpenItsEntriesAreRefused() async throws {
        let home = try await Self.open(10389)
        let held = ServerInfo(rootDSE: try await home.rootDSE()).namingContexts
        await home.setRoutes(ForestRoutes(held: held, domains: [.init(root: Self.child, dnsName: "child.corp.example", failure: "it did not answer")]))
        let wire = WireLog()
        await home.observeReceivedBytes { wire.append($0) }
        await #expect(throws: LDAPError.self) { _ = try await home.read(Self.lieve) }
        await #expect(throws: LDAPError.self) { try await home.modify(Self.lieve, [.replace("description", ["x"])]) }
        #expect(wire.bytes.isEmpty)
        #expect(try await home.read("CN=Pieter Van Damme,OU=Engineering,OU=Users,OU=Corp,\(Self.corp)", attributes: ["cn"]) != nil)
        await home.close()
    }
}
