// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import LDAPKit
import Observation

/// The entry shown on the right, and its group memberships.
@MainActor @Observable
final class InspectorModel {
    enum Tab: String, CaseIterable, Identifiable {
        case overview, attributes, membership, permissions, replication, ldif
        var id: String { rawValue }
        var label: String {
            switch self {
            case .overview: return "Overview"
            case .attributes: return "Attributes"
            case .membership: return "Membership"
            case .permissions: return "Permissions"
            case .replication: return "Replication"
            case .ldif: return "LDIF"
            }
        }
    }

    weak var session: DirectorySession?

    private(set) var dn: String?
    private(set) var entry: LDAPEntry?
    private(set) var kind: ObjectKind = .other
    private(set) var loading = false
    private(set) var error: String?
    /// The entry is in another domain of the forest (found by a search of the
    /// whole forest), which this connection's server does not hold.
    private(set) var otherDomain: String?
    var tab: Tab = .overview

    let membership = MembershipModel()

    @ObservationIgnored private var task: Task<Void, Never>?

    /// Constructed attributes AD only returns when asked by name.
    static let adConstructed = ["msDS-User-Account-Control-Computed", "msDS-UserPasswordExpiryTimeComputed",
                                "msDS-PrincipalName", "canonicalName", "msDS-ResultantPSO", "allowedAttributesEffective"]

    var showsMembership: Bool {
        switch kind {
        case .user, .computer, .domainController, .serviceAccount, .contact, .group, .foreignSecurityPrincipal: return true
        default: return false
        }
    }

    func clear() {
        task?.cancel()
        dn = nil
        entry = nil
        error = nil
        loading = false
        membership.clear()
    }

    func load(_ dn: String?) {
        task?.cancel()
        membership.clear()
        self.dn = dn
        entry = nil
        error = nil
        otherDomain = nil
        guard let dn, let session else { loading = false; return }
        if session.hasADTools, !session.holdsEntry(dn) {
            loading = true
            task = Task { [weak self] in
                let domain = await session.otherDomain(of: dn)
                guard let self, !Task.isCancelled else { return }
                self.loading = false
                if let domain {
                    self.otherDomain = domain.dnsName
                    self.error = "\(DN.displayName(dn)) is in \(domain.dnsName), another domain of the forest. This connection's server does not hold it; open that domain to see it whole."
                } else {
                    self.error = "\(DN.displayName(dn)) is not held by this server, and \(DN.dnsDomain(dn) ?? "its domain") is not a domain of this forest, so Forester does not connect there for it."
                }
            }
            return
        }
        loading = true
        task = Task { [weak self] in
            do {
                let found: LDAPEntry?
                if dn.isEmpty {
                    found = try await session.run { try await $0.rootDSE() }
                } else {
                    let attributes = ["*", "+"] + Self.adConstructed
                    found = try await session.run { connection -> LDAPEntry? in
                        guard let raw = try await connection.read(dn, attributes: attributes) else { return nil }
                        return try await connection.completingRangedAttributes(raw)
                    }
                }
                guard let self, !Task.isCancelled else { return }
                self.loading = false
                guard let found else {
                    self.error = "This entry no longer exists, or you are not allowed to read it."
                    return
                }
                self.entry = found
                self.kind = ObjectKind.classify(found)
                if !self.showsMembership, self.tab == .membership { self.tab = .overview }
                if self.showsMembership { self.membership.load(found, kind: self.kind, session: session) }
            } catch {
                guard let self, !Task.isCancelled else { return }
                self.loading = false
                self.error = error.localizedDescription
            }
        }
    }

    func reload() {
        load(dn)
    }
}

/// Group membership in both directions, direct and nested.
@MainActor @Observable
final class MembershipModel {
    struct Ref: Identifiable, Hashable, Sendable {
        let id: String
        let dn: String
        var name: String
        var kind: ObjectKind?
        var detail: String
        var disabled = false
        /// Why it is listed when that is not obvious ("primary group").
        var note: String?

        init(dn: String, name: String? = nil, kind: ObjectKind? = nil, detail: String = "", note: String? = nil) {
            id = dn.isEmpty ? UUID().uuidString : DN.normalized(dn)
            self.dn = dn
            self.name = name ?? DN.displayName(dn)
            self.kind = kind
            self.detail = detail
            self.note = note
        }
    }

    private(set) var memberOf: [Ref] = []
    private(set) var members: [Ref] = []
    private(set) var nested: [Ref]?
    /// Members of a dynamic group, found by running its member URLs.
    private(set) var dynamic: [Ref]?
    private(set) var dynamicURLs: [String] = []
    private(set) var dynamicNote: String?
    private(set) var loading = false
    private(set) var nestedLoading = false
    private(set) var error: String?
    private(set) var nestedNote: String?
    private(set) var isGroup = false

    @ObservationIgnored private var task: Task<Void, Never>?
    /// "Show all nested" runs on its own and must not outlive the entry it was
    /// asked for: its answer would be shown as the next entry's.
    @ObservationIgnored private var nestedTask: Task<Void, Never>?
    @ObservationIgnored private var entry: LDAPEntry?
    @ObservationIgnored private weak var session: DirectorySession?

    static let lookupAttributes = ["objectClass", "sAMAccountName", "uid", "mail",
                                   "description", "displayName", "groupType", "dNSHostName"] + ObjectKind.disabledAttributes
    static let nestedLimit = 5000
    #if DEBUG
    /// Makes the in-chain query fail, so the automation can prove the fallback
    /// that a small test domain never needs.
    nonisolated(unsafe) static var failInChainForTesting = false
    struct ForcedFailure: Error {}
    #endif

    func clear() {
        task?.cancel()
        nestedTask?.cancel()
        nestedTask = nil
        memberOf = []
        members = []
        nested = nil
        dynamic = nil
        dynamicURLs = []
        dynamicNote = nil
        loading = false
        nestedLoading = false
        error = nil
        nestedNote = nil
        entry = nil
    }

    func load(_ entry: LDAPEntry, kind: ObjectKind, session: DirectorySession) {
        clear()
        self.entry = entry
        self.session = session
        isGroup = kind == .group
        loading = true
        task = Task { [weak self] in
            guard let self else { return }
            do {
                var groups = entry.strings("memberOf").map { Ref(dn: $0) }
                if groups.isEmpty, !session.isMicrosoft {
                    groups = try await self.groupsContaining(entry, session: session).map { Ref(dn: $0) }
                }
                if let primary = try await self.primaryGroup(of: entry, session: session) {
                    groups.insert(primary, at: 0)
                }
                var direct: [Ref] = []
                if kind == .group {
                    // A group can have tens of thousands of members: their
                    // names are taken from their DNs away from the main thread.
                    direct = await Self.offMain {
                        (entry.strings("member") + entry.strings("uniqueMember")).map { Ref(dn: $0) }
                            + entry.strings("memberUid").map { Ref(dn: "", name: $0, detail: "posix memberUid") }
                    }
                    direct += try await self.primaryMembers(of: entry, session: session)
                }
                // groupOfURLs (OpenLDAP, 389) and eDirectory's dynamicGroup keep a query, not a list.
                let urls = entry.strings("memberURL") + entry.strings("memberQueryURL")
                var dynamic: [Ref]?
                var dynamicNote: String?
                if !urls.isEmpty {
                    var found: [Ref] = []
                    for text in urls {
                        // Directory data: a query of a sensible size, or none.
                        guard text.utf8.count <= 8_192, let url = LDAPURL(text), let filter = try? LDAPFilter.parse(url.filter) else {
                            dynamicNote = "“\(text.count > 200 ? text.prefix(200) + "…" : text)” is not an LDAP URL this app can run."
                            continue
                        }
                        let request = LDAPSearchRequest(base: url.dn, scope: url.scope, filter: filter, attributes: Self.lookupAttributes)
                        let pageSize = session.profile.pageSize
                        let result = try await session.run { try await $0.pagedSearch(request, pageSize: pageSize, limit: Self.nestedLimit) }
                        found += result.entries.map(Self.ref(for:))
                        if result.stoppedAtLimit { dynamicNote = "Showing the first \(Self.nestedLimit.formatted())." }
                    }
                    dynamic = await Self.offMain { [found] in Self.sorted(found) }
                }
                let resolved = try await self.resolve(groups + direct, session: session)
                // The primary group stays first, the way AD's own tools show it.
                let (memberOf, members) = await Self.offMain { [groups] in
                    let resolvedGroups = Array(resolved.prefix(groups.count))
                    return (resolvedGroups.filter { $0.note != nil } + Self.sorted(resolvedGroups.filter { $0.note == nil }),
                            Self.sorted(Array(resolved.dropFirst(groups.count))))
                }
                guard !Task.isCancelled else { return }
                self.dynamicURLs = urls
                self.dynamic = dynamic
                self.dynamicNote = dynamicNote
                self.memberOf = memberOf
                self.members = members
                self.loading = false
            } catch {
                guard !Task.isCancelled else { return }
                self.error = error.localizedDescription
                self.loading = false
            }
        }
    }

    /// Every group this entry belongs to through nesting (for a group: every
    /// member, at any depth). On AD, see `nestedInAD`; elsewhere the graph is
    /// walked a level at a time. Both stop at groups already seen, so groups
    /// nested in a circle are each listed once.
    func loadNested() {
        guard let entry, let session, !nestedLoading else { return }
        nestedLoading = true
        nestedNote = nil
        let group = isGroup
        nestedTask = Task { [weak self] in
            guard let self else { return }
            do {
                let dns: [String]
                var note: String?
                if session.isMicrosoft {
                    dns = try await self.nestedInAD(entry, members: group, session: session)
                    note = group
                        ? "Members whose primary group is a nested group are not included."
                        : "Primary groups are not included; AD does not chain through them."
                } else {
                    dns = try await self.walk(from: entry, members: group, session: session)
                }
                if dns.isEmpty, note == nil { note = group ? "No members." : "No groups." }
                let resolved = try await self.resolve(dns.map { Ref(dn: $0) }, session: session)
                if dns.count >= Self.nestedLimit {
                    note = "Showing the first \(Self.nestedLimit.formatted())."
                }
                let sorted = await Self.offMain { Self.sorted(resolved) }
                guard !Task.isCancelled else { return }
                self.nestedNote = note
                self.nested = sorted
            } catch {
                guard !Task.isCancelled else { return }
                self.nestedNote = error.localizedDescription
                self.nested = []
            }
            self.nestedLoading = false
        }
    }

    // MARK: Queries

    private func searchBases(_ session: DirectorySession) -> [String] {
        let base = session.profile.baseDN.trimmingCharacters(in: .whitespaces)
        if !base.isEmpty { return [base] }
        if session.isMicrosoft, let defaultNC = session.server?.defaultNamingContext { return [defaultNC] }
        return session.server?.namingContexts ?? []
    }

    /// Groups listing the entry as a member, for servers without memberOf.
    private func groupsContaining(_ entry: LDAPEntry, session: DirectorySession) async throws -> [String] {
        var clauses = ["(member=\(LDAPFilter.escape(entry.dn)))", "(uniqueMember=\(LDAPFilter.escape(entry.dn)))"]
        if let uid = entry.string("uid") { clauses.append("(&(objectClass=posixGroup)(memberUid=\(LDAPFilter.escape(uid))))") }
        let filter = try LDAPFilter.parse("(|\(clauses.joined()))")
        var found: [String] = []
        for base in searchBases(session) {
            let request = LDAPSearchRequest(base: base, scope: .subtree, filter: filter, attributes: ["1.1"])
            let pageSize = session.profile.pageSize
            found += try await session.run { try await $0.pagedSearch(request, pageSize: pageSize, limit: Self.nestedLimit) }
                .entries.map(\.dn)
        }
        return found
    }

    /// AD keeps the primary group (normally Domain Users) out of memberOf and
    /// stores only its RID; find the group with that SID.
    private func primaryGroup(of entry: LDAPEntry, session: DirectorySession) async throws -> Ref? {
        guard let rid = entry.int("primaryGroupID"), let domainSID = session.domainSID,
              let sid = ADValues.sidData("\(domainSID)-\(rid)"), let base = session.server?.defaultNamingContext else { return nil }
        let request = LDAPSearchRequest(base: base, scope: .subtree, filter: .equality("objectSid", [UInt8](sid)),
                                        attributes: Self.lookupAttributes)
        guard let group = try await session.run({ try await $0.search(request) }).entries.first else {
            return Ref(dn: "", name: ADValues.wellKnownName("\(domainSID)-\(rid)") ?? "RID \(rid)", kind: .group,
                       detail: "Not found", note: "Primary group")
        }
        var ref = Self.ref(for: group)
        ref.note = "Primary group"
        return ref
    }

    /// Accounts whose primary group is this group; they are not in its member attribute.
    private func primaryMembers(of group: LDAPEntry, session: DirectorySession) async throws -> [Ref] {
        guard let sidData = group.values("objectSid").first, let sid = ADValues.sidString(sidData),
              let domainSID = session.domainSID, ADValues.domainSID(of: sid) == domainSID,
              let rid = ADValues.rid(sid), let base = session.server?.defaultNamingContext else { return [] }
        let request = LDAPSearchRequest(base: base, scope: .subtree, filter: .equality("primaryGroupID", String(rid)),
                                        attributes: Self.lookupAttributes)
        let pageSize = session.profile.pageSize
        let result = try await session.run { try await $0.pagedSearch(request, pageSize: pageSize, limit: Self.nestedLimit) }
        return result.entries.map {
            var ref = Self.ref(for: $0)
            ref.note = "Primary group"
            return ref
        }
    }

    /// Nesting on AD, by the cheapest way that gives the whole answer.
    ///
    /// 1. The entry's own transitive attribute (msds-memberOfTransitive, or
    ///    msds-memberTransitive for a group): AD computes it on a read of the
    ///    one entry, so it costs no search at all.
    /// 2. Without it (older servers, Samba): for the groups an account is in,
    ///    the in-chain matching rule, restricted to groups. Unrestricted, AD
    ///    tests the chain against every object in the domain, which on a large
    ///    one outlasts the request timeout; restricted, it uses the index.
    /// 3. For a group's members: a walk from group to group, asking AD for the
    ///    groups inside each one. Every group is visited once, so a circle of
    ///    nested groups ends where it started.
    private func nestedInAD(_ entry: LDAPEntry, members: Bool, session: DirectorySession) async throws -> [String] {
        let direct = members ? entry.strings("member") : entry.strings("memberOf")
        let transitiveName = members ? "msds-memberTransitive" : "msds-memberOfTransitive"
        // A refusal (an older server, or no right to read it) is not an answer: fall back.
        let transitive = (try? await session.run { try await $0.read(entry.dn, attributes: [transitiveName]) })??.strings(transitiveName) ?? []
        // Empty with direct links means the server does not have the attribute.
        if !transitive.isEmpty || direct.isEmpty {
            return Self.withoutSelf(transitive, entry.dn)
        }
        if !members {
            let filter = LDAPFilter.and([.equality("objectCategory", Array("group".utf8)),
                                         .extensible(rule: "1.2.840.113556.1.4.1941", attribute: "member",
                                                     value: Array(entry.dn.utf8), dnAttributes: false)])
            let request = LDAPSearchRequest(base: domainRoot(session), scope: .subtree, filter: filter, attributes: ["1.1"])
            let pageSize = session.profile.pageSize
            do {
                #if DEBUG
                if Self.failInChainForTesting { throw ForcedFailure() }
                #endif
                let found = try await session.run { try await $0.pagedSearch(request, pageSize: pageSize, limit: Self.nestedLimit) }
                return Self.withoutSelf(found.entries.map(\.dn), entry.dn)
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                // Too slow or refused on this domain: follow memberOf a group at a
                // time instead, which always finishes.
                return Self.withoutSelf(try await walk(from: entry, members: false, session: session), entry.dn)
            }
        }
        return try await membersByWalking(entry, session: session)
    }

    /// Every member of a group at any depth: its members, then the members of
    /// each group inside it, each group read once.
    private func membersByWalking(_ group: LDAPEntry, session: DirectorySession) async throws -> [String] {
        var visited: Set<String> = [DN.normalized(group.dn)]
        var listed: Set<String> = [DN.normalized(group.dn)]
        var order: [String] = []
        var queue = [group.dn]
        let pageSize = session.profile.pageSize
        while !queue.isEmpty, order.count < Self.nestedLimit {
            try Task.checkCancellation()
            let current = queue.removeFirst()
            let entry = try await session.run { try await $0.read(current, attributes: ["member"]) }
            for dn in entry?.strings("member") ?? [] where listed.insert(DN.normalized(dn)).inserted {
                order.append(dn)
            }
            let inside = LDAPSearchRequest(base: domainRoot(session), scope: .subtree,
                                           filter: .and([.equality("objectCategory", Array("group".utf8)),
                                                         .equality("memberOf", Array(current.utf8))]),
                                           attributes: ["1.1"])
            let groups = try await session.run { try await $0.pagedSearch(inside, pageSize: pageSize, limit: Self.nestedLimit) }.entries
            for nested in groups where visited.insert(DN.normalized(nested.dn)).inserted {
                queue.append(nested.dn)
            }
        }
        return Array(order.prefix(Self.nestedLimit))
    }

    /// Groups can sit anywhere in the domain, whatever part of it the
    /// connection is set to browse, so nesting is looked up from the root.
    private func domainRoot(_ session: DirectorySession) -> String {
        session.server?.defaultNamingContext ?? searchBases(session).first ?? ""
    }

    /// A group nested in a circle is, through it, a member of itself; that is
    /// not worth listing.
    private static func withoutSelf(_ dns: [String], _ dn: String) -> [String] {
        dns.filter { !DN.isSame($0, dn) }
    }

    /// Breadth-first walk of member / memberOf links, reading each entry once.
    private func walk(from start: LDAPEntry, members: Bool, session: DirectorySession) async throws -> [String] {
        var seen: Set<String> = [DN.normalized(start.dn)]
        var order: [String] = []
        var queue = [start]
        while !queue.isEmpty, order.count < Self.nestedLimit {
            try Task.checkCancellation()
            let current = queue.removeFirst()
            let next: [String]
            if members {
                next = current.strings("member") + current.strings("uniqueMember")
            } else {
                let direct = current.strings("memberOf")
                next = direct.isEmpty ? try await groupsContaining(current, session: session) : direct
            }
            for dn in next where seen.insert(DN.normalized(dn)).inserted {
                order.append(dn)
                let attributes = members ? ["objectClass", "member", "uniqueMember"] : ["objectClass", "memberOf", "uid"]
                if let entry = try await session.run({ try await $0.read(dn, attributes: attributes) }),
                   !members || ObjectKind.classify(entry) == .group {
                    queue.append(entry)
                }
            }
        }
        return order
    }

    /// Fills in kind and a detail line for each reference, in batches, so a
    /// list of 2,000 members does not become 2,000 round trips.
    private func resolve(_ refs: [Ref], session: DirectorySession) async throws -> [Ref] {
        let wanted = await Self.offMain { refs.filter { !$0.dn.isEmpty && $0.kind == nil }.map(\.dn) }
        guard !wanted.isEmpty else { return refs }
        var found: [String: LDAPEntry] = [:]
        let attribute: String? = switch session.server?.kind {
        case .activeDirectory?, .adLDS?: "distinguishedName"
        case .openLDAP?: "entryDN"
        default: nil
        }
        let roots = session.server?.namingContexts ?? []
        if let attribute {
            let byRoot = await Self.offMain {
                Dictionary(grouping: wanted.prefix(3000)) { dn in
                    roots.filter { DN.isWithin(dn, $0) }.max { DN.components($0).count < DN.components($1).count } ?? ""
                }
            }
            for (root, dns) in byRoot where !root.isEmpty {
                for start in stride(from: 0, to: dns.count, by: 40) {
                    try Task.checkCancellation()
                    let batch = dns[start..<min(start + 40, dns.count)]
                    let filter = LDAPFilter.or(batch.map { .equality(attribute, Array($0.utf8)) })
                    let request = LDAPSearchRequest(base: root, scope: .subtree, filter: filter, attributes: Self.lookupAttributes)
                    let result = try await session.run { try await $0.search(request) }
                    for entry in result.entries { found[DN.normalized(entry.dn)] = entry }
                }
            }
        } else {
            for dn in wanted.prefix(300) {
                try Task.checkCancellation()
                if let entry = try await session.run({ try await $0.read(dn, attributes: Self.lookupAttributes) }) {
                    found[DN.normalized(entry.dn)] = entry
                }
            }
        }
        return await Self.offMain { [found] in
            refs.map { ref in
                guard ref.kind == nil, let entry = found[ref.id] else { return ref }
                var resolved = Self.ref(for: entry)
                resolved.note = ref.note
                return resolved
            }
        }
    }

    /// Work on every member of a big group, done away from the main thread.
    nonisolated static func offMain<T: Sendable>(_ work: @escaping @Sendable () -> T) async -> T {
        await Task.detached(priority: .userInitiated, operation: work).value
    }

    nonisolated static func ref(for entry: LDAPEntry) -> Ref {
        let kind = ObjectKind.classify(entry)
        var detail: String
        switch kind {
        case .group:
            detail = entry.int("groupType").map(ADValues.groupTypeDescription) ?? entry.string("description") ?? ""
        case .computer, .domainController:
            detail = entry.string("dNSHostName") ?? entry.string("sAMAccountName") ?? ""
        case .foreignSecurityPrincipal:
            detail = ADValues.wellKnownName(DN.rdnValue(entry.dn)) ?? ""
        default:
            detail = entry.string("sAMAccountName") ?? entry.string("uid") ?? entry.string("mail") ?? ""
        }
        var ref = Ref(dn: entry.dn, kind: kind, detail: detail)
        if kind == .groupPolicy, let name = entry.string("displayName") { ref.name = name }
        ref.disabled = isDisabled(entry)
        return ref
    }

    nonisolated static func sorted(_ refs: [Ref]) -> [Ref] {
        refs.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }
}
