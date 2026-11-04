// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

// MARK: Domain information

/// The facts about an AD domain an administrator looks up most: names and
/// levels, who holds the FSMO roles, the domain controllers and sites, trusts,
/// and the default and fine-grained password policies.
@MainActor @Observable
final class DomainInfoModel {
    struct DomainController: Identifiable {
        var id: String { dn }
        let dn: String
        let name: String
        let host: String
        let os: String
        let site: String
        let lastSeen: Date?
        let readOnly: Bool
        let globalCatalog: Bool
    }

    struct Role: Identifiable {
        var id: String { name }
        let name: String
        let holder: String
    }

    struct Trust: Identifiable {
        var id: String { dn }
        let dn: String
        let partner: String
        let direction: String
        let type: String
        let attributes: String
    }

    var loading = true
    var error: String?
    var domain: LDAPEntry?
    var netbiosName: String?
    var dnsName: String?
    var recycleBin = false
    var tombstoneLifetime: Int?
    var roles: [Role] = []
    var controllers: [DomainController] = []
    var sites: [String] = []
    var trusts: [Trust] = []
    var forestDomains: [ForestDomain] = []
    var policies: [LDAPEntry] = []
    var counts: [(String, Int)] = []
    var counting = false

    func load(_ session: DirectorySession) async {
        guard let server = session.server, let base = server.defaultNamingContext else {
            error = "The server does not name a default naming context."
            loading = false
            return
        }
        loading = true
        let config = server.configurationNamingContext ?? "CN=Configuration,\(base)"
        func read(_ dn: String, _ attributes: [String]) async -> LDAPEntry? {
            try? await session.run { try await $0.read(dn, attributes: attributes) }
        }
        func search(_ base: String, _ scope: LDAPScope, _ filter: String, _ attributes: [String]) async -> [LDAPEntry] {
            guard let parsed = try? LDAPFilter.parse(filter) else { return [] }
            let request = LDAPSearchRequest(base: base, scope: scope, filter: parsed, attributes: attributes)
            return (try? await session.run { try await $0.pagedSearch(request, pageSize: 500) })?.entries ?? []
        }
        domain = await read(base, ["*", "msDS-Behavior-Version", "ms-DS-MachineAccountQuota", "fSMORoleOwner"])
        forestDomains = await session.forestDomains()
        dnsName = DN.dnsDomain(base)
        let partitions = "CN=Partitions,\(config)"
        if let crossRef = await search(partitions, .oneLevel, "(nCName=\(LDAPFilter.escape(base)))", ["nETBIOSName", "dnsRoot"]).first {
            netbiosName = crossRef.string("nETBIOSName")
            dnsName = crossRef.string("dnsRoot") ?? dnsName
        }
        let partitionEntry = await read(partitions, ["fSMORoleOwner", "msDS-EnabledFeature"])
        recycleBin = partitionEntry?.strings("msDS-EnabledFeature").contains { $0.lowercased().hasPrefix("cn=recycle bin feature") } ?? false
        tombstoneLifetime = await read("CN=Directory Service,CN=Windows NT,CN=Services,\(config)", ["tombstoneLifetime"])?
            .int("tombstoneLifetime").map(Int.init)

        func holder(_ entry: LDAPEntry?) -> String {
            guard let owner = entry?.string("fSMORoleOwner") else { return "—" }
            let parts = DN.components(owner)
            let server = parts.count > 1 ? DN.rdnValue(parts[1]) : owner
            let site = parts.count > 3 ? DN.rdnValue(parts[3]) : nil
            return site.map { "\(server) (\($0))" } ?? server
        }
        roles = [
            Role(name: "PDC emulator", holder: holder(domain)),
            Role(name: "RID master", holder: holder(await read("CN=RID Manager$,CN=System,\(base)", ["fSMORoleOwner"]))),
            Role(name: "Infrastructure master", holder: holder(await read("CN=Infrastructure,\(base)", ["fSMORoleOwner"]))),
            Role(name: "Schema master", holder: holder(await read(server.schemaNamingContext ?? "CN=Schema,\(config)", ["fSMORoleOwner"]))),
            Role(name: "Domain naming master", holder: holder(partitionEntry)),
        ]

        // Which site each DC is in, and whether it is a global catalog, from its NTDS Settings.
        var siteOf: [String: String] = [:]
        var globalCatalogs: Set<String> = []
        for settings in await search("CN=Sites,\(config)", .subtree, "(objectClass=nTDSDSA)", ["options"]) {
            let parts = DN.components(settings.dn)
            guard parts.count > 3 else { continue }
            let server = DN.rdnValue(parts[1]).lowercased()
            siteOf[server] = DN.rdnValue(parts[3])
            if (settings.int("options") ?? 0) & 1 != 0 { globalCatalogs.insert(server) }
        }
        sites = await search("CN=Sites,\(config)", .oneLevel, "(objectClass=site)", ["cn"]).map { DN.rdnValue($0.dn) }.sorted()
        controllers = await search(base, .subtree, "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                                   ["cn", "dNSHostName", "operatingSystem", "lastLogonTimestamp", "userAccountControl"]).map { entry in
            let name = entry.string("cn") ?? DN.rdnValue(entry.dn)
            var lastSeen: Date?
            if let raw = entry.int("lastLogonTimestamp"), case .date(let date) = ADValues.fileTime(raw) { lastSeen = date }
            return DomainController(dn: entry.dn, name: name, host: entry.string("dNSHostName") ?? "", os: entry.string("operatingSystem") ?? "",
                                    site: siteOf[name.lowercased()] ?? "", lastSeen: lastSeen,
                                    readOnly: (entry.int("userAccountControl") ?? 0) & 0x4000000 != 0,
                                    globalCatalog: globalCatalogs.contains(name.lowercased()))
        }.sorted { $0.name < $1.name }
        trusts = await search("CN=System,\(base)", .oneLevel, "(objectClass=trustedDomain)", ["*"]).map { entry in
            Trust(dn: entry.dn, partner: entry.string("trustPartner") ?? DN.rdnValue(entry.dn),
                  direction: ADValues.trustDirection(entry.int("trustDirection") ?? 0),
                  type: ADValues.trustType(entry.int("trustType") ?? 0),
                  attributes: ADValues.flags(entry.int("trustAttributes") ?? 0, in: ADValues.trustAttributeFlags).map(\.label).joined(separator: ", "))
        }
        policies = await search("CN=Password Settings Container,CN=System,\(base)", .oneLevel, "(objectClass=msDS-PasswordSettings)", ["*"])
            .sorted { ($0.int("msDS-PasswordSettingsPrecedence") ?? 0) < ($1.int("msDS-PasswordSettingsPrecedence") ?? 0) }
        loading = false
        if domain == nil { error = "The domain object \(base) could not be read." }
    }

    func countObjects(_ session: DirectorySession) async {
        guard let base = session.server?.defaultNamingContext else { return }
        counting = true
        counts = []
        let queries = [("Users", "(&(objectClass=user)(!(objectClass=computer)))"),
                       ("Enabled users", "(&(objectClass=user)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"),
                       ("Groups", "(objectClass=group)"), ("Computers", "(objectClass=computer)"),
                       ("Organizational units", "(objectClass=organizationalUnit)")]
        for (label, filter) in queries {
            guard let parsed = try? LDAPFilter.parse(filter) else { continue }
            let request = LDAPSearchRequest(base: base, scope: .subtree, filter: parsed, attributes: ["1.1"])
            let count = (try? await session.run { try await $0.pagedSearch(request, pageSize: 1000) })?.entries.count ?? 0
            counts.append((label, count))
        }
        counting = false
    }
}

struct DomainInfoView: View {
    /// Absent when the view is drawn on its own (pictures for the website).
    @Environment(AppModel.self) private var appModel: AppModel?
    let session: DirectorySession
    @State private var model = DomainInfoModel()

    var body: some View {
        ScrollView {
            if model.loading {
                ProgressView("Reading the domain…").padding(40)
            } else if let error = model.error {
                ContentUnavailableView("Cannot Read the Domain", systemImage: "exclamationmark.triangle", description: Text(error))
            } else {
                VStack(alignment: .leading, spacing: 22) {
                    overview
                    policy
                    if !model.policies.isEmpty { fineGrained }
                    roles
                    controllers
                    if model.forestDomains.count > 1 { forest }
                    if !model.trusts.isEmpty { trusts }
                    objectCounts
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .task { await model.load(session) }
        .toolbar {
            Button { Task { await model.load(session) } } label: { Label("Refresh", systemImage: "arrow.clockwise") }
        }
    }

    private func section<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline)
            content()
        }
    }

    private func row(_ label: String, _ value: String?) -> some View {
        GridRow {
            // One width for every section, so their values start on one line.
            Text(label).foregroundStyle(.secondary).frame(minWidth: 180, alignment: .trailing).gridColumnAlignment(.trailing)
            Text(value ?? "—").textSelection(.enabled)
        }
    }

    private func formatted(_ attribute: String) -> String? {
        model.domain?.values(attribute).first.map { AttributeFormatter.format(attribute, $0).text }
    }

    private var overview: some View {
        section("Domain") {
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                row("DNS name", model.dnsName)
                row("NetBIOS name", model.netbiosName)
                row("Distinguished name", model.domain?.dn)
                row("SID", session.domainSID)
                row("Domain functional level", session.server?.domainFunctionality.map(ADValues.functionalLevelName) ?? formatted("msDS-Behavior-Version"))
                row("Forest functional level", session.server?.forestFunctionality.map(ADValues.functionalLevelName))
                row("Created", formatted("whenCreated"))
                row("Recycle Bin", model.recycleBin ? "Enabled" : "Not enabled")
                row("Tombstone lifetime", model.tombstoneLifetime.map { "\($0) days" })
                row("Computers a user may join", model.domain?.string("ms-DS-MachineAccountQuota"))
                row("Sites", model.sites.joined(separator: ", "))
            }
            .font(.callout)
        }
    }

    private var forest: some View {
        section("Domains in this forest") {
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                ForEach(model.forestDomains) { domain in
                    GridRow {
                        Text(domain.dnsName).frame(minWidth: 180, alignment: .trailing).gridColumnAlignment(.trailing)
                        HStack(spacing: 10) {
                            Text(domain.netbiosName ?? "").foregroundStyle(.secondary)
                            if session.holdsEntry(domain.dn) {
                                Text("This connection").foregroundStyle(.secondary)
                            } else if let appModel {
                                Button("Open") { Task { await appModel.openDomain(domain.dnsName, from: session) } }
                                    .help("Browse \(domain.dnsName) with this connection's settings and user")
                            }
                        }
                    }
                }
            }
            .font(.callout)
            Text("Each domain is browsed through a connection of its own. Search › Whole forest finds entries in all of them at once.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var policy: some View {
        section("Default password and lockout policy") {
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                row("Minimum length", model.domain?.string("minPwdLength").map { "\($0) characters" })
                row("History", model.domain?.string("pwdHistoryLength").map { "\($0) passwords remembered" })
                row("Maximum age", formatted("maxPwdAge"))
                row("Minimum age", formatted("minPwdAge"))
                row("Properties", model.domain?.int("pwdProperties").map {
                    ADValues.flags($0, in: ADValues.passwordPropertyFlags).map(\.label).joined(separator: ", ")
                })
                row("Lockout after", model.domain?.string("lockoutThreshold").map { $0 == "0" ? "Never locks out" : "\($0) failed attempts" })
                row("Lockout duration", formatted("lockoutDuration"))
                row("Counter reset after", formatted("lockoutObservationWindow"))
            }
            .font(.callout)
        }
    }

    private var fineGrained: some View {
        section("Fine-grained password policies") {
            ForEach(model.policies, id: \.dn) { pso in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Button(DN.rdnValue(pso.dn)) { session.open(pso.dn) }.buttonStyle(.link).font(.callout.weight(.semibold))
                        Text("precedence \(pso.string("msDS-PasswordSettingsPrecedence") ?? "?")").font(.caption).foregroundStyle(.secondary)
                    }
                    let age = pso.values("msDS-MaximumPasswordAge").first.map { AttributeFormatter.format("maxPwdAge", $0).text } ?? "—"
                    let duration = pso.values("msDS-LockoutDuration").first.map { AttributeFormatter.format("lockoutDuration", $0).text } ?? "—"
                    let threshold = pso.string("msDS-LockoutThreshold") ?? "?"
                    let lockout = threshold == "0" ? "no lockout" : "lockout after \(threshold) attempts for \(duration)"
                    Text("Minimum \(pso.string("msDS-MinimumPasswordLength") ?? "?") characters, history \(pso.string("msDS-PasswordHistoryLength") ?? "?"), complexity \(pso.string("msDS-PasswordComplexityEnabled") == "TRUE" ? "on" : "off"), maximum age \(age), \(lockout).")
                        .font(.callout).foregroundStyle(.secondary)
                    HStack(spacing: 4) {
                        Text("Applies to").font(.caption).foregroundStyle(.secondary)
                        ForEach(pso.strings("msDS-PSOAppliesTo"), id: \.self) { target in
                            Button(DN.displayName(target)) { session.open(target) }.buttonStyle(.link).font(.caption)
                        }
                    }
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }

    private var roles: some View {
        section("Operations master (FSMO) roles") {
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                ForEach(model.roles) { role in row(role.name, role.holder) }
            }
            .font(.callout)
        }
    }

    private var controllers: some View {
        section("Domain controllers (\(model.controllers.count))") {
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                GridRow {
                    Text("Name"); Text("Host"); Text("Site"); Text("Operating system"); Text("Last seen"); Text("")
                }
                .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                ForEach(model.controllers) { dc in
                    GridRow {
                        Button(dc.name) { session.open(dc.dn) }.buttonStyle(.link)
                        Text(dc.host)
                        Text(dc.site)
                        Text(dc.os)
                        Text(dc.lastSeen.map { AttributeFormatter.dateText($0) } ?? "—")
                        Text([dc.globalCatalog ? "GC" : nil, dc.readOnly ? "RODC" : nil].compactMap { $0 }.joined(separator: " "))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .font(.callout)
        }
    }

    private var trusts: some View {
        section("Trusts") {
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                ForEach(model.trusts) { trust in
                    GridRow {
                        Button(trust.partner) { session.open(trust.dn) }.buttonStyle(.link)
                        Text(trust.direction)
                        Text(trust.type)
                        Text(trust.attributes).foregroundStyle(.secondary)
                    }
                }
            }
            .font(.callout)
        }
    }

    private var objectCounts: some View {
        section("Objects") {
            if model.counts.isEmpty && !model.counting {
                Button("Count Objects") { Task { await model.countObjects(session) } }
                Text("Pages through the domain; on a large one this takes a while.").font(.caption).foregroundStyle(.secondary)
            } else {
                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                    ForEach(model.counts, id: \.0) { label, count in row(label, count.formatted()) }
                }
                .font(.callout)
                if model.counting { ProgressView().controlSize(.small) }
            }
        }
    }
}

// MARK: Account status across domain controllers

/// lastLogon, badPwdCount and badPasswordTime are kept per domain controller
/// and never replicated, so the true state of an account is only visible by
/// asking every DC, which is what this does (like Microsoft's LockoutStatus).
struct AccountStatusSheet: View {
    let session: DirectorySession
    let entry: LDAPEntry
    @Environment(\.dismiss) private var dismiss

    struct Row: Identifiable {
        let id = UUID()
        let server: String
        var state: String = "Reading…"
        var badCount: String = ""
        var lastBad: String = ""
        var lastLogon: String = ""
        var passwordSet: String = ""
        var locked = false
        var failed = false
        /// Not contacted, for the reason in `state`.
        var skipped = false
    }

    @State private var rows: [Row] = []

    private var failures: [Row] { rows.filter(\.failed) }

    var body: some View {
        SheetLayout(title: "Account Status on Each Domain Controller", subtitle: DN.displayName(entry.dn), width: 1000, height: 440) {
            VStack(alignment: .leading, spacing: 0) {
                Table(rows) {
                    TableColumn("Domain controller") { row in Text(row.server).lineLimit(1).help(row.server) }
                        .width(min: 140, ideal: 170)
                    TableColumn("State") { row in
                        Label {
                            Text(row.skipped ? "Not contacted" : (row.failed ? "Not reachable" : row.state))
                        } icon: {
                            Image(systemName: row.skipped ? "minus.circle"
                                  : (row.failed ? "exclamationmark.triangle.fill" : (row.locked ? "lock.fill" : "checkmark.circle")))
                        }
                        .foregroundStyle(row.skipped ? Color.secondary : (row.failed ? Color.red : (row.locked ? Color.orange : Color.primary)))
                        .help(row.state)
                    }
                    .width(min: 115, ideal: 125)
                    // Wide enough for its title: the count itself is short.
                    TableColumn("Bad passwords") { row in Text(row.badCount).monospacedDigit() }
                        .width(min: 95, ideal: 95)
                    TableColumn("Last bad password", value: \.lastBad).width(min: 115, ideal: 130)
                    TableColumn("Last sign-in", value: \.lastLogon).width(min: 115, ideal: 130)
                    TableColumn("Password set", value: \.passwordSet).width(min: 150, ideal: 175)
                }
                .tableStyle(.inset(alternatesRowBackgrounds: true))
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(failures) { row in
                        Label { Text("\(row.server): \(row.state)").textSelection(.enabled) } icon: {
                            Image(systemName: row.skipped ? "minus.circle" : "exclamationmark.triangle.fill")
                                .foregroundStyle(row.skipped ? Color.secondary : Color.red)
                        }
                        .font(.callout)
                    }
                    Text("Bad password counts and last sign-in are kept by each domain controller separately; a lockout replicates. The others are signed in to with this connection's credentials, encrypted, and only when this Mac trusts their certificate.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 10)
            }
        } buttons: {
            if rows.contains(where: \.locked) {
                Button("Unlock") {
                    Task {
                        await AccountActions.unlock(entry, session: session)
                        await load()
                    }
                }
                .disabled(!session.canWrite)
                .help(session.canWrite ? "Unlock the account." : "Turn on editing to unlock.")
            }
            Button("Refresh") { Task { await load() } }
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
        }
        .task { await load() }
    }

    static let attributes = ["lockoutTime", "badPwdCount", "badPasswordTime", "lastLogon", "pwdLastSet", "msDS-User-Account-Control-Computed"]

    private func load() async {
        let base = session.server?.defaultNamingContext ?? ""
        let request = LDAPSearchRequest(base: base, scope: .subtree,
                                        filter: (try? LDAPFilter.parse("(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))")) ?? .present("objectClass"),
                                        attributes: ["dNSHostName", "cn"])
        let controllers = (try? await session.run { try await $0.pagedSearch(request, pageSize: 500) })?.entries ?? []
        let connected = session.profile.host
        // The password goes to each of these, so only to names the directory
        // gives inside its own domain.
        let domain = DN.dnsDomain(base)?.lowercased()
        let encrypted = session.profile.security != .none || session.profile.authentication != .simple
        rows = [Row(server: "\(connected) (connected)")] + controllers.compactMap { dc in
            let host = (dc.string("dNSHostName") ?? "").trimmingCharacters(in: .whitespaces)
            if host.caseInsensitiveCompare(connected) == .orderedSame { return nil }
            if !encrypted {
                return Row(server: host.isEmpty ? DN.rdnValue(dc.dn) : host,
                           state: "This connection is not encrypted, so signing in there would send the password in clear text.",
                           failed: true, skipped: true)
            }
            if host.isEmpty {
                return Row(server: DN.rdnValue(dc.dn), state: "The directory gives no DNS name for it.", failed: true, skipped: true)
            }
            if let domain, host.lowercased() != domain, !host.lowercased().hasSuffix("." + domain) {
                return Row(server: host, state: "Its name is outside the domain \(domain).", failed: true, skipped: true)
            }
            return Row(server: host)
        }
        // The connected server first, through the session.
        let current = try? await session.run { try await $0.read(entry.dn, attributes: Self.attributes) }
        update(0, with: current, error: current == nil ? "Could not read the account" : nil)
        await withTaskGroup(of: (Int, LDAPEntry?, String?).self) { group in
            for index in rows.indices.dropFirst() where !rows[index].skipped {
                let host = rows[index].server
                group.addTask { @MainActor in
                    do {
                        let connection = try await session.openConnection(to: host, timeout: 8)
                        defer { Task { await connection.close() } }
                        return (index, try await connection.read(entry.dn, attributes: Self.attributes), nil)
                    } catch {
                        return (index, nil, error.localizedDescription)
                    }
                }
            }
            for await (index, result, error) in group { update(index, with: result, error: error) }
        }
    }

    private func update(_ index: Int, with result: LDAPEntry?, error: String?) {
        guard rows.indices.contains(index) else { return }
        if let error {
            rows[index].state = error
            rows[index].failed = true
            return
        }
        guard let result else { return }
        func time(_ name: String) -> String {
            guard let raw = result.int(name) else { return "—" }
            if case .date(let date) = ADValues.fileTime(raw) { return date.formatted(date: .abbreviated, time: .shortened) }
            return name == "pwdLastSet" ? "Must change at next sign-in" : "Never"
        }
        rows[index].locked = AccountActions.isLocked(result)
        rows[index].state = rows[index].locked ? "Locked out" : "Not locked"
        rows[index].badCount = result.string("badPwdCount") ?? "0"
        rows[index].lastBad = time("badPasswordTime")
        rows[index].lastLogon = time("lastLogon")
        rows[index].passwordSet = time("pwdLastSet")
    }
}

// MARK: Replication metadata

/// When each attribute last changed, where, and how many times; and for
/// linked attributes such as member, when each value was added.
struct ReplicationView: View {
    let session: DirectorySession
    let entry: LDAPEntry
    @State private var attributes: [ReplicationMetadata] = []
    @State private var values: [ValueReplicationMetadata] = []
    @State private var loading = true
    @State private var error: String?

    var body: some View {
        Group {
            if loading {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error {
                ContentUnavailableView("No Replication Metadata", systemImage: "arrow.triangle.2.circlepath", description: Text(error))
            } else {
                VSplitView {
                    Table(attributes) {
                        // The date and time is the longest value and is read in full;
                        // the server and USN are short.
                        TableColumn("Attribute", value: \.attribute).width(min: 110, ideal: 170)
                        TableColumn("Version") { Text(String($0.version)).monospacedDigit() }.width(60)
                        TableColumn("Last change") { meta in
                            Text(meta.lastOriginatingChange.map { $0.formatted(date: .abbreviated, time: .standard) } ?? "—")
                        }
                        .width(min: 170, ideal: 190)
                        TableColumn("On") { Text($0.originatingServer).help($0.originatingDSA) }.width(min: 50, ideal: 70)
                        TableColumn("USN") { Text(String($0.originatingUSN)).monospacedDigit() }.width(min: 50, ideal: 70)
                    }
                    if !values.isEmpty {
                        Table(values) {
                            TableColumn("Linked value") { meta in
                                Button(DN.displayName(meta.value)) { session.open(meta.value) }.buttonStyle(.link).help(meta.value)
                            }
                            TableColumn("Attribute", value: \.attribute).width(80)
                            TableColumn("Added") { Text($0.created.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? "—") }
                            TableColumn("Removed") { meta in
                                Text(meta.isDeleted ? (meta.deleted?.formatted(date: .abbreviated, time: .shortened) ?? "yes") : "")
                            }
                            TableColumn("Version") { Text(String($0.version)).monospacedDigit() }.width(60)
                        }
                    }
                }
            }
        }
        .task(id: entry.dn) { await load() }
    }

    private func load() async {
        loading = true
        do {
            let found = try await session.run {
                try await $0.read(entry.dn, attributes: ["msDS-ReplAttributeMetaData", "msDS-ReplValueMetaData"])
            }
            attributes = ReplicationMetadata.parse(found?.strings("msDS-ReplAttributeMetaData") ?? [])
            values = ValueReplicationMetadata.parse(found?.strings("msDS-ReplValueMetaData") ?? [])
            error = attributes.isEmpty ? "The server returned no msDS-ReplAttributeMetaData for this entry." : nil
        } catch {
            self.error = error.localizedDescription
        }
        loading = false
    }
}
