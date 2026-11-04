// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import LDAPKit
import Observation

struct SearchRow: Identifiable, Hashable, Sendable {
    let id: String
    let entry: LDAPEntry
    let name: String
    let kind: ObjectKind
    let account: String
    let detail: String
    let location: String
    let disabled: Bool

    var kindLabel: String { kind.label }

    init(_ entry: LDAPEntry) {
        self.entry = entry
        id = entry.dn
        let kind = ObjectKind.classify(entry)
        self.kind = kind
        name = (kind == .groupPolicy ? entry.string("displayName") : nil) ?? DN.displayName(entry.dn)
        account = entry.string("sAMAccountName") ?? entry.string("uid") ?? entry.string("userPrincipalName") ?? ""
        detail = entry.string("mail") ?? entry.string("dNSHostName") ?? entry.string("description") ?? ""
        location = DN.parent(entry.dn).map(DN.canonicalName) ?? ""
        disabled = isDisabled(entry)
    }
}

/// A ready-made filter. Filters that depend on the date are built when chosen.
struct SearchPreset: Identifiable {
    enum Group: String, CaseIterable {
        case accounts = "Users", security = "Security review", groups = "Groups", computers = "Computers",
             structure = "Structure", standard = "Standard LDAP"
    }

    let id: String
    let group: Group
    let title: String
    let note: String?
    let filter: (Date) -> String

    init(_ group: Group, _ title: String, note: String? = nil, _ filter: @escaping (Date) -> String) {
        id = "\(group.rawValue)/\(title)"
        self.group = group
        self.title = title
        self.note = note
        self.filter = filter
    }

    init(_ group: Group, _ title: String, note: String? = nil, _ filter: String) {
        self.init(group, title, note: note) { _ in filter }
    }

    static func fileTime(_ date: Date, minusDays days: Int) -> String {
        String(ADValues.fileTimeValue(date.addingTimeInterval(-Double(days) * 86400)))
    }

    // (&(objectClass=user)(!(objectClass=computer))) rather than objectCategory=person:
    // it means the same in AD, and also works on directories that hold AD-shaped
    // data without AD's objectCategory shorthand.
    static let user = "(objectClass=user)(!(objectClass=computer))"
    static func bit(_ attribute: String, _ value: Int) -> String { "(\(attribute):1.2.840.113556.1.4.803:=\(value))" }

    static let all: [SearchPreset] = [
        SearchPreset(.accounts, "All users", "(&\(user))"),
        SearchPreset(.accounts, "Enabled users", "(&\(user)(!\(bit("userAccountControl", 2))))"),
        SearchPreset(.accounts, "Disabled users", "(&\(user)\(bit("userAccountControl", 2)))"),
        SearchPreset(.accounts, "Locked-out users", note: "lockoutTime stays set until the next sign-in, so this can include lockouts that have since expired.",
                     "(&\(user)(lockoutTime>=1))"),
        SearchPreset(.accounts, "Password never expires", "(&\(user)\(bit("userAccountControl", 65536)))"),
        SearchPreset(.accounts, "Must change password at next sign-in", "(&\(user)(pwdLastSet=0))"),
        SearchPreset(.accounts, "Not signed in for 90 days") { "(&\(user)(lastLogonTimestamp<=\(fileTime($0, minusDays: 90))))" },
        SearchPreset(.accounts, "Never signed in", "(&\(user)(|(!(lastLogonTimestamp=*))(lastLogonTimestamp=0)))"),
        SearchPreset(.accounts, "Accounts expiring within 30 days") {
            "(&\(user)(accountExpires>=\(fileTime($0, minusDays: 0)))(accountExpires<=\(fileTime($0, minusDays: -30))))"
        },
        SearchPreset(.security, "Privileged accounts (adminCount=1)", "(&\(user)(adminCount=1))"),
        SearchPreset(.security, "Users with a service principal name", note: "Accounts whose Kerberos tickets can be requested by any user and cracked offline (Kerberoasting).",
                     "(&\(user)(servicePrincipalName=*))"),
        SearchPreset(.security, "Kerberos pre-authentication not required", "(&\(user)\(bit("userAccountControl", 4194304)))"),
        SearchPreset(.security, "Password not required", "(&(objectClass=user)\(bit("userAccountControl", 32)))"),
        SearchPreset(.security, "Unconstrained delegation (excluding DCs)",
                     "(&(objectClass=user)\(bit("userAccountControl", 524288))(!\(bit("userAccountControl", 8192))))"),
        SearchPreset(.security, "Password last set over a year ago") { "(&\(user)(pwdLastSet>=1)(pwdLastSet<=\(fileTime($0, minusDays: 365))))" },
        SearchPreset(.groups, "All groups", "(objectClass=group)"),
        SearchPreset(.groups, "Security groups", "(&(objectClass=group)\(bit("groupType", -2147483648)))"),
        SearchPreset(.groups, "Distribution groups", "(&(objectClass=group)(!\(bit("groupType", -2147483648))))"),
        SearchPreset(.groups, "Empty groups", "(&(objectClass=group)(!(member=*)))"),
        SearchPreset(.groups, "Privileged groups (adminCount=1)", "(&(objectClass=group)(adminCount=1))"),
        SearchPreset(.computers, "All computers", "(objectClass=computer)"),
        SearchPreset(.computers, "Domain controllers", "(&(objectClass=computer)\(bit("userAccountControl", 8192)))"),
        SearchPreset(.computers, "Servers", "(&(objectClass=computer)(operatingSystem=*Server*))"),
        SearchPreset(.computers, "Not seen for 90 days") { "(&(objectClass=computer)(lastLogonTimestamp<=\(fileTime($0, minusDays: 90))))" },
        SearchPreset(.computers, "Disabled computers", "(&(objectClass=computer)\(bit("userAccountControl", 2)))"),
        SearchPreset(.structure, "Organizational units", "(objectClass=organizationalUnit)"),
        SearchPreset(.structure, "Group Policy objects", "(objectClass=groupPolicyContainer)"),
        SearchPreset(.structure, "Contacts", "(objectClass=contact)"),
        SearchPreset(.structure, "Managed service accounts",
                     "(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))"),
        SearchPreset(.standard, "People", "(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(&(objectClass=person)(!(objectClass=computer))))"),
        SearchPreset(.standard, "Groups", "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup)(objectClass=group))"),
        SearchPreset(.standard, "Everything", "(objectClass=*)"),
    ]
}

@MainActor @Observable
final class SearchModel {
    weak var session: DirectorySession?

    var filterText = "(objectClass=*)"
    var base = ""
    var scope: LDAPScope = .subtree
    /// Search every domain of the forest through the global catalog, instead
    /// of beneath `base` on this connection (Active Directory only).
    var wholeForest = false
    /// Extra attributes to fetch, for export. Comma or space separated.
    var attributesText = ""
    var limit = 5000
    var sortOrder = [KeyPathComparator(\SearchRow.name, comparator: .localizedStandard)]
    /// Same-value writes are dropped; see `TreeModel.selection`.
    var selection: Set<SearchRow.ID> {
        get { selectionStorage }
        set { if newValue != selectionStorage { selectionStorage = newValue } }
    }
    private var selectionStorage: Set<SearchRow.ID> = []
    var presetNote: String?

    private(set) var rows: [SearchRow] = []
    private(set) var entries: [LDAPEntry] = []
    private(set) var exportAttributes: [String] = []
    private(set) var running = false
    private(set) var progress = 0
    private(set) var summary: String?
    private(set) var warnings: [String] = []
    private(set) var error: String?
    private(set) var hasRun = false

    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var lastRequest: LDAPSearchRequest?
    /// The last search went to the global catalog; exporting it does too.
    @ObservationIgnored private var lastOnForest = false

    /// Runs a search on this connection, or on the global catalog for a search
    /// of the whole forest.
    private static func onServer<T>(_ session: DirectorySession, forest: Bool, _ body: (LDAPConnection) async throws -> T) async throws -> T {
        forest ? try await session.runOnGlobalCatalog(body) : try await session.run(body)
    }
    /// The extra attributes of the search the results came from.
    @ObservationIgnored private var lastExtra: [String] = []
    private(set) var exporting = false

    static let displayAttributes = ["objectClass", "displayName", "sAMAccountName", "uid", "userPrincipalName",
                                    "mail", "description", "userAccountControl", "dNSHostName", "groupType"]

    var filterProblem: String? {
        do {
            _ = try LDAPFilter.parse(filterText)
            return nil
        } catch let error as LDAPFilterError {
            return error.errorDescription
        } catch {
            return error.localizedDescription
        }
    }

    var extraAttributes: [String] {
        attributesText.split(whereSeparator: { $0 == "," || $0 == " " || $0 == "\n" }).map(String.init).filter { !$0.isEmpty }
    }

    func clear() {
        cancel()
        rows = []
        entries = []
        summary = nil
        warnings = []
        error = nil
        hasRun = false
        selection = []
    }

    func prepare(base: String) {
        if self.base.isEmpty || !(session?.server?.namingContexts.contains { DN.isWithin(self.base, $0) } ?? false) {
            self.base = base
        }
    }

    func apply(_ preset: SearchPreset) {
        filterText = preset.filter(Date())
        presetNote = preset.note
        run()
    }

    /// A search by name, for the toolbar and the directory picker, as two
    /// filters on AD. AD's ambiguous name resolution covers "First Last",
    /// account names and mail addresses from the start of a value, through its
    /// indexes, so it is fast. Matching inside a name (K8S_MINFRA in
    /// GRP_GSU_APP_K8S_MINFRA_ADMIN) cannot use an index: AD reads every object
    /// for it. In one filter with the first, it made the whole search that
    /// slow, so it is a second search, run after the first has answered.
    /// Elsewhere one substring search covers both.
    static func nameFilters(_ text: String, activeDirectory: Bool) -> (first: String, inside: String?) {
        let value = LDAPFilter.escape(text)
        func anywhere(_ attributes: [String]) -> String { "(|" + attributes.map { "(\($0)=*\(value)*)" }.joined() + ")" }
        if activeDirectory {
            return ("(anr=\(value))", anywhere(["name", "sAMAccountName", "displayName"]))
        }
        return (anywhere(["cn", "uid", "sAMAccountName", "displayName", "mail", "sn", "givenName", "userPrincipalName", "ou", "description"]), nil)
    }

    /// The toolbar search field: a filter if it looks like one, otherwise a
    /// search by name.
    func quickFind(_ text: String) {
        let query = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return }
        var inside: LDAPFilter?
        if query.hasPrefix("(") {
            filterText = query
        } else {
            let filters = Self.nameFilters(query, activeDirectory: session?.isMicrosoft == true)
            filterText = filters.first
            inside = filters.inside.flatMap { try? LDAPFilter.parse($0) }
        }
        presetNote = nil
        if base.isEmpty, let root = session?.tree.roots.first.flatMap({ session?.tree.node($0)?.dn }) { base = root }
        scope = .subtree
        session?.mode = .search
        run(alsoInside: inside)
    }

    /// The second half of a name search on AD is running: the results shown
    /// are complete for names that start with the text, and more may come.
    private(set) var lookingInside = false
    @ObservationIgnored private var insideTask: Task<Void, Never>?

    func cancel() {
        task?.cancel()
        task = nil
        insideTask?.cancel()
        insideTask = nil
        lookingInside = false
    }

    /// Which run may still update the results: a search replaced by a newer
    /// one finishes (or is cancelled) without touching what the newer one shows.
    @ObservationIgnored private var currentRun = 0

    func run(alsoInside inside: LDAPFilter? = nil) {
        guard let session else { return }
        let filter: LDAPFilter
        do {
            filter = try LDAPFilter.parse(filterText)
        } catch {
            self.error = (error as? LDAPFilterError)?.errorDescription ?? error.localizedDescription
            return
        }
        cancel()
        let extra = extraAttributes
        var requested = Self.displayAttributes + ObjectKind.disabledAttributes.filter { !Self.displayAttributes.contains($0) }
        for attribute in extra where !requested.contains(where: { $0.caseInsensitiveCompare(attribute) == .orderedSame }) {
            requested.append(attribute)
        }
        // The global catalog searches every partition it holds from the empty base.
        let forest = wholeForest && session.hasADTools
        let request = LDAPSearchRequest(base: forest ? "" : base.trimmingCharacters(in: .whitespaces), scope: forest ? .subtree : scope,
                                        filter: filter, attributes: requested)
        let pageSize = session.profile.pageSize
        let limit = max(1, self.limit)
        // Taken over with the rows they describe, so an export never mixes the
        // shown results with a newer search's columns.
        let columns = extra.isEmpty ? Self.displayAttributes.filter { $0 != "objectClass" } : extra
        currentRun += 1
        let run = currentRun
        running = true
        progress = 0
        error = nil
        warnings = []
        summary = nil
        hasRun = true
        selection = []
        let started = Date()
        task = Task { [weak self] in
            do {
                let result = try await Self.onServer(session, forest: forest) { connection in
                    try await connection.pagedSearch(request, pageSize: pageSize, limit: limit, progress: { count in
                        Task { @MainActor in self?.progress = count }
                    })
                }
                guard let self, !Task.isCancelled, self.currentRun == run else { return }
                let entries = Array(result.entries.prefix(limit))
                let rows = await Self.rows(for: entries, sortedBy: self.sortOrder)
                guard !Task.isCancelled, self.currentRun == run else { return }
                self.lastRequest = request
                self.lastOnForest = forest
                self.lastExtra = extra
                self.exportAttributes = columns
                self.entries = entries
                self.rows = rows
                let elapsed = Date().timeIntervalSince(started)
                self.summary = "\(self.entries.count.formatted()) \(self.entries.count == 1 ? "entry" : "entries") in \(elapsed.formatted(.number.precision(.fractionLength(elapsed < 10 ? 2 : 0)))) s"
                var notes: [String] = []
                if result.stoppedAtLimit || result.entries.count > limit {
                    notes.append("Stopped at \(limit.formatted()) entries. Narrow the filter or raise the limit.")
                }
                switch result.result.code {
                case .sizeLimitExceeded:
                    notes.append("The server's size limit cut the results short. It may not allow paging for this account.")
                case .timeLimitExceeded:
                    notes.append("The server's time limit cut the results short.")
                case .adminLimitExceeded:
                    notes.append("The server refused to return more (administrative limit).")
                default: break
                }
                if forest {
                    notes.append("From the global catalog, which holds every domain's entries but only some of their attributes; an entry opens with all of them in its own domain.")
                }
                if !result.references.isEmpty, !forest {
                    notes.append("\(result.references.count) continuation reference\(result.references.count == 1 ? "" : "s") to other partitions were not followed.")
                }
                self.warnings = notes
                if let inside { self.lookInside(inside, request: request, forest: forest, run: run, started: started) }
            } catch is CancellationError {
                guard let self, self.currentRun == run else { return }
                self.summary = "Stopped."
            } catch {
                guard let self, !Task.isCancelled, self.currentRun == run else { return }
                self.error = error.localizedDescription
                self.rows = []
                self.entries = []
            }
            guard let self, self.currentRun == run else { return }
            self.running = false
        }
    }

    /// Runs the matching-inside-names search and adds what it finds that the
    /// first search did not, keeping the rows already shown (and selected).
    private func lookInside(_ inside: LDAPFilter, request: LDAPSearchRequest, forest: Bool, run: Int, started: Date) {
        guard let session else { return }
        var insideRequest = request
        insideRequest.filter = inside
        let pageSize = session.profile.pageSize
        let limit = max(1, self.limit)
        lookingInside = true
        insideTask = Task { [weak self] in
            do {
                let result = try await Self.onServer(session, forest: forest) { try await $0.pagedSearch(insideRequest, pageSize: pageSize, limit: limit) }
                guard let self, !Task.isCancelled, self.currentRun == run else { return }
                let (added, rows) = await Self.adding(result.entries, to: self.entries, rows: self.rows,
                                                      sortedBy: self.sortOrder, limit: limit)
                guard !Task.isCancelled, self.currentRun == run else { return }
                if !added.isEmpty {
                    self.entries += added
                    self.rows = rows  // the selection is kept
                }
                // An export searches again; it should find what is shown.
                var combined = request
                combined.filter = .or([request.filter, inside])
                self.lastRequest = combined
                let elapsed = Date().timeIntervalSince(started)
                let count = self.entries.count
                self.summary = "\(count.formatted()) \(count == 1 ? "entry" : "entries"), \(added.count.formatted()) of them matched inside a name, in \(elapsed.formatted(.number.precision(.fractionLength(elapsed < 10 ? 2 : 0)))) s"
            } catch is CancellationError {
                return
            } catch {
                guard let self, !Task.isCancelled, self.currentRun == run else { return }
                self.warnings.append("Matching inside names failed: \(error.localizedDescription)")
            }
            guard let self, self.currentRun == run else { return }
            self.lookingInside = false
        }
    }

    func resort() {
        rows.sort(using: sortOrder)
    }

    /// Rows for entries, sorted, away from the main thread: tens of thousands
    /// of DNs to take apart and names to compare would hold up the window.
    nonisolated private static func rows(for entries: [LDAPEntry], sortedBy order: [KeyPathComparator<SearchRow>]) async -> [SearchRow] {
        await Task.detached(priority: .userInitiated) {
            entries.map(SearchRow.init).sorted(using: order)
        }.value
    }

    /// The entries of `found` not already shown, up to the limit, and the rows
    /// with them added, also away from the main thread.
    nonisolated private static func adding(_ found: [LDAPEntry], to shown: [LDAPEntry], rows: [SearchRow],
                                           sortedBy order: [KeyPathComparator<SearchRow>], limit: Int) async -> ([LDAPEntry], [SearchRow]) {
        await Task.detached(priority: .userInitiated) {
            let known = Set(shown.map { DN.normalized($0.dn) })
            let added = Array(found.filter { !known.contains(DN.normalized($0.dn)) }.prefix(max(0, limit - shown.count)))
            return (added, (rows + added.map(SearchRow.init)).sorted(using: order))
        }.value
    }

    /// LDIF of the results with every attribute, not just the columns shown.
    /// The whole result is searched again with `*`; a selection is read entry
    /// by entry. Ranged attributes are completed so large groups export whole.
    func exportLDIF(only selection: Set<String>? = nil) {
        guard let session, var request = lastRequest, !exporting else { return }
        request.attributes = ["*"] + lastExtra
        let pageSize = session.profile.pageSize
        let limit = max(1, self.limit)
        let forest = lastOnForest
        exporting = true
        Task { [weak self] in
            do {
                let entries: [LDAPEntry] = try await Self.onServer(session, forest: forest) { connection in
                    var found: [LDAPEntry] = []
                    if let selection {
                        for dn in selection.sorted() {
                            if let entry = try await connection.read(dn, attributes: request.attributes) { found.append(entry) }
                        }
                    } else {
                        found = try await connection.pagedSearch(request, pageSize: pageSize, limit: limit).entries
                    }
                    var completed: [LDAPEntry] = []
                    for entry in found { completed.append(try await connection.completingRangedAttributes(entry)) }
                    return completed
                }
                self?.exporting = false
                Exporter.saveLDIF(entries, suggestedName: selection == nil ? "search" : "selection")
            } catch {
                self?.exporting = false
                self?.error = error.localizedDescription
            }
        }
    }
}
