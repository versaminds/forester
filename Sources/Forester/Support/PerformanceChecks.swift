// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

#if DEBUG
import AppKit
import LDAPKit
import SwiftUI

/// How the app copes with a big directory: the test directory started with a
/// large Bulk Import OU, whose users are all members of one group.
///   LDAP_TEST_BULK=50000 TestDirectory/start.sh
///   FORESTER_AUTOMATION_ONLY=performance …
/// Each step is timed until what it shows is on screen, and the longest the
/// main thread went without answering is measured alongside: that is what
/// a person feels as the app hanging.
@MainActor
enum PerformanceChecks {
    static let base = Automation.base
    static let bulk = "OU=Bulk Import,OU=Corp,\(Automation.base)"
    static let group = "CN=UG-All-Staff,OU=Groups,OU=Corp,\(Automation.base)"
    /// Longer than this without answering and a person sees the spinning cursor's prelude.
    /// FORESTER_STALL_LIMIT_MS raises it where the Mac itself is slower: a CI
    /// runner's virtual machine has a few cores of an older chip.
    static let longestAllowedStall = (ProcessInfo.processInfo.environment["FORESTER_STALL_LIMIT_MS"].flatMap(Double.init) ?? 500) / 1000

    static func run(_ model: AppModel, output: URL) async throws {
        let session = try await Automation.connectCorp(model)
        let window = try Automation.require(Automation.mainWindow())
        var report: [String] = []
        var failures: [String] = []

        func measure(_ what: String, _ action: () async throws -> Void) async throws {
            let watch = StallWatch()
            let started = Date()
            try await action()
            window.displayIfNeeded()
            // Whatever SwiftUI deferred to the next pass belongs to this step too.
            try await Automation.settle(0.3)
            window.displayIfNeeded()
            let elapsed = Date().timeIntervalSince(started) - 0.3
            let stall = watch.stop()
            let line = String(format: "perf: %@: %.2f s, longest stall %.0f ms, %d MB in use", what, elapsed, stall * 1000, footprintMB())
            Automation.log(line)
            report.append(line)
            if stall > longestAllowedStall { failures.append(line) }
        }

        // ── The tree: a container far bigger than the tree shows ─────────────
        session.mode = .browse
        try await measure("expand an OU of more than \(TreeModel.childLimit.formatted()) entries") {
            await session.tree.reveal(bulk)
            await session.tree.expand(DN.normalized(bulk))
            try await Automation.waitFor("bulk children") { session.tree.node(DN.normalized(bulk))?.children != nil }
        }
        let shown = session.tree.node(DN.normalized(bulk))?.children?.count ?? 0
        try Automation.verify("the tree stops at its limit", shown == TreeModel.childLimit)
        try await measure("show containers only, with that OU open") { session.tree.setContainersOnly(true) }
        try await measure("show everything again") { session.tree.setContainersOnly(false) }
        try await measure("scroll the tree to its last entry") {
            if let last = session.tree.node(DN.normalized(bulk))?.children?.last, let node = session.tree.node(last) {
                await session.tree.reveal(node.dn)
            }
        }
        try await measure("collapse it") { session.tree.collapse(DN.normalized(bulk)) }

        // ── Search: every user of the OU ─────────────────────────────────────
        session.mode = .search
        session.search.base = bulk
        session.search.scope = .oneLevel
        session.search.filterText = "(objectClass=user)"
        session.search.limit = 100_000
        try await measure("search for every user of the OU") {
            session.search.run()
            try await Automation.waitFor("search", timeout: 120) { !session.search.running }
        }
        let rows = session.search.rows.count
        try Automation.verify("every user found (\(rows.formatted()))", rows > 10_000)
        try await measure("sort \(rows.formatted()) results by account") {
            session.search.sortOrder = [KeyPathComparator(\SearchRow.account, comparator: .localizedStandard)]
        }
        try await measure("sort them back by name") {
            session.search.sortOrder = [KeyPathComparator(\SearchRow.name, comparator: .localizedStandard)]
        }
        try await measure("select a result") {
            let row = session.search.rows[rows / 2]
            session.search.selection = [row.id]
            session.select(row.entry.dn)
            try await Automation.waitFor("selected entry") { session.inspector.entry.map { DN.isSame($0.dn, row.entry.dn) } == true }
        }
        try await measure("select all \(rows.formatted()) results") {
            session.search.selection = Set(session.search.rows.map(\.id))
        }
        session.search.selection = []
        try await measure("search again, replacing the results") {
            session.search.run()
            try await Automation.waitFor("search again", timeout: 120) { !session.search.running }
        }
        // More searches, for the memory each replaced result set leaves
        // behind. The figures move by tens of megabytes as the allocator
        // keeps and returns freed memory; whether results are really let go
        // is what `heap` counts (TESTING.md), not these.
        for round in ["third", "fourth", "fifth"] {
            try await measure("search a \(round) time") {
                session.search.run()
                try await Automation.waitFor("search a \(round) time", timeout: 120) { !session.search.running }
            }
        }

        // ── A group with every one of them as a member ───────────────────────
        session.mode = .browse
        for tab in [InspectorModel.Tab.overview, .attributes, .membership, .ldif] {
            session.inspector.tab = tab
            try await measure("open the group on \(tab.label)") {
                session.select(nil)
                try await Automation.settle(0.2)
                session.open(group)
                try await Automation.waitFor("group on \(tab.label)", timeout: 60) {
                    session.inspector.entry.map { DN.isSame($0.dn, group) } == true && !session.inspector.membership.loading
                }
            }
        }
        session.inspector.tab = .overview
        try? Automation.write(window, name: "P-group", output: output)

        let summary = output.appendingPathComponent("performance.txt")
        try (report.joined(separator: "\n") + "\n").write(to: summary, atomically: true, encoding: .utf8)
        guard failures.isEmpty else {
            throw Automation.AutomationError("the app stopped answering for longer than \(Int(longestAllowedStall * 1000)) ms:\n" + failures.joined(separator: "\n"))
        }
        Automation.log("verified: no step kept the app from answering for more than \(Int(longestAllowedStall * 1000)) ms")
    }
}

/// The memory the app uses as Activity Monitor counts it.
func footprintMB() -> Int {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
    let result = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count) }
    }
    return result == KERN_SUCCESS ? Int(info.phys_footprint / 1_048_576) : -1
}

/// Measures the longest time the main thread took to run a block queued on
/// it, from a thread of its own, every 5 ms.
final class StallWatch: @unchecked Sendable {
    private let lock = NSLock()
    private var longest: TimeInterval = 0
    private var running = true

    init() {
        Thread.detachNewThread { [self] in
            let answered = DispatchSemaphore(value: 0)
            while lock.withLock({ running }) {
                let asked = Date()
                DispatchQueue.main.async { answered.signal() }
                answered.wait()
                let waited = Date().timeIntervalSince(asked)
                lock.withLock { longest = max(longest, waited) }
                Thread.sleep(forTimeInterval: 0.005)
            }
        }
    }

    func stop() -> TimeInterval {
        lock.withLock {
            running = false
            return longest
        }
    }
}
#endif
