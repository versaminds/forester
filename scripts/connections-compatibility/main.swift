// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds
// The connections file as this Forester writes it, read and written back by
// Forester 1.1.1's own decoder and encoder (OldProfile, taken from the
// v1.1.1 tag by scripts/check-connections-compatibility.sh). See that script.
import Foundation
import LDAPKit
// For the `move(fromOffsets:)` ProfileStore uses.
import SwiftUI

enum ForesterInfo { static let fromAppStore = false }

var failures = 0
func check(_ what: String, _ ok: Bool) {
    print(ok ? "ok   " : "FAIL ", what)
    if !ok { failures += 1 }
}

@MainActor func run() throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("storeprobe-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: dir) }
    let main = dir.appendingPathComponent("connections.json")
    let later = dir.appendingPathComponent(ProfileStore.laterFileName)

    func profile(_ name: String, _ auth: ConnectionProfile.Authentication) -> ConnectionProfile {
        var p = ConnectionProfile()
        p.name = name
        p.host = "\(name.lowercased()).example"
        p.authentication = auth
        if auth == .certificate { p.clientCertificate = "AB:CD" }
        return p
    }
    let store = ProfileStore(directory: dir)
    let a = profile("A", .simple), b = profile("B", .scram), c = profile("C", .anonymous), d = profile("D", .certificate)
    for p in [a, b, c, d] { store.save(p) }

    // What 1.1.1 does with connections.json: decode it whole.
    let old = try JSONDecoder().decode([OldProfile].self, from: Data(contentsOf: main))
    check("1.1.1 reads connections.json: the two connections it knows", old.map(\.id) == [a.id, c.id])
    check("the later file exists", FileManager.default.fileExists(atPath: later.path))

    // 1.1.1 changes one, adds one, reorders, and saves: its own encoder.
    var changed = old
    changed[1].name = "C renamed by 1.1"
    var e = OldProfile()
    e.name = "E"
    e.host = "e.example"
    changed = [changed[1], changed[0], e]
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(changed).write(to: main, options: .atomic)

    let reread = ProfileStore(directory: dir)
    check("after 1.1.1 saved, every connection is still there",
          Set(reread.profiles.map(\.id)) == Set([a.id, b.id, c.id, d.id, e.id]))
    check("the order last saved here holds, and 1.1.1's new one goes last",
          reread.profiles.map(\.id) == [a.id, b.id, c.id, d.id, e.id])
    check("1.1.1's change is kept", reread.profile(c.id)?.name == "C renamed by 1.1")
    check("SCRAM and certificate connections are as they were",
          reread.profile(b.id)?.authentication == .scram && reread.profile(d.id)?.authentication == .certificate
              && reread.profile(d.id)?.clientCertificate == "AB:CD")

    // A connection a newer version wrote that this one cannot read is kept.
    var file = try JSONSerialization.jsonObject(with: Data(contentsOf: later)) as! [String: Any]
    var entries = file["profiles"] as! [[String: Any]]
    entries.append(["id": UUID().uuidString, "name": "From 1.3", "authentication": "something-new", "port": 389])
    file["profiles"] = entries
    try JSONSerialization.data(withJSONObject: file).write(to: later, options: .atomic)
    let third = ProfileStore(directory: dir)
    check("a connection this version cannot read is not shown", third.profiles.count == 5)
    var f = third.profile(b.id)!
    f.authentication = .simple
    third.save(f)
    let afterSave = try String(contentsOf: later, encoding: .utf8)
    check("…and survives a save", afterSave.contains("something-new") && afterSave.contains("From 1.3"))
    let oldAgain = try JSONDecoder().decode([OldProfile].self, from: Data(contentsOf: main))
    check("a connection changed to a simple bind moves where 1.1.1 reads it", oldAgain.contains { $0.id == b.id })
    let laterEntries = (try JSONSerialization.jsonObject(with: Data(contentsOf: later)) as! [String: Any])["profiles"] as! [[String: Any]]
    check("…and out of the later file's connections", !laterEntries.contains { $0["id"] as? String == b.id.uuidString })
    let fourth = ProfileStore(directory: dir)
    check("read again: the same five, in the same order", fourth.profiles.map(\.id) == [a.id, b.id, c.id, d.id, e.id])
}

try MainActor.assumeIsolated { try run() }
print(failures == 0 ? "all passed" : "\(failures) failed")
exit(failures == 0 ? 0 : 1)
