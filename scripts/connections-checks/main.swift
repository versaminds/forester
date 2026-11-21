// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds
// The connections file as this Forester writes it, read and written back by
// Forester 1.1.1's own decoder and encoder (OldProfile, taken from the
// v1.1.1 tag by scripts/check-connections.sh). See that script.
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

/// What the connections file may not decide on this Mac, and what an import
/// may not do.
@MainActor func runTrust() throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("storeprobe-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: dir) }
    let main = dir.appendingPathComponent("connections.json")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let encoder = JSONEncoder()

    // As 1.1 left it: a pinned certificate and changes allowed. The first
    // start of this version keeps them, on this Mac.
    var old = ConnectionProfile()
    old.name = "Old"
    old.host = "dc.example"
    old.trust = TrustPolicy(pinnedFingerprints: ["AA:BB"])
    old.readOnly = false
    try encoder.encode([old]).write(to: main)
    let first = ProfileStore(directory: dir)
    check("upgrading keeps this Mac's pins and allowed changes",
          first.profile(old.id)?.trust.pinnedFingerprints == ["AA:BB"] && first.profile(old.id)?.readOnly == false)

    // Then someone writes the file: pins their certificate, allows changes
    // on a read-only connection, picks a client certificate, and adds one.
    var readOnlyOne = ConnectionProfile()
    readOnlyOne.host = "ro.example"
    first.save(readOnlyOne)
    var written = try JSONDecoder().decode([ConnectionProfile].self, from: Data(contentsOf: main))
    for index in written.indices {
        written[index].trust = TrustPolicy(pinnedFingerprints: ["EV:IL"], trustAnyCertificate: true)
        written[index].readOnly = false
        written[index].clientCertificate = "CE:RT"
    }
    var arrived = ConnectionProfile()
    arrived.host = "arrived.example"
    arrived.readOnly = false
    arrived.trust = TrustPolicy(pinnedFingerprints: ["EV:IL"])
    arrived.authentication = .simple
    written.append(arrived)
    try encoder.encode(written).write(to: main)
    let second = ProfileStore(directory: dir)
    let kept = second.profile(old.id), ro = second.profile(readOnlyOne.id), new = second.profile(arrived.id)
    check("a written file does not change this Mac's pins, certificate checking, changes allowed or client certificate",
          kept?.trust == TrustPolicy(pinnedFingerprints: ["AA:BB"]) && kept?.readOnly == false && kept?.clientCertificate == ""
              && ro?.readOnly == true && ro?.trust == TrustPolicy() && ro?.clientCertificate == "")
    check("a connection that arrives in the file starts read-only, trusting the system's certificates only",
          new?.readOnly == true && new?.trust == TrustPolicy() && new?.clientCertificate == "")

    // A client certificate is shown only to what it was chosen for.
    var withCertificate = ConnectionProfile()
    withCertificate.host = "ca.example"
    withCertificate.port = 636
    withCertificate.security = .ldaps
    withCertificate.authentication = .certificate
    withCertificate.clientCertificate = "AB:CD"
    second.save(withCertificate)
    check("a certificate saved without being chosen in the editor is not shown", second.profile(withCertificate.id)?.certificateIsBoundHere == false)
    second.save(withCertificate, choosingCertificate: true)
    check("chosen in the editor, it is shown to that server", second.profile(withCertificate.id)?.certificateIsBoundHere == true)
    var moved = try requireValue(second.profile(withCertificate.id))
    moved.host = "elsewhere.example"
    second.save(moved)
    var anyCertificate = try requireValue(second.profile(withCertificate.id))
    anyCertificate.host = "ca.example"
    anyCertificate.trust.trustAnyCertificate = true
    let afterMove = second.profile(withCertificate.id)?.certificateIsBoundHere
    second.save(anyCertificate)
    check("another host, or any certificate accepted, asks for it again",
          afterMove == false && second.profile(withCertificate.id)?.certificateIsBoundHere == false)
    let third = ProfileStore(directory: dir)
    check("…and the choice is this Mac's, kept across starts", third.profile(withCertificate.id)?.clientCertificate == "AB:CD")

    // An import never replaces a connection here.
    var imported = third.profile(old.id)!
    imported.name = "Imported over it"
    let file = dir.appendingPathComponent("import.forester")
    try encoder.encode([imported, third.profile(readOnlyOne.id)!]).write(to: file)
    let before = third.profiles.count
    let added = try third.importProfiles(from: file)
    check("an imported connection with an id already here comes in as one of its own, the same one is not added twice",
          added == 1 && third.profiles.count == before + 1 && third.profile(old.id)?.name == "Old"
              && third.profiles.contains { $0.name == "Imported over it" && $0.id != old.id && $0.readOnly && $0.trust == TrustPolicy() })

    // Other connections made with this one's settings.
    var lab = ConnectionProfile()
    lab.host = "dc1.corp.example"
    lab.trust = TrustPolicy(pinnedFingerprints: ["PI:N1"], trustAnyCertificate: true)
    check("the global catalog on the same host: this connection's pins and those trusted once, never any certificate",
          lab.trustForOtherConnection(to: "DC1.corp.example", trustedOnce: ["ON:CE"]) == TrustPolicy(pinnedFingerprints: ["PI:N1", "ON:CE"]))
    check("another host: the system's certificates only", lab.trustForOtherConnection(to: "dc2.corp.example", trustedOnce: ["ON:CE"]) == TrustPolicy())

    // Opening another domain finds a saved connection only if it signs in the same way.
    var certificate = ConnectionProfile(), simple = ConnectionProfile()
    certificate.host = "child.corp.example"
    certificate.authentication = .certificate
    certificate.clientCertificate = "AB:CD"
    simple.host = "child.corp.example"
    simple.authentication = .simple
    var otherCertificate = certificate
    otherCertificate.clientCertificate = "EF:01"
    check("a saved connection is reused for another domain only with the same kind of sign-in, user and certificate",
          !simple.signsIn(to: "child.corp.example", as: certificate) && certificate.signsIn(to: "CHILD.corp.example", as: certificate)
              && !otherCertificate.signsIn(to: "child.corp.example", as: certificate))

    // What the password prompt says.
    var prompt = ConnectionProfile()
    prompt.security = .none
    let plain = prompt.passwordExposure
    prompt.authentication = .scram
    let scram = prompt.passwordExposure
    prompt.security = .startTLS
    prompt.trust.trustAnyCertificate = true
    let anyTrusted = prompt.passwordExposure
    prompt.trust.trustAnyCertificate = false
    check("the password prompt says when the password goes in clear text or to any certificate, and not otherwise",
          plain?.contains("clear text") == true && scram?.contains("is not sent") == true
              && anyTrusted?.contains("Any certificate") == true && prompt.passwordExposure == nil)
}

/// "User cannot change password" changes only its own rules, and its undo
/// puts back just those, where they were.
func runCannotChangePassword() throws {
    typealias ACE = SecurityDescriptor.ACE
    let right = SecurityDescriptor.changePasswordRight
    func ace(_ type: UInt8, _ sid: String, object: UUID? = nil, flags: UInt8 = 0) -> ACE {
        ACE(type: type, flags: flags, mask: object == nil ? 0x20094 : 0x100, objectType: object, sid: sid)
    }
    var sd = try SecurityDescriptor(data: Data([1, 0, 0x04, 0x94, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 4, 0, 8, 0, 0, 0, 0, 0]))
    sd.owner = "S-1-5-32-544"
    sd.dacl?.aces = [ace(ACE.accessAllowed, "S-1-5-18"), ace(ACE.accessAllowedObject, "S-1-1-0", object: right),
                     ace(ACE.accessAllowed, "S-1-5-11"), ace(ACE.accessAllowedObject, "S-1-5-10", object: right),
                     ace(ACE.accessAllowed, "S-1-5-32-554", flags: 0x12)]
    let original = try sd.encoded()
    var changed = try SecurityDescriptor(data: original)
    let found = CannotChangePassword.rules(changed)
    try changed.setUserCannotChangePassword(true)
    _ = try CannotChangePassword.checked(try SecurityDescriptor(data: original), changed)
    // Someone else adds a rule before the undo.
    changed.dacl?.aces.insert(ace(ACE.accessAllowed, "S-1-5-21-1-2-3-1105"), at: 4)
    let withTheirs = try changed.encoded()
    var undone = try SecurityDescriptor(data: withTheirs)
    try CannotChangePassword.restore(found, in: &undone)
    let aces = undone.dacl?.aces ?? []
    check("undoing it puts back the rules it replaced, where they were, and keeps a rule added since",
          !undone.userCannotChangePassword && aces.contains(ace(ACE.accessAllowed, "S-1-5-21-1-2-3-1105"))
              && aces.filter(CannotChangePassword.owns) == found.map(\.ace)
              && aces.firstIndex(of: found[0].ace) == 1)
    var exact = try SecurityDescriptor(data: original)
    try exact.setUserCannotChangePassword(true)
    try CannotChangePassword.restore(found, in: &exact)
    check("…and with nothing added since, the very bytes it started from", try exact.encoded() == original)
    var tampered = try SecurityDescriptor(data: original)
    tampered.dacl?.aces.removeLast()
    var refused = false
    do { _ = try CannotChangePassword.checked(try SecurityDescriptor(data: original), tampered) } catch { refused = true }
    check("a change that would touch an inherited rule is not written", refused)

    // Undone (forced) after others put denials at the top: a rule's old place
    // is now among the denials, so it goes after them instead, in order.
    var denied = try SecurityDescriptor(data: original)
    try denied.setUserCannotChangePassword(true)
    denied.dacl?.aces.insert(contentsOf: [ace(ACE.accessDenied, "S-1-5-21-1-2-3-1106"), ace(ACE.accessDenied, "S-1-5-21-1-2-3-1107")], at: 2)
    try CannotChangePassword.restore(found, in: &denied)
    check("undone after denials were added before its place, each rule goes where the order allows",
          SecurityDescriptor.isCanonical(denied.dacl?.aces ?? []) && !denied.userCannotChangePassword
              && (denied.dacl?.aces ?? []).filter(CannotChangePassword.owns).count == found.count
              && found.allSatisfy { rule in denied.dacl?.aces.contains(rule.ace) == true })
    // Undone after someone put the list out of order: refused, not made worse.
    var disordered = try SecurityDescriptor(data: original)
    try disordered.setUserCannotChangePassword(true)
    disordered.dacl?.aces.append(ace(ACE.accessDenied, "S-1-5-21-1-2-3-1108"))
    var refusedOrder = false
    do { try CannotChangePassword.restore(found, in: &disordered) } catch { refusedOrder = true }
    check("undone on a list someone put out of order, it is refused", refusedOrder)
}

/// This Mac's settings are taken from the connections file once, on the
/// first start of this version, and never again.
@MainActor func runMigrationOnce() throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("storeprobe-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: dir) }
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let main = dir.appendingPathComponent("connections.json"), settings = dir.appendingPathComponent("connection-settings.json")
    var profile = ConnectionProfile()
    profile.host = "dc.example"
    profile.readOnly = false
    profile.trust = TrustPolicy(pinnedFingerprints: ["AA:BB"])
    try JSONEncoder().encode([profile]).write(to: main)
    let first = ProfileStore(directory: dir)
    check("the first start takes this Mac's settings from the file", first.profile(profile.id)?.readOnly == false)
    // Then the settings file goes, and the connections file says otherwise.
    try FileManager.default.removeItem(at: settings)
    var written = profile
    written.trust = TrustPolicy(pinnedFingerprints: ["EV:IL"], trustAnyCertificate: true)
    try JSONEncoder().encode([written]).write(to: main)
    let second = ProfileStore(directory: dir)
    check("without the settings file later, nothing is taken from the connections file again",
          second.profile(profile.id)?.readOnly == true && second.profile(profile.id)?.trust == TrustPolicy())
    // A settings file that cannot be read is kept aside, and nothing is taken from the file.
    try Data("not json".utf8).write(to: settings)
    let third = ProfileStore(directory: dir)
    let backups = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasPrefix("connection-settings.unreadable-") }
    check("an unreadable settings file is kept aside, and every connection starts read-only, trusting the system's certificates",
          backups.count == 1 && third.profile(profile.id)?.readOnly == true && third.profile(profile.id)?.trust == TrustPolicy()
              && third.loadError?.contains("could not be read") == true)
}

extension Optional {
    struct Missing: Error {}
    static func requireValue(_ value: Wrapped?) throws -> Wrapped {
        guard let value else { throw Missing() }
        return value
    }
}

func requireValue<T>(_ value: T?) throws -> T { try Optional.requireValue(value) }

/// The same against the domain controller of TestDirectory/start-ad.sh,
/// with FORESTER_TEST_AD=1: AD then refuses the user's own change, and the
/// undo keeps a rule another administrator added in between.
func runCannotChangePasswordOnAD() async throws {
    let connection = LDAPConnection(.init(host: "localhost", port: 11636, security: .ldaps, timeout: 30,
                                          trust: TrustPolicy(trustAnyCertificate: true)))
    try await connection.open()
    try await connection.bind(dn: "Administrator@corp.example", password: "Forester-Lab-Admin-2026!")
    let sam = "ccp\(UInt32.random(in: 0..<100_000))"
    let dn = "CN=\(sam),OU=Corp,DC=corp,DC=example"
    let password = "Cannot-Change-Check-2026!"
    try await connection.add(dn, attributes: [
        LDAPAttribute(name: "objectClass", values: [Data("user".utf8)]),
        LDAPAttribute(name: "sAMAccountName", values: [Data(sam.utf8)]),
        LDAPAttribute(name: "unicodePwd", values: [ADValues.unicodePwd(password)]),
        LDAPAttribute(name: "userAccountControl", values: [Data("512".utf8)]),
    ])
    func dacl() async throws -> Data {
        try requireValue(try await connection.read(dn, attributes: ["nTSecurityDescriptor"], controls: [.sdFlags(4)])?
            .values("nTSecurityDescriptor").first)
    }
    func ownChange(_ old: String, _ new: String) async -> Bool {
        let user = LDAPConnection(.init(host: "localhost", port: 11636, security: .ldaps, timeout: 30, trust: TrustPolicy(trustAnyCertificate: true)))
        defer { Task { await user.close() } }
        do {
            try await user.open()
            try await user.bind(dn: dn, password: old)
            try await user.modify(dn, [LDAPModification(.delete, "unicodePwd", [ADValues.unicodePwd(old)]),
                                       LDAPModification(.add, "unicodePwd", [ADValues.unicodePwd(new)])])
            return true
        } catch {
            return false
        }
    }
    let original = try await dacl()
    let found = CannotChangePassword.Found()
    try await CannotChangePassword.rewrite(dn, on: connection) { descriptor in
        found.rules = CannotChangePassword.rules(descriptor)
        try descriptor.setUserCannotChangePassword(true)
    }
    let refusedOwn = !(await ownChange(password, "Cannot-Change-Check-2027!"))
    check("AD: turned on, the user's own password change is refused", refusedOwn)
    // Another administrator adds a rule meanwhile.
    var draft = AccessRuleDraft()
    draft.sid = "S-1-5-11"
    draft.mask = 0x20
    draft.objectType = UUID(uuidString: "bf967950-0de6-11d0-a285-00aa003049e2")
    let theirs = try draft.ace()
    try await connection.changePermissions(of: dn, .add(theirs))
    try await CannotChangePassword.rewrite(dn, on: connection) { try CannotChangePassword.restore(found.rules, in: &$0) }
    let undone = try SecurityDescriptor(data: try await dacl())
    var expected = try SecurityDescriptor(data: original)
    try expected.apply(.add(theirs))
    check("AD: undone, the rules it replaced are back and the rule added meanwhile stays",
          !undone.userCannotChangePassword && undone.dacl?.aces == expected.dacl?.aces)
    let ownAgain = await ownChange(password, "Cannot-Change-Check-2028!")
    check("AD: and the user may change the password again", ownAgain)
    try await connection.delete(dn)
    await connection.close()
}

try run()
try runTrust()
try runCannotChangePassword()
try runMigrationOnce()
if ProcessInfo.processInfo.environment["FORESTER_TEST_AD"] == "1" {
    try await runCannotChangePasswordOnAD()
} else {
    print("note: the domain controller part runs with FORESTER_TEST_AD=1 and TestDirectory/start-ad.sh")
}
print(failures == 0 ? "all passed" : "\(failures) failed")
exit(failures == 0 ? 0 : 1)
