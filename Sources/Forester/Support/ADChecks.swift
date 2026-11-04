// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

#if DEBUG
import AppKit
import LDAPKit
import SwiftUI

/// Everything Forester does to Active Directory, against a real AD domain
/// controller (TestDirectory/start-ad.sh), through the same functions the
/// app's controls call, each result read back from the server. Where AD keeps
/// a result to itself (passwords, effective rights), the check signs in as the
/// account, which is the only proof AD gives.
///   FORESTER_TEST_AD=1 FORESTER_AUTOMATION_ONLY=ad FORESTER_TEST_PASSWORD='Forester-Lab-Admin-2026!' …
@MainActor
enum ADChecks {
    static let base = Automation.base
    static let seeded = Automation.TestServer.seededPassword

    static func run(_ model: AppModel, output: URL) async throws {
        guard Automation.TestServer.current.isActiveDirectory else {
            throw Automation.AutomationError("the ad part needs FORESTER_TEST_AD=1 and the domain controller from TestDirectory/start-ad.sh")
        }
        // The container publishes the global catalog's 3268 on 13268.
        setenv("FORESTER_TEST_GC_PORT", "13268", 0)
        let session = try await Automation.connectCorp(model)
        var passed = 0
        func expect(_ what: String, _ condition: Bool) throws {
            guard condition else { throw Automation.AutomationError("check failed (AD): \(what)") }
            passed += 1
            Automation.log("verified (AD): \(what)")
        }
        func read(_ dn: String, _ attributes: [String] = ["*", "+"]) async throws -> LDAPEntry? {
            try await session.run { try await $0.read(dn, attributes: attributes) }
        }
        func signIn(_ dn: String, _ password: String) async throws -> UITour.SignIn {
            try await UITour.signIn(session, dn, password)
        }
        func open(_ dn: String) async throws {
            session.open(dn)
            try await Automation.waitFor("\(DN.displayName(dn)) shown") {
                session.inspector.entry.map { DN.isSame($0.dn, dn) } == true && !session.inspector.membership.loading
            }
        }

        // ── Recognising AD and signing in ────────────────────────────────────
        try expect("the server is recognised as Active Directory, and the AD tools are on",
                   session.server?.kind == .activeDirectory && session.hasADTools && session.isSecure)
        for name in ["Administrator@corp.example", "CORP\\Administrator", "CN=Administrator,CN=Users,\(base)"] {
            let connection = LDAPConnection(session.profile.options)
            try await connection.open()
            try await connection.bind(dn: name, password: Automation.testPassword)
            let who = try await connection.whoAmI() ?? ""
            await connection.close()
            try expect("signs in as \(name)", who.localizedCaseInsensitiveContains("Administrator"))
        }
        let pieter = "CN=Pieter Van Damme,OU=Engineering,OU=Users,OU=Corp,\(base)"
        // Earlier runs' wrong passwords count towards a lockout; clear it first,
        // and sign in properly afterwards, which resets AD's count.
        _ = try await session.run { try await $0.modify(pieter, [.replace("lockoutTime", ["0"])]) }
        let wrong = try await signIn(pieter, "not-the-password")
        let right = try await signIn(pieter, seeded)
        try expect("a wrong password is reported as a wrong password, the right one signs in", wrong == .wrongPassword && right == .success)
        try await Automation.waitFor("schema") { session.schema != nil }
        try expect("the schema is read from AD: user, group and their attributes",
                   session.schema?.objectClass("user") != nil && session.schema?.attributeType("unicodePwd") != nil
                   && session.schema?.allowedAttributes(for: ["top", "person", "organizationalPerson", "user"]).may.contains("thumbnailPhoto") == true)

        // ── Reading ──────────────────────────────────────────────────────────
        let bulk = "OU=Bulk Import,OU=Corp,\(base)"
        await session.tree.reveal(bulk)
        await session.tree.expand(DN.normalized(bulk))
        try await Automation.waitFor("Bulk Import listed") { session.tree.node(DN.normalized(bulk))?.children != nil }
        try expect("the tree lists all 1,500 accounts of an OU, past AD's 1,000-entry page",
                   session.tree.node(DN.normalized(bulk))?.children?.count == 1_500)

        let allStaff = "CN=UG-All-Staff,OU=Groups,OU=Corp,\(base)"
        try await open(allStaff)
        try expect("a group of 1,544 members is read in full, past AD's 1,500-value limit",
                   session.inspector.entry?.values("member").count == 1_544)

        try await open(pieter)
        try expect("direct membership comes from AD's memberOf",
                   session.inspector.membership.memberOf.contains { DN.isSame($0.dn, "CN=GG-Engineering,OU=Groups,OU=Corp,\(base)") })
        session.inspector.membership.loadNested()
        try await Automation.waitFor("nested groups") { session.inspector.membership.nested != nil }
        let nested = session.inspector.membership.nested ?? []
        try expect("nested membership in one query: GG-Engineering, DL-VPN-Users and GG-Workstation-Admins",
                   ["GG-Engineering", "DL-VPN-Users", "GG-Workstation-Admins"].allSatisfy { name in nested.contains { $0.name == name } })

        let metadata = ReplicationMetadata.parse(try await read(pieter, ["msDS-ReplAttributeMetaData"])?.strings("msDS-ReplAttributeMetaData") ?? [])
        let isSamba = session.server?.rootDSE.string("vendorName")?.contains("Samba") == true
        if isSamba && metadata.isEmpty {
            // Windows AD computes msDS-ReplAttributeMetaData; Samba only stores the
            // binary replPropertyMetaData, so the Replication tab says it has none.
            Automation.log("known (AD): Samba does not provide msDS-ReplAttributeMetaData; the Replication tab says so instead of showing data")
        } else {
            try expect("replication metadata is read per attribute", metadata.contains { $0.attribute == "cn" && $0.version >= 1 })
        }

        // Thomas Wouters is locked out by start-ad.sh; a run before this one may
        // have unlocked him, so lock him again the same way: wrong passwords.
        let thomas = "CN=Thomas Wouters,OU=Sales,OU=Users,OU=Corp,\(base)"
        if let entry = try await read(thomas), !AccountActions.isLocked(entry) {
            for _ in 0..<6 { _ = try await signIn(thomas, "not-the-password") }
        }

        session.mode = .search
        session.search.base = base
        session.search.quickFind("Pieter Van")
        try await Automation.waitFor("quick find") { !session.search.running && !session.search.lookingInside && session.search.hasRun }
        try expect("Find by name uses AD's name resolution", session.search.rows.contains { DN.isSame($0.id, pieter) })
        for (preset, expected) in [("Password never expires", "CN=svc_sql,OU=Service Accounts,OU=Corp,\(base)"),
                                   ("Users with a service principal name", "CN=svc_sql,OU=Service Accounts,OU=Corp,\(base)"),
                                   ("Locked-out users", "CN=Thomas Wouters,OU=Sales,OU=Users,OU=Corp,\(base)"),
                                   ("Disabled users", "CN=Guest,CN=Users,\(base)")] {
            session.search.apply(try Automation.require(SearchPreset.all.first { $0.title == preset }))
            try await Automation.waitFor("preset \(preset)") { !session.search.running && session.search.hasRun }
            try expect("the preset \"\(preset)\" finds \(DN.displayName(expected))", session.search.rows.contains { DN.isSame($0.id, expected) })
        }
        session.mode = .browse

        let info = DomainInfoModel()
        await info.load(session)
        let policies = info.policies.map { DN.displayName($0.dn) }
        try expect("domain information: NetBIOS name, the DC and its operations master roles",
                   info.netbiosName == "CORP" && info.controllers.contains { $0.name.uppercased() == "DC1" }
                   && !info.roles.isEmpty && info.roles.allSatisfy { $0.holder.uppercased().contains("DC1") })
        try expect("password policy: the domain's (12 characters, lockout after 5) and both fine-grained ones",
                   info.domain?.int("minPwdLength") == 12 && info.domain?.int("lockoutThreshold") == 5
                   && policies.contains("PSO-Admins") && policies.contains("PSO-ServiceAccounts"))

        // ── Changing: everything below happens in an OU of its own ────────────
        let ou = "OU=Forester AD Checks,OU=Corp,\(base)"
        // Leftovers of an interrupted run, wherever it left them.
        _ = try? await session.run { connection in
            let found = try await connection.search(LDAPSearchRequest(base: base, scope: .subtree,
                filter: try LDAPFilter.parse("(|(sAMAccountName=ada.checks)(sAMAccountName=GG-Forester-Checks)(sAMAccountName=CHECKS-PC$))"),
                attributes: ["1.1"]))
            for entry in found.entries { try? await connection.delete(entry.dn) }
            try? await connection.deleteSubtree(ou, useTreeDelete: true)
        }
        let sentWhileReadOnly = await session.change("x") { try await $0.add(ou, attributes: []) }
        try expect("a change is refused while the connection is read-only", session.profile.readOnly && !sentWhileReadOnly)
        session.setReadOnly(false)
        let created = await session.change("Created the OU.") {
            try await $0.add(ou, attributes: [LDAPAttribute(name: "objectClass", values: [Data("organizationalUnit".utf8)])])
        }
        try expect("an OU is created", created)

        // A user as the New Entry sheet's AD user template sends it.
        let user = "CN=Ada Checks,\(ou)"
        let first = "Ada-Checks-Password-1!"
        let added = await session.change("Created Ada.") {
            try await $0.add(user, attributes: [
                LDAPAttribute(name: "objectClass", values: ["top", "person", "organizationalPerson", "user"].map { Data($0.utf8) }),
                LDAPAttribute(name: "cn", values: [Data("Ada Checks".utf8)]), LDAPAttribute(name: "sn", values: [Data("Checks".utf8)]),
                LDAPAttribute(name: "givenName", values: [Data("Ada".utf8)]), LDAPAttribute(name: "displayName", values: [Data("Ada Checks".utf8)]),
                LDAPAttribute(name: "sAMAccountName", values: [Data("ada.checks".utf8)]),
                LDAPAttribute(name: "userPrincipalName", values: [Data("ada.checks@corp.example".utf8)]),
                LDAPAttribute(name: "unicodePwd", values: [ADValues.unicodePwd(first)]),
                LDAPAttribute(name: "userAccountControl", values: [Data("512".utf8)]),
                LDAPAttribute(name: "pwdLastSet", values: [Data("0".utf8)]),
            ])
        }
        let firstSignIn = try await signIn(user, first)
        try expect("a user is created enabled, with a password that must be changed", added && firstSignIn == .mustChange)
        var ada = try Automation.require(try await read(user))
        await AccountActions.setMustChangePassword(false, ada, session: session)
        let afterMustChangeOff = try await signIn(user, first)
        try expect("\"must change password\" turned off: the user signs in", afterMustChangeOff == .success)
        await AccountActions.setMustChangePassword(true, ada, session: session)
        let pwdLastSet = try await read(user)?.int("pwdLastSet")
        let mustChangeSignIn = try await signIn(user, first)
        try expect("\"must change password\" turned on: pwdLastSet is 0 and sign-in asks for a change",
                   pwdLastSet == 0 && mustChangeSignIn == .mustChange)

        // Passwords, as the Reset Password sheet sends them. AD keeps accepting
        // the previous password for an hour ("old password allowed period"), so
        // proof of a reset is the new password working, and a new pwdLastSet.
        let setBefore = try await read(user)?.int("pwdLastSet") ?? 0
        let reset = "Ada-Checks-Password-2!"
        let resetOK = await session.change("Reset.") {
            try await $0.modify(user, [LDAPModification(.replace, "unicodePwd", [ADValues.unicodePwd(reset)]),
                                       .replace("pwdLastSet", ["-1"])])
        }
        let withReset = try await signIn(user, reset)
        let setAfter = try await read(user)?.int("pwdLastSet") ?? 0
        try expect("a password reset works: the new password signs in, and pwdLastSet is new",
                   resetOK && withReset == .success && setAfter > setBefore)
        let weak = await session.change("Reset.") {
            try await $0.modify(user, [LDAPModification(.replace, "unicodePwd", [ADValues.unicodePwd("short")])])
        }
        let refusal = session.notice?.message ?? ""
        try expect("a password the policy refuses is refused, and the message says why",
                   !weak && refusal.localizedCaseInsensitiveContains("password"))
        Automation.log("  the refusal reads: \(refusal)")
        let changed = "Ada-Checks-Password-3!"
        let changeOK = await session.change("Changed.") {
            try await $0.modify(user, [LDAPModification(.delete, "unicodePwd", [ADValues.unicodePwd(reset)]),
                                       LDAPModification(.add, "unicodePwd", [ADValues.unicodePwd(changed)])])
        }
        let withChanged = try await signIn(user, changed)
        try expect("a password change knowing the current one works", changeOK && withChanged == .success)

        // "User cannot change password": the deny entries ADUC writes, and AD obeying them.
        func changeOwn(_ old: String, _ new: String) async -> Bool {
            let connection = LDAPConnection(session.profile.options)
            defer { Task { await connection.close() } }
            do {
                try await connection.open()
                try await connection.bind(dn: user, password: old)
                try await connection.modify(user, [LDAPModification(.delete, "unicodePwd", [ADValues.unicodePwd(old)]),
                                                   LDAPModification(.add, "unicodePwd", [ADValues.unicodePwd(new)])])
                return true
            } catch {
                Automation.log("  changing the password as the user: \(error.localizedDescription)")
                return false
            }
        }
        ada = try Automation.require(try await read(user))
        let denied = await AccountActions.setCannotChangePassword(true, ada, session: session)
        let descriptor = try await AccountActions.readSecurityDescriptor(user, session: session)
        try expect("\"user cannot change password\" is written as AD's deny entries", denied && descriptor?.userCannotChangePassword == true)
        let refusedOwnChange = !(await changeOwn(changed, "Ada-Checks-Password-4!"))
        try expect("…and AD refuses the user's own password change", refusedOwnChange)
        _ = await AccountActions.setCannotChangePassword(false, ada, session: session)
        let allowedAgain = try await AccountActions.readSecurityDescriptor(user, session: session)?.userCannotChangePassword == false
        let ownChange = await changeOwn(changed, "Ada-Checks-Password-5!")
        try expect("turned off again, the user may change their own password", allowedAgain && ownChange)
        let current = "Ada-Checks-Password-5!"

        // Undo: the security descriptor and the account flags come back.
        ada = try Automation.require(try await read(user))
        _ = await AccountActions.setCannotChangePassword(true, ada, session: session)
        _ = await session.undo(try Automation.require(session.history.first).id)
        let undoneDeny = try await AccountActions.readSecurityDescriptor(user, session: session)?.userCannotChangePassword == false
        try expect("undoing \"user cannot change password\" puts the security descriptor back", undoneDeny)
        ada = try Automation.require(try await read(user))
        await AccountActions.setFlag(0x10000, on: true, ada, session: session, label: "Password never expires")
        _ = await session.undo(try Automation.require(session.history.first).id)
        try expect("undoing an account option clears it again", (try await read(user)?.int("userAccountControl") ?? 0) & 0x10000 == 0)

        // Permissions: the access rules in words, with names for who they are about.
        let permissions = try await session.permissions(of: user)
        var principals = Set(permissions.rules.map(\.sid))
        if let owner = permissions.owner { principals.insert(owner) }
        let names = await session.principalNames(principals)
        try expect("a user's permissions are read, with its owner",
                   !permissions.rules.isEmpty && permissions.owner.flatMap { names[$0]?.name } != nil)
        try expect("rules name AD's extended rights and the accounts they are about",
                   permissions.rules.contains { $0.access.contains { $0.hasSuffix("Change Password") } }
                       && permissions.rules.contains { names[$0.sid]?.name == "Domain Admins" })
        try expect("schema GUIDs are named, not shown as numbers",
                   permissions.rules.contains { rule in rule.access.contains { $0.contains("Personal Information") || $0.contains("General Information") } })
        try expect("what the signed-in account may do here is read", !permissions.writableAttributes.isEmpty && permissions.mayChangePermissions)
        // The forest: its domains, a search of all of them, and entries of
        // another domain sent to a connection of their own.
        let domains = await session.forestDomains()
        try expect("the forest's domains are read from the configuration partition",
                   domains.map(\.dnsName) == ["corp.example"] && domains.first?.netbiosName == "CORP")
        try expect("the server says it is a global catalog", session.isGlobalCatalog)
        session.search.filterText = "(sAMAccountName=ada.checks)"
        session.search.wholeForest = true
        session.search.run()
        try await Automation.waitFor("forest search") { !session.search.running }
        try expect("a search of the whole forest goes through the global catalog and finds the user",
                   session.search.rows.contains { DN.isSame($0.id, user) } && session.search.warnings.contains { $0.contains("global catalog") }
                       && session.search.error == nil)
        session.search.wholeForest = false
        let elsewhere = "CN=Someone,OU=Users,DC=child,DC=corp,DC=example"
        session.open(elsewhere)
        try await Automation.waitFor("other domain noticed") { session.inspector.error != nil }
        try expect("an entry this server does not hold is not read from it, and a domain the forest does not list is not offered",
                   session.inspector.otherDomain == nil && session.inspector.error?.contains("not a domain of this forest") == true
                       && session.holdsEntry(user)
                       && session.holdsEntry("DC=host,DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,\(base)")
                       && session.holdsEntry("CN=user,CN=Schema,CN=Configuration,\(base)"))
        await model.openDomain("child.corp.example", from: session)
        try expect("a domain the forest does not list is not opened", !model.store.profiles.contains { $0.host == "child.corp.example" })
        // The forest's own domain, by its DNS name: a connection of its own,
        // read-only, given this connection's password.
        await model.openDomain("corp.example", from: session)
        let opened = try Automation.require(model.store.profiles.first { $0.host == "corp.example" })
        let other = try Automation.require(model.existingSession(opened.id))
        try await Automation.waitFor("the forest's domain tried") {
            if case .failed = other.phase { return true }
            return other.passwordRequest != nil || other.phase.isConnected
        }
        try expect("a domain the forest lists opens read-only, trusting no certificate, with the password lent",
                   opened.readOnly && opened.trust == TrustPolicy() && opened.baseDN == base && other.passwordRequest == nil)
        other.disconnect()
        model.delete(opened.id)
        model.requestedSelection = session.id

        // Kerberos: start-ad.sh leaves a ticket in a cache of its own, found
        // through KRB5CCNAME; without one this part is skipped.
        if ProcessInfo.processInfo.environment["KRB5CCNAME"] != nil {
            var kerberos = session.profile
            kerberos.id = UUID()
            kerberos.name = "Corp with Kerberos"
            kerberos.authentication = .kerberos
            kerberos.bindName = ""
            model.store.save(kerberos)
            let signedIn = try Automation.require(model.session(for: kerberos.id))
            signedIn.connect()
            try await Automation.waitFor("Kerberos sign-in") {
                if case .failed = signedIn.phase { return true }
                return signedIn.phase.isConnected
            }
            let identity = signedIn.identity ?? ""
            if case .failed(let message) = signedIn.phase { Automation.log("  Kerberos: \(message)") }
            try expect("signs in with the Kerberos ticket, no password, as the ticket's owner",
                       signedIn.phase.isConnected && identity.localizedCaseInsensitiveContains("Administrator") && signedIn.passwordRequest == nil)
            signedIn.disconnect()
            model.delete(kerberos.id)
        } else {
            Automation.log("note: Kerberos not checked; run with KRB5_CONFIG and KRB5CCNAME from TestDirectory/start-ad.sh")
        }

        try await open(user)
        session.inspector.tab = .permissions
        try await Automation.settle(3)
        try Automation.snapshot("AD-permissions", output)
        session.inspector.tab = .overview

        // Enabling, disabling, the account options.
        ada = try Automation.require(try await read(user))
        await AccountActions.setEnabled(false, ada, session: session)
        let disabledFlag = (try await read(user)?.int("userAccountControl") ?? 0) & 2 != 0
        let disabledSignIn = try await signIn(user, current)
        try expect("disabled: the flag is set and AD refuses the sign-in as disabled", disabledFlag && disabledSignIn == .disabled)
        await AccountActions.setEnabled(true, try Automation.require(try await read(user)), session: session)
        let enabledSignIn = try await signIn(user, current)
        try expect("enabled again: the user signs in", enabledSignIn == .success)
        for (bit, label) in [(Int64(0x10000), "Password never expires"),
                             (0x100000, "Account is sensitive and cannot be delegated"), (0x400000, "Do not require Kerberos pre-authentication")] {
            await AccountActions.setFlag(bit, on: true, try Automation.require(try await read(user)), session: session, label: label)
            let on = (try await read(user)?.int("userAccountControl") ?? 0) & bit != 0
            await AccountActions.setFlag(bit, on: false, try Automation.require(try await read(user)), session: session, label: label)
            let off = (try await read(user)?.int("userAccountControl") ?? bit) & bit == 0
            try expect("\(label): on, then off again", on && off)
        }

        let stillSignsIn = try await signIn(user, current)
        try expect("those options leave the password alone", stillSignsIn == .success)
        // Requiring a smart card makes AD replace the password with a random one.
        await AccountActions.setFlag(0x40000, on: true, try Automation.require(try await read(user)), session: session, label: "Smart card")
        let smartCardOn = (try await read(user)?.int("userAccountControl") ?? 0) & 0x40000 != 0
        let afterSmartCard = try await signIn(user, current)
        Automation.log("  after requiring a smart card, the old password gives: \(afterSmartCard)")
        await AccountActions.setFlag(0x40000, on: false, try Automation.require(try await read(user)), session: session, label: "Smart card")
        let smartCardOff = (try await read(user)?.int("userAccountControl") ?? 0x40000) & 0x40000 == 0
        try expect("Smart card is required: on, then off; AD replaced the password when it went on",
                   smartCardOn && smartCardOff && afterSmartCard != .success)
        _ = await session.change("Reset.") {
            try await $0.modify(user, [LDAPModification(.replace, "unicodePwd", [ADValues.unicodePwd(current)])])
        }

        // Unlocking the account locked out with wrong passwords.
        let lockedEntry = try Automation.require(try await read(thomas))
        let lockedSignIn = try await signIn(thomas, seeded)
        try expect("a locked-out account is shown as locked, and AD refuses even its right password",
                   AccountActions.isLocked(lockedEntry) && lockedSignIn == .lockedOut)
        await AccountActions.unlock(lockedEntry, session: session)
        let lockoutTime = try await read(thomas)?.int("lockoutTime")
        let unlockedSignIn = try await signIn(thomas, seeded)
        try expect("unlocked: lockoutTime is 0 and the user signs in", lockoutTime == 0 && unlockedSignIn == .success)

        // Groups: membership as the attribute editor sends it, and the group type.
        let engineering = "CN=GG-Engineering,OU=Groups,OU=Corp,\(base)"
        _ = await session.change("Added.") { try await $0.modify(engineering, [.add("member", [user])]) }
        try expect("added to a group: AD lists the group in the user's memberOf",
                   try await read(user)?.strings("memberOf").contains { DN.isSame($0, engineering) } == true)
        _ = await session.change("Removed.") { try await $0.modify(engineering, [.delete("member", [user])]) }
        try expect("removed again", try await read(user)?.strings("memberOf").contains { DN.isSame($0, engineering) } == false)
        let group = "CN=GG-Forester-Checks,\(ou)"
        let groupMade = await session.change("Created the group.") {
            try await $0.add(group, attributes: [LDAPAttribute(name: "objectClass", values: [Data("group".utf8)]),
                                                 LDAPAttribute(name: "sAMAccountName", values: [Data("GG-Forester-Checks".utf8)]),
                                                 LDAPAttribute(name: "groupType", values: [Data("-2147483646".utf8)])])
        }
        let converted = await session.change("Converted.") { try await $0.modify(group, [.replace("groupType", ["-2147483640"])]) }
        // An empty group of its own, so the preset does not depend on the seeded
        // GG-Empty-Legacy, which the UI tour's LDIF import deletes.
        session.mode = .search
        session.search.base = base
        session.search.apply(try Automation.require(SearchPreset.all.first { $0.title == "Empty groups" }))
        try await Automation.waitFor("preset Empty groups") { !session.search.running && session.search.hasRun }
        try expect("the preset \"Empty groups\" finds a new, empty group", session.search.rows.contains { DN.isSame($0.id, group) })
        session.mode = .browse
        let groupType = try await read(group)?.int("groupType")
        try expect("a global security group is created and converted to universal", groupMade && converted && groupType == -2_147_483_640)

        // Groups nested in a circle (AD allows it): A contains Ada and B, B contains A.
        func makeGroup(_ name: String) async -> Bool {
            await session.change("Created \(name).") {
                try await $0.add("CN=\(name),\(ou)", attributes: [LDAPAttribute(name: "objectClass", values: [Data("group".utf8)]),
                                                                LDAPAttribute(name: "sAMAccountName", values: [Data(name.utf8)])])
            }
        }
        let cycleA = "CN=GG-Cycle-A,\(ou)", cycleB = "CN=GG-Cycle-B,\(ou)"
        let madeA = await makeGroup("GG-Cycle-A")
        let madeB = await makeGroup("GG-Cycle-B")
        let circle = madeA && madeB
        _ = await session.change("Nested.") { try await $0.modify(cycleA, [.add("member", [user, cycleB])]) }
        _ = await session.change("Nested.") { try await $0.modify(cycleB, [.add("member", [cycleA])]) }
        let hasTransitive = !(try await read(user, ["msds-memberOfTransitive"])?.strings("msds-memberOfTransitive").isEmpty ?? true)
        Automation.log("  nesting via \(hasTransitive ? "msds-memberOfTransitive" : "the in-chain query on groups and the group walk (no msds-*Transitive on this server)")")
        func nestedList(of dn: String) async throws -> (names: [String], seconds: Double) {
            try await open(dn)
            let started = Date()
            session.inspector.membership.loadNested()
            try await Automation.waitFor("nested for \(DN.displayName(dn))", timeout: 30) { session.inspector.membership.nested != nil }
            return ((session.inspector.membership.nested ?? []).map(\.name), Date().timeIntervalSince(started))
        }
        let ofAda = try await nestedList(of: user)
        try expect("groups nested in a circle: an account's nested groups list each once, in \(String(format: "%.1f", ofAda.seconds)) s",
                   circle && ofAda.names.sorted() == ["GG-Cycle-A", "GG-Cycle-B"])
        MembershipModel.failInChainForTesting = true
        let walked = try await nestedList(of: user)
        MembershipModel.failInChainForTesting = false
        try expect("…and the same when the in-chain query fails and the groups are walked one by one (\(String(format: "%.1f", walked.seconds)) s)",
                   walked.names.sorted() == ["GG-Cycle-A", "GG-Cycle-B"])
        let ofA = try await nestedList(of: cycleA)
        try expect("…a group's nested members end where the circle closes, without the group itself (\(String(format: "%.1f", ofA.seconds)) s)",
                   ofA.names.sorted() == ["Ada Checks", "GG-Cycle-B"])
        let ofB = try await nestedList(of: cycleB)
        try expect("…and from the other group in the circle too", ofB.names.sorted() == ["Ada Checks", "GG-Cycle-A"])
        let vpn = try await nestedList(of: "CN=DL-VPN-Users,OU=Groups,OU=Corp,\(base)")
        try expect("a group's members at any depth: DL-VPN-Users reaches Pieter through GG-Engineering (\(vpn.names.count) members, \(String(format: "%.1f", vpn.seconds)) s)",
                   vpn.names.contains("Pieter Van Damme") && vpn.names.contains("GG-Engineering"))

        // Find by name matches inside a name, not only at its start.
        let k8s = "CN=GRP_GSU_APP_K8S_MINFRA_ADMIN,\(ou)"
        _ = await makeGroup("GRP_GSU_APP_K8S_MINFRA_ADMIN")
        session.search.base = base
        // The fast half answers first, on its own; the inside-names half adds to it.
        session.search.quickFind("K8S_MINFRA")
        try await Automation.waitFor("the name search's first half") { !session.search.running }
        let firstHalf = session.search.filterText
        try await Automation.waitFor("inside names") { !session.search.lookingInside }
        try expect("Find by name answers from AD's index first, then adds matches inside names (\(session.search.summary ?? ""))",
                   firstHalf == "(anr=K8S_MINFRA)" && session.search.rows.contains { DN.isSame($0.id, k8s) }
                   && session.search.summary?.contains("matched inside a name") == true)
        for query in ["K8S_MINFRA", "k8s_minfra", "MINFRA_ADMIN"] {
            session.search.quickFind(query)
            try await Automation.waitFor("find \(query)") { !session.search.running && !session.search.lookingInside && session.search.hasRun }
            try expect("Find by name \"\(query)\" finds GRP_GSU_APP_K8S_MINFRA_ADMIN", session.search.rows.contains { DN.isSame($0.id, k8s) })
        }
        session.search.quickFind("Pieter Van")
        try await Automation.waitFor("find Pieter Van") { !session.search.running && !session.search.lookingInside && session.search.hasRun }
        try expect("…and still finds people by \"First Last\" through AD's name resolution", session.search.rows.contains { DN.isSame($0.id, pieter) })
        session.mode = .browse

        // A computer and a contact, as their templates send them.
        let computer = "CN=CHECKS-PC,\(ou)"
        let computerMade = await session.change("Created the computer.") {
            try await $0.add(computer, attributes: [
                LDAPAttribute(name: "objectClass", values: ["top", "person", "organizationalPerson", "user", "computer"].map { Data($0.utf8) }),
                LDAPAttribute(name: "sAMAccountName", values: [Data("CHECKS-PC$".utf8)]),
                LDAPAttribute(name: "userAccountControl", values: [Data("4128".utf8)]),
            ])
        }
        let contactMade = await session.change("Created the contact.") {
            try await $0.add("CN=Grace Contact,\(ou)", attributes: [
                LDAPAttribute(name: "objectClass", values: ["top", "person", "organizationalPerson", "contact"].map { Data($0.utf8) }),
                LDAPAttribute(name: "mail", values: [Data("grace@partner.example".utf8)]),
            ])
        }
        let computerName = try await read(computer)?.string("sAMAccountName")
        try expect("a computer account and a contact are created", computerMade && contactMade && computerName == "CHECKS-PC$")

        // Rename and move.
        let renamed = "CN=Ada Renamed,\(ou)"
        let moved = "CN=Ada Renamed,OU=Disabled Users,OU=Corp,\(base)"
        let renameOK = await session.change("Renamed.") { try await $0.modifyDN(user, newRDN: "CN=Ada Renamed") }
        let moveOK = await session.change("Moved.") { try await $0.modifyDN(renamed, newRDN: "CN=Ada Renamed", newSuperior: "OU=Disabled Users,OU=Corp,\(base)") }
        let movedEntry = try await read(moved)
        let movedSignIn = try await signIn(moved, current)
        Automation.log("  rename: \(renameOK), move: \(moveOK) (\(session.notice?.message ?? "")), found: \(movedEntry != nil), sign-in: \(movedSignIn)")
        try expect("renamed and moved, and still signs in", renameOK && moveOK && movedEntry != nil && movedSignIn == .success)
        _ = await session.change("Moved back.") { try await $0.modifyDN(moved, newRDN: "CN=Ada Renamed", newSuperior: ou) }

        // Deleting: one entry, then the OU with everything in it, as the Delete sheet does.
        let deleted = await session.change("Deleted the contact.") { try await $0.delete("CN=Grace Contact,\(ou)") }
        let contactLeft = try await read("CN=Grace Contact,\(ou)")
        try expect("one entry is deleted", deleted && contactLeft == nil)
        try expect("the server offers AD's tree delete", session.server?.supportsTreeDelete == true)
        let treeDeleted = await session.change("Deleted the OU.") { try await $0.deleteSubtree(ou, useTreeDelete: true) }
        let ouLeft = try await read(ou)
        try expect("an OU with users, a group and a computer in it is deleted in one go", treeDeleted && ouLeft == nil)

        session.setReadOnly(true)
        Automation.log("verified (AD): all \(passed) checks against \(session.server.map { $0.rootDSE.string("vendorName") ?? "" } ?? "")")
    }
}
#endif
