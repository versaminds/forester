// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

/// What kind of entry to create. Each template fixes the object classes and
/// naming attribute, and lists the attributes worth asking for; the server's
/// schema adds whatever else it requires.
enum EntryTemplate: String, CaseIterable, Identifiable {
    case adUser, adGroup, adComputer, adContact, organizationalUnit
    case inetOrgPerson, posixAccount, groupOfNames, posixGroup, container, custom

    var id: String { rawValue }

    var label: String {
        switch self {
        case .adUser: return "User (Active Directory)"
        case .adGroup: return "Group (Active Directory)"
        case .adComputer: return "Computer (Active Directory)"
        case .adContact: return "Contact (Active Directory)"
        case .organizationalUnit: return "Organizational unit"
        case .inetOrgPerson: return "Person (inetOrgPerson)"
        case .posixAccount: return "POSIX account"
        case .groupOfNames: return "Group (groupOfNames)"
        case .posixGroup: return "POSIX group"
        case .container: return "Container"
        case .custom: return "Other, choose object classes…"
        }
    }

    var kind: ObjectKind {
        switch self {
        case .adUser, .inetOrgPerson, .posixAccount: return .user
        case .adGroup, .groupOfNames, .posixGroup: return .group
        case .adComputer: return .computer
        case .adContact: return .contact
        case .organizationalUnit: return .organizationalUnit
        case .container, .custom: return .container
        }
    }

    var isAD: Bool { [.adUser, .adGroup, .adComputer, .adContact].contains(self) }

    var objectClasses: [String] {
        switch self {
        case .adUser: return ["top", "person", "organizationalPerson", "user"]
        case .adGroup: return ["top", "group"]
        case .adComputer: return ["top", "person", "organizationalPerson", "user", "computer"]
        case .adContact: return ["top", "person", "organizationalPerson", "contact"]
        case .organizationalUnit: return ["top", "organizationalUnit"]
        case .inetOrgPerson: return ["top", "person", "organizationalPerson", "inetOrgPerson"]
        case .posixAccount: return ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"]
        case .groupOfNames: return ["top", "groupOfNames"]
        case .posixGroup: return ["top", "posixGroup"]
        case .container: return ["top", "container"]
        case .custom: return []
        }
    }

    var namingAttribute: String {
        switch self {
        case .organizationalUnit: return "ou"
        case .inetOrgPerson, .posixAccount: return "uid"
        default: return "cn"
        }
    }

    /// Attributes to offer, in order, beyond the naming attribute.
    var fields: [String] {
        switch self {
        case .adUser: return ["givenName", "sn", "displayName", "sAMAccountName", "userPrincipalName", "mail", "title", "department", "description"]
        case .adGroup: return ["sAMAccountName", "description", "mail"]
        case .adComputer: return ["sAMAccountName", "dNSHostName", "description"]
        case .adContact: return ["givenName", "sn", "displayName", "mail", "telephoneNumber"]
        case .organizationalUnit: return ["description"]
        case .inetOrgPerson: return ["cn", "givenName", "sn", "mail", "telephoneNumber"]
        case .posixAccount: return ["cn", "givenName", "sn", "mail", "uidNumber", "gidNumber", "homeDirectory", "loginShell"]
        case .groupOfNames: return ["member", "description"]
        case .posixGroup: return ["gidNumber", "memberUid", "description"]
        case .container: return ["description"]
        case .custom: return []
        }
    }

    @MainActor static func available(for session: DirectorySession) -> [EntryTemplate] {
        session.hasADTools
            ? [.adUser, .adGroup, .adComputer, .adContact, .organizationalUnit, .container, .custom]
            : [.inetOrgPerson, .posixAccount, .groupOfNames, .posixGroup, .organizationalUnit, .container, .custom]
    }
}

/// Creates an entry from a template, or as a copy of an existing one.
struct NewEntrySheet: View {
    let session: DirectorySession
    let parentDN: String
    /// Set to clone: its classes and copyable attributes prefill the form.
    var source: LDAPEntry?
    /// The kind to start with; the first one this directory offers otherwise.
    var initialTemplate: EntryTemplate?
    @Environment(\.dismiss) private var dismiss

    @State private var parent = ""
    @State private var template: EntryTemplate = .organizationalUnit
    @State private var customClasses: [String] = []
    @State private var namingAttribute = "cn"
    @State private var name = ""
    @State private var values: [String: String] = [:]
    @State private var extraFields: [String] = []
    @State private var password = ""
    @State private var confirm = ""
    @State private var mustChange = true
    @State private var enabled = true
    @State private var groupType: Int64 = -2147483646
    @State private var copied: [LDAPAttribute] = []
    @State private var copyAttributes: Set<String> = []
    @State private var addToGroups = true
    @State private var sourceGroups: [String] = []
    /// Source groups that grant administrative rights (adminCount=1 in AD).
    @State private var privilegedGroups: [String] = []
    @State private var creating = false
    @State private var error: String?
    @State private var choosingParent = false
    @State private var addingAttribute = false
    @State private var choosingMembers = false
    @State private var showingLDIF = false
    @State private var revealPassword = false
    /// Fields the user typed into, which the name no longer fills in.
    @State private var customized: Set<String> = []

    /// Attributes never copied from a source entry: identity, state the server
    /// keeps, and anything unique to the original.
    static let notCopied: Set<String> = [
        "objectguid", "objectsid", "samaccountname", "userprincipalname", "mail", "distinguishedname", "name", "cn",
        "displayname", "givenname", "sn", "uid", "uidnumber", "whencreated", "whenchanged", "usncreated", "usnchanged",
        "memberof", "member", "directreports", "pwdlastset", "lastlogon", "lastlogontimestamp", "lastlogoff", "badpwdcount",
        "badpasswordtime", "logoncount", "lockouttime", "ntsecuritydescriptor", "unicodepwd", "userpassword",
        "thumbnailphoto", "jpegphoto", "primarygroupid", "samaccounttype", "iscriticalsystemobject", "instancetype",
        "objectcategory", "dscorepropagationdata", "serviceprincipalname", "msds-replattributemetadata",
        "msds-replvaluemetadata", "msds-resultantpso", "telephonenumber", "mobile", "employeeid", "employeenumber",
        "homedirectory", "allowedattributeseffective", "canonicalname", "msds-principalname",
        // Identities that must stay unique: the Entra ID source anchor, mail
        // addresses, certificate and key mappings, SID history.
        "ms-ds-consistencyguid", "msds-externaldirectoryobjectid", "proxyaddresses", "mailnickname", "targetaddress",
        "legacyexchangedn", "altsecurityidentities", "usercertificate", "usersmimecertificate", "msds-keycredentiallink",
        "sidhistory", "homemdb", "homemta",
        // Set by AD on members of protected groups, not by anyone copying them.
        "admincount",
    ]

    /// Copied only when the user ticks them: they hand out rights of their own.
    static let notCopiedByDefault: Set<String> = ["msds-allowedtodelegateto"]

    /// Exchange and Skype/Teams attributes describe one mailbox or SIP address;
    /// their own tools provision them, so a copy would point at the original's.
    static let notCopiedPrefixes = ["msexch", "msrtcsip-"]

    static func isCopyable(_ name: String) -> Bool {
        let key = name.lowercased()
        return !notCopied.contains(key) && !notCopiedPrefixes.contains { key.hasPrefix($0) }
    }

    private var classes: [String] { template == .custom ? customClasses : template.objectClasses }
    private var trimmedName: String { name.trimmingCharacters(in: .whitespaces) }
    private var newDN: String { "\(namingAttribute)=\(DN.escape(trimmedName)),\(parent)" }
    private var adPasswordAllowed: Bool { session.isSecure }

    /// Template fields, then anything the schema requires, then what the user added.
    private var fieldNames: [String] {
        var names: [String] = []
        var seen = setByForm.union(["objectclass", namingAttribute.lowercased()])
        func add(_ name: String) { if seen.insert(name.lowercased()).inserted { names.append(name) } }
        template.fields.forEach(add)
        required.forEach(add)
        extraFields.forEach(add)
        return names
    }

    /// Attributes the form sets from its own controls (password, group type),
    /// which must not also be asked for as text.
    private var setByForm: Set<String> {
        var names: Set<String> = []
        if template == .adGroup { names.insert("grouptype") }
        if template == .adComputer { names.insert("useraccountcontrol") }
        if template == .adUser || (source != nil && isADUser) { names.formUnion(["useraccountcontrol", "unicodepwd", "pwdlastset"]) }
        return names
    }

    /// Required by the schema, but filled in by the server, never typed: AD
    /// gives every new object its category, security descriptor and instance
    /// type, and every security principal its SID. Asking for them only kept
    /// Create disabled (found against a real domain controller).
    static let setByServer: Set<String> = ["objectcategory", "ntsecuritydescriptor", "instancetype", "objectsid"]

    private var required: [String] {
        guard let schema = session.schema else { return [] }
        return schema.allowedAttributes(for: classes).must.filter { name in
            let key = name.lowercased()
            return key != "objectclass" && key != namingAttribute.lowercased() && !setByForm.contains(key)
                && !Self.setByServer.contains(key) && schema.attributeType(name)?.noUserModification != true
        }
    }

    /// AD users only: a computer's password is set by the computer itself.
    private var showsPassword: Bool {
        template == .adUser || (source != nil && isADUser)
    }

    var body: some View {
        SheetLayout(title: source == nil ? "New Entry" : "Duplicate “\(DN.displayName(source!.dn))”",
                    subtitle: source == nil ? nil : "A new entry with this one's settings. Names, IDs and passwords are not copied.",
                    width: 660, height: 700) {
            VStack(spacing: 0) {
                form
                if showingLDIF {
                    Divider()
                    ScrollView {
                        Text(LDIF.record(LDIFRecord(dn: newDN, change: .add(previewAttributes), line: 0, isContent: false)))
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 20)
                            .padding(.vertical, 10)
                    }
                    .frame(height: 150)
                    .background(.background.secondary)
                }
            }
        } status: {
            HStack(spacing: 14) {
                Toggle("Show LDIF", isOn: $showingLDIF).toggleStyle(.checkbox)
                    .help("Show the entry as it will be sent to the server.")
                SheetStatus(problem: validationProblem, error: error)
            }
        } buttons: {
            Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
            Button { create() } label: {
                if creating { ProgressView().controlSize(.small) } else { Text("Create") }
            }
            .keyboardShortcut(.defaultAction)
            .disabled(creating || validationProblem != nil)
        }
        .onAppear(perform: prepare)
        .onChange(of: template) { _, new in
            namingAttribute = new.namingAttribute
            if new == .custom, customClasses.isEmpty { customClasses = ["top"] }
        }
        .sheet(isPresented: $choosingParent) {
            DNPickerSheet(session: session, containersOnly: true, startAt: parent) { if let first = $0.first { parent = first } }
        }
        .sheet(isPresented: $choosingMembers) {
            DNPickerSheet(session: session, allowsMultiple: true, title: "Choose Members") { picked in
                let existing = (values["member"] ?? "").split(separator: "\n").map(String.init).filter { !$0.isEmpty }
                values["member"] = (existing + picked).joined(separator: "\n")
            }
        }
        .sheet(isPresented: $addingAttribute) {
            NavigationStack {
                AttributePicker(session: session, entry: LDAPEntry(dn: newDN, attributes: [
                    LDAPAttribute(name: "objectClass", values: classes.map { Data($0.utf8) }),
                ] + fieldNames.map { LDAPAttribute(name: $0, values: [Data("x".utf8)]) })) { chosen in
                    extraFields.append(chosen)
                    addingAttribute = false
                }
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { addingAttribute = false } } }
            }
            .frame(width: 480, height: 480)
        }
    }

    private var form: some View {
        Form {
            Section {
                DNFieldRow(label: "In", dn: $parent) { choosingParent = true }
                if source == nil {
                    PickerRow(label: "Type", selection: $template) {
                        ForEach(EntryTemplate.available(for: session)) { Text($0.label).tag($0) }
                    }
                }
                if template == .custom && source == nil {
                    ClassChooser(session: session, classes: $customClasses)
                }
                FieldRow(label: "Name", required: true, help: "The value the entry is named by, the first part of its DN.") {
                    HStack(spacing: 6) {
                        if template == .custom || source != nil {
                            TextField("Naming attribute", text: $namingAttribute)
                                .labelsHidden()
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 70)
                                .help("The attribute the entry is named by: cn, ou, uid…")
                            Text("=").foregroundStyle(.secondary)
                        } else {
                            Text("\(namingAttribute)=").foregroundStyle(.secondary)
                        }
                        TextField("Name", text: $name, prompt: Text(namePrompt))
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                    }
                }
                ValueRow(label: "DN", value: newDN, monospaced: true)
            }
            Section {
                ForEach(fieldNames, id: \.self) { field in fieldRow(field) }
                FieldRow(label: "") {
                    Button { addingAttribute = true } label: { Label("Add Attribute…", systemImage: "plus") }
                        .buttonStyle(.borderless)
                }
            } header: {
                Text("Attributes")
            } footer: {
                if session.schema == nil {
                    FormFooter("The schema could not be read, so required attributes are not marked here; the server will say what is missing.")
                }
            }
            if showsPassword {
                Section("Password") {
                    if adPasswordAllowed {
                        PasswordFieldRow(label: "Password", text: $password, reveal: $revealPassword)
                        PasswordFieldRow(label: "Confirm", text: $confirm, reveal: $revealPassword, showsRevealButton: false)
                        Toggle("User must change password at next sign-in", isOn: $mustChange)
                            .formSwitch("User must change password at next sign-in")
                        Toggle("Account enabled", isOn: $enabled)
                            .formSwitch("Account enabled")
                    } else {
                        Label("AD accepts a password only over an encrypted connection (StartTLS or LDAPS). The account is created disabled; set a password and enable it later.",
                              systemImage: "lock.trianglebadge.exclamationmark")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
            }
            if template == .adGroup {
                Section("Group Type") { GroupTypeRows(value: $groupType) }
            }
            if source != nil {
                copiedSection
            }
        }
        .formStyle(.grouped)
        .formLabelWidth(150)
    }

    /// What a common attribute holds, shown in its empty field.
    static func hint(for attribute: String) -> String? {
        switch attribute.lowercased() {
        case "givenname": return "First name"
        case "sn": return "Last name"
        case "cn": return "Full name"
        case "displayname": return "Name shown in lists"
        case "samaccountname": return "Sign-in name, at most 20 characters"
        case "userprincipalname": return "Sign-in name as user@domain"
        case "mail": return "Email address"
        case "title": return "Job title"
        case "department": return "Department"
        case "description": return "Description"
        case "telephonenumber": return "Phone number"
        case "dnshostname": return "Host name, such as wks-0042.corp.example"
        case "uid": return "Login name"
        case "uidnumber": return "Numeric user ID"
        case "gidnumber": return "Numeric group ID"
        case "homedirectory": return "Home directory, such as /home/jdoe"
        case "loginshell": return "Shell, such as /bin/zsh"
        case "memberuid": return "Login names, one per line or separated by commas"
        default: return nil
        }
    }

    private var namePrompt: String {
        switch template.kind {
        case .user: return "Jane Doe"
        case .group: return "GG-Finance"
        case .computer: return "WKS-0042"
        case .organizationalUnit: return "Finance"
        default: return "Name"
        }
    }

    @ViewBuilder
    private func fieldRow(_ field: String) -> some View {
        let isRequired = required.contains { $0.caseInsensitiveCompare(field) == .orderedSame }
        let help = session.schema?.attributeType(field)?.description.map { "\(field): \($0)" } ?? field
        if field == "member" {
            FieldRow(label: field, required: isRequired, help: help) {
                VStack(alignment: .leading, spacing: 6) {
                    TextEditor(text: binding(field))
                        .font(.callout.monospaced())
                        .scrollContentBackground(.hidden)
                        .padding(4)
                        .frame(height: 64)
                        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
                        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color(nsColor: .separatorColor)))
                        .accessibilityLabel(field)
                    Button("Choose Members…") { choosingMembers = true }
                }
            }
        } else if Self.passwordAttributes.contains(field.lowercased()) {
            PasswordFieldRow(label: field, text: binding(field), reveal: $revealPassword, required: isRequired)
        } else {
            TextFieldRow(label: field, text: binding(field), prompt: Self.hint(for: field),
                         required: isRequired, help: help)
        }
    }

    /// A field the name fills in shows the value worked out from the name as
    /// it is now, until the user types something else into it. Working it out
    /// on each read, rather than copying on each change of the name, means a
    /// change notification missed while typing fast cannot leave it a letter behind.
    private func value(_ field: String) -> String {
        if !customized.contains(field.lowercased()), let derived = derived(field) { return derived }
        return values[field] ?? ""
    }

    private func binding(_ field: String) -> Binding<String> {
        Binding(get: { value(field) }, set: { newValue in
            values[field] = newValue
            if newValue != derived(field) { customized.insert(field.lowercased()) }
        })
    }

    @ViewBuilder
    private var copiedSection: some View {
        Section {
            if copied.isEmpty {
                Text("Nothing else to copy.").foregroundStyle(.secondary)
            }
            ForEach(copied, id: \.name) { attribute in
                Toggle(isOn: Binding(get: { copyAttributes.contains(attribute.name) },
                                     set: { if $0 { copyAttributes.insert(attribute.name) } else { copyAttributes.remove(attribute.name) } })) {
                    HStack(alignment: .firstTextBaseline, spacing: 12) {
                        Text(attribute.name).frame(width: 130, alignment: .leading).lineLimit(1).truncationMode(.middle)
                        Text(attribute.values.map { AttributeFormatter.format(attribute.name, $0).text }.joined(separator: "; "))
                            .foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .toggleStyle(.checkbox)
            }
            if !sourceGroups.isEmpty {
                Toggle(isOn: $addToGroups) {
                    Text("Add to the same \(sourceGroups.count) group\(sourceGroups.count == 1 ? "" : "s")")
                    Text(sourceGroups.map(DN.displayName).joined(separator: ", ")).lineLimit(4)
                }
                .toggleStyle(.checkbox)
                .help(sourceGroups.map(DN.displayName).joined(separator: "\n"))
                if !privilegedGroups.isEmpty {
                    Label("Including \(privilegedGroups.map(DN.displayName).joined(separator: ", ")), which grant\(privilegedGroups.count == 1 ? "s" : "") administrative rights.",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                }
            }
        } header: {
            Text("Copy from \(DN.displayName(source?.dn ?? ""))")
        }
    }

    // MARK: Building the entry

    private var attributes: [LDAPAttribute] {
        var result: [LDAPAttribute] = [LDAPAttribute(name: "objectClass", values: classes.map { Data($0.utf8) })]
        func set(_ name: String, _ values: [String]) {
            let cleaned = values.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            guard !cleaned.isEmpty else { return }
            result.removeAll { $0.name.caseInsensitiveCompare(name) == .orderedSame }
            result.append(LDAPAttribute(name: name, values: cleaned.map { Data($0.utf8) }))
        }
        set(namingAttribute, [trimmedName])
        if source != nil {
            // The naming attribute is the new name, never the original's.
            for attribute in copied where copyAttributes.contains(attribute.name)
                && attribute.baseName.caseInsensitiveCompare(namingAttribute) != .orderedSame {
                result.removeAll { $0.name.caseInsensitiveCompare(attribute.name) == .orderedSame }
                result.append(attribute)
            }
        }
        for field in fieldNames {
            let text = value(field)
            if ["member", "memberUid"].contains(field) {
                set(field, text.split(whereSeparator: { $0 == "\n" || $0 == "," && field == "memberUid" }).map(String.init))
            } else {
                set(field, [text])
            }
        }
        if template == .adUser || (source != nil && isADUser) {
            let hasPassword = adPasswordAllowed && !password.isEmpty
            // A duplicate keeps the original's settings (password never expires,
            // smart card, delegation) but not its state: disabled, locked out,
            // password not required, password expired.
            var base: Int64 = 512
            if source != nil, copyAttributes.contains(where: { $0.caseInsensitiveCompare("userAccountControl") == .orderedSame }),
               let copiedUAC = copied.first(where: { $0.baseName.caseInsensitiveCompare("userAccountControl") == .orderedSame })?
                .stringValues.first.flatMap({ Int64($0) }) {
                base = (copiedUAC & ~(0x2 | 0x10 | 0x20 | 0x800000)) | 0x200
            }
            // +2 disabled; without a password AD needs PASSWD_NOTREQD (32) to create it.
            let uac = base | (hasPassword && enabled ? 0 : 2) | (hasPassword ? 0 : 32)
            set("userAccountControl", [String(uac)])
            if hasPassword {
                result.append(LDAPAttribute(name: "unicodePwd", values: [ADValues.unicodePwd(password)]))
                if mustChange { set("pwdLastSet", ["0"]) }
            }
        }
        if template == .adComputer { set("userAccountControl", ["4128"]) }
        if template == .adGroup { set("groupType", [String(groupType)]) }
        return result
    }

    /// The entry as it will be sent, with passwords shown as stars: the
    /// preview is selectable text, and the password field may be hidden.
    private var previewAttributes: [LDAPAttribute] {
        attributes.map { attribute in
            guard Self.passwordAttributes.contains(attribute.baseName.lowercased()) else { return attribute }
            return LDAPAttribute(name: attribute.name, values: attribute.values.map { _ in Data("********".utf8) })
        }
    }

    static let passwordAttributes: Set<String> = ["unicodepwd", "userpassword", "clearpassword", "sambantpassword", "sambalmpassword"]

    private var isADUser: Bool {
        session.hasADTools && classes.contains { $0.caseInsensitiveCompare("user") == .orderedSame }
            && !classes.contains { $0.caseInsensitiveCompare("computer") == .orderedSame }
    }

    private var validationProblem: String? {
        if parent.trimmingCharacters(in: .whitespaces).isEmpty { return "Choose where to create it." }
        if trimmedName.isEmpty { return "Enter a name." }
        if classes.filter({ $0 != "top" }).isEmpty { return "Choose at least one object class." }
        let present = Set(attributes.map { $0.name.lowercased() })
        if let missing = required.first(where: { !present.contains($0.lowercased()) }) { return "\(missing) is required." }
        if template == .adUser || (source != nil && isADUser), adPasswordAllowed, password != confirm { return "The passwords do not match." }
        if session.hasADTools, case let sam = value("sAMAccountName"), sam.count > 20 { return "sAMAccountName is at most 20 characters." }
        return nil
    }

    private func prepare() {
        parent = parentDN
        if let source {
            customClasses = source.objectClasses
            template = .custom
            namingAttribute = DN.rdnAttribute(source.dn) ?? "cn"
            copied = source.attributes.filter { attribute in
                let key = attribute.baseName.lowercased()
                guard key != "objectclass", key != namingAttribute.lowercased(), Self.isCopyable(key), !attribute.name.contains(";") else { return false }
                if let type = session.schema?.attributeType(attribute.name), type.noUserModification || type.isOperational { return false }
                return true
            }
            copyAttributes = Set(copied.map(\.name).filter { !Self.notCopiedByDefault.contains($0.lowercased()) })
            sourceGroups = source.strings("memberOf")
            if session.hasADTools, !sourceGroups.isEmpty { Task { await findPrivilegedGroups() } }
            if session.hasADTools, classes.contains(where: { $0.caseInsensitiveCompare("user") == .orderedSame }) {
                extraFields = ["sAMAccountName", "userPrincipalName", "givenName", "sn", "displayName"]
            }
        } else {
            template = initialTemplate ?? EntryTemplate.available(for: session).first ?? .organizationalUnit
            if template == .custom, customClasses.isEmpty { customClasses = ["top"] }
            namingAttribute = template.namingAttribute
        }
    }

    /// Group memberships are copied by default, except into a group that
    /// grants administrative rights: that one the user asks for explicitly.
    private func findPrivilegedGroups() async {
        guard let base = session.server?.defaultNamingContext else { return }
        let request = LDAPSearchRequest(base: base, scope: .subtree, filter: .and([.equality("objectCategory", "group"), .equality("adminCount", "1")]),
                                        attributes: ["1.1"])
        guard let found = try? await session.run({ try await $0.pagedSearch(request, pageSize: 500, limit: 1_000) }) else { return }
        let protected = Set(found.entries.map { DN.normalized($0.dn) })
        privilegedGroups = sourceGroups.filter { protected.contains(DN.normalized($0)) }
        if !privilegedGroups.isEmpty { addToGroups = false }
    }

    /// What the name fills in: sAMAccountName, userPrincipalName and
    /// displayName for an AD user, and the like. nil for other fields.
    private func derived(_ field: String) -> String? {
        let name = trimmedName
        guard !name.isEmpty else { return nil }
        let dotted = name.replacingOccurrences(of: " ", with: ".").lowercased()
        let domain = session.server?.domainDNSName ?? ""
        // Classes chosen by hand (or copied by Duplicate) count only when they make an AD user.
        let adUser = template == .adUser || (template == .custom && isADUser)
        switch field.lowercased() {
        case "samaccountname" where adUser: return String(dotted.prefix(20))
        case "userprincipalname" where adUser: return domain.isEmpty ? nil : "\(dotted)@\(domain)"
        case "displayname" where adUser: return name
        case "samaccountname" where template == .adGroup: return name
        case "samaccountname" where template == .adComputer: return "\(name.uppercased())$"
        case "dnshostname" where template == .adComputer: return domain.isEmpty ? nil : "\(name.lowercased()).\(domain)"
        case "cn" where template == .inetOrgPerson || template == .posixAccount: return name
        default:
            return nil
        }
    }

    private func create() {
        creating = true
        error = nil
        let dn = newDN
        let entryAttributes = attributes
        let groups = source != nil && addToGroups ? sourceGroups : []
        let parentDN = parent
        let name = trimmedName
        Task {
            let created = await session.change("Created \(name).", refreshing: [parentDN], select: dn,
                                               undo: .inverse(dn: dn, keepsChange: false) { try await $0.delete(dn) }) { connection in
                try await connection.add(dn, attributes: entryAttributes)
            }
            guard created else {
                creating = false
                error = session.notice?.message
                return
            }
            if !groups.isEmpty {
                // The entry exists whatever happens here, so the sheet closes and
                // the notice names any group that refused it.
                let leave = UndoPlan.inverse(dn: dn) { connection in
                    for group in groups { try await connection.modify(group, [.delete("member", [dn])]) }
                }
                await session.change("Created \(name) and added it to \(groups.count) group\(groups.count == 1 ? "" : "s").", undo: leave) { connection in
                    for group in groups {
                        do {
                            try await connection.modify(group, [.add("member", [dn])])
                        } catch {
                            throw GroupAddError(entry: name, group: DN.displayName(group), underlying: error)
                        }
                    }
                }
            }
            creating = false
            dismiss()
        }
    }
}

/// The entry was created; adding it to one of the source's groups was not.
struct GroupAddError: LocalizedError {
    let entry: String
    let group: String
    let underlying: Error

    var errorDescription: String? {
        "\(entry) was created, but could not be added to \(group): \(underlying.localizedDescription)"
    }
}

/// Picks the structural class and any auxiliary classes, from the schema.
struct ClassChooser: View {
    let session: DirectorySession
    @Binding var classes: [String]
    @State private var auxiliary = ""

    private var structural: [String] {
        (session.schema?.structuralClasses.map(\.name) ?? []).sorted { $0.lowercased() < $1.lowercased() }
    }

    private var auxiliaryChosen: [String] {
        classes.filter { session.schema?.objectClass($0)?.kind == .auxiliary }
    }

    var body: some View {
        FieldRow(label: "Object class", help: "The structural class decides what the entry is; its superclasses are added for you.") {
            Picker("Object class", selection: Binding(
                get: { classes.first { name in structural.contains(where: { $0.caseInsensitiveCompare(name) == .orderedSame }) } ?? "" },
                set: { chosen in
                    let aux = classes.filter { name in session.schema?.objectClass(name)?.kind == .auxiliary }
                    let chain = session.schema?.superclassChain(chosen).map(\.name).reversed() ?? [chosen]
                    classes = Array(chain) + aux
                })) {
                Text("Choose…").tag("")
                ForEach(structural, id: \.self) { Text($0).tag($0) }
            }
            .labelsHidden()
            .fixedSize()
        }
        FieldRow(label: "Auxiliary", help: "Auxiliary classes add attributes to an entry of any structural class.") {
            HStack {
                Text(auxiliaryChosen.isEmpty ? "None" : auxiliaryChosen.joined(separator: ", "))
                    .foregroundStyle(.secondary)
                Spacer()
                if !auxiliaryChosen.isEmpty {
                    Button("Clear") { classes.removeAll { name in auxiliaryChosen.contains(name) } }
                }
                Menu("Add") {
                    ForEach((session.schema?.auxiliaryClasses.map(\.name) ?? []).sorted(), id: \.self) { name in
                        Button(name) { if !classes.contains(name) { classes.append(name) } }
                    }
                }
                .fixedSize()
            }
        }
        ValueRow(label: "All classes", value: classes.joined(separator: ", "), monospaced: true)
    }
}
