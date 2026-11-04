// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import Security

/// How a value should be shown and what can be done with it.
public enum AttributeKind: String, Sendable {
    case text, distinguishedName, sid, guid, fileTime, generalizedTime, interval
    case userAccountControl, groupType, samAccountType, encryptionTypes, passwordProperties, functionalLevel
    case image, certificate, binary, gpLink
}

public struct FormattedValue: Hashable, Sendable {
    /// One line for a table cell.
    public var text: String
    /// The raw or secondary form (the integer behind a date, the flags behind a number).
    public var detail: String?
    public var kind: AttributeKind
    /// DNs the value refers to, for navigation.
    public var links: [String]

    public init(text: String, detail: String? = nil, kind: AttributeKind, links: [String] = []) {
        self.text = text
        self.detail = detail
        self.kind = kind
        self.links = links
    }
}

/// Turns raw attribute values into something a person can read: SIDs, GUIDs,
/// Windows timestamps and flag words decoded, DNs recognised as links, binary
/// summarised instead of printed as mojibake.
public enum AttributeFormatter {
    static let sidAttributes: Set<String> = [
        "objectsid", "securityidentifier", "sidhistory", "tokengroups", "tokengroupsglobalanduniversal",
        "tokengroupsnogcacceptable", "ms-ds-creatorsid", "msds-principalsid",
    ]
    static let fileTimeAttributes: Set<String> = [
        "pwdlastset", "lastlogon", "lastlogontimestamp", "lastlogoff", "accountexpires", "badpasswordtime",
        "lockouttime", "msds-userpasswordexpirytimecomputed", "ms-mcs-admpwdexpirationtime",
        "mslaps-passwordexpirationtime", "msds-lastsuccessfulinteractivelogontime",
        "msds-lastfailedinteractivelogontime", "creationtime", "msds-lastknownrdn-time",
    ]
    static let intervalAttributes: Set<String> = [
        "maxpwdage", "minpwdage", "lockoutduration", "lockoutobservationwindow", "forcelogoff",
        "msds-maximumpasswordage", "msds-minimumpasswordage", "msds-lockoutduration",
        "msds-lockoutobservationwindow",
    ]
    static let generalizedTimeAttributes: Set<String> = [
        "whencreated", "whenchanged", "createtimestamp", "modifytimestamp", "dscorepropagationdata",
        "pwdchangedtime", "pwdaccountlockedtime", "pwdfailuretime", "currenttime", "krbpasswordexpiration",
        "krblastsuccessfulauth", "krblastfailedauth", "msexchwhenmailboxcreated",
    ]
    static let dnAttributes: Set<String> = [
        "member", "memberof", "manager", "directreports", "managedby", "managedobjects", "distinguishedname",
        "defaultnamingcontext", "rootdomainnamingcontext", "configurationnamingcontext", "schemanamingcontext",
        "namingcontexts", "subschemasubentry", "servername", "dsservicename", "objectcategory", "uniquemember",
        "roleoccupant", "owner", "seealso", "secretary", "creatorsname", "modifiersname", "entrydn",
        "serverreference", "serverreferencebl", "homemdb", "publicdelegates", "publicdelegatesbl",
        "showinaddressbook", "msds-hostserviceaccount", "msds-hostserviceaccountbl", "lastknownparent",
        "msds-memberoftransitive", "msds-membertransitive", "msds-ncreplicalocations", "masteredby",
        "fsmoroleowner", "msexchhomeservername", "frscomputerreference", "msds-managedpasswordid",
        "msds-allowedtoactonbehalfofotheridentity",
    ]
    static let imageAttributes: Set<String> = ["thumbnailphoto", "jpegphoto", "photo", "thumbnaillogo"]
    static let certificateAttributes: Set<String> = [
        "usercertificate", "cacertificate", "usersmimecertificate", "mspki-ra-signature",
    ]
    static let guidAttributes: Set<String> = [
        "objectguid", "schemaidguid", "attributesecurityguid", "invocationid", "msexchmailboxguid",
        "msexcharchiveguid", "ms-ds-consistencyguid", "netbootguid", "msds-optionalfeatureguid",
        "msds-deviceid",
    ]

    public static func kind(of attribute: String, value: Data) -> AttributeKind {
        let name = (attribute.split(separator: ";").first.map(String.init) ?? attribute).lowercased()
        if sidAttributes.contains(name), ADValues.sidString(value) != nil { return .sid }
        if value.count == 16, guidAttributes.contains(name) || (name.hasSuffix("guid") && isBinary(value)) {
            return .guid
        }
        if fileTimeAttributes.contains(name) { return .fileTime }
        if intervalAttributes.contains(name) { return .interval }
        if generalizedTimeAttributes.contains(name) { return .generalizedTime }
        switch name {
        case "useraccountcontrol", "msds-user-account-control-computed": return .userAccountControl
        case "grouptype": return .groupType
        case "samaccounttype": return .samAccountType
        case "msds-supportedencryptiontypes": return .encryptionTypes
        case "pwdproperties": return .passwordProperties
        case "domainfunctionality", "forestfunctionality", "domaincontrollerfunctionality", "msds-behavior-version":
            return .functionalLevel
        case "gplink": return .gpLink
        default: break
        }
        if imageAttributes.contains(name) || imageType(value) != nil { return imageType(value) != nil ? .image : .binary }
        if certificateAttributes.contains(name) { return .certificate }
        if isBinary(value) { return .binary }
        if dnAttributes.contains(name) { return .distinguishedName }
        let text = String(decoding: value, as: UTF8.self)
        if dnWithBinary(text) != nil { return .distinguishedName }
        if DN.looksLikeDN(text) { return .distinguishedName }
        if text.count >= 15, text.hasSuffix("Z"), text.prefix(14).allSatisfy(\.isNumber),
           ADValues.generalizedTime(text) != nil { return .generalizedTime }
        return .text
    }

    public static func format(_ attribute: String, _ value: Data, now: Date = Date()) -> FormattedValue {
        let name = attribute.lowercased()
        let kind = kind(of: attribute, value: value)
        let text = String(decoding: value, as: UTF8.self)
        switch kind {
        case .sid:
            let sid = ADValues.sidString(value) ?? hex(value)
            let known = ADValues.wellKnownName(sid)
            return FormattedValue(text: known.map { "\(sid)  (\($0))" } ?? sid, kind: .sid)
        case .guid:
            return FormattedValue(text: ADValues.guidString(value) ?? hex(value), kind: .guid)
        case .fileTime:
            guard let raw = Int64(text.trimmingCharacters(in: .whitespaces)) else { return plain(text) }
            return FormattedValue(text: describeFileTime(name, raw, now: now), detail: text, kind: .fileTime)
        case .interval:
            guard let raw = Int64(text), let seconds = ADValues.interval(raw) else {
                return FormattedValue(text: "Never", detail: text, kind: .interval)
            }
            return FormattedValue(text: duration(seconds), detail: text, kind: .interval)
        case .generalizedTime:
            guard let date = ADValues.generalizedTime(text) else { return plain(text) }
            return FormattedValue(text: dateText(date, now: now), detail: text, kind: .generalizedTime)
        case .userAccountControl:
            return flagValue(text, table: ADValues.userAccountControlFlags, kind: .userAccountControl)
        case .encryptionTypes:
            return flagValue(text, table: ADValues.supportedEncryptionTypeFlags, kind: .encryptionTypes)
        case .passwordProperties:
            return flagValue(text, table: ADValues.passwordPropertyFlags, kind: .passwordProperties)
        case .groupType:
            guard let raw = Int64(text) else { return plain(text) }
            return FormattedValue(text: ADValues.groupTypeDescription(raw), detail: text, kind: .groupType)
        case .samAccountType:
            guard let raw = Int64(text), let label = ADValues.samAccountTypeDescription(raw) else { return plain(text) }
            return FormattedValue(text: label, detail: text, kind: .samAccountType)
        case .functionalLevel:
            guard let raw = Int(text) else { return plain(text) }
            return FormattedValue(text: ADValues.functionalLevelName(raw), detail: text, kind: .functionalLevel)
        case .gpLink:
            let links = gpLinks(text)
            let summary = links.map { "\(DN.rdnValue($0.dn))\($0.options)" }.joined(separator: ", ")
            return FormattedValue(text: summary.isEmpty ? text : summary, detail: text, kind: .gpLink,
                                  links: links.map(\.dn))
        case .image:
            return FormattedValue(text: "\(imageType(value) ?? "Image"), \(byteCount(value.count))", kind: .image)
        case .certificate:
            return FormattedValue(text: certificateSummary(value), detail: hex(value, limit: 32), kind: .certificate)
        case .binary:
            return FormattedValue(text: "\(byteCount(value.count)): \(hex(value, limit: 24))", kind: .binary)
        case .distinguishedName:
            if let (_, dn) = dnWithBinary(text) {
                return FormattedValue(text: dn, detail: text, kind: .distinguishedName, links: [dn])
            }
            return FormattedValue(text: text, kind: .distinguishedName, links: [text])
        case .text:
            return plain(text)
        }
    }

    // MARK: Pieces

    static func plain(_ text: String) -> FormattedValue {
        FormattedValue(text: text, kind: .text)
    }

    static func describeFileTime(_ attribute: String, _ raw: Int64, now: Date) -> String {
        switch ADValues.fileTime(raw) {
        case .date(let date):
            return dateText(date, now: now)
        case .never:
            return attribute.hasPrefix("msds-userpasswordexpiry") ? "Never expires" : "Never"
        case .zero:
            switch attribute {
            case "pwdlastset": return "Must change at next sign-in"
            case "lastlogon", "lastlogontimestamp", "badpasswordtime", "lastlogoff": return "Never"
            case "accountexpires": return "Never"
            case "lockouttime": return "Not locked out"
            case "msds-userpasswordexpirytimecomputed": return "Expired (must change)"
            default: return "Not set"
            }
        }
    }

    static func flagValue(_ text: String, table: [ADValues.Flag], kind: AttributeKind) -> FormattedValue {
        guard let raw = Int64(text) else { return plain(text) }
        let flags = ADValues.flags(raw, in: table).map(\.label)
        var parts = flags
        let unknown = ADValues.unknownBits(raw, in: table)
        if unknown != 0 { parts.append(String(format: "0x%llx", unknown)) }
        return FormattedValue(text: parts.isEmpty ? "None" : parts.joined(separator: ", "),
                              detail: "\(raw) (0x\(String(raw, radix: 16)))", kind: kind)
    }

    public struct GPLink: Hashable, Sendable {
        public var dn: String
        /// "", " (disabled)", " (enforced)" or both.
        public var options: String
    }

    /// `[LDAP://cn={GUID},cn=policies,…;0][…]` → the linked GPO DNs and their options.
    public static func gpLinks(_ text: String) -> [GPLink] {
        text.components(separatedBy: "[").compactMap { piece -> GPLink? in
            let body = piece.replacingOccurrences(of: "]", with: "")
            guard let separator = body.lastIndex(of: ";") else { return nil }
            var target = String(body[..<separator])
            if target.lowercased().hasPrefix("ldap://") { target = String(target.dropFirst(7)) }
            guard !target.isEmpty else { return nil }
            let flags = Int(body[body.index(after: separator)...]) ?? 0
            var options = ""
            if flags & 1 != 0 { options += " (disabled)" }
            if flags & 2 != 0 { options += " (enforced)" }
            return GPLink(dn: target, options: options)
        }
    }

    /// AD's DN-with-binary syntax, `B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=…`.
    static func dnWithBinary(_ text: String) -> (binary: String, dn: String)? {
        guard text.hasPrefix("B:") else { return nil }
        let parts = text.split(separator: ":", maxSplits: 3, omittingEmptySubsequences: false)
        guard parts.count == 4, Int(parts[1]) != nil else { return nil }
        return (String(parts[2]), String(parts[3]))
    }

    public static func isBinary(_ value: Data) -> Bool {
        guard let text = String(data: value, encoding: .utf8) else { return true }
        return text.unicodeScalars.contains { $0.value < 0x20 && $0 != "\t" && $0 != "\n" && $0 != "\r" }
    }

    public static func imageType(_ value: Data) -> String? {
        let b = [UInt8](value.prefix(8))
        if b.starts(with: [0xFF, 0xD8, 0xFF]) { return "JPEG" }
        if b.starts(with: [0x89, 0x50, 0x4E, 0x47]) { return "PNG" }
        if b.starts(with: [0x47, 0x49, 0x46, 0x38]) { return "GIF" }
        if b.starts(with: [0x42, 0x4D]), value.count > 54 {
            // "BM" also starts ordinary text ("BMC Software…"): a real BMP header
            // carries the file's size and two reserved zero words after it.
            let bytes = [UInt8](value.prefix(10))
            let size = Int(bytes[2]) | Int(bytes[3]) << 8 | Int(bytes[4]) << 16 | Int(bytes[5]) << 24
            if size == value.count, bytes[6...9].allSatisfy({ $0 == 0 }) { return "BMP" }
        }
        return nil
    }

    public static func certificateSummary(_ value: Data) -> String {
        guard let certificate = SecCertificateCreateWithData(nil, value as CFData),
              let subject = SecCertificateCopySubjectSummary(certificate) as String? else {
            return "Certificate, \(byteCount(value.count))"
        }
        return "Certificate: \(subject)"
    }

    public static func hex(_ value: Data, limit: Int = .max) -> String {
        let shown = value.prefix(limit).map { String(format: "%02x", $0) }.joined(separator: " ")
        return value.count > limit ? shown + " …" : shown
    }

    public static func byteCount(_ count: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(count), countStyle: .file)
    }

    public static func duration(_ seconds: TimeInterval) -> String {
        if seconds == 0 { return "None" }
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = [.day, .hour, .minute, .second]
        formatter.unitsStyle = .full
        formatter.maximumUnitCount = 2
        return formatter.string(from: seconds) ?? "\(Int(seconds)) seconds"
    }

    public static func dateText(_ date: Date, now: Date = Date()) -> String {
        let absolute = date.formatted(date: .abbreviated, time: .shortened)
        // Within a minute either way reads "just now", not "in 0 seconds" for a
        // server clock a moment ahead.
        if abs(date.timeIntervalSince(now)) < 60 { return "\(absolute) (just now)" }
        let relative = RelativeDateTimeFormatter()
        relative.unitsStyle = .full
        return "\(absolute) (\(relative.localizedString(for: date, relativeTo: now)))"
    }
}
