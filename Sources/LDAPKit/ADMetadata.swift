// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// AD's per-attribute replication metadata (msDS-ReplAttributeMetaData), which
/// says when each attribute last changed, on which DC, and how often.
public struct ReplicationMetadata: Sendable, Hashable, Identifiable {
    public var attribute: String
    public var version: Int
    public var lastOriginatingChange: Date?
    public var originatingDSA: String
    public var originatingInvocationID: String
    public var originatingUSN: Int64
    public var localUSN: Int64

    public var id: String { attribute }

    /// The DC that made the change: `CN=NTDS Settings,CN=DC01,CN=Servers,…` → `DC01`.
    public var originatingServer: String {
        let parts = DN.components(originatingDSA)
        return parts.count > 1 ? DN.rdnValue(parts[1]) : originatingDSA
    }

    public static func parse(_ values: [String]) -> [ReplicationMetadata] {
        values.compactMap { value in
            let fields = SimpleXML.fields(value)
            guard let name = fields["pszAttributeName"] else { return nil }
            return ReplicationMetadata(
                attribute: name,
                version: Int(fields["dwVersion"] ?? "") ?? 0,
                lastOriginatingChange: fields["ftimeLastOriginatingChange"].flatMap(ISO8601DateFormatter().date(from:)),
                originatingDSA: fields["pszLastOriginatingDsaDN"] ?? "",
                originatingInvocationID: fields["uuidLastOriginatingDsaInvocationID"] ?? "",
                originatingUSN: Int64(fields["usnOriginatingChange"] ?? "") ?? 0,
                localUSN: Int64(fields["usnLocalChange"] ?? "") ?? 0)
        }
        .sorted { ($0.lastOriginatingChange ?? .distantPast) > ($1.lastOriginatingChange ?? .distantPast) }
    }
}

/// Metadata of linked values (msDS-ReplValueMetaData): when each member was
/// added to a group, or removed.
public struct ValueReplicationMetadata: Sendable, Hashable, Identifiable {
    public var attribute: String
    public var value: String
    public var created: Date?
    public var deleted: Date?
    public var lastOriginatingChange: Date?
    public var version: Int
    public var originatingDSA: String

    public var id: String { attribute + "|" + value }
    public var isDeleted: Bool { deleted.map { $0 > Date(timeIntervalSince1970: 0) } ?? false }

    public static func parse(_ values: [String]) -> [ValueReplicationMetadata] {
        let iso = ISO8601DateFormatter()
        return values.compactMap { value in
            let fields = SimpleXML.fields(value)
            guard let attribute = fields["pszAttributeName"], let object = fields["pszObjectDn"] else { return nil }
            return ValueReplicationMetadata(
                attribute: attribute, value: object,
                created: fields["ftimeCreated"].flatMap(iso.date(from:)),
                deleted: fields["ftimeDeleted"].flatMap(iso.date(from:)),
                lastOriginatingChange: fields["ftimeLastOriginatingChange"].flatMap(iso.date(from:)),
                version: Int(fields["dwVersion"] ?? "") ?? 0,
                originatingDSA: fields["pszLastOriginatingDsaDN"] ?? "")
        }
    }
}

/// The flat XML AD uses for metadata: one element per field, no nesting that
/// matters, terminated by a NUL. Parsed with XMLParser for correct entity handling.
enum SimpleXML {
    static func fields(_ text: String) -> [String: String] {
        let cleaned = text.replacingOccurrences(of: "\0", with: "")
        guard let data = cleaned.data(using: .utf8) else { return [:] }
        let delegate = Collector()
        let parser = XMLParser(data: data)
        parser.delegate = delegate
        parser.parse()
        return delegate.fields
    }

    private final class Collector: NSObject, XMLParserDelegate {
        var fields: [String: String] = [:]
        private var current = ""
        private var text = ""

        func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?,
                    attributes: [String: String] = [:]) {
            current = name
            text = ""
        }

        func parser(_ parser: XMLParser, foundCharacters string: String) { text += string }

        func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
            if name == current { fields[name] = text.trimmingCharacters(in: .whitespacesAndNewlines) }
            current = ""
        }
    }
}

/// An LDAP URL (RFC 4516), as dynamic groups store their member query:
/// `ldap:///ou=people,dc=example,dc=org??sub?(objectClass=person)`.
public struct LDAPURL: Sendable, Hashable {
    public var host: String?
    public var port: Int?
    public var dn: String
    public var attributes: [String]
    public var scope: LDAPScope
    public var filter: String

    public init?(_ string: String) {
        let trimmed = string.trimmingCharacters(in: .whitespaces)
        let lower = trimmed.lowercased()
        let scheme = ["ldap://", "ldaps://", "ldapi://"].first { lower.hasPrefix($0) }
        guard let scheme else { return nil }
        let rest = trimmed.dropFirst(scheme.count)
        let slash = rest.firstIndex(of: "/") ?? rest.endIndex
        let hostPort = rest[..<slash]
        if !hostPort.isEmpty {
            let pieces = hostPort.split(separator: ":", maxSplits: 1)
            host = pieces.first.map { String($0).removingPercentEncoding ?? String($0) }
            port = pieces.count > 1 ? Int(pieces[1]) : nil
        }
        let path = slash < rest.endIndex ? rest[rest.index(after: slash)...] : ""
        let parts = path.split(separator: "?", maxSplits: 4, omittingEmptySubsequences: false).map {
            String($0).removingPercentEncoding ?? String($0)
        }
        dn = parts.first ?? ""
        attributes = parts.count > 1 ? parts[1].split(separator: ",").map(String.init) : []
        switch parts.count > 2 ? parts[2].lowercased() : "" {
        case "base": scope = .base
        case "one": scope = .oneLevel
        case "sub": scope = .subtree
        default: scope = .base // RFC 4516's default
        }
        let filterText = parts.count > 3 ? parts[3] : ""
        filter = filterText.isEmpty ? "(objectClass=*)" : filterText
    }
}

extension ADValues {
    /// trustDirection on a trustedDomain object.
    public static func trustDirection(_ value: Int64) -> String {
        switch value {
        case 0: return "Disabled"
        case 1: return "Inbound"
        case 2: return "Outbound"
        case 3: return "Two-way"
        default: return "Direction \(value)"
        }
    }

    /// trustType on a trustedDomain object.
    public static func trustType(_ value: Int64) -> String {
        switch value {
        case 1: return "Windows NT (downlevel)"
        case 2: return "Active Directory"
        case 3: return "Kerberos realm (MIT)"
        case 4: return "DCE"
        case 5: return "Entra ID"
        default: return "Type \(value)"
        }
    }

    public static let trustAttributeFlags: [Flag] = [
        Flag(bit: 0x1, name: "NON_TRANSITIVE", label: "Non-transitive", notable: false),
        Flag(bit: 0x2, name: "UPLEVEL_ONLY", label: "Windows 2000 and later only", notable: false),
        Flag(bit: 0x4, name: "QUARANTINED_DOMAIN", label: "SID filtering (quarantined)", notable: false),
        Flag(bit: 0x8, name: "FOREST_TRANSITIVE", label: "Forest trust", notable: false),
        Flag(bit: 0x10, name: "CROSS_ORGANIZATION", label: "Selective authentication", notable: false),
        Flag(bit: 0x20, name: "WITHIN_FOREST", label: "Within the forest", notable: false),
        Flag(bit: 0x40, name: "TREAT_AS_EXTERNAL", label: "Treated as external", notable: true),
        Flag(bit: 0x80, name: "USES_RC4_ENCRYPTION", label: "RC4 encryption", notable: true),
        Flag(bit: 0x200, name: "CROSS_ORGANIZATION_NO_TGT_DELEGATION", label: "No TGT delegation", notable: false),
        Flag(bit: 0x400, name: "PIM_TRUST", label: "PIM trust", notable: false),
    ]

    /// pwdProperties on the domain object.
    public static let passwordPropertyFlags: [Flag] = [
        Flag(bit: 0x1, name: "DOMAIN_PASSWORD_COMPLEX", label: "Complexity required", notable: false),
        Flag(bit: 0x2, name: "DOMAIN_PASSWORD_NO_ANON_CHANGE", label: "No anonymous change", notable: false),
        Flag(bit: 0x4, name: "DOMAIN_PASSWORD_NO_CLEAR_CHANGE", label: "No clear-text change", notable: false),
        Flag(bit: 0x8, name: "DOMAIN_LOCKOUT_ADMINS", label: "Administrators can be locked out", notable: false),
        Flag(bit: 0x10, name: "DOMAIN_PASSWORD_STORE_CLEARTEXT", label: "Reversible encryption", notable: true),
        Flag(bit: 0x20, name: "DOMAIN_REFUSE_PASSWORD_CHANGE", label: "Machine password changes refused", notable: true),
    ]
}
