// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

public enum LDAPScope: Int, Sendable, CaseIterable, Codable {
    case base = 0
    case oneLevel = 1
    case subtree = 2

    public var label: String {
        switch self {
        case .base: return "Base object"
        case .oneLevel: return "One level"
        case .subtree: return "Subtree"
        }
    }
}

public enum LDAPDerefAliases: Int, Sendable {
    case never = 0, inSearching = 1, findingBaseObject = 2, always = 3
}

public struct LDAPControl: Equatable, Sendable {
    public var oid: String
    public var critical: Bool
    public var value: [UInt8]?

    public init(oid: String, critical: Bool = false, value: [UInt8]? = nil) {
        self.oid = oid
        self.critical = critical
        self.value = value
    }

    var encoded: [UInt8] {
        var parts = [BER.octetString(oid)]
        if critical { parts.append(BER.boolean(true)) }
        if let value { parts.append(BER.octetString(value)) }
        return BER.sequence(parts)
    }

    // MARK: Simple paged results (RFC 2696)

    public static let pagedResultsOID = "1.2.840.113556.1.4.319"

    public static func pagedResults(size: Int, cookie: [UInt8]) -> LDAPControl {
        LDAPControl(oid: pagedResultsOID, critical: false,
                    value: BER.sequence([BER.integer(size), BER.octetString(cookie)]))
    }

    /// The server's cookie from a paged-results response control; empty when
    /// there are no more pages.
    public var pagedResultsCookie: [UInt8]? {
        guard oid == Self.pagedResultsOID, let value,
              let (outer, _) = try? BERDecoder.element(in: value),
              let parts = try? outer.children(), parts.count >= 2 else { return nil }
        return parts[1].content
    }
}

/// An LDAP result code (RFC 4511 §4.1.9), with the names admins recognise.
public struct LDAPResultCode: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public var rawValue: Int
    public init(rawValue: Int) { self.rawValue = rawValue }

    public static let success = Self(rawValue: 0)
    public static let operationsError = Self(rawValue: 1)
    public static let protocolError = Self(rawValue: 2)
    public static let timeLimitExceeded = Self(rawValue: 3)
    public static let sizeLimitExceeded = Self(rawValue: 4)
    public static let authMethodNotSupported = Self(rawValue: 7)
    public static let strongerAuthRequired = Self(rawValue: 8)
    public static let referral = Self(rawValue: 10)
    public static let adminLimitExceeded = Self(rawValue: 11)
    public static let unavailableCriticalExtension = Self(rawValue: 12)
    public static let confidentialityRequired = Self(rawValue: 13)
    public static let saslBindInProgress = Self(rawValue: 14)
    public static let noSuchAttribute = Self(rawValue: 16)
    public static let undefinedAttributeType = Self(rawValue: 17)
    public static let inappropriateMatching = Self(rawValue: 18)
    public static let noSuchObject = Self(rawValue: 32)
    public static let invalidDNSyntax = Self(rawValue: 34)
    public static let inappropriateAuthentication = Self(rawValue: 48)
    public static let invalidCredentials = Self(rawValue: 49)
    public static let insufficientAccessRights = Self(rawValue: 50)
    public static let busy = Self(rawValue: 51)
    public static let unavailable = Self(rawValue: 52)
    public static let unwillingToPerform = Self(rawValue: 53)
    public static let other = Self(rawValue: 80)

    static let names: [Int: String] = [
        0: "Success", 1: "Operations error", 2: "Protocol error", 3: "Time limit exceeded",
        4: "Size limit exceeded", 5: "Compare false", 6: "Compare true",
        7: "Authentication method not supported", 8: "Stronger authentication required",
        10: "Referral", 11: "Administrative limit exceeded", 12: "Unavailable critical extension",
        13: "Confidentiality required", 14: "SASL bind in progress", 16: "No such attribute",
        17: "Undefined attribute type", 18: "Inappropriate matching", 19: "Constraint violation",
        20: "Attribute or value exists", 21: "Invalid attribute syntax", 32: "No such object",
        33: "Alias problem", 34: "Invalid DN syntax", 36: "Alias dereferencing problem",
        48: "Inappropriate authentication", 49: "Invalid credentials", 50: "Insufficient access rights",
        51: "Busy", 52: "Unavailable", 53: "Unwilling to perform", 54: "Loop detected",
        64: "Naming violation", 65: "Object class violation", 66: "Not allowed on non-leaf",
        67: "Not allowed on RDN", 68: "Entry already exists", 69: "Object class modifications prohibited",
        71: "Affects multiple DSAs", 80: "Other", 118: "Canceled", 119: "No such operation",
        120: "Too late", 121: "Cannot cancel",
    ]

    public var name: String { Self.names[rawValue] ?? "Result \(rawValue)" }
    public var description: String { "\(name) (\(rawValue))" }
}

public struct LDAPResult: Equatable, Sendable {
    public var code: LDAPResultCode
    public var matchedDN: String
    public var diagnosticMessage: String
    public var referrals: [String]

    public init(code: LDAPResultCode, matchedDN: String = "", diagnosticMessage: String = "", referrals: [String] = []) {
        self.code = code
        self.matchedDN = matchedDN
        self.diagnosticMessage = diagnosticMessage
        self.referrals = referrals
    }
}

public struct LDAPAttribute: Hashable, Sendable {
    /// The attribute description as the server returned it, options included
    /// (`member;range=0-1499`, `userCertificate;binary`).
    public var name: String
    public var values: [Data]

    public init(name: String, values: [Data]) {
        self.name = name
        self.values = values
    }

    /// The attribute type without options.
    public var baseName: String {
        name.split(separator: ";", maxSplits: 1).first.map(String.init) ?? name
    }

    public var stringValues: [String] { values.map { String(decoding: $0, as: UTF8.self) } }
}

public struct LDAPEntry: Hashable, Sendable, Identifiable {
    public var dn: String
    public var attributes: [LDAPAttribute]

    public init(dn: String, attributes: [LDAPAttribute]) {
        self.dn = dn
        self.attributes = attributes
    }

    public var id: String { dn }

    /// The attribute whose type matches `name`, ignoring case. Options are part of
    /// the match only when `name` carries them.
    public func attribute(_ name: String) -> LDAPAttribute? {
        if let exact = attributes.first(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) {
            return exact
        }
        guard !name.contains(";") else { return nil }
        return attributes.first(where: { $0.baseName.caseInsensitiveCompare(name) == .orderedSame })
    }

    public func values(_ name: String) -> [Data] { attribute(name)?.values ?? [] }
    public func strings(_ name: String) -> [String] { attribute(name)?.stringValues ?? [] }
    public func string(_ name: String) -> String? { strings(name).first }

    public func int(_ name: String) -> Int64? {
        string(name).flatMap { Int64($0.trimmingCharacters(in: .whitespaces)) }
    }

    public var objectClasses: [String] { strings("objectClass") }

    public func hasObjectClass(_ name: String) -> Bool {
        objectClasses.contains { $0.caseInsensitiveCompare(name) == .orderedSame }
    }
}

/// A response from the server, decoded from one LDAPMessage.
public struct LDAPResponse: Sendable {
    public enum Kind: Sendable {
        case bind(LDAPResult, serverSaslCredentials: [UInt8]?)
        case searchEntry(LDAPEntry)
        case searchReference([String])
        case searchDone(LDAPResult)
        case extended(LDAPResult, name: String?, value: [UInt8]?)
        case intermediate(name: String?, value: [UInt8]?)
        case other(tag: UInt8, LDAPResult?)

        /// Whether this response completes its operation. Search entries,
        /// references and intermediate responses are followed by more.
        public var isFinal: Bool {
            switch self {
            case .searchEntry, .searchReference, .intermediate: return false
            default: return true
            }
        }
    }

    public var messageID: Int
    public var kind: Kind
    public var controls: [LDAPControl]
}

/// Encodes requests and decodes responses (RFC 4511 §4).
public enum LDAPCodec {
    public static func message(id: Int, op: [UInt8], controls: [LDAPControl] = []) -> [UInt8] {
        var parts = [BER.integer(id), op]
        if !controls.isEmpty {
            parts.append(BER.sequence(controls.map(\.encoded), tag: 0xA0))
        }
        return BER.sequence(parts)
    }

    public static func simpleBind(dn: String, password: String) -> [UInt8] {
        BER.sequence([BER.integer(3), BER.octetString(dn), BER.octetString(password, tag: 0x80)], tag: 0x60)
    }

    public static let unbind: [UInt8] = BER.null(tag: 0x42)

    public static func abandon(_ id: Int) -> [UInt8] {
        BER.integer(id, tag: 0x50)
    }

    public static func search(base: String, scope: LDAPScope, deref: LDAPDerefAliases = .never,
                              sizeLimit: Int = 0, timeLimit: Int = 0, typesOnly: Bool = false,
                              filter: LDAPFilter, attributes: [String]) -> [UInt8] {
        BER.sequence([
            BER.octetString(base),
            BER.enumerated(scope.rawValue),
            BER.enumerated(deref.rawValue),
            BER.integer(sizeLimit),
            BER.integer(timeLimit),
            BER.boolean(typesOnly),
            filter.encoded,
            BER.sequence(attributes.map { BER.octetString($0) }),
        ], tag: 0x63)
    }

    public static func extended(oid: String, value: [UInt8]? = nil) -> [UInt8] {
        var parts = [BER.octetString(oid, tag: 0x80)]
        if let value { parts.append(BER.octetString(value, tag: 0x81)) }
        return BER.sequence(parts, tag: 0x77)
    }

    // MARK: Decoding

    public static func decodeResponse(_ element: BERElement) throws -> LDAPResponse {
        guard element.tag == 0x30 else { throw BERError.malformed("LDAPMessage is not a SEQUENCE") }
        let parts = try element.children()
        guard parts.count >= 2, parts[0].tag == 0x02 else { throw BERError.malformed("LDAPMessage without a message ID") }
        let id = try parts[0].int()
        let op = parts[1]
        var controls: [LDAPControl] = []
        if parts.count > 2, parts[2].tag == 0xA0 {
            controls = try parts[2].children().map(decodeControl)
        }
        return LDAPResponse(messageID: id, kind: try decodeOperation(op), controls: controls)
    }

    static func decodeControl(_ element: BERElement) throws -> LDAPControl {
        let parts = try element.children()
        guard let first = parts.first, first.tag == 0x04 else { throw BERError.malformed("control without a type") }
        var control = LDAPControl(oid: first.string)
        for part in parts.dropFirst() {
            switch part.tag {
            case 0x01: control.critical = part.boolean
            case 0x04: control.value = part.content
            default: break
            }
        }
        return control
    }

    static func decodeResult(_ parts: [BERElement]) throws -> LDAPResult {
        guard parts.count >= 3 else { throw BERError.malformed("LDAPResult has \(parts.count) components") }
        var result = LDAPResult(code: LDAPResultCode(rawValue: try parts[0].int()),
                                matchedDN: parts[1].string,
                                diagnosticMessage: parts[2].string)
        if parts.count > 3, parts[3].tag == 0xA3 {
            result.referrals = try parts[3].children().map(\.string)
        }
        return result
    }

    static func decodeOperation(_ op: BERElement) throws -> LDAPResponse.Kind {
        switch op.tag {
        case 0x61:
            let parts = try op.children()
            return .bind(try decodeResult(parts), serverSaslCredentials: parts.first { $0.tag == 0x87 }?.content)
        case 0x64:
            let parts = try op.children()
            guard parts.count >= 2 else { throw BERError.malformed("SearchResultEntry has \(parts.count) components") }
            let attributes = try parts[1].children().map { attribute -> LDAPAttribute in
                let pieces = try attribute.children()
                guard pieces.count >= 2 else { throw BERError.malformed("PartialAttribute has \(pieces.count) components") }
                return LDAPAttribute(name: pieces[0].string, values: try pieces[1].children().map(\.data))
            }
            return .searchEntry(LDAPEntry(dn: parts[0].string, attributes: attributes))
        case 0x65:
            return .searchDone(try decodeResult(try op.children()))
        case 0x73:
            return .searchReference(try op.children().map(\.string))
        case 0x78:
            let parts = try op.children()
            return .extended(try decodeResult(parts),
                             name: parts.first { $0.tag == 0x8A }?.string,
                             value: parts.first { $0.tag == 0x8B }?.content)
        case 0x79:
            let parts = try op.children()
            return .intermediate(name: parts.first { $0.tag == 0x80 }?.string,
                                 value: parts.first { $0.tag == 0x81 }?.content)
        default:
            let result = op.isConstructed ? try? decodeResult(try op.children()) : nil
            return .other(tag: op.tag, result)
        }
    }
}
