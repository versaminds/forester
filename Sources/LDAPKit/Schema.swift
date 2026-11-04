// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// The server's schema (RFC 4512 §4.1), read from its subschema subentry:
/// attribute types, object classes and syntaxes. It is what makes editing
/// schema-aware: which attributes an entry may have, which must be present,
/// which hold one value, and which are binary.
public struct LDAPSchema: Sendable {
    public struct AttributeType: Sendable, Hashable {
        public var oid: String
        public var names: [String]
        public var description: String?
        public var superior: String?
        public var equality: String?
        public var ordering: String?
        public var substring: String?
        public var syntax: String?
        public var syntaxLength: Int?
        public var singleValue = false
        public var collective = false
        public var noUserModification = false
        public var usage = "userApplications"
        public var obsolete = false

        public var name: String { names.first ?? oid }
        public var isOperational: Bool { usage != "userApplications" }
    }

    public struct ObjectClass: Sendable, Hashable {
        public enum Kind: String, Sendable { case abstract = "ABSTRACT", structural = "STRUCTURAL", auxiliary = "AUXILIARY" }

        public var oid: String
        public var names: [String]
        public var description: String?
        public var superiors: [String] = []
        public var kind: Kind = .structural
        public var must: [String] = []
        public var may: [String] = []
        public var obsolete = false

        public var name: String { names.first ?? oid }
    }

    public struct Syntax: Sendable, Hashable {
        public var oid: String
        public var description: String?
    }

    public private(set) var attributeTypes: [AttributeType] = []
    public private(set) var objectClasses: [ObjectClass] = []
    public private(set) var syntaxes: [Syntax] = []
    /// Definitions that could not be parsed, kept so a schema browser can say so.
    public private(set) var unparsed: [String] = []

    private var attributeIndex: [String: Int] = [:]
    private var classIndex: [String: Int] = [:]
    private var syntaxIndex: [String: Int] = [:]

    public init(subschema: LDAPEntry) {
        for definition in subschema.strings("attributeTypes") {
            if let parsed = SchemaDefinition(definition), let type = parsed.attributeType { add(type) } else { unparsed.append(definition) }
        }
        for definition in subschema.strings("objectClasses") {
            if let parsed = SchemaDefinition(definition), let objectClass = parsed.objectClass { add(objectClass) } else { unparsed.append(definition) }
        }
        for definition in subschema.strings("ldapSyntaxes") {
            if let parsed = SchemaDefinition(definition) {
                syntaxIndex[parsed.oid.lowercased()] = syntaxes.count
                syntaxes.append(Syntax(oid: parsed.oid, description: parsed.strings["DESC"]?.first))
            }
        }
        attributeNames = attributeTypes.filter { !$0.obsolete }
            .map { (operational: $0.isOperational, key: $0.name.lowercased(), name: $0.name) }
            .sorted { ($0.operational ? 1 : 0, $0.key) < ($1.operational ? 1 : 0, $1.key) }
            .map(\.name)
        classNames = objectClasses.map(\.name).sorted()
    }

    public var isEmpty: Bool { attributeTypes.isEmpty && objectClasses.isEmpty }

    private mutating func add(_ type: AttributeType) {
        let index = attributeTypes.count
        attributeTypes.append(type)
        attributeIndex[type.oid.lowercased()] = index
        for name in type.names { attributeIndex[name.lowercased()] = index }
    }

    private mutating func add(_ objectClass: ObjectClass) {
        let index = objectClasses.count
        objectClasses.append(objectClass)
        classIndex[objectClass.oid.lowercased()] = index
        for name in objectClass.names { classIndex[name.lowercased()] = index }
    }

    // MARK: Lookup

    /// The attribute type for a description, options (`;binary`, `;range=…`) ignored.
    public func attributeType(_ name: String) -> AttributeType? {
        let base = name.split(separator: ";").first.map(String.init) ?? name
        return attributeIndex[base.lowercased()].map { attributeTypes[$0] }
    }

    public func objectClass(_ name: String) -> ObjectClass? {
        classIndex[name.lowercased()].map { objectClasses[$0] }
    }

    /// The syntax OID, inherited from the superior type when not stated.
    public func syntax(of attribute: String) -> String? {
        var current = attributeType(attribute)
        var seen: Set<String> = []
        while let type = current, seen.insert(type.oid).inserted {
            if let syntax = type.syntax { return syntax }
            current = type.superior.flatMap { attributeType($0) }
        }
        return nil
    }

    public func syntaxDescription(_ oid: String) -> String? {
        if let index = syntaxIndex[oid.lowercased()], let description = syntaxes[index].description { return description }
        return KnownSyntax(rawValue: oid)?.description
    }

    public func isSingleValued(_ attribute: String) -> Bool {
        attributeType(attribute)?.singleValue ?? false
    }

    /// The canonical spelling of an attribute name, as the schema defines it.
    public func canonicalName(_ attribute: String) -> String {
        attributeType(attribute)?.name ?? attribute
    }

    /// The class and every class it inherits from, nearest first.
    public func superclassChain(_ name: String) -> [ObjectClass] {
        var chain: [ObjectClass] = []
        var queue = [name]
        var seen: Set<String> = []
        while !queue.isEmpty {
            let next = queue.removeFirst()
            guard let objectClass = objectClass(next), seen.insert(objectClass.oid).inserted else { continue }
            chain.append(objectClass)
            queue += objectClass.superiors
        }
        return chain
    }

    /// What entries with these object classes must and may hold, with every
    /// superclass's attributes included. Names are the schema's spelling.
    public func allowedAttributes(for classes: [String]) -> (must: [String], may: [String]) {
        var must: [String] = [], may: [String] = []
        var seenMust: Set<String> = [], seenMay: Set<String> = []
        for objectClass in classes.flatMap(superclassChain) {
            for name in objectClass.must {
                let canonical = canonicalName(name)
                if seenMust.insert(canonical.lowercased()).inserted { must.append(canonical) }
            }
            for name in objectClass.may {
                let canonical = canonicalName(name)
                if seenMay.insert(canonical.lowercased()).inserted { may.append(canonical) }
            }
        }
        may.removeAll { seenMust.contains($0.lowercased()) }
        return (must, may)
    }

    public var structuralClasses: [ObjectClass] { objectClasses.filter { $0.kind == .structural && !$0.obsolete } }
    public var auxiliaryClasses: [ObjectClass] { objectClasses.filter { $0.kind == .auxiliary && !$0.obsolete } }

    /// Every attribute name, user attributes first, for pickers and completion.
    /// Sorted once: views ask for it every time they are drawn, and AD's
    /// schema has some 1,500 attributes.
    public private(set) var attributeNames: [String] = []
    /// Every object class name, sorted.
    public private(set) var classNames: [String] = []

    /// Classes that use an attribute, for the schema browser.
    public func classes(using attribute: String) -> [ObjectClass] {
        let key = canonicalName(attribute).lowercased()
        return objectClasses.filter { objectClass in
            (objectClass.must + objectClass.may).contains { canonicalName($0).lowercased() == key }
        }
    }
}

/// The handful of syntaxes the app treats specially (RFC 4517 and AD).
public enum KnownSyntax: String, Sendable {
    case boolean = "1.3.6.1.4.1.1466.115.121.1.7"
    case dn = "1.3.6.1.4.1.1466.115.121.1.12"
    case directoryString = "1.3.6.1.4.1.1466.115.121.1.15"
    case generalizedTime = "1.3.6.1.4.1.1466.115.121.1.24"
    case ia5String = "1.3.6.1.4.1.1466.115.121.1.26"
    case integer = "1.3.6.1.4.1.1466.115.121.1.27"
    case jpeg = "1.3.6.1.4.1.1466.115.121.1.28"
    case octetString = "1.3.6.1.4.1.1466.115.121.1.40"
    case oid = "1.3.6.1.4.1.1466.115.121.1.38"
    case telephone = "1.3.6.1.4.1.1466.115.121.1.50"
    case binary = "1.3.6.1.4.1.1466.115.121.1.5"
    case certificate = "1.3.6.1.4.1.1466.115.121.1.8"
    case printableString = "1.3.6.1.4.1.1466.115.121.1.44"
    case numericString = "1.3.6.1.4.1.1466.115.121.1.36"
    case utcTime = "1.3.6.1.4.1.1466.115.121.1.53"
    case adLargeInteger = "1.2.840.113556.1.4.906"
    case adSecurityDescriptor = "1.2.840.113556.1.4.907"
    case adDNWithBinary = "1.2.840.113556.1.4.903"

    public var description: String {
        switch self {
        case .boolean: return "Boolean"
        case .dn: return "Distinguished name"
        case .directoryString: return "Directory string"
        case .generalizedTime: return "Generalized time"
        case .ia5String: return "IA5 string"
        case .integer: return "Integer"
        case .jpeg: return "JPEG"
        case .octetString: return "Octet string"
        case .oid: return "OID"
        case .telephone: return "Telephone number"
        case .binary: return "Binary"
        case .certificate: return "Certificate"
        case .printableString: return "Printable string"
        case .numericString: return "Numeric string"
        case .utcTime: return "UTC time"
        case .adLargeInteger: return "Large integer (AD)"
        case .adSecurityDescriptor: return "Security descriptor (AD)"
        case .adDNWithBinary: return "DN with binary (AD)"
        }
    }

    /// Values of this syntax are bytes, not text.
    public var isBinary: Bool {
        switch self {
        case .jpeg, .octetString, .binary, .certificate, .adSecurityDescriptor: return true
        default: return false
        }
    }
}

/// One parsed definition: `( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )`.
/// Keywords map to their values; flag keywords (SINGLE-VALUE) map to [].
struct SchemaDefinition {
    var oid: String
    var strings: [String: [String]] = [:]

    init?(_ text: String) {
        var tokens = SchemaTokenizer(text).tokens[...]
        guard tokens.first == .open else { return nil }
        tokens.removeFirst()
        // Some servers quote the numeric OID; accept both.
        guard case let first? = tokens.first, let oid = first.word ?? first.quoted else { return nil }
        tokens.removeFirst()
        self.oid = oid
        while let token = tokens.first, token != .close {
            tokens.removeFirst()
            guard let keyword = token.word else { continue }
            var values: [String] = []
            switch tokens.first {
            case .quoted(let value)?:
                tokens.removeFirst()
                values = [value]
            case .open?:
                tokens.removeFirst()
                while let inner = tokens.first, inner != .close {
                    tokens.removeFirst()
                    if let value = inner.word ?? inner.quoted, value != "$" { values.append(value) }
                }
                if tokens.first == .close { tokens.removeFirst() }
            // Whether a keyword takes a value is decided by the keyword, never by
            // the value: in `SUP name`, `name` is a value although NAME is a keyword.
            case .word(let value)? where !Self.flagKeywords.contains(keyword.uppercased()):
                tokens.removeFirst()
                values = [value]
            default:
                break
            }
            strings[keyword.uppercased(), default: []] += values
        }
    }

    static let flagKeywords: Set<String> = ["SINGLE-VALUE", "COLLECTIVE", "NO-USER-MODIFICATION", "OBSOLETE",
                                            "ABSTRACT", "STRUCTURAL", "AUXILIARY"]

    var attributeType: LDAPSchema.AttributeType? {
        var type = LDAPSchema.AttributeType(oid: oid, names: strings["NAME"] ?? [])
        type.description = strings["DESC"]?.first
        type.superior = strings["SUP"]?.first
        type.equality = strings["EQUALITY"]?.first
        type.ordering = strings["ORDERING"]?.first
        type.substring = strings["SUBSTR"]?.first
        if var syntax = strings["SYNTAX"]?.first {
            if let brace = syntax.firstIndex(of: "{") {
                type.syntaxLength = Int(syntax[syntax.index(after: brace)...].dropLast())
                syntax = String(syntax[..<brace])
            }
            type.syntax = syntax
        }
        type.singleValue = strings["SINGLE-VALUE"] != nil
        type.collective = strings["COLLECTIVE"] != nil
        type.noUserModification = strings["NO-USER-MODIFICATION"] != nil
        type.usage = strings["USAGE"]?.first ?? "userApplications"
        type.obsolete = strings["OBSOLETE"] != nil
        return type
    }

    var objectClass: LDAPSchema.ObjectClass? {
        var objectClass = LDAPSchema.ObjectClass(oid: oid, names: strings["NAME"] ?? [])
        objectClass.description = strings["DESC"]?.first
        objectClass.superiors = strings["SUP"] ?? []
        if strings["ABSTRACT"] != nil { objectClass.kind = .abstract }
        else if strings["AUXILIARY"] != nil { objectClass.kind = .auxiliary }
        objectClass.must = strings["MUST"] ?? []
        objectClass.may = strings["MAY"] ?? []
        objectClass.obsolete = strings["OBSOLETE"] != nil
        return objectClass
    }
}

enum SchemaToken: Equatable {
    case open, close
    case word(String)
    case quoted(String)

    var word: String? { if case .word(let w) = self { return w } else { return nil } }
    var quoted: String? { if case .quoted(let q) = self { return q } else { return nil } }
}

struct SchemaTokenizer {
    var tokens: [SchemaToken] = []

    init(_ text: String) {
        let chars = Array(text)
        var i = 0
        while i < chars.count {
            let c = chars[i]
            if c.isWhitespace { i += 1; continue }
            if c == "(" { tokens.append(.open); i += 1; continue }
            if c == ")" { tokens.append(.close); i += 1; continue }
            if c == "'" {
                var value = ""
                i += 1
                while i < chars.count, chars[i] != "'" {
                    // RFC 4512 escapes a quote as \27 and a backslash as \5C.
                    if chars[i] == "\\", i + 2 < chars.count, let byte = UInt8(String(chars[(i + 1)...(i + 2)]), radix: 16) {
                        value.append(Character(UnicodeScalar(byte)))
                        i += 3
                    } else {
                        value.append(chars[i])
                        i += 1
                    }
                }
                i += 1
                tokens.append(.quoted(value))
                continue
            }
            var word = ""
            while i < chars.count, !chars[i].isWhitespace, chars[i] != "(", chars[i] != ")", chars[i] != "'" {
                word.append(chars[i])
                i += 1
            }
            tokens.append(.word(word))
        }
    }
}

extension LDAPConnection {
    /// Reads the schema the root DSE points at. Returns nil when the server
    /// does not publish one, or does not let this connection read it.
    public func schema(rootDSE: LDAPEntry) async throws -> LDAPSchema? {
        let location = rootDSE.string("subschemaSubentry") ?? "cn=Subschema"
        let request = LDAPSearchRequest(base: location, scope: .base, filter: .equality("objectClass", "subschema"),
                                        attributes: ["attributeTypes", "objectClasses", "ldapSyntaxes"])
        do {
            guard let found = try await search(request).entries.first else { return nil }
            // A large AD forest (Exchange adds thousands) can send these in ranges.
            let entry = try await completingRangedAttributes(found)
            let schema = LDAPSchema(subschema: entry)
            return schema.isEmpty ? nil : schema
        } catch let error as LDAPError where error.resultCode == .noSuchObject || error.resultCode == .insufficientAccessRights {
            return nil
        }
    }
}
