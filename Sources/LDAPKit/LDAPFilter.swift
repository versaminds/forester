// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// A search filter (RFC 4511 §4.5.1), parsed from and rendered to the RFC 4515
/// string form.
public indirect enum LDAPFilter: Equatable, Sendable, CustomStringConvertible {
    case and([LDAPFilter])
    case or([LDAPFilter])
    case not(LDAPFilter)
    case equality(String, [UInt8])
    case substrings(String, initial: [UInt8]?, any: [[UInt8]], final: [UInt8]?)
    case greaterOrEqual(String, [UInt8])
    case lessOrEqual(String, [UInt8])
    case present(String)
    case approx(String, [UInt8])
    case extensible(rule: String?, attribute: String?, value: [UInt8], dnAttributes: Bool)

    public static func equality(_ attribute: String, _ value: String) -> LDAPFilter {
        .equality(attribute, Array(value.utf8))
    }

    /// Parses an RFC 4515 filter. A filter typed without its outer parentheses
    /// (`cn=admin`) is accepted, because that is how people type them, and
    /// whitespace between components is ignored.
    public static func parse(_ text: String) throws -> LDAPFilter {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw LDAPFilterError(message: "The filter is empty", position: 0) }
        let source = trimmed.hasPrefix("(") ? trimmed : "(\(trimmed))"
        var parser = FilterParser(bytes: Array(source.utf8), offset: trimmed.hasPrefix("(") ? 0 : -1)
        let filter = try parser.parseFilter()
        parser.skipSpace()
        if parser.index < parser.bytes.count {
            throw parser.error("Unexpected text after the filter")
        }
        return filter
    }

    // MARK: Encoding

    public var encoded: [UInt8] {
        switch self {
        case .and(let fs): return BER.set(fs.map(\.encoded), tag: 0xA0)
        case .or(let fs): return BER.set(fs.map(\.encoded), tag: 0xA1)
        case .not(let f): return BER.tlv(0xA2, f.encoded)
        case .equality(let a, let v): return BER.sequence([BER.octetString(a), BER.octetString(v)], tag: 0xA3)
        case .substrings(let a, let initial, let any, let final):
            var parts: [[UInt8]] = []
            if let initial { parts.append(BER.octetString(initial, tag: 0x80)) }
            parts += any.map { BER.octetString($0, tag: 0x81) }
            if let final { parts.append(BER.octetString(final, tag: 0x82)) }
            return BER.sequence([BER.octetString(a), BER.sequence(parts)], tag: 0xA4)
        case .greaterOrEqual(let a, let v): return BER.sequence([BER.octetString(a), BER.octetString(v)], tag: 0xA5)
        case .lessOrEqual(let a, let v): return BER.sequence([BER.octetString(a), BER.octetString(v)], tag: 0xA6)
        case .present(let a): return BER.octetString(a, tag: 0x87)
        case .approx(let a, let v): return BER.sequence([BER.octetString(a), BER.octetString(v)], tag: 0xA8)
        case .extensible(let rule, let attribute, let value, let dn):
            var parts: [[UInt8]] = []
            if let rule { parts.append(BER.octetString(rule, tag: 0x81)) }
            if let attribute { parts.append(BER.octetString(attribute, tag: 0x82)) }
            parts.append(BER.octetString(value, tag: 0x83))
            if dn { parts.append(BER.boolean(true, tag: 0x84)) }
            return BER.sequence(parts, tag: 0xA9)
        }
    }

    // MARK: Rendering

    public var description: String {
        switch self {
        case .and(let fs): return "(&" + fs.map(\.description).joined() + ")"
        case .or(let fs): return "(|" + fs.map(\.description).joined() + ")"
        case .not(let f): return "(!" + f.description + ")"
        case .equality(let a, let v): return "(\(a)=\(Self.escape(v)))"
        case .substrings(let a, let initial, let any, let final):
            let middle = any.map { Self.escape($0) + "*" }.joined()
            return "(\(a)=\(initial.map(Self.escape) ?? "")*\(middle)\(final.map(Self.escape) ?? ""))"
        case .greaterOrEqual(let a, let v): return "(\(a)>=\(Self.escape(v)))"
        case .lessOrEqual(let a, let v): return "(\(a)<=\(Self.escape(v)))"
        case .present(let a): return "(\(a)=*)"
        case .approx(let a, let v): return "(\(a)~=\(Self.escape(v)))"
        case .extensible(let rule, let attribute, let value, let dn):
            var lhs = attribute ?? ""
            if dn { lhs += ":dn" }
            if let rule { lhs += ":\(rule)" }
            return "(\(lhs):=\(Self.escape(value)))"
        }
    }

    // MARK: Escaping

    /// Escapes a value for use inside a filter: `*`, `(`, `)`, `\` and NUL, plus
    /// anything that is not valid UTF-8 text (RFC 4515 §3).
    public static func escape(_ value: String) -> String {
        escape(Array(value.utf8))
    }

    public static func escape(_ bytes: [UInt8]) -> String {
        guard String(bytes: bytes, encoding: .utf8) != nil else { return escapeAll(bytes) }
        var out = ""
        for scalar in String(decoding: bytes, as: UTF8.self).unicodeScalars {
            switch scalar {
            case "*": out += "\\2a"
            case "(": out += "\\28"
            case ")": out += "\\29"
            case "\\": out += "\\5c"
            case "\0": out += "\\00"
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out
    }

    /// Escapes every byte, the form a binary value such as an objectSid needs.
    public static func escapeAll(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "\\%02x", $0) }.joined()
    }
}

public struct LDAPFilterError: Error, LocalizedError, Equatable {
    public var message: String
    /// Character offset in the text as typed.
    public var position: Int

    public var errorDescription: String? { "\(message) (at character \(position + 1))" }
}

private struct FilterParser {
    let bytes: [UInt8]
    /// Added to `index` when reporting positions, so an error points at the text
    /// the user typed rather than the parenthesised copy.
    let offset: Int
    var index = 0
    var depth = 0
    /// Deeper nesting is refused: parsing and encoding recurse, and a filter
    /// can come from directory data (a dynamic group's memberURL).
    static let maxDepth = 64

    init(bytes: [UInt8], offset: Int) {
        self.bytes = bytes
        self.offset = offset
    }

    func error(_ message: String, at position: Int? = nil) -> LDAPFilterError {
        LDAPFilterError(message: message, position: max(0, (position ?? index) + offset))
    }

    mutating func skipSpace() {
        while index < bytes.count, bytes[index] == 0x20 || bytes[index] == 0x0A || bytes[index] == 0x09 || bytes[index] == 0x0D {
            index += 1
        }
    }

    mutating func expect(_ char: UInt8, _ what: String) throws {
        guard index < bytes.count else { throw error("Expected \(what) but the filter ended") }
        guard bytes[index] == char else { throw error("Expected \(what)") }
        index += 1
    }

    mutating func parseFilter() throws -> LDAPFilter {
        depth += 1
        defer { depth -= 1 }
        guard depth <= Self.maxDepth else { throw error("The filter is nested more than \(Self.maxDepth) levels deep") }
        skipSpace()
        try expect(UInt8(ascii: "("), "'('")
        skipSpace()
        guard index < bytes.count else { throw error("Unexpected end of filter") }
        let filter: LDAPFilter
        switch bytes[index] {
        case UInt8(ascii: "&"):
            index += 1
            filter = .and(try parseList())
        case UInt8(ascii: "|"):
            index += 1
            filter = .or(try parseList())
        case UInt8(ascii: "!"):
            index += 1
            filter = .not(try parseFilter())
        default:
            filter = try parseItem()
        }
        skipSpace()
        try expect(UInt8(ascii: ")"), "')'")
        return filter
    }

    mutating func parseList() throws -> [LDAPFilter] {
        var list: [LDAPFilter] = []
        skipSpace()
        while index < bytes.count, bytes[index] == UInt8(ascii: "(") {
            list.append(try parseFilter())
            skipSpace()
        }
        return list
    }

    mutating func parseItem() throws -> LDAPFilter {
        let start = index
        while index < bytes.count, bytes[index] != UInt8(ascii: ")") {
            if bytes[index] == UInt8(ascii: "(") {
                throw error("Unescaped '(' inside a value; write it as \\28")
            }
            // An escaped character, \) included, is part of the value.
            index += bytes[index] == UInt8(ascii: "\\") ? 2 : 1
        }
        index = min(index, bytes.count)
        guard index < bytes.count else { throw error("Missing ')'") }
        let item = Array(bytes[start..<index])
        guard let eq = item.firstIndex(of: UInt8(ascii: "=")) else {
            throw error("Expected an operator such as '=' in this condition", at: start)
        }

        enum Kind { case equal, approx, greater, less, extensible }
        var kind = Kind.equal
        var lhsEnd = eq
        if eq > 0 {
            switch item[eq - 1] {
            case UInt8(ascii: "~"): kind = .approx; lhsEnd = eq - 1
            case UInt8(ascii: ">"): kind = .greater; lhsEnd = eq - 1
            case UInt8(ascii: "<"): kind = .less; lhsEnd = eq - 1
            case UInt8(ascii: ":"): kind = .extensible; lhsEnd = eq - 1
            default: break
            }
        }
        let lhs = String(decoding: item[0..<lhsEnd], as: UTF8.self).trimmingCharacters(in: .whitespaces)
        let rhs = Array(item[(eq + 1)...])
        let valueStart = start + eq + 1

        if kind == .extensible {
            return try parseExtensible(lhs, rhs, at: start, valueStart: valueStart)
        }
        try validateAttribute(lhs, at: start)

        switch kind {
        case .approx: return .approx(lhs, try unescape(rhs, at: valueStart))
        case .greater: return .greaterOrEqual(lhs, try unescape(rhs, at: valueStart))
        case .less: return .lessOrEqual(lhs, try unescape(rhs, at: valueStart))
        default: break
        }

        if rhs == [UInt8(ascii: "*")] { return .present(lhs) }
        guard rhs.contains(UInt8(ascii: "*")) else { return .equality(lhs, try unescape(rhs, at: valueStart)) }

        // Split on the stars that are not escaped (\2a, or the older \*).
        var pieces: [[UInt8]] = [[]]
        var escapedNext = false
        for byte in rhs {
            if escapedNext {
                pieces[pieces.count - 1].append(byte)
                escapedNext = false
            } else if byte == UInt8(ascii: "\\") {
                pieces[pieces.count - 1].append(byte)
                escapedNext = true
            } else if byte == UInt8(ascii: "*") {
                pieces.append([])
            } else {
                pieces[pieces.count - 1].append(byte)
            }
        }
        // Every star was escaped: an equality match on a value containing stars.
        if pieces.count == 1 { return .equality(lhs, try unescape(rhs, at: valueStart)) }
        let initial = pieces.first!.isEmpty ? nil : try unescape(pieces.first!, at: valueStart)
        let final = pieces.last!.isEmpty ? nil : try unescape(pieces.last!, at: valueStart)
        let any = try pieces.dropFirst().dropLast().filter { !$0.isEmpty }.map { try unescape($0, at: valueStart) }
        return .substrings(lhs, initial: initial, any: any, final: final)
    }

    func parseExtensible(_ lhs: String, _ rhs: [UInt8], at start: Int, valueStart: Int) throws -> LDAPFilter {
        let parts = lhs.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        let attribute = parts.first.flatMap { $0.isEmpty ? nil : $0 }
        var rule: String?
        var dn = false
        for part in parts.dropFirst() {
            if part.caseInsensitiveCompare("dn") == .orderedSame {
                dn = true
            } else if !part.isEmpty {
                guard rule == nil else { throw error("Only one matching rule is allowed", at: start) }
                rule = part
            }
        }
        if let attribute { try validateAttribute(attribute, at: start) }
        guard attribute != nil || rule != nil else {
            throw error("An extensible match needs an attribute or a matching rule", at: start)
        }
        return .extensible(rule: rule, attribute: attribute, value: try unescape(rhs, at: valueStart), dnAttributes: dn)
    }

    func validateAttribute(_ name: String, at position: Int) throws {
        guard !name.isEmpty else { throw error("Missing attribute name", at: position) }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-;."))
        guard name.unicodeScalars.allSatisfy({ allowed.contains($0) && $0.isASCII }) else {
            throw error("“\(name)” is not a valid attribute name", at: position)
        }
    }

    /// Turns `\xx` escapes into bytes. A backslash before `*`, `(`, `)` or `\`
    /// is the older RFC 1960 form and stands for that character. Before
    /// anything else it is kept as typed, so a DN pasted with its own escapes
    /// (`CN=Smith\, John`) is searched for as written.
    func unescape(_ value: [UInt8], at position: Int) throws -> [UInt8] {
        var out: [UInt8] = []
        var i = 0
        while i < value.count {
            let byte = value[i]
            if byte == UInt8(ascii: "\\") {
                guard i + 1 < value.count else { throw error("A value ends with a lone backslash", at: position + i) }
                if i + 2 < value.count, let hi = hex(value[i + 1]), let lo = hex(value[i + 2]) {
                    out.append(hi << 4 | lo)
                    i += 3
                } else if [UInt8(ascii: "*"), UInt8(ascii: "("), UInt8(ascii: ")"), UInt8(ascii: "\\")].contains(value[i + 1]) {
                    out.append(value[i + 1])
                    i += 2
                } else {
                    out.append(byte)
                    out.append(value[i + 1])
                    i += 2
                }
            } else {
                out.append(byte)
                i += 1
            }
        }
        return out
    }

    func hex(_ c: UInt8) -> UInt8? {
        switch c {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return c - UInt8(ascii: "A") + 10
        default: return nil
        }
    }
}
