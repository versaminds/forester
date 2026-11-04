// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// Distinguished name helpers (RFC 4514), written for the DNs servers actually
/// return: escaped commas (`CN=Smith\, John`), hex escapes (`\C4\8D`) and the
/// occasional quoted value from older servers.
public enum DN {
    /// The RDNs, leaf first, split on unescaped commas (or semicolons, which
    /// RFC 1779 allowed and some servers still send).
    public static func components(_ dn: String) -> [String] {
        var parts: [String] = []
        var current = ""
        var escaped = false
        var quoted = false
        for char in dn {
            if escaped {
                current.append(char)
                escaped = false
                continue
            }
            switch char {
            case "\\":
                current.append(char)
                escaped = true
            case "\"":
                current.append(char)
                quoted.toggle()
            case "," where !quoted, ";" where !quoted:
                parts.append(trimUnescaped(current))
                current = ""
            default:
                current.append(char)
            }
        }
        let last = trimUnescaped(current)
        if !last.isEmpty || !parts.isEmpty { parts.append(last) }
        return parts.filter { !$0.isEmpty }
    }

    public static func parent(_ dn: String) -> String? {
        let parts = components(dn)
        guard parts.count > 1 else { return nil }
        return parts.dropFirst().joined(separator: ",")
    }

    public static func rdn(_ dn: String) -> String {
        components(dn).first ?? dn
    }

    public static func rdnAttribute(_ dn: String) -> String? {
        let rdn = rdn(dn)
        guard let eq = rdn.firstIndex(of: "=") else { return nil }
        return rdn[..<eq].trimmingCharacters(in: .whitespaces)
    }

    /// The unescaped value of the first RDN: `CN=Smith\, John,…` → `Smith, John`.
    /// For a multi-valued RDN (`cn=x+uid=y`) the first value is used.
    public static func rdnValue(_ dn: String) -> String {
        let rdn = rdn(dn)
        guard let eq = rdn.firstIndex(of: "=") else { return rdn }
        var value = String(rdn[rdn.index(after: eq)...])
        if let plus = unescapedIndex(of: "+", in: value) { value = String(value[..<plus]) }
        return unescape(trimUnescaped(value))
    }

    /// Trims surrounding whitespace, except a space that is escaped: in
    /// `OU=Sales\ ` the space belongs to the value.
    static func trimUnescaped(_ text: String) -> String {
        var chars = Array(text)
        while let first = chars.first, first.isWhitespace { chars.removeFirst() }
        while let last = chars.last, last.isWhitespace {
            var backslashes = 0
            var index = chars.count - 2
            while index >= 0, chars[index] == "\\" { backslashes += 1; index -= 1 }
            if backslashes % 2 == 1 { break }
            chars.removeLast()
        }
        return String(chars)
    }

    /// Whether an RDN names the entry by more than one value (`cn=John+uid=jdoe`).
    public static func isMultiValued(rdn: String) -> Bool {
        unescapedIndex(of: "+", in: rdn) != nil
    }

    /// A short label for the entry, as a tree or list shows it.
    public static func displayName(_ dn: String) -> String {
        dn.isEmpty ? "Root DSE" : rdnValue(dn)
    }

    public static func unescape(_ value: String) -> String {
        var v = value
        if v.count >= 2, v.hasPrefix("\""), v.hasSuffix("\"") { v = String(v.dropFirst().dropLast()) }
        guard v.contains("\\") else { return v }
        var bytes: [UInt8] = []
        let chars = Array(v.utf8)
        var i = 0
        while i < chars.count {
            if chars[i] == UInt8(ascii: "\\"), i + 1 < chars.count {
                if i + 2 < chars.count, let hi = hexValue(chars[i + 1]), let lo = hexValue(chars[i + 2]) {
                    bytes.append(hi << 4 | lo)
                    i += 3
                } else {
                    bytes.append(chars[i + 1])
                    i += 2
                }
            } else {
                bytes.append(chars[i])
                i += 1
            }
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Escapes a value for use in a DN (RFC 4514 §2.4).
    public static func escape(_ value: String) -> String {
        // By scalar, not by Character: a combining mark after a comma would
        // otherwise hide the comma inside one Character and leave it unescaped.
        var out = ""
        let scalars = Array(value.unicodeScalars)
        for (i, c) in scalars.enumerated() {
            switch c {
            case ",", "+", "\"", "\\", "<", ">", ";", "=":
                out += "\\" + String(c)
            case "#" where i == 0:
                out += "\\#"
            case " " where i == 0 || i == scalars.count - 1:
                out += "\\ "
            case "\0":
                out += "\\00"
            default:
                out.unicodeScalars.append(c)
            }
        }
        return out
    }

    /// A form for comparing DNs: attribute types and values lowercased, every
    /// value escaped one way (`\2C`, `\,` and a quoted value all become `\,`),
    /// whitespace around separators dropped. Values stay escaped, so the result
    /// splits back into the same RDNs. Not a full RFC 4518 matching rule, but it
    /// agrees on everything AD and OpenLDAP send back.
    public static func normalized(_ dn: String) -> String {
        components(dn).map { rdn -> String in
            guard let eq = rdn.firstIndex(of: "=") else { return rdn.lowercased() }
            let type = rdn[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let value = unescape(trimUnescaped(String(rdn[rdn.index(after: eq)...]))).lowercased()
            return "\(type)=\(escape(value))"
        }.joined(separator: ",")
    }

    public static func isSame(_ a: String, _ b: String) -> Bool {
        normalized(a) == normalized(b)
    }

    /// `dn` is `ancestor` or lies beneath it.
    public static func isWithin(_ dn: String, _ ancestor: String) -> Bool {
        if ancestor.isEmpty { return true }
        let d = components(normalized(dn)), a = components(normalized(ancestor))
        guard d.count >= a.count else { return false }
        return Array(d.suffix(a.count)) == a
    }

    /// The DNs from `root` (included) down to `dn`'s parent, in that order, so a
    /// tree can expand each in turn to reveal `dn`.
    public static func path(from root: String, to dn: String) -> [String] {
        guard isWithin(dn, root) else { return [] }
        let parts = components(dn)
        let depth = components(root).count
        guard parts.count > depth else { return [] }
        return (max(depth, 1)..<parts.count).map { parts.suffix($0).joined(separator: ",") }
    }

    /// `corp.example` from `DC=corp,DC=example`.
    public static func dnsDomain(_ dn: String) -> String? {
        let dcs = components(dn).compactMap { rdn -> String? in
            guard rdnAttribute(rdn)?.lowercased() == "dc" else { return nil }
            return rdnValue(rdn)
        }
        return dcs.isEmpty ? nil : dcs.joined(separator: ".")
    }

    /// AD's canonical name, `corp.example/Corp/Users/Jane Doe`, which reads as a path.
    public static func canonicalName(_ dn: String) -> String {
        let parts = components(dn)
        let dcCount = parts.reversed().prefix { rdnAttribute($0)?.lowercased() == "dc" }.count
        let domain = parts.suffix(dcCount).map(rdnValue).joined(separator: ".")
        let rest = parts.dropLast(dcCount).reversed().map(rdnValue)
        return ([domain.isEmpty ? nil : domain].compactMap { $0 } + rest).joined(separator: "/")
    }

    static let commonTypes: Set<String> = [
        "cn", "ou", "dc", "o", "c", "l", "st", "uid", "street", "serialnumber", "mail", "sn", "givenname", "title",
    ]

    /// Whether a string value is plausibly a DN, for attributes the app does not
    /// already know hold DNs. Requires two or more RDNs with familiar types, so
    /// prose with an "=" in it is not turned into a link.
    public static func looksLikeDN(_ value: String) -> Bool {
        guard value.contains("="), value.count < 2048 else { return false }
        let parts = components(value)
        guard parts.count >= 2 else { return false }
        return parts.allSatisfy { rdn in
            guard let type = rdnAttribute(rdn)?.lowercased(), !type.isEmpty else { return false }
            return commonTypes.contains(type) || type.allSatisfy { $0.isNumber || $0 == "." }
        }
    }

    private static func unescapedIndex(of target: Character, in value: String) -> String.Index? {
        var escaped = false
        for index in value.indices {
            let c = value[index]
            if escaped { escaped = false; continue }
            if c == "\\" { escaped = true; continue }
            if c == target { return index }
        }
        return nil
    }

    private static func hexValue(_ c: UInt8) -> UInt8? {
        switch c {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return c - UInt8(ascii: "A") + 10
        default: return nil
        }
    }
}
