// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// LDIF content records (RFC 2849), for export and copying.
public enum LDIF {
    public static let header = "version: 1\n\n"

    public static func entry(_ entry: LDAPEntry) -> String {
        var out = line("dn", Data(entry.dn.utf8))
        for attribute in entry.attributes {
            for value in attribute.values {
                out += line(attribute.name, value)
            }
        }
        return out + "\n"
    }

    public static func document(_ entries: [LDAPEntry]) -> String {
        header + entries.map(entry).joined()
    }

    /// Parents before their children, so the file can be imported again: a
    /// subtree search returns entries in whatever order the server keeps them,
    /// and AD's is not parent-first. Otherwise the server's order is kept.
    public static func parentsFirst(_ entries: [LDAPEntry]) -> [LDAPEntry] {
        // Each DN parsed once, not twice per comparison.
        let depths = entries.map { DN.components($0.dn).count }
        let order = entries.indices.sorted { a, b in
            depths[a] != depths[b] ? depths[a] < depths[b] : a < b
        }
        return order.map { entries[$0] }
    }

    /// One `name: value` line, base64-encoded (`name:: …`) when the value is not
    /// a SAFE-STRING, and folded at 76 columns.
    static func line(_ name: String, _ value: Data) -> String {
        // The name comes from the server: one with a line break in it would
        // otherwise start a record of its own when the file is imported.
        guard isAttributeDescription(name) else { return "# A value of an attribute whose name is not valid LDAP was left out.\n" }
        let text: String
        if isSafe(value) {
            text = "\(name): \(String(decoding: value, as: UTF8.self))"
        } else {
            text = "\(name):: \(value.base64EncodedString())"
        }
        return fold(text) + "\n"
    }

    /// An attribute name or OID with options (`member;range=0-1499`), RFC 4512 §2.5.
    static func isAttributeDescription(_ name: String) -> Bool {
        guard let first = name.unicodeScalars.first, first.isASCII, first.properties.isAlphabetic || ("0"..."9").contains(first) else { return false }
        return name.unicodeScalars.allSatisfy { $0.isASCII && ($0.properties.isAlphabetic || ("0"..."9").contains($0) || $0 == "-" || $0 == "." || $0 == ";" || $0 == "=") }
    }

    /// RFC 2849 SAFE-STRING: ASCII without NUL, CR or LF, not starting with a
    /// space, colon or "<", and not ending with a space.
    static func isSafe(_ value: Data) -> Bool {
        guard let first = value.first else { return true }
        if first == 0x20 || first == 0x3A || first == 0x3C { return false }
        if value.last == 0x20 { return false }
        return value.allSatisfy { $0 != 0 && $0 != 0x0A && $0 != 0x0D && $0 < 0x80 }
    }

    static func fold(_ line: String, width: Int = 76) -> String {
        guard line.utf8.count > width else { return line }
        var out = ""
        var current = ""
        var currentWidth = 0
        var limit = width
        for char in line {
            let size = String(char).utf8.count
            if currentWidth + size > limit {
                out += current + "\n "
                current = ""
                currentWidth = 0
                limit = width - 1
            }
            current.append(char)
            currentWidth += size
        }
        return out + current
    }
}
