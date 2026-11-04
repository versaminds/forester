// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import AppKit
import LDAPKit
import UniformTypeIdentifiers

/// Saves entries as LDIF or CSV through the standard save panel.
@MainActor
enum Exporter {
    static func saveLDIF(_ entries: [LDAPEntry], suggestedName: String) {
        save(LDIF.document(entries), name: "\(suggestedName).ldif", type: UTType(filenameExtension: "ldif") ?? .plainText)
    }

    static func saveCSV(_ entries: [LDAPEntry], attributes: [String], suggestedName: String) {
        save(csv(entries, attributes: attributes), name: "\(suggestedName).csv", type: .commaSeparatedText)
    }

    /// One row per entry, DN first. Multi-valued attributes are joined with "; ".
    /// SIDs and GUIDs are written in their text form and Windows timestamps as
    /// ISO 8601, so a spreadsheet can sort and filter them; other binary values
    /// are base64.
    static func csv(_ entries: [LDAPEntry], attributes: [String]) -> String {
        let iso = ISO8601DateFormatter()
        func cell(_ attribute: String, _ value: Data) -> String {
            let formatted = AttributeFormatter.format(attribute, value)
            switch formatted.kind {
            case .sid, .guid: return formatted.text.components(separatedBy: "  (").first ?? formatted.text
            case .fileTime:
                if let raw = Int64(String(decoding: value, as: UTF8.self)), case .date(let date) = ADValues.fileTime(raw) {
                    return iso.string(from: date)
                }
                return String(decoding: value, as: UTF8.self)
            case .generalizedTime:
                return ADValues.generalizedTime(String(decoding: value, as: UTF8.self)).map(iso.string) ?? String(decoding: value, as: UTF8.self)
            case .binary, .image, .certificate:
                return value.base64EncodedString()
            default:
                return String(decoding: value, as: UTF8.self)
            }
        }
        func quote(_ field: String) -> String {
            // Values come from the directory, and many users may write their own
            // phone number or web page: one starting like a formula is kept as
            // text, so a spreadsheet does not run it (CSV injection).
            var field = field
            if let first = field.unicodeScalars.first, "=+-@\t\r".unicodeScalars.contains(first), Double(field) == nil {
                field = "'" + field
            }
            guard field.contains(where: { $0 == "," || $0 == "\"" || $0 == "\n" || $0 == "\r" || $0 == ";" }) else { return field }
            return "\"" + field.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        var lines = [(["dn"] + attributes).map(quote).joined(separator: ",")]
        for entry in entries {
            let fields = [entry.dn] + attributes.map { attribute in
                entry.values(attribute).map { cell(attribute, $0) }.joined(separator: "; ")
            }
            lines.append(fields.map(quote).joined(separator: ","))
        }
        // The byte order mark makes Excel read the file as UTF-8.
        return "\u{FEFF}" + lines.joined(separator: "\r\n") + "\r\n"
    }

    static func save(_ text: String, name: String, type: UTType) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = name
        panel.allowedContentTypes = [type]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
        } catch {
            NSAlert(error: error).runModal()
        }
    }

    static func save(_ data: Data, name: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = name
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try data.write(to: url, options: .atomic)
        } catch {
            NSAlert(error: error).runModal()
        }
    }
}
