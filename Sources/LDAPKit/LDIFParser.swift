// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// One LDIF record (RFC 2849): an entry to add, or a change to apply.
public struct LDIFRecord: Sendable {
    public enum Change: Sendable {
        /// A content record, or `changetype: add`.
        case add([LDAPAttribute])
        case delete
        case modify([LDAPModification])
        case modifyDN(newRDN: String, deleteOldRDN: Bool, newSuperior: String?)
    }

    public var dn: String
    public var change: Change
    /// Line where the record starts, for error messages and logs.
    public var line: Int
    /// The record had no changetype (a plain entry, as an export writes).
    public var isContent: Bool

    public init(dn: String, change: Change, line: Int = 0, isContent: Bool = false) {
        self.dn = dn
        self.change = change
        self.line = line
        self.isContent = isContent
    }

    public var summary: String {
        switch change {
        case .add: return isContent ? "entry" : "add"
        case .delete: return "delete"
        case .modify(let changes): return "modify (\(changes.count) change\(changes.count == 1 ? "" : "s"))"
        case .modifyDN(_, _, let superior): return superior == nil ? "rename" : "move"
        }
    }
}

public struct LDIFParseError: Error, LocalizedError, Equatable {
    public var line: Int
    public var message: String
    public var errorDescription: String? { "Line \(line): \(message)" }
}

/// What an `attr:< file:///…` value may read. An LDIF file can come from
/// anyone, and such a value sends a file from this Mac to the directory.
public enum LDIFFileReferences: Sendable {
    /// Refused: nothing is read unless the user agreed.
    case refuse
    /// Regular files in this folder or below it, each at most `maxFileBytes`.
    case within(URL)

    public static let maxFileBytes = 10 << 20
}

public enum LDIFParser {
    /// Parses a whole LDIF document. `files` decides whether `attr:< file:…`
    /// values are read, and from where; relative ones are resolved against
    /// that folder.
    public static func parse(_ text: String, files: LDIFFileReferences = .refuse) throws -> [LDIFRecord] {
        var records: [LDIFRecord] = []
        for block in logicalBlocks(text) {
            if let record = try parseRecord(block, base: files) { records.append(record) }
        }
        return records
    }

    /// The files a document's `attr:< …` values refer to, as written, with
    /// their line numbers, without reading any of them.
    public static func fileReferences(in text: String) -> [(line: Int, reference: String)] {
        logicalBlocks(text).joined().compactMap { line in
            guard let colon = line.text.firstIndex(of: ":") else { return nil }
            let rest = line.text[line.text.index(after: colon)...]
            guard rest.first == "<" else { return nil }
            return (line.number, rest.dropFirst().trimmingCharacters(in: .whitespaces))
        }
    }

    /// A logical line: a physical line with its continuations joined, and the
    /// line number it started on.
    struct Line {
        var number: Int
        var text: String
    }

    /// Splits into records: unfolds continuation lines (a leading single space),
    /// drops comments, and separates records at blank lines.
    static func logicalBlocks(_ text: String) -> [[Line]] {
        var blocks: [[Line]] = []
        var current: [Line] = []
        var inComment = false
        let physical = text.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n")
            .split(separator: "\n", omittingEmptySubsequences: false)
        for (index, raw) in physical.enumerated() {
            var line = String(raw)
            if index == 0, line.hasPrefix("\u{FEFF}") { line.removeFirst() }
            if line.hasPrefix(" ") {
                // A continuation of the previous line (or of a comment).
                if inComment { continue }
                if !current.isEmpty { current[current.count - 1].text += String(line.dropFirst()) }
                continue
            }
            inComment = false
            if line.hasPrefix("#") {
                inComment = true
                continue
            }
            if line.trimmingCharacters(in: .whitespaces).isEmpty {
                if !current.isEmpty { blocks.append(current); current = [] }
                continue
            }
            current.append(Line(number: index + 1, text: line))
        }
        if !current.isEmpty { blocks.append(current) }
        return blocks
    }

    /// `name: value`, `name:: base64` or `name:< url`.
    static func split(_ line: Line, base: LDIFFileReferences) throws -> (name: String, value: Data) {
        guard let colon = line.text.firstIndex(of: ":") else {
            throw LDIFParseError(line: line.number, message: "Expected “name: value”")
        }
        let name = String(line.text[..<colon]).trimmingCharacters(in: .whitespaces)
        var rest = line.text[line.text.index(after: colon)...]
        guard !name.isEmpty else { throw LDIFParseError(line: line.number, message: "Missing attribute name") }
        if rest.first == ":" {
            rest = rest.dropFirst()
            let encoded = rest.trimmingCharacters(in: .whitespaces)
            guard let data = Data(base64Encoded: encoded, options: .ignoreUnknownCharacters) else {
                throw LDIFParseError(line: line.number, message: "“\(name)” is not valid base64")
            }
            return (name, data)
        }
        if rest.first == "<" {
            let reference = rest.dropFirst().trimmingCharacters(in: .whitespaces)
            return (name, try readReference(reference, line: line.number, files: base))
        }
        // One space after the colon is the separator; any more belong to SAFE-STRING rules
        // that forbid a leading space, so trimming all leading spaces is what parsers do.
        let value = String(rest.drop(while: { $0 == " " }))
        return (name, Data(value.utf8))
    }

    static func readReference(_ reference: String, line: Int, files: LDIFFileReferences) throws -> Data {
        func refuse(_ message: String) -> LDIFParseError { LDIFParseError(line: line, message: message) }
        let scheme = URL(string: reference)?.scheme?.lowercased()
        guard scheme == nil || scheme == "file" else { throw refuse("Only file: URLs are supported (\(reference))") }
        guard case .within(let folderURL) = files else {
            throw refuse("The value is read from the file “\(reference)” on this Mac, which needs your consent")
        }
        let folder = URL(fileURLWithPath: folderURL.standardizedFileURL.resolvingSymlinksInPath().path, isDirectory: true)
        guard let url = URL(string: reference, relativeTo: folder), url.isFileURL,
              url.host.map({ $0.isEmpty || $0.lowercased() == "localhost" }) ?? true else {
            throw refuse("“\(reference)” is not a file on this Mac")
        }
        let resolved = url.standardizedFileURL.resolvingSymlinksInPath()
        guard resolved.path.hasPrefix(folder.path.hasSuffix("/") ? folder.path : folder.path + "/") else {
            throw refuse("“\(reference)” is outside the LDIF file's folder; only files beside it or below it are read")
        }
        let values = try? resolved.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard values?.isRegularFile == true else { throw refuse("“\(reference)” is not a regular file") }
        guard let size = values?.fileSize, size <= LDIFFileReferences.maxFileBytes else {
            throw refuse("“\(reference)” is larger than \(LDIFFileReferences.maxFileBytes >> 20) MB")
        }
        do {
            return try Data(contentsOf: resolved)
        } catch {
            throw refuse("Cannot read \(resolved.path): \(error.localizedDescription)")
        }
    }

    static func parseRecord(_ lines: [Line], base: LDIFFileReferences) throws -> LDIFRecord? {
        var lines = lines[...]
        guard let first = lines.first else { return nil }
        // A "version: 1" line on its own, or at the head of the first record.
        if first.text.lowercased().hasPrefix("version:") {
            lines = lines.dropFirst()
            guard !lines.isEmpty else { return nil }
        }
        let dnLine = lines.removeFirst()
        let (dnName, dnValue) = try split(dnLine, base: base)
        guard dnName.lowercased() == "dn" else {
            throw LDIFParseError(line: dnLine.number, message: "A record must start with “dn:”, found “\(dnName)”")
        }
        let dn = String(decoding: dnValue, as: UTF8.self)

        // A control changes what an operation does (only if, or as a dry run),
        // and the importer applies plain operations: running the record
        // without it could do more than the file asks for.
        if let line = lines.first, line.text.lowercased().hasPrefix("control:") {
            throw LDIFParseError(line: line.number, message: "Controls are not supported, and the record would run without them")
        }

        guard let next = lines.first, next.text.lowercased().hasPrefix("changetype:") else {
            return LDIFRecord(dn: dn, change: .add(try attributes(lines, base: base)), line: dnLine.number, isContent: true)
        }
        lines.removeFirst()
        let changeType = String(decoding: try split(next, base: base).value, as: UTF8.self).lowercased()
        switch changeType {
        case "add":
            return LDIFRecord(dn: dn, change: .add(try attributes(lines, base: base)), line: dnLine.number, isContent: false)
        case "delete":
            return LDIFRecord(dn: dn, change: .delete, line: dnLine.number, isContent: false)
        case "modrdn", "moddn":
            var newRDN: String?
            var deleteOld = true
            var superior: String?
            for line in lines {
                let (name, value) = try split(line, base: base)
                let text = String(decoding: value, as: UTF8.self)
                switch name.lowercased() {
                case "newrdn": newRDN = text
                case "deleteoldrdn": deleteOld = text.trimmingCharacters(in: .whitespaces) != "0"
                case "newsuperior": superior = text
                default: throw LDIFParseError(line: line.number, message: "Unexpected “\(name)” in a \(changeType) record")
                }
            }
            guard let newRDN else { throw LDIFParseError(line: next.number, message: "A \(changeType) record needs “newrdn:”") }
            return LDIFRecord(dn: dn, change: .modifyDN(newRDN: newRDN, deleteOldRDN: deleteOld, newSuperior: superior),
                              line: dnLine.number, isContent: false)
        case "modify":
            return LDIFRecord(dn: dn, change: .modify(try modifications(lines, base: base)), line: dnLine.number, isContent: false)
        default:
            throw LDIFParseError(line: next.number, message: "Unknown changetype “\(changeType)”")
        }
    }

    static func attributes(_ lines: ArraySlice<Line>, base: LDIFFileReferences) throws -> [LDAPAttribute] {
        var attributes: [LDAPAttribute] = []
        for line in lines {
            let (name, value) = try split(line, base: base)
            if let index = attributes.firstIndex(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) {
                attributes[index].values.append(value)
            } else {
                attributes.append(LDAPAttribute(name: name, values: [value]))
            }
        }
        return attributes
    }

    static func modifications(_ lines: ArraySlice<Line>, base: LDIFFileReferences) throws -> [LDAPModification] {
        var changes: [LDAPModification] = []
        var current: LDAPModification?
        for line in lines {
            if line.text.trimmingCharacters(in: .whitespaces) == "-" {
                if let current { changes.append(current) }
                current = nil
                continue
            }
            let (name, value) = try split(line, base: base)
            if current == nil {
                let operation: LDAPModification.Operation
                switch name.lowercased() {
                case "add": operation = .add
                case "delete": operation = .delete
                case "replace": operation = .replace
                case "increment": operation = .increment
                default: throw LDIFParseError(line: line.number, message: "Expected add:, delete:, replace: or increment:, found “\(name)”")
                }
                current = LDAPModification(operation, String(decoding: value, as: UTF8.self).trimmingCharacters(in: .whitespaces))
            } else if var change = current {
                guard name.caseInsensitiveCompare(change.attribute) == .orderedSame else {
                    throw LDIFParseError(line: line.number, message: "“\(name)” inside a change to “\(change.attribute)”; is a “-” missing?")
                }
                change.values.append(value)
                current = change
            }
        }
        if let current { changes.append(current) }
        return changes
    }
}

extension LDIF {
    /// A change record in LDIF, for logs and "copy as LDIF".
    public static func record(_ record: LDIFRecord) -> String {
        var out = line("dn", Data(record.dn.utf8))
        switch record.change {
        case .add(let attributes):
            if !record.isContent { out += "changetype: add\n" }
            for attribute in attributes { for value in attribute.values { out += line(attribute.name, value) } }
        case .delete:
            out += "changetype: delete\n"
        case .modify(let changes):
            out += "changetype: modify\n"
            for change in changes {
                guard isAttributeDescription(change.attribute) else { continue }
                out += "\(change.operation.label): \(change.attribute)\n"
                for value in change.values { out += line(change.attribute, value) }
                out += "-\n"
            }
        case .modifyDN(let newRDN, let deleteOld, let superior):
            out += "changetype: modrdn\n" + line("newrdn", Data(newRDN.utf8)) + "deleteoldrdn: \(deleteOld ? 1 : 0)\n"
            if let superior { out += line("newsuperior", Data(superior.utf8)) }
        }
        return out + "\n"
    }
}
