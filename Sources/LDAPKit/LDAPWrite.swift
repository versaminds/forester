// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// One change to an attribute in a modify request (RFC 4511 §4.6).
public struct LDAPModification: Equatable, Sendable {
    public enum Operation: Int, Sendable, CaseIterable {
        case add = 0, delete = 1, replace = 2, increment = 3

        public var label: String {
            switch self {
            case .add: return "add"
            case .delete: return "delete"
            case .replace: return "replace"
            case .increment: return "increment"
            }
        }
    }

    public var operation: Operation
    public var attribute: String
    public var values: [Data]

    public init(_ operation: Operation, _ attribute: String, _ values: [Data] = []) {
        self.operation = operation
        self.attribute = attribute
        self.values = values
    }

    public static func replace(_ attribute: String, _ values: [String]) -> LDAPModification {
        LDAPModification(.replace, attribute, values.map { Data($0.utf8) })
    }

    public static func add(_ attribute: String, _ values: [String]) -> LDAPModification {
        LDAPModification(.add, attribute, values.map { Data($0.utf8) })
    }

    /// Deletes the given values, or the whole attribute when `values` is empty.
    public static func delete(_ attribute: String, _ values: [String] = []) -> LDAPModification {
        LDAPModification(.delete, attribute, values.map { Data($0.utf8) })
    }
}

extension LDAPCodec {
    public static func modify(dn: String, changes: [LDAPModification]) -> [UInt8] {
        BER.sequence([
            BER.octetString(dn),
            BER.sequence(changes.map { change in
                BER.sequence([
                    BER.enumerated(change.operation.rawValue),
                    BER.sequence([BER.octetString(change.attribute), BER.set(change.values.map { BER.octetString([UInt8]($0)) })]),
                ])
            }),
        ], tag: 0x66)
    }

    public static func add(dn: String, attributes: [LDAPAttribute]) -> [UInt8] {
        BER.sequence([
            BER.octetString(dn),
            BER.sequence(attributes.map { attribute in
                BER.sequence([BER.octetString(attribute.name), BER.set(attribute.values.map { BER.octetString([UInt8]($0)) })])
            }),
        ], tag: 0x68)
    }

    /// DelRequest is a primitive [APPLICATION 10] holding the DN itself.
    public static func delete(dn: String) -> [UInt8] {
        BER.octetString(dn, tag: 0x4A)
    }

    public static func modifyDN(dn: String, newRDN: String, deleteOldRDN: Bool, newSuperior: String?) -> [UInt8] {
        var parts = [BER.octetString(dn), BER.octetString(newRDN), BER.boolean(deleteOldRDN)]
        if let newSuperior { parts.append(BER.octetString(newSuperior, tag: 0x80)) }
        return BER.sequence(parts, tag: 0x6C)
    }

    /// RFC 3062 PasswdModifyRequestValue.
    static func passwordModifyValue(user: String?, oldPassword: String?, newPassword: String?) -> [UInt8] {
        var parts: [[UInt8]] = []
        if let user { parts.append(BER.octetString(user, tag: 0x80)) }
        if let oldPassword { parts.append(BER.octetString(oldPassword, tag: 0x81)) }
        if let newPassword { parts.append(BER.octetString(newPassword, tag: 0x82)) }
        return BER.sequence(parts)
    }
}

extension LDAPControl {
    /// AD's tree delete: removes an entry and everything beneath it in one request.
    public static let treeDeleteOID = "1.2.840.113556.1.4.805"
    /// AD's security descriptor flags: which parts of nTSecurityDescriptor to read or write.
    public static let sdFlagsOID = "1.2.840.113556.1.4.801"
    /// AD's permissive modify: adding a value that exists, or deleting one that
    /// does not, succeeds instead of failing.
    public static let permissiveModifyOID = "1.2.840.113556.1.4.1413"

    public static var treeDelete: LDAPControl { LDAPControl(oid: treeDeleteOID, critical: true) }

    /// `flags` is a combination of OWNER (1), GROUP (2), DACL (4) and SACL (8).
    /// Not critical, so a server without it carries on with its default.
    public static func sdFlags(_ flags: Int) -> LDAPControl {
        LDAPControl(oid: sdFlagsOID, critical: false, value: BER.sequence([BER.integer(flags)]))
    }

    public static var permissiveModify: LDAPControl { LDAPControl(oid: permissiveModifyOID, critical: false) }
}

extension LDAPConnection {
    public static let passwordModifyOID = "1.3.6.1.4.1.4203.1.11.1"

    /// Sends a write request and throws unless the server reports success.
    private func write(_ op: [UInt8], controls: [LDAPControl], name: String, timeout: TimeInterval? = nil) async throws {
        let responses = try await perform(op, controls: controls, name: name, timeout: timeout)
        guard let last = responses.last else { throw LDAPError.protocolError("\(name) got no response") }
        let result: LDAPResult
        switch last.kind {
        case .other(_, let decoded?): result = decoded
        case .extended(let decoded, _, _): result = decoded // a notice of disconnection, say
        default: throw LDAPError.protocolError("\(name) got an unexpected response")
        }
        guard result.code == .success else { throw LDAPError.server(result, operation: name) }
    }

    public func modify(_ dn: String, _ changes: [LDAPModification], controls: [LDAPControl] = []) async throws {
        guard !changes.isEmpty else { return }
        try await write(LDAPCodec.modify(dn: dn, changes: changes), controls: controls, name: "Modify")
    }

    public func add(_ dn: String, attributes: [LDAPAttribute], controls: [LDAPControl] = []) async throws {
        try await write(LDAPCodec.add(dn: dn, attributes: attributes), controls: controls, name: "Add")
    }

    public func delete(_ dn: String, controls: [LDAPControl] = [], timeout: TimeInterval? = nil) async throws {
        try await write(LDAPCodec.delete(dn: dn), controls: controls, name: "Delete", timeout: timeout)
    }

    /// AD answers a tree delete only once the whole subtree is gone.
    public static let treeDeleteTimeout: TimeInterval = 900

    /// Renames an entry (`newRDN`) and/or moves it under `newSuperior`.
    public func modifyDN(_ dn: String, newRDN: String, deleteOldRDN: Bool = true, newSuperior: String? = nil,
                         controls: [LDAPControl] = []) async throws {
        try await write(LDAPCodec.modifyDN(dn: dn, newRDN: newRDN, deleteOldRDN: deleteOldRDN, newSuperior: newSuperior),
                        controls: controls, name: newSuperior == nil ? "Rename" : "Move")
    }

    /// Deletes an entry and everything beneath it: with AD's tree delete control
    /// when `useTreeDelete`, otherwise leaves first, one entry at a time.
    /// Reports progress as (deleted, total).
    public func deleteSubtree(_ dn: String, useTreeDelete: Bool, pageSize: Int = 500,
                              progress: (@Sendable (Int, Int) -> Void)? = nil) async throws {
        if useTreeDelete {
            try await delete(dn, controls: [.treeDelete], timeout: max(options.timeout, Self.treeDeleteTimeout))
            return
        }
        let request = LDAPSearchRequest(base: dn, scope: .subtree, attributes: ["1.1"])
        let listing = try await pagedSearch(request, pageSize: pageSize)
        // Deleting from a partial list would remove some leaves and then stop
        // at the first container it never saw the contents of.
        guard listing.result.code == .success, !listing.stoppedAtLimit else {
            throw LDAPError.server(listing.result.code == .success
                                   ? LDAPResult(code: .sizeLimitExceeded, diagnosticMessage: "the subtree is larger than one listing")
                                   : listing.result,
                                   operation: "Listing the subtree before deleting it")
        }
        let found = listing.entries.map(\.dn)
        // Deepest first, so every entry is a leaf by the time it is deleted.
        let ordered = found.sorted { DN.components($0).count > DN.components($1).count }
        for (index, entry) in ordered.enumerated() {
            try Task.checkCancellation()
            try await delete(entry)
            progress?(index + 1, ordered.count)
        }
    }

    /// RFC 3062 password modify. With no `user` it changes the bound user's own
    /// password; with no `newPassword` the server generates one and returns it.
    @discardableResult
    public func passwordModify(user: String?, oldPassword: String?, newPassword: String?) async throws -> String? {
        let value = LDAPCodec.passwordModifyValue(user: user, oldPassword: oldPassword, newPassword: newPassword)
        let responses = try await perform(LDAPCodec.extended(oid: Self.passwordModifyOID, value: value), name: "Password change")
        guard case .extended(let result, _, let responseValue)? = responses.last?.kind else {
            throw LDAPError.protocolError("password change got no extended response")
        }
        guard result.code == .success else { throw LDAPError.server(result, operation: "Password change") }
        // PasswdModifyResponseValue ::= SEQUENCE { genPasswd [0] OCTET STRING OPTIONAL }
        guard let responseValue, let (outer, _) = try? BERDecoder.element(in: responseValue),
              let generated = try? outer.children().first(where: { $0.tag == 0x80 }) else { return nil }
        return generated.string
    }

    /// Any extended operation, for tools that need one the client does not wrap.
    public func extendedOperation(oid: String, value: [UInt8]? = nil) async throws -> (LDAPResult, String?, [UInt8]?) {
        let responses = try await perform(LDAPCodec.extended(oid: oid, value: value), name: "Extended operation")
        guard case .extended(let result, let name, let responseValue)? = responses.last?.kind else {
            throw LDAPError.protocolError("no extended response")
        }
        return (result, name, responseValue)
    }
}

extension ADValues {
    /// The value AD expects in unicodePwd: the password in double quotes,
    /// encoded as UTF-16LE. AD accepts it only over an encrypted connection.
    public static func unicodePwd(_ password: String) -> Data {
        Data(("\"" + password + "\"").utf16.flatMap { [UInt8($0 & 0xFF), UInt8($0 >> 8)] })
    }
}
