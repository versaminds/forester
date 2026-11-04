// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation
import LDAPKit

/// An Active Directory object's permissions, in words, and what the signed-in
/// account may do with it.
struct Permissions {
    var owner: String?
    var rules: [AccessRule]
    /// Attributes this account may write here (allowedAttributesEffective).
    var writableAttributes: [String]
    /// Classes this account may create beneath it (allowedChildClassesEffective).
    var creatableClasses: [String]
    /// Which parts of the security descriptor this account may change.
    var mayChangePermissions: Bool
    var mayChangeOwner: Bool
}

extension DirectorySession {
    /// What each GUID in an access rule stands for, read once per connection
    /// from the schema and the Extended-Rights container, keyed by lowercase
    /// GUID. Empty when neither could be read; the rules then show GUIDs.
    func schemaGUIDNames() async -> [String: SchemaGUIDName] {
        if let cached = guidNames { return cached }
        var names: [String: SchemaGUIDName] = [:]
        if let schemaNC = server?.schemaNamingContext {
            let request = LDAPSearchRequest(base: schemaNC, scope: .oneLevel, filter: .present("schemaIDGUID"),
                                            attributes: ["lDAPDisplayName", "schemaIDGUID", "objectClass"])
            for entry in (try? await run({ try await $0.pagedSearch(request, pageSize: 1000) }))?.entries ?? [] {
                guard let data = entry.values("schemaIDGUID").first, let guid = ADValues.guidString(data),
                      let name = entry.string("lDAPDisplayName") else { continue }
                let isClass = entry.objectClasses.contains { $0.caseInsensitiveCompare("classSchema") == .orderedSame }
                names[guid.lowercased()] = SchemaGUIDName(name: name, kind: isClass ? .objectClass : .attribute)
            }
        }
        if let configuration = server?.configurationNamingContext {
            let request = LDAPSearchRequest(base: "CN=Extended-Rights,\(configuration)", scope: .oneLevel,
                                            filter: .equality("objectClass", "controlAccessRight"),
                                            attributes: ["displayName", "rightsGuid", "validAccesses"])
            for entry in (try? await run({ try await $0.pagedSearch(request, pageSize: 1000) }))?.entries ?? [] {
                guard let guid = entry.string("rightsGuid")?.lowercased(), let name = entry.string("displayName") else { continue }
                // validAccesses says which kind of right it is: read and write
                // property for a property set, self for a validated write.
                let valid = entry.int("validAccesses") ?? 0x100
                let kind: SchemaGUIDName.Kind = valid & 0x30 != 0 ? .propertySet : (valid & 0x8 != 0 ? .validatedWrite : .extendedRight)
                names[guid] = SchemaGUIDName(name: name, kind: kind)
            }
        }
        if !names.isEmpty { guidNames = names }
        return names
    }

    /// Names for SIDs: the well-known ones, then the account, group or foreign
    /// security principal holding each in this domain. A SID found nowhere
    /// keeps its S-1-… form. Returns the name and, when found, the entry's DN.
    func principalNames(_ sids: Set<String>) async -> [String: (name: String, dn: String?)] {
        var result: [String: (name: String, dn: String?)] = [:]
        var unknown: [String] = []
        for sid in sids {
            if let cached = sidNames[sid] {
                result[sid] = cached
            } else if let name = ADValues.wellKnownName(sid), !sid.hasPrefix("S-1-5-21-") {
                result[sid] = (name, nil)
            } else {
                unknown.append(sid)
            }
        }
        guard let base = server?.defaultNamingContext else { return result }
        for start in stride(from: 0, to: unknown.count, by: 50) {
            let chunk = Array(unknown[start..<min(start + 50, unknown.count)])
            let filters = chunk.compactMap { sid in ADValues.sidData(sid).map { LDAPFilter.equality("objectSid", [UInt8]($0)) } }
            guard !filters.isEmpty else { continue }
            let request = LDAPSearchRequest(base: base, scope: .subtree, filter: .or(filters),
                                            attributes: ["objectSid", "sAMAccountName", "displayName", "cn"])
            for entry in (try? await run({ try await $0.pagedSearch(request, pageSize: 500) }))?.entries ?? [] {
                guard let data = entry.values("objectSid").first, let sid = ADValues.sidString(data) else { continue }
                let name = entry.string("sAMAccountName") ?? entry.string("displayName") ?? entry.string("cn") ?? DN.displayName(entry.dn)
                result[sid] = (name, entry.dn)
            }
        }
        for sid in unknown where result[sid] == nil {
            result[sid] = (ADValues.wellKnownName(sid) ?? sid, nil)
        }
        for (sid, value) in result { sidNames[sid] = value }
        return result
    }

    /// The owner and DACL of `dn`, in words, with what this account may do there.
    func permissions(of dn: String) async throws -> Permissions {
        // Owner and DACL only: reading the SACL needs a privilege most
        // administrators lack, and asking for it makes AD return nothing.
        let entry = try await run {
            try await $0.read(dn, attributes: ["nTSecurityDescriptor", "allowedAttributesEffective", "allowedChildClassesEffective", "sDRightsEffective"],
                              controls: [.sdFlags(0x5)])
        }
        guard let entry, let data = entry.values("nTSecurityDescriptor").first else {
            throw PermissionsError.notReadable
        }
        let descriptor = try SecurityDescriptor(data: data)
        let names = await schemaGUIDNames()
        let rules = AccessRules.describe(descriptor.dacl) { names[$0] }
        let sdRights = entry.int("sDRightsEffective") ?? 0
        return Permissions(owner: descriptor.owner, rules: rules,
                           writableAttributes: entry.strings("allowedAttributesEffective").sorted { $0.localizedStandardCompare($1) == .orderedAscending },
                           creatableClasses: entry.strings("allowedChildClassesEffective").sorted { $0.localizedStandardCompare($1) == .orderedAscending },
                           mayChangePermissions: sdRights & 0x4 != 0, mayChangeOwner: sdRights & 0x1 != 0)
    }
}

enum PermissionsError: LocalizedError {
    case notReadable
    var errorDescription: String? {
        "The server returned no security descriptor for this entry. Reading one needs the right to read its permissions."
    }
}
