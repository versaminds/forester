// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// What the root DSE says about the server, in the terms the app uses.
public struct ServerInfo: Sendable {
    public enum Kind: Sendable, Equatable {
        case activeDirectory
        case adLDS
        case openLDAP
        case the389DirectoryServer
        case eDirectory
        case other(String?)

        public var label: String {
            switch self {
            case .activeDirectory: return "Active Directory"
            case .adLDS: return "AD LDS"
            case .openLDAP: return "OpenLDAP"
            case .the389DirectoryServer: return "389 Directory Server"
            case .eDirectory: return "eDirectory"
            case .other(let vendor): return vendor ?? "LDAP server"
            }
        }

        /// AD and AD LDS share the AD-only features: ANR, the in-chain matching
        /// rule, ranged attributes and the user/group/computer schema.
        public var isMicrosoft: Bool { self == .activeDirectory || self == .adLDS }
    }

    public let rootDSE: LDAPEntry
    public let kind: Kind

    public init(rootDSE: LDAPEntry) {
        self.rootDSE = rootDSE
        let capabilities = Set(rootDSE.strings("supportedCapabilities"))
        let vendor = rootDSE.string("vendorName")
        if capabilities.contains("1.2.840.113556.1.4.1851") {
            kind = .adLDS
        } else if capabilities.contains("1.2.840.113556.1.4.800") {
            kind = .activeDirectory
        } else if rootDSE.hasObjectClass("OpenLDAProotDSE") || vendor?.contains("OpenLDAP") == true {
            kind = .openLDAP
        } else if vendor?.contains("389 Project") == true || vendor?.contains("Red Hat") == true {
            kind = .the389DirectoryServer
        } else if vendor?.contains("NetIQ") == true || vendor?.contains("Novell") == true
                    || rootDSE.string("vendorVersion")?.contains("eDirectory") == true {
            kind = .eDirectory
        } else {
            kind = .other(vendor)
        }
    }

    public var namingContexts: [String] { rootDSE.strings("namingContexts") }

    /// The partition to start in: AD names it; otherwise the first naming context.
    public var defaultNamingContext: String? {
        rootDSE.string("defaultNamingContext") ?? namingContexts.first
    }

    public var dnsHostName: String? { rootDSE.string("dnsHostName") }
    public var vendorVersion: String? { rootDSE.string("vendorVersion") }

    public var supportsPaging: Bool {
        rootDSE.strings("supportedControl").contains(LDAPControl.pagedResultsOID)
    }

    public var supportsPasswordModify: Bool {
        rootDSE.strings("supportedExtension").contains(LDAPConnection.passwordModifyOID)
    }

    public var supportsTreeDelete: Bool {
        rootDSE.strings("supportedControl").contains(LDAPControl.treeDeleteOID)
    }

    public var configurationNamingContext: String? {
        rootDSE.string("configurationNamingContext")
            ?? defaultNamingContext.map { "CN=Configuration,\($0)" }
    }

    public var schemaNamingContext: String? {
        rootDSE.string("schemaNamingContext") ?? configurationNamingContext.map { "CN=Schema,\($0)" }
    }

    public var supportsStartTLS: Bool {
        rootDSE.strings("supportedExtension").contains(LDAPConnection.startTLSOID)
    }

    public var domainFunctionality: Int? { rootDSE.int("domainFunctionality").map(Int.init) }
    public var forestFunctionality: Int? { rootDSE.int("forestFunctionality").map(Int.init) }

    /// The domain's SID prefix is not in the root DSE; the app reads it from the
    /// domain object. Kept here so callers can share one value.
    public var domainDNSName: String? {
        defaultNamingContext.flatMap(DN.dnsDomain)
    }
}

/// Friendly names for the OIDs a root DSE lists.
public enum KnownOIDs {
    public static func name(_ oid: String) -> String? { names[oid] }

    static let names: [String: String] = [
        // Controls
        "1.2.840.113556.1.4.319": "Paged results",
        "1.2.840.113556.1.4.473": "Server-side sort",
        "1.2.840.113556.1.4.474": "Sort response",
        "1.2.840.113556.1.4.528": "Change notification",
        "1.2.840.113556.1.4.417": "Show deleted objects",
        "1.2.840.113556.1.4.619": "Lazy commit",
        "1.2.840.113556.1.4.841": "DirSync",
        "1.2.840.113556.1.4.801": "Security descriptor flags",
        "1.2.840.113556.1.4.805": "Tree delete",
        "1.2.840.113556.1.4.521": "Cross-domain move",
        "1.2.840.113556.1.4.970": "Search statistics",
        "1.2.840.113556.1.4.1338": "Verify name",
        "1.2.840.113556.1.4.1339": "Domain scope",
        "1.2.840.113556.1.4.1340": "Search options",
        "1.2.840.113556.1.4.1341": "RODC DCPROMO",
        "1.2.840.113556.1.4.1413": "Permissive modify",
        "1.2.840.113556.1.4.1504": "Attribute scoped query",
        "1.2.840.113556.1.4.1852": "Quota",
        "1.2.840.113556.1.4.1907": "Shutdown notify",
        "1.2.840.113556.1.4.1948": "Range retrieval without error",
        "1.2.840.113556.1.4.1974": "Force update",
        "1.2.840.113556.1.4.2026": "Input DN",
        "1.2.840.113556.1.4.2064": "Show recycled",
        "1.2.840.113556.1.4.2065": "Show deactivated links",
        "1.2.840.113556.1.4.2066": "Policy hints (deprecated)",
        "1.2.840.113556.1.4.2090": "DirSync extended",
        "1.2.840.113556.1.4.2204": "Tree delete extended",
        "1.2.840.113556.1.4.2205": "Update statistics",
        "1.2.840.113556.1.4.2206": "Search hints",
        "1.2.840.113556.1.4.2211": "Expected entry count",
        "1.2.840.113556.1.4.2239": "Policy hints",
        "1.2.840.113556.1.4.2255": "Set owner",
        "1.2.840.113556.1.4.2256": "Bypass quota",
        "1.2.840.113556.1.4.2309": "Link TTL",
        "1.2.840.113556.1.4.2330": "Set correlation ID",
        "1.2.840.113556.1.4.2354": "Thread trace override",
        "2.16.840.1.113730.3.4.9": "Virtual list view",
        "2.16.840.1.113730.3.4.10": "Virtual list view response",
        "2.16.840.1.113730.3.4.2": "ManageDsaIT",
        "2.16.840.1.113730.3.4.18": "Proxied authorization",
        "2.16.840.1.113730.3.4.3": "Persistent search",
        "1.3.6.1.4.1.4203.1.9.1.1": "Content synchronization (syncrepl)",
        "1.3.6.1.4.1.4203.666.5.16": "Dereference",
        "1.3.6.1.4.1.4203.1.10.1": "Subentries",
        "1.3.6.1.4.1.4203.1.10.2": "No-op",
        "1.2.826.0.1.3344810.2.3": "Matched values",
        "1.3.6.1.1.13.1": "Pre-read",
        "1.3.6.1.1.13.2": "Post-read",
        "1.3.6.1.1.12": "Assertion",
        "1.3.6.1.1.22": "Don't use copy",
        "1.3.6.1.4.1.42.2.27.8.5.1": "Password policy",
        // Extended operations
        "1.3.6.1.4.1.1466.20037": "StartTLS",
        "1.3.6.1.4.1.4203.1.11.1": "Password modify",
        "1.3.6.1.4.1.4203.1.11.3": "Who am I?",
        "1.3.6.1.1.8": "Cancel",
        "1.3.6.1.4.1.1466.101.119.1": "Dynamic refresh",
        "1.2.840.113556.1.4.1781": "Fast concurrent bind",
        "1.2.840.113556.1.4.2212": "Batch request",
        // Features
        "1.3.6.1.1.14": "Modify-increment",
        "1.3.6.1.4.1.4203.1.5.1": "All operational attributes (+)",
        "1.3.6.1.4.1.4203.1.5.2": "Attributes by object class (@class)",
        "1.3.6.1.4.1.4203.1.5.3": "Absolute true and false filters",
        "1.3.6.1.4.1.4203.1.5.4": "Language tag options",
        "1.3.6.1.4.1.4203.1.5.5": "Language range options",
        // Active Directory capabilities
        "1.2.840.113556.1.4.800": "Active Directory",
        "1.2.840.113556.1.4.1670": "Active Directory (Windows Server 2003)",
        "1.2.840.113556.1.4.1791": "LDAP signing and sealing (NTLM)",
        "1.2.840.113556.1.4.1935": "Active Directory (Windows Server 2008)",
        "1.2.840.113556.1.4.2080": "Active Directory (Windows Server 2008 R2)",
        "1.2.840.113556.1.4.2237": "Active Directory (Windows Server 2012)",
        "1.2.840.113556.1.4.1851": "AD LDS",
        "1.2.840.113556.1.4.1880": "Digest authentication for user objects",
        "1.2.840.113556.1.4.1920": "Read-only domain controller",
    ]
}
