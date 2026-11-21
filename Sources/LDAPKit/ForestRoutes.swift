// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// Which connection answers for a DN in an Active Directory forest, when
/// more than one domain is browsed in one window.
///
/// A domain controller holds its own domain and the forest's configuration
/// and schema; another domain's entries are on that domain's controllers.
/// Given to a connection (`LDAPConnection.setRoutes`), every request it is
/// asked to make about a DN goes to the connection of the domain holding
/// it: one place, so no request anywhere in the app can send a DN of one
/// domain to another domain's server. A DN of a domain that is not open, or
/// whose connection failed, is refused, never sent where it does not belong.
public struct ForestRoutes: Sendable {
    /// Another domain of the forest, from its crossRef.
    public struct Domain: Sendable {
        public var root: String
        public var dnsName: String
        /// Open in this window; nil when it is not, or failed.
        public var connection: LDAPConnection?
        /// Why it is not open, when it was tried.
        public var failure: String?

        public init(root: String, dnsName: String, connection: LDAPConnection? = nil, failure: String? = nil) {
            self.root = root
            self.dnsName = dnsName
            self.connection = connection
            self.failure = failure
        }
    }

    public enum Route {
        /// This connection's server holds it.
        case here
        /// Another domain's connection holds it.
        case connection(LDAPConnection)
        /// Another domain holds it, and it is not open: why.
        case refused(String)
    }

    /// The naming contexts this connection's server holds.
    public var held: [String]
    /// The forest's other domains.
    public var domains: [Domain]

    public init(held: [String], domains: [Domain]) {
        self.held = held
        self.domains = domains
    }

    /// The other domain that holds `dn`: the deepest domain root containing
    /// it, when that is deeper than every naming context this server holds
    /// that contains it. nil when this server holds it (also when this is a
    /// child domain and the other an ancestor, whose root contains this
    /// domain's entries too).
    public func domain(holding dn: String) -> Domain? {
        guard !dn.isEmpty, !DN.isExtended(dn) else { return nil }
        let heldDepth = Self.deepest(held.filter { DN.isWithin(dn, $0) })?.depth ?? 0
        guard let domain = domains.filter({ DN.isWithin(dn, $0.root) })
            .max(by: { DN.components($0.root).count < DN.components($1.root).count }),
              DN.components(domain.root).count > heldDepth else { return nil }
        return domain
    }

    public func route(_ dn: String) -> Route {
        guard !dn.isEmpty else { return .here }
        // <GUID=…> and <SID=…> name an entry without saying where it is: with
        // other domains of the forest about, which one holds it is unknown,
        // and the parent's server could be asked for a child's entry.
        if DN.isExtended(dn) {
            return domains.isEmpty ? .here
                : .refused("\(dn.trimmingCharacters(in: .whitespaces).prefix(60)) names an entry by GUID or SID; with other domains of the forest about, Forester cannot tell which domain holds it, so it is not asked for. Use its DN.")
        }
        let heldDepth = Self.deepest(held.filter { DN.isWithin(dn, $0) })
        if let domain = domain(holding: dn) {
            if let connection = domain.connection { return .connection(connection) }
            if let failure = domain.failure {
                return .refused("\(DN.displayName(dn)) is in \(domain.dnsName), which could not be opened: \(failure)")
            }
            return .refused("\(DN.displayName(dn)) is in \(domain.dnsName), another domain of the forest, which is not open in this window.")
        }
        guard let (context, depth) = heldDepth else { return .here }
        // A child domain's names end in its parent's (DC=child,DC=corp is
        // beneath DC=corp), so lying beneath a naming context is not enough:
        // a DC= part right beneath it starts a domain of its own.
        // Normalized, so dc written as domainComponent or its OID counts too.
        let parts = DN.components(DN.normalized(dn))
        let below = parts.count - depth
        if below > 0, DN.rdnAttribute(parts[below - 1]) == "dc" {
            let name = DN.dnsDomain(parts[(below - 1)...].joined(separator: ",")) ?? DN.displayName(dn)
            return .refused("\(DN.displayName(dn)) is in \(name), another domain than \(DN.dnsDomain(context) ?? context), which this window does not have open.")
        }
        return .here
    }

    /// A crossRef whose DNS name is the one its naming context spells
    /// (DC=child,DC=corp,DC=example is child.corp.example). Anything else is
    /// not taken for a domain of the forest: its dnsRoot is where Forester
    /// would connect, and a crossRef written to point elsewhere would send
    /// the sign-in to another host.
    public static func isConsistent(nCName: String, dnsRoot: String) -> Bool {
        // A domain's naming context is DC= parts only.
        let parts = DN.components(DN.normalized(nCName))
        guard !parts.isEmpty, parts.allSatisfy({ DN.rdnAttribute($0) == "dc" }),
              let spelled = DN.dnsDomain(nCName) else { return false }
        return spelled.caseInsensitiveCompare(dnsRoot.trimmingCharacters(in: .whitespaces)) == .orderedSame
    }

    /// This server holds `dn`.
    public func holds(_ dn: String) -> Bool {
        if case .here = route(dn) { return true }
        return false
    }

    private static func deepest(_ contexts: [String]) -> (String, depth: Int)? {
        contexts.map { ($0, DN.components($0).count) }.max { $0.1 < $1.1 }
    }
}
