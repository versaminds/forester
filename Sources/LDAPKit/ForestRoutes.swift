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

    public func route(_ dn: String) -> Route {
        guard !dn.isEmpty else { return .here }
        let heldDepth = Self.deepest(held.filter { DN.isWithin(dn, $0) })
        let domain = domains.filter { DN.isWithin(dn, $0.root) }
            .max { DN.components($0.root).count < DN.components($1.root).count }
        if let domain, DN.components(domain.root).count > heldDepth?.depth ?? 0 {
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
        let parts = DN.components(dn)
        let below = parts.count - depth
        if below > 0, DN.rdnAttribute(parts[below - 1])?.lowercased() == "dc" {
            let name = DN.dnsDomain(parts[(below - 1)...].joined(separator: ",")) ?? DN.displayName(dn)
            return .refused("\(DN.displayName(dn)) is in \(name), another domain than \(DN.dnsDomain(context) ?? context), which this window does not have open.")
        }
        return .here
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
