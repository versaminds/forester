// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// A server certificate the system did not trust, with what a person needs to
/// decide whether to trust it anyway.
public struct CertificateTrustFailure: Sendable, Equatable {
    public var subject: String
    public var sha256Fingerprint: String
    public var reason: String
    /// DER encoding of the chain, leaf first, for the system certificate viewer.
    public var chain: [Data]

    public init(subject: String, sha256Fingerprint: String, reason: String, chain: [Data]) {
        self.subject = subject
        self.sha256Fingerprint = sha256Fingerprint
        self.reason = reason
        self.chain = chain
    }
}

public enum LDAPError: Error, LocalizedError, Equatable {
    case notConnected
    case connectionClosed
    case connectionFailed(String)
    case timedOut(String)
    case untrustedCertificate(CertificateTrustFailure)
    case tlsFailed(String)
    case server(LDAPResult, operation: String)
    case protocolError(String)
    case emptyPassword
    case serverDisconnected(String)
    case kerberos(String)

    public var errorDescription: String? {
        switch self {
        case .notConnected:
            return "Not connected."
        case .connectionClosed:
            return "The server closed the connection."
        case .connectionFailed(let why):
            return why
        case .timedOut(let operation):
            return "\(operation) timed out."
        case .untrustedCertificate(let failure):
            return "The server's certificate is not trusted: \(failure.reason)"
        case .tlsFailed(let why):
            return "TLS failed: \(why)"
        case .server(let result, let operation):
            var text = "\(operation) failed: \(result.code.name) (\(result.code.rawValue))."
            let diagnostic = result.diagnosticMessage.trimmingCharacters(in: .whitespacesAndNewlines.union(.controlCharacters))
            if let hint = ADBindError.explain(result.diagnosticMessage) {
                text += " \(hint)"
            } else if !diagnostic.isEmpty {
                text += " " + diagnostic.prefix(1).uppercased() + diagnostic.dropFirst()
                if let last = diagnostic.last, !".!?".contains(last) { text += "." }
            }
            // OpenLDAP answers an anonymous write with code 8 too ("modifications
            // require authentication"), where encryption is not the problem.
            if result.code == .strongerAuthRequired, diagnostic.localizedCaseInsensitiveContains("require authentication") {
                text += " Connect with a name and password to make changes."
            } else if result.code == .strongerAuthRequired || result.code == .confidentialityRequired {
                text += " The server requires an encrypted connection: use StartTLS or LDAPS."
            }
            return text
        case .protocolError(let why):
            return "Unexpected response from the server: \(why)"
        case .emptyPassword:
            return "Enter a password. A simple bind with a name and no password is an unauthenticated bind, which most servers accept as anonymous."
        case .serverDisconnected(let why):
            return "The server ended the session: \(why)"
        case .kerberos(let why):
            return why
        }
    }

    /// The failure is on the transport, so a fresh connection may succeed.
    public var isConnectionLoss: Bool {
        switch self {
        case .connectionClosed, .notConnected, .serverDisconnected: return true
        case .connectionFailed: return true
        default: return false
        }
    }

    public var resultCode: LDAPResultCode? {
        if case .server(let result, _) = self { return result.code }
        return nil
    }
}

/// Active Directory reports why a bind failed as a hex sub-code inside the
/// diagnostic message ("AcceptSecurityContext error, data 52e, v4563").
public enum ADBindError {
    static let codes: [String: String] = [
        "525": "The user does not exist.",
        "52e": "The user name or password is wrong.",
        "530": "The account may not sign in at this time of day.",
        "531": "The account may not sign in from this workstation.",
        "532": "The password has expired.",
        "533": "The account is disabled.",
        "568": "The account has too many security IDs (token too large).",
        "701": "The account has expired.",
        "773": "The password must be changed before the account can be used.",
        "775": "The account is locked out.",
    ]

    public static func explain(_ diagnostic: String) -> String? {
        guard let range = diagnostic.range(of: #"data ([0-9a-fA-F]+)"#, options: .regularExpression) else { return nil }
        let code = diagnostic[range].dropFirst(5).lowercased()
        guard let text = codes[code] else { return nil }
        return "\(text) (AD code \(code))"
    }
}
