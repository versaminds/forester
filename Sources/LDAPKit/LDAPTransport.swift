// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import CryptoKit
import Foundation
import Security

/// Which server certificates to accept beyond what the system already trusts.
public struct TrustPolicy: Sendable, Hashable, Codable {
    /// SHA-256 fingerprints of leaf certificates the user chose to trust.
    public var pinnedFingerprints: [String]
    /// Accept any certificate. Only for a lab; the connection is then open to
    /// interception, and the UI says so.
    public var trustAnyCertificate: Bool

    public init(pinnedFingerprints: [String] = [], trustAnyCertificate: Bool = false) {
        self.pinnedFingerprints = pinnedFingerprints
        self.trustAnyCertificate = trustAnyCertificate
    }

    func accepts(fingerprint: String) -> Bool {
        let wanted = Self.normalize(fingerprint)
        return pinnedFingerprints.contains { Self.normalize($0) == wanted }
    }

    static func normalize(_ fingerprint: String) -> String {
        fingerprint.lowercased().filter(\.isHexDigit)
    }
}

/// A TCP stream to the server, with TLS that can start on the first byte
/// (LDAPS) or later in the conversation (StartTLS).
///
/// Built on `URLSessionStreamTask` because it is the system API that can upgrade
/// an established connection to TLS (`startSecureConnection`), which StartTLS
/// requires and `NWConnection` cannot do; it also evaluates certificates against
/// the user's keychain trust settings, so a corporate root CA installed there is
/// honoured without configuration.
final class LDAPTransport: NSObject, URLSessionStreamDelegate, @unchecked Sendable {
    private let host: String
    private let port: Int
    private let trust: TrustPolicy
    private var session: URLSession!
    private var task: URLSessionStreamTask!
    private let lock = NSLock()
    private var _trustFailure: CertificateTrustFailure?
    private var _serverCertificate: Data?

    init(host: String, port: Int, trust: TrustPolicy) {
        self.host = host
        self.port = port
        self.trust = trust
        super.init()
        let configuration = URLSessionConfiguration.ephemeral
        // Directory traffic goes straight to the server; an HTTP or SOCKS proxy
        // configured for the web would only get in the way.
        configuration.connectionProxyDictionary = [:]
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        queue.name = "LDAPTransport \(host):\(port)"
        session = URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
        task = session.streamTask(withHostName: host, port: port)
    }

    /// The leaf certificate of the handshake that was accepted (DER).
    var serverCertificate: Data? {
        lock.lock(); defer { lock.unlock() }
        return _serverCertificate
    }

    /// The certificate failure from the most recent handshake, if one was refused.
    var trustFailure: CertificateTrustFailure? {
        lock.lock(); defer { lock.unlock() }
        return _trustFailure
    }

    func resume() {
        task.resume()
    }

    /// Queues the TLS handshake behind anything already written; it runs when the
    /// next read or write needs the connection.
    func startTLS() {
        task.startSecureConnection()
    }

    func write(_ bytes: [UInt8], timeout: TimeInterval) async throws {
        try await task.write(Data(bytes), timeout: timeout)
    }

    /// Waits for at least one byte. A timeout of 0 waits indefinitely.
    func read(timeout: TimeInterval = 0) async throws -> (Data?, Bool) {
        try await task.readData(ofMinLength: 1, maxLength: 1 << 20, timeout: timeout)
    }

    func close() {
        task.cancel()
        // A URLSession holds its delegate until invalidated.
        session.invalidateAndCancel()
    }

    // MARK: URLSessionDelegate

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        evaluate(challenge, completionHandler)
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        evaluate(challenge, completionHandler)
    }

    private func evaluate(_ challenge: URLAuthenticationChallenge,
                          _ completion: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            // Client certificates are not supported; let the server decide.
            completion(.performDefaultHandling, nil)
            return
        }
        var error: CFError?
        let trusted = SecTrustEvaluateWithError(serverTrust, &error)
        let chain = (SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate]) ?? []
        let fingerprint = chain.first.map(Self.fingerprint) ?? ""

        if trusted || trust.trustAnyCertificate || (!fingerprint.isEmpty && trust.accepts(fingerprint: fingerprint)) {
            lock.lock()
            _serverCertificate = chain.first.map { SecCertificateCopyData($0) as Data }
            lock.unlock()
            completion(.useCredential, URLCredential(trust: serverTrust))
            return
        }
        let reason = (error.map { CFErrorCopyDescription($0) as String })
            ?? "The certificate could not be verified."
        let failure = CertificateTrustFailure(
            subject: chain.first.flatMap { SecCertificateCopySubjectSummary($0) as String? } ?? host,
            sha256Fingerprint: fingerprint,
            reason: reason,
            chain: chain.map { SecCertificateCopyData($0) as Data })
        lock.lock()
        _trustFailure = failure
        lock.unlock()
        completion(.cancelAuthenticationChallenge, nil)
    }

    static func fingerprint(_ certificate: SecCertificate) -> String {
        let der = SecCertificateCopyData(certificate) as Data
        return SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    /// Turns a networking error into something that names the likely cause.
    ///
    /// A stream task reports failures from three layers, each in its own
    /// domain: URL loading (NSURLErrorDomain), the socket (NSPOSIXErrorDomain:
    /// refused, unreachable, timed out) and name resolution (CFNetwork). Left
    /// untranslated the last reads "kCFErrorDomainCFNetwork error 2".
    func translate(_ error: Error, security: LDAPConnection.Security, timeout: TimeInterval) -> LDAPError {
        if let failure = trustFailure { return .untrustedCertificate(failure) }
        if let ldap = error as? LDAPError { return ldap }
        let ns = error as NSError
        let endpoint = "\(host):\(port)"
        let refused = LDAPError.connectionFailed("Could not connect to \(endpoint). The server refused the connection; check the host and port.")
        let notFound = LDAPError.connectionFailed("The host “\(host)” could not be found. Check the name, or your VPN.")
        let unreachable = LDAPError.connectionFailed("\(host) cannot be reached from this Mac. Check your network or VPN.")
        let silent = Self.noResponse(endpoint: endpoint, port: port, seconds: timeout, security: security)

        switch ns.domain {
        case NSPOSIXErrorDomain:
            switch Int32(ns.code) {
            case ECONNREFUSED: return refused
            case ETIMEDOUT: return silent
            case EHOSTUNREACH, ENETUNREACH, EHOSTDOWN, ENETDOWN: return unreachable
            case ECONNRESET, EPIPE, ENOTCONN, ECONNABORTED: return .connectionClosed
            default: return .connectionFailed(ns.localizedDescription)
            }
        case "kCFErrorDomainCFNetwork", "kCFStreamErrorDomainNetDB":
            // CFNetwork codes 1 and 2 are host lookup failures; -9800…-9899 are TLS.
            if ns.code == 1 || ns.code == 2 || ns.userInfo["kCFGetAddrInfoFailureKey"] != nil { return notFound }
            if (-9899)...(-9800) ~= ns.code { return .tlsFailed(Self.tlsHint(ns.localizedDescription, port: port, security: security)) }
            return .connectionFailed(ns.localizedDescription)
        case NSOSStatusErrorDomain, "kCFStreamErrorDomainSSL":
            return .tlsFailed(Self.tlsHint(ns.localizedDescription, port: port, security: security))
        case NSURLErrorDomain:
            break
        default:
            return .connectionFailed(ns.localizedDescription)
        }

        switch ns.code {
        case NSURLErrorCannotFindHost, NSURLErrorDNSLookupFailed:
            return notFound
        case NSURLErrorCannotConnectToHost:
            return refused
        case NSURLErrorTimedOut:
            return silent
        case NSURLErrorNotConnectedToInternet:
            return .connectionFailed("This Mac is not connected to a network.")
        case NSURLErrorNetworkConnectionLost, NSURLErrorCancelled:
            return .connectionClosed
        case NSURLErrorSecureConnectionFailed, NSURLErrorServerCertificateHasBadDate,
             NSURLErrorServerCertificateUntrusted, NSURLErrorServerCertificateHasUnknownRoot,
             NSURLErrorServerCertificateNotYetValid, NSURLErrorClientCertificateRejected:
            return .tlsFailed(Self.tlsHint(ns.localizedDescription, port: port, security: security))
        default:
            return .connectionFailed(ns.localizedDescription)
        }
    }

    static func tlsHint(_ description: String, port: Int, security: LDAPConnection.Security) -> String {
        switch security {
        case .ldaps: return description + " Is \(port) an LDAPS port? LDAPS is usually 636 (3269 for the global catalog)."
        case .startTLS: return description + " The server may not support StartTLS on this port."
        case .none: return description
        }
    }

    /// Nothing came back at all. Either the host is not reachable (a firewall
    /// dropping packets looks exactly like this), or it is listening but not
    /// speaking the protocol we started with: TLS sent to a plain LDAP port
    /// gets no answer from many servers.
    static func noResponse(endpoint: String, port: Int, seconds: TimeInterval, security: LDAPConnection.Security) -> LDAPError {
        var text = "No response from \(endpoint) within \(Int(seconds)) seconds. Check that the host is reachable (network, VPN, firewall) and that the port is right."
        if security == .ldaps {
            text += " For LDAPS, \(port) must be a TLS port: usually 636, or 3269 for the global catalog."
        }
        return .connectionFailed(text)
    }
}
