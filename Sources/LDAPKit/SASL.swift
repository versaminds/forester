// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import CommonCrypto
import CryptoKit
import Foundation

/// SASL sign-ins besides Kerberos: a TLS client certificate (EXTERNAL,
/// RFC 4422 appendix A) and SCRAM-SHA-256 (RFC 5802, RFC 7677). Each is used
/// only as asked: a server that cannot do it is refused, never answered with
/// something weaker.
extension LDAPConnection {
    /// Signs in as the client certificate the TLS handshake presented. The
    /// server maps the certificate to an account; no name or password is sent.
    public func bindExternal() async throws {
        guard options.clientIdentity != nil else {
            throw LDAPError.signIn("Choose the certificate to sign in with.")
        }
        guard usesTLS else {
            throw LDAPError.signIn("Signing in with a certificate needs StartTLS or LDAPS: the certificate is shown in the TLS handshake.")
        }
        let offered = try await offeredSASLMechanisms()
        // Asked only when the handshake has happened, which reading the
        // mechanisms just made sure of.
        guard clientCertificateRequested else {
            throw LDAPError.signIn("The server did not ask for a certificate when the connection was encrypted, so it cannot sign you in with one. Its administrator can have it ask (OpenLDAP: TLSVerifyClient try).")
        }
        guard offered.isEmpty || offered.contains(where: { $0.caseInsensitiveCompare("EXTERNAL") == .orderedSame }) else {
            throw LDAPError.signIn("The server asked for the certificate but does not offer signing in with it (SASL EXTERNAL); it offers \(offered.joined(separator: ", ")). Either it does not sign in with certificates, or it does not trust this certificate's issuer.")
        }
        // An empty authorization identity: the one the certificate maps to.
        // A server that wants it asked for separately gets the same again.
        var (result, _) = try await saslBind(mechanism: "EXTERNAL", credentials: [])
        if result.code == .saslBindInProgress {
            (result, _) = try await saslBind(mechanism: "EXTERNAL", credentials: [])
        }
        guard result.code == .success else { throw LDAPError.server(result, operation: "Certificate sign-in") }
        boundDN = nil
    }

    /// Signs in with SCRAM-SHA-256: the password proves itself without being
    /// sent, and the server proves it knows it too. Over TLS, the server's
    /// certificate is bound into the exchange when the server can check that
    /// (SCRAM-SHA-256-PLUS), so nobody in between can pass the exchange on.
    public func bindSCRAM(user: String, password: String) async throws {
        guard !user.isEmpty else { throw LDAPError.signIn("Enter a user name.") }
        guard !password.isEmpty else { throw LDAPError.signIn("Enter a password.") }
        // Whoever is in between, with any certificate accepted, ends the TLS
        // connection and reads the exchange: the salt, the rounds and the
        // proof, enough to guess the password at leisure. Refused before
        // anything is sent, as Kerberos is.
        if options.security != .none, options.trust.trustAnyCertificate {
            throw LDAPError.signIn("SCRAM sign-in is not used with “Accept any certificate”: whoever is between this Mac and the server would see the exchange and could guess the password from it. Trust the server's certificate instead.")
        }
        let root = try await read("", attributes: ["supportedSASLMechanisms", "objectClass", "vendorName"])
        let offered = (root?.strings("supportedSASLMechanisms") ?? []).map { $0.uppercased() }
        let plus = usesTLS && offered.contains("SCRAM-SHA-256-PLUS")
        // A server that lists nothing is tried: it says so if it cannot.
        guard plus || offered.contains("SCRAM-SHA-256") || offered.isEmpty else {
            throw LDAPError.signIn("The server does not offer SCRAM-SHA-256 sign-in (it offers \(offered.joined(separator: ", "))).")
        }
        let binding: SCRAM.Binding
        if usesTLS {
            guard let certificate = serverCertificate, let hash = ChannelBinding.certificateHash(certificate),
                  let prefixed = ChannelBinding.tlsServerEndPoint(certificate) else {
                throw LDAPError.signIn("The server's TLS certificate was not seen, so the sign-in could not be bound to this connection.")
            }
            // A server that can check the binding gets it. One that cannot is
            // told this side could have (RFC 5802 "y"), so a server that can
            // and was made to look as if it cannot notices. OpenLDAP names
            // every binding "ldap" and checks it with the GSS-API prefix; the
            // certificate's hash is bound either way.
            if !plus {
                binding = .notOffered
            } else if root.map({ ServerInfo(rootDSE: $0).kind }) == .openLDAP {
                binding = .bound(type: "ldap", data: [UInt8](prefixed))
            } else {
                binding = .bound(type: "tls-server-end-point", data: hash)
            }
        } else {
            binding = .none
        }
        try await bindSCRAM(mechanism: plus ? "SCRAM-SHA-256-PLUS" : "SCRAM-SHA-256",
                            SCRAM(user: user, password: password, binding: binding))
    }

    /// The exchange itself, with the binding given: tests use it to bind
    /// what someone in between would.
    func bindSCRAM(mechanism: String, _ start: SCRAM) async throws {
        var scram = start
        let (first, serverFirst) = try await saslBind(mechanism: mechanism, credentials: scram.clientFirst)
        guard first.code == .saslBindInProgress, let serverFirst else {
            throw LDAPError.server(first, operation: "SCRAM sign-in")
        }
        let clientFinal = try scram.clientFinal(serverFirst: serverFirst)
        let (final, serverFinal) = try await saslBind(mechanism: mechanism, credentials: clientFinal)
        switch final.code {
        case .success:
            // Signed in, but whoever answered must also prove it knows the
            // password; otherwise the connection is not used.
            guard let serverFinal else {
                throw LDAPError.signIn("The server accepted the SCRAM sign-in without proving that it knows the password, so the connection was not used.")
            }
            try scram.verify(serverFinal: serverFinal)
        case .saslBindInProgress:
            try scram.verify(serverFinal: serverFinal ?? [])
            let (done, _) = try await saslBind(mechanism: mechanism, credentials: [])
            guard done.code == .success else { throw LDAPError.server(done, operation: "SCRAM sign-in") }
        default:
            if let serverFinal, let reason = SCRAM.serverError(serverFinal) {
                throw LDAPError.signIn("SCRAM sign-in failed: \(reason).")
            }
            throw LDAPError.server(final, operation: "SCRAM sign-in")
        }
        boundDN = nil
    }

    /// One SASL bind request: the server's result and its token, if any.
    /// `credentials` nil leaves them out altogether.
    func saslBind(mechanism: String, credentials: [UInt8]?) async throws -> (LDAPResult, [UInt8]?) {
        let responses = try await perform(LDAPCodec.saslBind(mechanism: mechanism, credentials: credentials), name: "Bind")
        guard case .bind(let result, let serverCredentials)? = responses.last?.kind else {
            throw LDAPError.protocolError("bind got no bind response")
        }
        return (result, serverCredentials)
    }

    /// The SASL mechanisms the root DSE lists. Asking also starts TLS, which
    /// starts with the first request.
    func offeredSASLMechanisms() async throws -> [String] {
        try await read("", attributes: ["supportedSASLMechanisms"])?.strings("supportedSASLMechanisms") ?? []
    }
}

extension LDAPCodec {
    /// BindRequest with SaslCredentials (RFC 4511 §4.2): version, an empty
    /// name, and [3] { mechanism, credentials OPTIONAL }.
    static func saslBind(mechanism: String, credentials: [UInt8]?) -> [UInt8] {
        var sasl = [BER.octetString(mechanism)]
        if let credentials { sasl.append(BER.octetString(credentials)) }
        return BER.sequence([BER.integer(3), BER.octetString(""), BER.sequence(sasl, tag: 0xA3)], tag: 0x60)
    }
}

/// The client side of one SCRAM exchange (RFC 5802), with SHA-256 or, for
/// RFC 5802's own examples, SHA-1.
struct SCRAM {
    enum Hash { case sha1, sha256 }

    enum Binding: Equatable {
        /// No TLS: nothing to bind ("n").
        case none
        /// TLS, but the server offers no -PLUS mechanism ("y").
        case notOffered
        /// The TLS channel bound in ("p=type").
        case bound(type: String, data: [UInt8])

        var header: String {
            switch self {
            case .none: return "n,,"
            case .notOffered: return "y,,"
            case .bound(let type, _): return "p=\(type),,"
            }
        }
    }

    /// Fewer rounds make a recorded exchange quick to guess passwords
    /// against; anyone on an unencrypted path could ask for one. More than
    /// the upper bound would keep the app busy for many seconds.
    static let iterations = 4_096...2_000_000

    let hash: Hash
    let binding: Binding
    private let password: [UInt8]
    private let clientNonce: String
    private let clientFirstBare: String
    private var serverSignature: [UInt8]?

    init(user: String, password: String, binding: Binding, hash: Hash = .sha256, nonce: String? = nil) throws {
        self.hash = hash
        self.binding = binding
        self.password = Array(try Self.saslPrep(password, field: "password").utf8)
        clientNonce = try nonce ?? Self.makeNonce()
        // "=" and "," would end the name early: RFC 5802 §5.1 escapes them.
        let name = try Self.saslPrep(user, field: "user name").replacingOccurrences(of: "=", with: "=3D").replacingOccurrences(of: ",", with: "=2C")
        clientFirstBare = "n=\(name),r=\(clientNonce)"
    }

    var clientFirst: [UInt8] { Array((binding.header + clientFirstBare).utf8) }

    /// The answer to the server's challenge, with the proof of the password.
    mutating func clientFinal(serverFirst: [UInt8]) throws -> [UInt8] {
        let message = String(decoding: serverFirst, as: UTF8.self)
        if let reason = Self.serverError(serverFirst) { throw LDAPError.signIn("SCRAM sign-in failed: \(reason).") }
        let fields = Self.fields(message)
        guard !message.hasPrefix("m="), let nonce = fields["r"], let saltText = fields["s"], let countText = fields["i"],
              let salt = Data(base64Encoded: saltText), !salt.isEmpty, let count = Int(countText) else {
            throw LDAPError.signIn("The server's SCRAM challenge is malformed.")
        }
        // The server adds to this side's nonce; anything else is not an answer to it.
        guard nonce.hasPrefix(clientNonce), nonce.count > clientNonce.count, !nonce.contains(",") else {
            throw LDAPError.signIn("The server's SCRAM challenge does not answer this sign-in.")
        }
        guard Self.iterations.contains(count) else {
            throw LDAPError.signIn(count < Self.iterations.lowerBound
                ? "The server asked for \(count) rounds of password hashing, fewer than the \(Self.iterations.lowerBound) SCRAM requires; anyone who recorded the sign-in could then guess the password quickly. It was not sent."
                : "The server asked for \(count) rounds of password hashing, more than Forester does (\(Self.iterations.upperBound)).")
        }
        var bindingData = Array(binding.header.utf8)
        if case .bound(_, let data) = binding { bindingData += data }
        let withoutProof = "c=\(Data(bindingData).base64EncodedString()),r=\(nonce)"
        let authMessage = Array("\(clientFirstBare),\(message),\(withoutProof)".utf8)
        let salted = try Self.pbkdf2(password, salt: [UInt8](salt), rounds: count, hash: hash)
        let clientKey = Self.hmac(salted, Array("Client Key".utf8), hash: hash)
        let storedKey = Self.digest(clientKey, hash: hash)
        let clientSignature = Self.hmac(storedKey, authMessage, hash: hash)
        let proof = zip(clientKey, clientSignature).map { $0 ^ $1 }
        serverSignature = Self.hmac(Self.hmac(salted, Array("Server Key".utf8), hash: hash), authMessage, hash: hash)
        return Array("\(withoutProof),p=\(Data(proof).base64EncodedString())".utf8)
    }

    /// Checks the server's proof that it knows the password.
    func verify(serverFinal: [UInt8]) throws {
        if let reason = Self.serverError(serverFinal) { throw LDAPError.signIn("SCRAM sign-in failed: \(reason).") }
        guard let expected = serverSignature, let text = Self.fields(String(decoding: serverFinal, as: UTF8.self))["v"],
              let signature = Data(base64Encoded: text), Self.constantTimeEqual([UInt8](signature), expected) else {
            throw LDAPError.signIn("The server could not prove that it knows the password, so the connection was not used. Something between this Mac and the server may be pretending to be it.")
        }
    }

    /// The server's "e=" reason, in words where SCRAM names it.
    static func serverError(_ message: [UInt8]) -> String? {
        guard let reason = fields(String(decoding: message, as: UTF8.self))["e"] else { return nil }
        switch reason {
        case "invalid-proof": return "the user name or password is wrong"
        case "unknown-user": return "the user name is not known"
        case "channel-bindings-dont-match": return "the TLS connection the server sees is not the one this Mac made, so something may be in between"
        case "server-does-support-channel-binding": return "something between this Mac and the server hid that the server binds TLS connections"
        default: return "the server says \(reason)"
        }
    }

    private static func fields(_ message: String) -> [String: String] {
        var fields: [String: String] = [:]
        for part in message.split(separator: ",", omittingEmptySubsequences: false) {
            guard let equals = part.firstIndex(of: "="), part.distance(from: part.startIndex, to: equals) == 1 else { continue }
            let key = String(part[..<equals])
            if fields[key] == nil { fields[key] = String(part[part.index(after: equals)...]) }
        }
        return fields
    }

    /// A nonce from the system's random numbers. Should they fail, the
    /// buffer would stay zeros, the same nonce every time: refused instead.
    static func makeNonce(random: (inout [UInt8]) -> OSStatus = { SecRandomCopyBytes(kSecRandomDefault, $0.count, &$0) }) throws -> String {
        var bytes = [UInt8](repeating: 0, count: 24)
        guard random(&bytes) == errSecSuccess else {
            throw LDAPError.signIn("This Mac could not make the random numbers a SCRAM sign-in needs, so nothing was sent.")
        }
        return Data(bytes).base64EncodedString()
    }

    /// Equal in time that does not depend on where the two differ, so the
    /// time an answer takes says nothing about how much of a forged proof
    /// was right.
    static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for index in a.indices { difference |= a[index] ^ b[index] }
        return difference == 0
    }

    private static func hmac(_ key: [UInt8], _ data: [UInt8], hash: Hash) -> [UInt8] {
        let key = SymmetricKey(data: key)
        switch hash {
        case .sha1: return Array(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: key))
        case .sha256: return Array(HMAC<SHA256>.authenticationCode(for: data, using: key))
        }
    }

    private static func digest(_ data: [UInt8], hash: Hash) -> [UInt8] {
        switch hash {
        case .sha1: return Array(Insecure.SHA1.hash(data: data))
        case .sha256: return Array(SHA256.hash(data: data))
        }
    }

    /// Hi() of RFC 5802: PBKDF2 with HMAC, one block.
    private static func pbkdf2(_ password: [UInt8], salt: [UInt8], rounds: Int, hash: Hash) throws -> [UInt8] {
        var derived = [UInt8](repeating: 0, count: hash == .sha256 ? 32 : 20)
        let derivedCount = derived.count
        let status = password.withUnsafeBufferPointer { passwordBytes in
            passwordBytes.withMemoryRebound(to: Int8.self) { passwordChars in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), passwordChars.baseAddress, password.count, salt, salt.count,
                                     CCPseudoRandomAlgorithm(hash == .sha256 ? kCCPRFHmacAlgSHA256 : kCCPRFHmacAlgSHA1),
                                     UInt32(rounds), &derived, derivedCount)
            }
        }
        guard status == kCCSuccess else { throw LDAPError.signIn("The password could not be hashed for SCRAM (\(status)).") }
        return derived
    }

    // MARK: SASLprep (RFC 4013)

    /// User names and passwords as SCRAM compares them: other spaces become
    /// a space, invisible joiners go, compatibility forms are unified (NFKC),
    /// and control and private-use characters are refused, as is
    /// right-to-left text mixed with left-to-right. Unassigned code points
    /// are let through, as RFC 4013 allows for what is not stored.
    ///
    /// `field` names what was refused ("password"). The character itself is
    /// never named: it may be one of the password's, and the message reaches
    /// Diagnostics.
    static func saslPrep(_ text: String, field: String = "user name or password") throws -> String {
        var mapped = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            let value = scalar.value
            if value == 0x00A0 || value == 0x1680 || (0x2000...0x200B).contains(value) || value == 0x202F || value == 0x205F || value == 0x3000 {
                mapped.append(" ")
            } else if [0x00AD, 0x034F, 0x1806, 0x180B, 0x180C, 0x180D, 0x200C, 0x200D, 0x2060, 0xFEFF].contains(value)
                        || (0xFE00...0xFE0F).contains(value) {
                continue
            } else {
                mapped.append(scalar)
            }
        }
        let normalized = String(mapped).precomposedStringWithCompatibilityMapping
        if normalized.unicodeScalars.contains(where: { prohibited($0.value) }) {
            throw LDAPError.signIn("The \(field) holds a character SCRAM does not allow, such as a control or private-use character.")
        }
        // RFC 3454 §6: right-to-left text is not mixed with left-to-right,
        // and starts and ends right to left, so it cannot be read two ways.
        let scalars = Array(normalized.unicodeScalars)
        if scalars.contains(where: { rightToLeft($0.value) }) {
            guard !scalars.contains(where: leftToRight), let first = scalars.first, let last = scalars.last,
                  rightToLeft(first.value), rightToLeft(last.value) else {
                throw LDAPError.signIn("The \(field) mixes right-to-left and left-to-right text in a way SCRAM does not allow.")
            }
        }
        return normalized
    }

    /// RFC 3454 table D.1: characters with bidirectional property R or AL.
    private static func rightToLeft(_ value: UInt32) -> Bool {
        switch value {
        case 0x05BE, 0x05C0, 0x05C3, 0x05D0...0x05EA, 0x05F0...0x05F4, 0x061B, 0x061F, 0x0621...0x063A, 0x0640...0x064A,
             0x066D...0x066F, 0x0671...0x06D5, 0x06DD, 0x06E5...0x06E6, 0x06FA...0x06FE, 0x0700...0x070D, 0x0710,
             0x0712...0x072C, 0x0780...0x07A5, 0x07B1, 0x200F, 0xFB1D, 0xFB1F...0xFB28, 0xFB2A...0xFB36, 0xFB38...0xFB3C,
             0xFB3E, 0xFB40...0xFB41, 0xFB43...0xFB44, 0xFB46...0xFBB1, 0xFBD3...0xFD3D, 0xFD50...0xFD8F, 0xFD92...0xFDC7,
             0xFDF0...0xFDFC, 0xFE70...0xFE74, 0xFE76...0xFEFC:
            return true
        default:
            return false
        }
    }

    /// RFC 3454 table D.2, bidirectional property L, read from the general
    /// category: letters and spacing marks, outside the right-to-left
    /// blocks (whose letters added since table D.1 are not left to right).
    /// Digits, spaces, punctuation and other neutral characters are not L.
    private static func leftToRight(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x0590...0x08FF, 0xFB1D...0xFDFF, 0xFE70...0xFEFF, 0x10800...0x10FFF, 0x1E800...0x1EFFF: return false
        default: break
        }
        switch scalar.properties.generalCategory {
        case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .modifierLetter, .otherLetter, .spacingMark: return true
        default: return false
        }
    }

    private static func prohibited(_ value: UInt32) -> Bool {
        value < 0x20 || (0x7F...0x9F).contains(value) || value == 0x06DD || value == 0x070F || value == 0x180E
            || (0x200E...0x200F).contains(value) || (0x2028...0x202E).contains(value) || (0x2060...0x2063).contains(value)
            || (0x206A...0x206F).contains(value) || (0xFFF9...0xFFFD).contains(value) || (0x1D173...0x1D17A).contains(value)
            || (0xE000...0xF8FF).contains(value) || (0xF0000...0xFFFFD).contains(value) || (0x100000...0x10FFFD).contains(value)
            || (0xFDD0...0xFDEF).contains(value) || value & 0xFFFE == 0xFFFE || (0x2FF0...0x2FFB).contains(value)
            || value == 0x0340 || value == 0x0341 || value == 0xE0001 || (0xE0020...0xE007F).contains(value)
    }
}
