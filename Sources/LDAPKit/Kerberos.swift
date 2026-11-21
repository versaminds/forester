// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import CryptoKit
import Foundation
import GSS

/// Signing in with the user's Kerberos ticket: a SASL GSSAPI bind (RFC 4752)
/// through macOS's GSS framework, which finds the ticket wherever the user
/// got it (Ticket Viewer, kinit, the Kerberos SSO extension). No password
/// passes through Forester.
///
/// Over TLS there is no SASL security layer: TLS already protects the
/// connection, and Active Directory refuses Kerberos signing or sealing on
/// top of TLS. The TLS certificate is bound into the Kerberos exchange
/// (RFC 5929 tls-server-end-point), which domain controllers can require
/// ("LDAP channel binding"), so a ticket cannot be relayed through another
/// TLS connection.
///
/// Without TLS, Kerberos itself encrypts every message after the bind (the
/// SASL security layer with confidentiality, RFC 4752 §3.3). A server that
/// does not offer that is refused rather than used with signing alone or
/// with nothing: the connection is encrypted or it is not made.
extension LDAPConnection {
    public func bindKerberos() async throws {
        // The binding ties the ticket to the certificate this connection saw.
        // Accepting any certificate would tie it to whoever is in between,
        // who could pass the exchange on to the real server and be signed in.
        if usesTLS, options.trust.trustAnyCertificate {
            throw LDAPError.kerberos("Kerberos sign-in is not used with “Accept any certificate”: it would sign in whoever is between this Mac and the server. Trust the server's certificate instead.")
        }
        // TLS starts with the first request, and the binding needs its
        // certificate: asking which mechanisms the server offers does both.
        let offered = try await offeredSASLMechanisms()
        guard offered.isEmpty || offered.contains(where: { $0.caseInsensitiveCompare("GSSAPI") == .orderedSame }) else {
            throw LDAPError.kerberos("The server does not offer Kerberos sign-in (it offers \(offered.joined(separator: ", "))).")
        }
        guard usesTLS else {
            try await bindKerberos(channelBinding: nil, sealing: true)
            return
        }
        // Without the certificate there is nothing to bind to, and a ticket
        // that is not bound could be used over another connection.
        guard let certificate = serverCertificate, let binding = ChannelBinding.tlsServerEndPoint(certificate) else {
            throw LDAPError.kerberos("The server's TLS certificate was not seen, so the Kerberos sign-in could not be bound to this connection.")
        }
        try await bindKerberos(channelBinding: binding, sealing: false)
    }

    /// `sealing`: ask Kerberos to encrypt everything after the bind, and
    /// refuse to finish the sign-in without it. `serviceHost`, for tests:
    /// the name asked for, as DNS might have turned the host into another.
    func bindKerberos(channelBinding binding: Data?, sealing: Bool, serviceHost: String? = nil) async throws {
        kerberosServer = nil
        let context = try GSSContext(service: "ldap@\(serviceHost ?? options.host)", channelBinding: binding, sealing: sealing)
        var token = try context.step(nil)
        // Without TLS nothing but Kerberos says who the server is, and GSS
        // may have asked for the name DNS gave the host (an alias followed,
        // an address looked up), which whoever answers DNS can choose. The
        // server must be the LDAP service of the very host connected to.
        var server: String?
        func checkServer() throws {
            guard server == nil, context.isComplete else { return }
            let name = try context.acceptorName()
            if sealing, !GSSContext.acceptorMatches(name, host: options.host) {
                throw LDAPError.kerberos("Kerberos signed in to “\(name)”, not to the LDAP service of “\(options.host)”, so the connection was not used: without TLS, only that name says who the server is. Connect by the server's own name, as its Kerberos name has it, or use StartTLS or LDAPS.")
            }
            server = name
        }
        // A layer agreed on for a bind that then failed must not seal what
        // this connection sends next.
        defer { disarmSecurityLayer() }
        // Token exchanges, an empty turn once the context is complete, then
        // the security-layer offer and answer: a handful of rounds at most.
        for _ in 0..<8 {
            let (result, serverToken) = try await saslBind(mechanism: "GSSAPI", credentials: token)
            if result.code == .success {
                guard context.isComplete else { throw LDAPError.kerberos("The server accepted the sign-in before proving who it is.") }
                try checkServer()
                // The layer takes effect with the bind's answer. A server that
                // says yes without having agreed on one would read what comes
                // next in the clear.
                if sealing, !isSealed {
                    throw LDAPError.kerberos("The server accepted the Kerberos sign-in without agreeing to encrypt the connection, so it is not used. Use StartTLS or LDAPS.")
                }
                boundDN = nil
                kerberosServer = server
                return
            }
            guard result.code == .saslBindInProgress else { throw LDAPError.server(result, operation: "Kerberos sign-in") }
            if !context.isComplete {
                token = try context.step(serverToken ?? [])
                // Checked before anything else is sent on its word.
                try checkServer()
                continue
            }
            try checkServer()
            // The server offers its security layers: one octet of flags (1
            // none, 2 signing, 4 encryption) and three of the largest message
            // it takes, wrapped but not encrypted (RFC 4752 §3.1).
            let offer = try context.unwrap(serverToken ?? [])
            guard offer.count == 4 else { throw LDAPError.kerberos("The server's Kerberos security-layer offer is malformed.") }
            guard sealing else {
                guard offer[0] & 0x01 != 0 else {
                    throw LDAPError.kerberos("The server requires a Kerberos security layer on top of TLS, which Forester does not use.")
                }
                token = try context.wrap([0x01, 0, 0, 0])
                continue
            }
            guard offer[0] & 0x04 != 0 else {
                let what = offer[0] & 0x02 != 0 ? "only signing, which leaves every answer readable on the network" : "no protection at all"
                throw LDAPError.kerberos("The server offers Kerberos \(what), not encryption, so the connection was not made. Use StartTLS or LDAPS.")
            }
            let serverLimit = Int(offer[1]) << 16 | Int(offer[2]) << 8 | Int(offer[3])
            let sendLimit = try context.wrapSizeLimit(tokensOf: serverLimit)
            guard sendLimit > 0 else {
                throw LDAPError.kerberos("The server's Kerberos security layer takes messages too small to carry anything (\(serverLimit) bytes).")
            }
            let receiveLimit = SASLSecurityLayer.receiveLimit
            armSecurityLayer(SASLSecurityLayer(context: context, sendLimit: sendLimit, receiveLimit: receiveLimit))
            // Encryption, the largest message Forester takes, and no
            // authorization identity: the ticket's own.
            token = try context.wrap([0x04, UInt8(truncatingIfNeeded: receiveLimit >> 16),
                                      UInt8(truncatingIfNeeded: receiveLimit >> 8), UInt8(truncatingIfNeeded: receiveLimit)])
        }
        throw LDAPError.kerberos("The Kerberos sign-in took more rounds than the protocol needs.")
    }
}

/// A SASL security layer in force (RFC 4422 §3.7): after the bind, every
/// message goes out encrypted by Kerberos, in frames of a four-octet length
/// and a wrapped token, and comes back the same way.
final class SASLSecurityLayer {
    let context: GSSContext
    /// The most plain bytes one frame may carry, so its token stays within
    /// what the server said it takes.
    let sendLimit: Int
    /// The largest token Forester takes from the server, as it told the
    /// server: one byte under 16 MB, the most three octets can say.
    let receiveLimit: Int
    static let receiveLimit = 0xFF_FFFF

    init(context: GSSContext, sendLimit: Int, receiveLimit: Int) {
        self.context = context
        self.sendLimit = sendLimit
        self.receiveLimit = receiveLimit
    }

    /// `message` sealed into as many frames as its size needs.
    func seal(_ message: [UInt8]) throws -> [UInt8] {
        var wire: [UInt8] = []
        var start = 0
        while start < message.count {
            let end = min(start + sendLimit, message.count)
            let token = try context.wrap(Array(message[start..<end]), encrypting: true)
            let length = token.count
            wire += [UInt8(truncatingIfNeeded: length >> 24), UInt8(truncatingIfNeeded: length >> 16),
                     UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length)]
            wire += token
            start = end
        }
        return wire
    }

    /// The plain bytes of every whole frame in `sealed`, which loses them;
    /// a frame not yet whole stays for the next read.
    func unseal(_ sealed: inout [UInt8]) throws -> [UInt8] {
        var plain: [UInt8] = []
        var offset = 0
        while sealed.count - offset >= 4 {
            let length = Int(sealed[offset]) << 24 | Int(sealed[offset + 1]) << 16 | Int(sealed[offset + 2]) << 8 | Int(sealed[offset + 3])
            guard length > 0, length <= receiveLimit else {
                throw LDAPError.protocolError("The server sent an encrypted frame of \(length) bytes, outside what was agreed (1 to \(receiveLimit)).")
            }
            guard sealed.count - offset - 4 >= length else { break }
            plain += try context.unwrap(Array(sealed[(offset + 4)..<(offset + 4 + length)]), mustBeEncrypted: true)
            offset += 4 + length
        }
        if offset > 0 { sealed.removeSubrange(0..<offset) }
        return plain
    }
}

/// RFC 5929 channel bindings.
enum ChannelBinding {
    /// `tls-server-end-point:` and a hash of the server's certificate: with the
    /// certificate's own signature hash, or SHA-256 where that is MD5 or SHA-1.
    static func tlsServerEndPoint(_ certificate: Data) -> Data? {
        guard let hash = certificateHash(certificate) else { return nil }
        return Data("tls-server-end-point:".utf8) + Data(hash)
    }

    /// The certificate hashed as tls-server-end-point hashes it.
    static func certificateHash(_ certificate: Data) -> [UInt8]? {
        switch signatureHash(certificate) {
        case .sha384: return Array(SHA384.hash(data: certificate))
        case .sha512: return Array(SHA512.hash(data: certificate))
        case .sha256: return Array(SHA256.hash(data: certificate))
        }
    }

    enum Hash { case sha256, sha384, sha512 }

    /// The hash of the certificate's signatureAlgorithm, the second element of
    /// the Certificate sequence.
    static func signatureHash(_ certificate: Data) -> Hash {
        guard let (outer, _) = try? BERDecoder.element(in: [UInt8](certificate)), let parts = try? outer.children(), parts.count >= 2,
              let algorithm = try? parts[1].children().first, algorithm.tag == 0x06 else { return .sha256 }
        switch algorithm.content {
        case [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C], [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03]: return .sha384
        case [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D], [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04]: return .sha512
        default: return .sha256
        }
    }
}

/// One GSS-API Kerberos security context, initiator side.
final class GSSContext {
    private var context: gss_ctx_id_t?
    private var name: gss_name_t?
    private let channelBinding: Data?
    /// Encryption and signing of every message were asked for.
    private let sealing: Bool
    private(set) var isComplete = false

    init(service: String, channelBinding: Data?, sealing: Bool = false) throws {
        self.channelBinding = channelBinding
        self.sealing = sealing
        var minor: OM_uint32 = 0
        var bytes = Array(service.utf8)
        let major = bytes.withUnsafeMutableBytes { raw -> OM_uint32 in
            var buffer = gss_buffer_desc(length: raw.count, value: raw.baseAddress)
            return gss_import_name(&minor, &buffer, &__gss_c_nt_hostbased_service_oid_desc, &name)
        }
        guard Self.succeeded(major) else { throw Self.error(major, minor, service: service) }
    }

    deinit {
        var minor: OM_uint32 = 0
        if context != nil { gss_delete_sec_context(&minor, &context, nil) }
        if name != nil { gss_release_name(&minor, &name) }
    }

    /// The next token to send, given the server's last one (nil to start).
    func step(_ input: [UInt8]?) throws -> [UInt8] {
        guard let name else { throw LDAPError.kerberos("No service name.") }
        var minor: OM_uint32 = 0
        var output = gss_buffer_desc()
        var flags: OM_uint32 = 0
        // Mutual authentication, so the server proves who it is too. Integrity
        // and confidentiality only without TLS: AD refuses them over TLS.
        var wanted = OM_uint32(GSS_C_MUTUAL_FLAG) | OM_uint32(GSS_C_SEQUENCE_FLAG)
        if sealing { wanted |= OM_uint32(GSS_C_INTEG_FLAG) | OM_uint32(GSS_C_CONF_FLAG) | OM_uint32(GSS_C_REPLAY_FLAG) }
        var inputBytes = input ?? []
        var applicationData = [UInt8](channelBinding ?? Data())
        let major = inputBytes.withUnsafeMutableBytes { inputRaw in
            applicationData.withUnsafeMutableBytes { bindingRaw -> OM_uint32 in
                var inputBuffer = gss_buffer_desc(length: inputRaw.count, value: inputRaw.baseAddress)
                var bindings = gss_channel_bindings_struct()
                bindings.initiator_addrtype = OM_uint32(GSS_C_AF_UNSPEC)
                bindings.acceptor_addrtype = OM_uint32(GSS_C_AF_UNSPEC)
                bindings.application_data = gss_buffer_desc(length: bindingRaw.count, value: bindingRaw.baseAddress)
                return withUnsafeMutablePointer(to: &bindings) { bindingsPointer in
                    withUnsafeMutablePointer(to: &inputBuffer) { inputPointer in
                        gss_init_sec_context(&minor, nil, &context, name, &__gss_krb5_mechanism_oid_desc, wanted, 0,
                                             channelBinding == nil ? nil : bindingsPointer,
                                             input == nil ? nil : inputPointer, nil, &output, &flags, nil)
                    }
                }
            }
        }
        defer { var ignored: OM_uint32 = 0; gss_release_buffer(&ignored, &output) }
        guard Self.succeeded(major) else { throw Self.error(major, minor, service: nil) }
        isComplete = major & Self.continueNeeded == 0
        if isComplete, let problem = Self.missingProtection(flags, sealing: sealing) {
            throw LDAPError.kerberos(problem)
        }
        return Self.bytes(output)
    }

    /// What the flags a complete context returned leave out, in words; nil
    /// when nothing. Sealing needs, besides encryption and signing, every
    /// message numbered (sequence) and a repeat refused (replay): without
    /// them a message recorded on the network could be sent again, or
    /// dropped, unnoticed.
    static func missingProtection(_ flags: OM_uint32, sealing: Bool) -> String? {
        guard flags & OM_uint32(GSS_C_MUTUAL_FLAG) != 0 else { return "The server did not prove who it is." }
        guard sealing else { return nil }
        let protects = OM_uint32(GSS_C_INTEG_FLAG) | OM_uint32(GSS_C_CONF_FLAG)
        guard flags & protects == protects else {
            return "Kerberos did not agree to encrypt this connection, so it was not used. Use StartTLS or LDAPS."
        }
        let ordered = OM_uint32(GSS_C_SEQUENCE_FLAG) | OM_uint32(GSS_C_REPLAY_FLAG)
        guard flags & ordered == ordered else {
            return "Kerberos did not agree to number the encrypted messages and refuse repeated ones, so the connection was not used. Use StartTLS or LDAPS."
        }
        return nil
    }

    /// The name of the server the completed context authenticated, as
    /// Kerberos displays it ("ldap/dc01.corp.example@CORP.EXAMPLE").
    func acceptorName() throws -> String {
        guard let context, isComplete else { throw LDAPError.kerberos("The Kerberos exchange is not complete.") }
        var minor: OM_uint32 = 0
        var target: gss_name_t?
        let major = gss_inquire_context(&minor, context, nil, &target, nil, nil, nil, nil, nil)
        defer { if target != nil { var ignored: OM_uint32 = 0; gss_release_name(&ignored, &target) } }
        guard Self.succeeded(major), let target else { throw Self.error(major, minor, service: nil) }
        var buffer = gss_buffer_desc()
        let shown = gss_display_name(&minor, target, &buffer, nil)
        defer { var ignored: OM_uint32 = 0; gss_release_buffer(&ignored, &buffer) }
        guard Self.succeeded(shown) else { throw Self.error(shown, minor, service: nil) }
        return String(decoding: Self.bytes(buffer), as: UTF8.self)
    }

    /// Whether `principal`, a Kerberos service name, is the LDAP service of
    /// `host` exactly: `ldap/host@REALM` (any realm) or `ldap@host`, in any
    /// case, a trailing dot aside. A name DNS turned the host into is not.
    static func acceptorMatches(_ principal: String, host: String) -> Bool {
        var name = Substring(principal)
        if let at = name.lastIndex(of: "@"), name.contains("/") { name = name[..<at] }
        let parts = name.split(separator: name.contains("/") ? "/" : "@", omittingEmptySubsequences: false)
        guard parts.count == 2, parts[0].caseInsensitiveCompare("ldap") == .orderedSame else { return false }
        func bare(_ text: Substring) -> String { (text.hasSuffix(".") ? text.dropLast() : text).lowercased() }
        return !parts[1].isEmpty && bare(parts[1]) == bare(Substring(host))
    }

    /// No calling or routine error (the top sixteen bits); the low bits are
    /// supplementary information such as "continue needed".
    static func succeeded(_ major: OM_uint32) -> Bool { major & 0xFFFF_0000 == 0 }
    static let continueNeeded: OM_uint32 = 1

    /// `mustBeEncrypted`: a token that is only signed is refused, so nobody
    /// on the network can slip a readable message into an encrypted session.
    func unwrap(_ token: [UInt8], mustBeEncrypted: Bool = false) throws -> [UInt8] {
        guard let context, isComplete else { throw LDAPError.kerberos("The Kerberos exchange is not complete.") }
        var minor: OM_uint32 = 0
        var output = gss_buffer_desc()
        var input = token
        var encrypted: Int32 = 0
        let major = input.withUnsafeMutableBytes { raw -> OM_uint32 in
            var buffer = gss_buffer_desc(length: raw.count, value: raw.baseAddress)
            return gss_unwrap(&minor, context, &buffer, &output, &encrypted, nil)
        }
        defer { var ignored: OM_uint32 = 0; gss_release_buffer(&ignored, &output) }
        guard Self.succeeded(major) else { throw Self.error(major, minor, service: nil) }
        // Supplementary bits say a token was repeated, out of order or missed;
        // in a session that numbers its messages, each is an attack or a loss.
        if mustBeEncrypted, major & 0xFFFF != 0 {
            throw LDAPError.kerberos("An encrypted message from the server arrived repeated or out of order, so the connection was closed.")
        }
        if mustBeEncrypted, encrypted == 0 {
            throw LDAPError.kerberos("The server sent a message that was not encrypted on a connection agreed to be, so the connection was closed.")
        }
        return Self.bytes(output)
    }

    /// `encrypting` false only signs, as the security-layer offer and answer are.
    func wrap(_ message: [UInt8], encrypting: Bool = false) throws -> [UInt8] {
        guard let context, isComplete else { throw LDAPError.kerberos("The Kerberos exchange is not complete.") }
        var minor: OM_uint32 = 0
        var output = gss_buffer_desc()
        var input = message
        var encrypted: Int32 = 0
        let major = input.withUnsafeMutableBytes { raw -> OM_uint32 in
            var buffer = gss_buffer_desc(length: raw.count, value: raw.baseAddress)
            return gss_wrap(&minor, context, encrypting ? 1 : 0, gss_qop_t(GSS_C_QOP_DEFAULT), &buffer, &encrypted, &output)
        }
        defer { var ignored: OM_uint32 = 0; gss_release_buffer(&ignored, &output) }
        guard Self.succeeded(major) else { throw Self.error(major, minor, service: nil) }
        if encrypting, encrypted == 0 { throw LDAPError.kerberos("Kerberos did not encrypt a message, so it was not sent.") }
        return Self.bytes(output)
    }

    /// The most plain bytes whose encrypted token is at most `size` bytes.
    func wrapSizeLimit(tokensOf size: Int) throws -> Int {
        guard let context, isComplete else { throw LDAPError.kerberos("The Kerberos exchange is not complete.") }
        guard size > 0 else { return 0 }
        var minor: OM_uint32 = 0
        var limit: OM_uint32 = 0
        let major = gss_wrap_size_limit(&minor, context, 1, gss_qop_t(GSS_C_QOP_DEFAULT), OM_uint32(clamping: size), &limit)
        guard Self.succeeded(major) else { throw Self.error(major, minor, service: nil) }
        return Int(limit)
    }

    private static func bytes(_ buffer: gss_buffer_desc) -> [UInt8] {
        guard let value = buffer.value, buffer.length > 0 else { return [] }
        return [UInt8](UnsafeRawBufferPointer(start: value, count: buffer.length))
    }

    /// The framework's own words for a failure, with what to do about the
    /// common ones.
    static func error(_ major: OM_uint32, _ minor: OM_uint32, service: String?) -> LDAPError {
        var text = ""
        var context: OM_uint32 = 0
        var status: OM_uint32 = 0
        var message = gss_buffer_desc()
        if gss_display_status(&status, minor, Int32(GSS_C_MECH_CODE), &__gss_krb5_mechanism_oid_desc, &context, &message) == GSS_S_COMPLETE {
            text = String(decoding: bytes(message), as: UTF8.self)
            gss_release_buffer(&status, &message)
        }
        if text.isEmpty, gss_display_status(&status, major, Int32(GSS_C_GSS_CODE), nil, &context, &message) == GSS_S_COMPLETE {
            text = String(decoding: bytes(message), as: UTF8.self)
            gss_release_buffer(&status, &message)
        }
        let lower = text.lowercased()
        if lower.contains("credential") && (lower.contains("not found") || lower.contains("no credentials")) || lower.contains("no kerberos credentials") {
            return .kerberos("There is no Kerberos ticket to sign in with (\(text)). Get one with Ticket Viewer or `kinit you@REALM`, then connect again.")
        }
        if lower.contains("expired") {
            return .kerberos("Your Kerberos ticket has expired (\(text)). Renew it with Ticket Viewer or kinit, then connect again.")
        }
        if lower.contains("server not found") || lower.contains("unknown server") {
            return .kerberos("Kerberos does not know this server's name (\(text)). Connect by the domain controller's full DNS name, not an IP address or an alias.")
        }
        return .kerberos(text.isEmpty ? String(format: "Kerberos failed (0x%08x, %u).", major, minor) : text)
    }
}
