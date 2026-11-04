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
/// Only over TLS, with no SASL security layer: TLS already protects the
/// connection, and Active Directory refuses Kerberos signing or sealing on
/// top of TLS. The TLS certificate is bound into the Kerberos exchange
/// (RFC 5929 tls-server-end-point), which domain controllers can require
/// ("LDAP channel binding"), so a ticket cannot be relayed through another
/// TLS connection.
extension LDAPConnection {
    public func bindKerberos() async throws {
        guard isSecure else {
            throw LDAPError.kerberos("Kerberos sign-in needs an encrypted connection: use StartTLS or LDAPS.")
        }
        // The binding ties the ticket to the certificate this connection saw.
        // Accepting any certificate would tie it to whoever is in between,
        // who could pass the exchange on to the real server and be signed in.
        guard !options.trust.trustAnyCertificate else {
            throw LDAPError.kerberos("Kerberos sign-in is not used with “Accept any certificate”: it would sign in whoever is between this Mac and the server. Trust the server's certificate instead.")
        }
        // TLS starts with the first request, and the binding needs its
        // certificate: asking which mechanisms the server offers does both.
        let offered = try await read("", attributes: ["supportedSASLMechanisms"])?.strings("supportedSASLMechanisms") ?? []
        guard offered.isEmpty || offered.contains(where: { $0.caseInsensitiveCompare("GSSAPI") == .orderedSame }) else {
            throw LDAPError.kerberos("The server does not offer Kerberos sign-in (it offers \(offered.joined(separator: ", "))).")
        }
        // Without the certificate there is nothing to bind to, and a ticket
        // that is not bound could be used over another connection.
        guard let certificate = serverCertificate, let binding = ChannelBinding.tlsServerEndPoint(certificate) else {
            throw LDAPError.kerberos("The server's TLS certificate was not seen, so the Kerberos sign-in could not be bound to this connection.")
        }
        try await bindKerberos(channelBinding: binding)
    }

    func bindKerberos(channelBinding binding: Data?) async throws {
        let context = try GSSContext(service: "ldap@\(options.host)", channelBinding: binding)
        var token = try context.step(nil)
        // Token exchanges, an empty turn once the context is complete, then
        // the security-layer offer and answer: a handful of rounds at most.
        for _ in 0..<8 {
            let (result, serverToken) = try await saslBind(mechanism: "GSSAPI", credentials: token)
            if result.code == .success {
                guard context.isComplete else { throw LDAPError.kerberos("The server accepted the sign-in before proving who it is.") }
                boundDN = nil
                return
            }
            guard result.code == .saslBindInProgress else { throw LDAPError.server(result, operation: "Kerberos sign-in") }
            if !context.isComplete {
                token = try context.step(serverToken ?? [])
            } else {
                // The server offers its security layers: one octet of flags and
                // three of buffer size, wrapped. Forester takes none (bit 1).
                let offer = try context.unwrap(serverToken ?? [])
                guard offer.count == 4, offer[0] & 0x01 != 0 else {
                    throw LDAPError.kerberos("The server requires a Kerberos security layer on top of TLS, which Forester does not use.")
                }
                token = try context.wrap([0x01, 0, 0, 0])
            }
        }
        throw LDAPError.kerberos("The Kerberos sign-in took more rounds than the protocol needs.")
    }

    /// One SASL bind request: the server's result and its token, if any.
    func saslBind(mechanism: String, credentials: [UInt8]) async throws -> (LDAPResult, [UInt8]?) {
        let responses = try await perform(LDAPCodec.saslBind(mechanism: mechanism, credentials: credentials), name: "Bind")
        guard case .bind(let result, let serverCredentials)? = responses.last?.kind else {
            throw LDAPError.protocolError("bind got no bind response")
        }
        return (result, serverCredentials)
    }
}

extension LDAPCodec {
    /// BindRequest with SaslCredentials (RFC 4511 §4.2): version, an empty
    /// name, and [3] { mechanism, credentials }.
    static func saslBind(mechanism: String, credentials: [UInt8]) -> [UInt8] {
        BER.sequence([BER.integer(3), BER.octetString(""),
                      BER.sequence([BER.octetString(mechanism), BER.octetString(credentials)], tag: 0xA3)], tag: 0x60)
    }
}

/// RFC 5929 channel bindings.
enum ChannelBinding {
    /// `tls-server-end-point:` and a hash of the server's certificate: with the
    /// certificate's own signature hash, or SHA-256 where that is MD5 or SHA-1.
    static func tlsServerEndPoint(_ certificate: Data) -> Data? {
        let hash: [UInt8]
        switch signatureHash(certificate) {
        case .sha384: hash = Array(SHA384.hash(data: certificate))
        case .sha512: hash = Array(SHA512.hash(data: certificate))
        case .sha256: hash = Array(SHA256.hash(data: certificate))
        }
        return Data("tls-server-end-point:".utf8) + Data(hash)
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
    private(set) var isComplete = false

    init(service: String, channelBinding: Data?) throws {
        self.channelBinding = channelBinding
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
        // Mutual authentication, so the server proves who it is too; no
        // integrity or confidentiality flags, which AD refuses over TLS.
        let wanted = OM_uint32(GSS_C_MUTUAL_FLAG) | OM_uint32(GSS_C_SEQUENCE_FLAG)
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
        if isComplete, flags & OM_uint32(GSS_C_MUTUAL_FLAG) == 0 {
            throw LDAPError.kerberos("The server did not prove who it is.")
        }
        return Self.bytes(output)
    }

    /// No calling or routine error (the top sixteen bits); the low bits are
    /// supplementary information such as "continue needed".
    static func succeeded(_ major: OM_uint32) -> Bool { major & 0xFFFF_0000 == 0 }
    static let continueNeeded: OM_uint32 = 1

    func unwrap(_ token: [UInt8]) throws -> [UInt8] {
        guard let context, isComplete else { throw LDAPError.kerberos("The Kerberos exchange is not complete.") }
        var minor: OM_uint32 = 0
        var output = gss_buffer_desc()
        var input = token
        let major = input.withUnsafeMutableBytes { raw -> OM_uint32 in
            var buffer = gss_buffer_desc(length: raw.count, value: raw.baseAddress)
            return gss_unwrap(&minor, context, &buffer, &output, nil, nil)
        }
        defer { var ignored: OM_uint32 = 0; gss_release_buffer(&ignored, &output) }
        guard Self.succeeded(major) else { throw Self.error(major, minor, service: nil) }
        return Self.bytes(output)
    }

    func wrap(_ message: [UInt8]) throws -> [UInt8] {
        guard let context, isComplete else { throw LDAPError.kerberos("The Kerberos exchange is not complete.") }
        var minor: OM_uint32 = 0
        var output = gss_buffer_desc()
        var input = message
        let major = input.withUnsafeMutableBytes { raw -> OM_uint32 in
            var buffer = gss_buffer_desc(length: raw.count, value: raw.baseAddress)
            return gss_wrap(&minor, context, 0, gss_qop_t(GSS_C_QOP_DEFAULT), &buffer, nil, &output)
        }
        defer { var ignored: OM_uint32 = 0; gss_release_buffer(&ignored, &output) }
        guard Self.succeeded(major) else { throw Self.error(major, minor, service: nil) }
        return Self.bytes(output)
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
