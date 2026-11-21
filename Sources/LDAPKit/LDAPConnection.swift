// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

public struct LDAPSearchRequest: Sendable {
    public var base: String
    public var scope: LDAPScope
    public var filter: LDAPFilter
    public var attributes: [String]
    public var sizeLimit: Int
    public var timeLimit: Int
    public var typesOnly: Bool
    public var derefAliases: LDAPDerefAliases
    public var controls: [LDAPControl]

    public init(base: String, scope: LDAPScope, filter: LDAPFilter = .present("objectClass"),
                attributes: [String] = [], sizeLimit: Int = 0, timeLimit: Int = 0, typesOnly: Bool = false,
                derefAliases: LDAPDerefAliases = .never, controls: [LDAPControl] = []) {
        self.base = base
        self.scope = scope
        self.filter = filter
        self.attributes = attributes
        self.sizeLimit = sizeLimit
        self.timeLimit = timeLimit
        self.typesOnly = typesOnly
        self.derefAliases = derefAliases
        self.controls = controls
    }
}

public struct LDAPSearchResult: Sendable {
    public var entries: [LDAPEntry]
    /// Continuation references the server returned instead of entries it does
    /// not hold (AD returns these for the DNS and configuration partitions).
    public var references: [String]
    public var result: LDAPResult
    public var responseControls: [LDAPControl]
    /// The client stopped paging because it reached the requested limit.
    public var stoppedAtLimit: Bool

    public init(entries: [LDAPEntry] = [], references: [String] = [], result: LDAPResult = LDAPResult(code: .success),
                responseControls: [LDAPControl] = [], stoppedAtLimit: Bool = false) {
        self.entries = entries
        self.references = references
        self.result = result
        self.responseControls = responseControls
        self.stoppedAtLimit = stoppedAtLimit
    }

    /// Everything matching was returned.
    public var isComplete: Bool { result.code == .success && !stoppedAtLimit }
}

/// One connection to a directory server. Requests are pipelined: each carries a
/// message ID, and responses are routed back to the request that is waiting
/// for them, so a slow search does not hold up a quick lookup.
public actor LDAPConnection {
    public enum Security: String, Codable, Sendable, CaseIterable {
        case none, startTLS, ldaps

        public var label: String {
            switch self {
            case .none: return "None"
            case .startTLS: return "StartTLS"
            case .ldaps: return "LDAPS"
            }
        }

        public var defaultPort: Int { self == .ldaps ? 636 : 389 }
    }

    public struct Options: Sendable {
        public var host: String
        public var port: Int
        public var security: Security
        /// Seconds to wait for each response, and for the connection itself.
        public var timeout: TimeInterval
        public var trust: TrustPolicy
        /// The certificate to show a server that asks for one (SASL EXTERNAL).
        public var clientIdentity: ClientIdentity?

        public init(host: String, port: Int, security: Security, timeout: TimeInterval = 30, trust: TrustPolicy = TrustPolicy(),
                    clientIdentity: ClientIdentity? = nil) {
            self.host = host
            self.port = port
            self.security = security
            self.timeout = timeout
            self.trust = trust
            self.clientIdentity = clientIdentity
        }
    }

    public static let startTLSOID = "1.3.6.1.4.1.1466.20037"
    public static let whoAmIOID = "1.3.6.1.4.1.4203.1.11.3"

    public let options: Options
    /// TLS protects the connection (LDAPS, or StartTLS once it is up).
    public private(set) var usesTLS = false
    /// Kerberos encrypts every message: a SASL security layer is in force.
    public var isSealed: Bool { securityLayer != nil }
    /// What is sent and received cannot be read on the network: TLS, or
    /// Kerberos encryption.
    public var isSecure: Bool { usesTLS || isSealed }
    public internal(set) var boundDN: String?

    private var transport: LDAPTransport?

    /// The certificate the server presented, once TLS is up (DER).
    var serverCertificate: Data? { transport?.serverCertificate }
    /// The server asked for a client certificate in the TLS handshake.
    var clientCertificateRequested: Bool { transport?.clientCertificateRequested ?? false }
    private var nextMessageID = 1
    /// Received bytes not yet decoded, after any security layer.
    private var buffer: [UInt8] = []
    /// Received bytes of encrypted frames not yet whole.
    private var sealedBuffer: [UInt8] = []
    private var securityLayer: SASLSecurityLayer?
    /// Agreed on during a bind, and in force from that bind's answer on.
    private var armedSecurityLayer: SASLSecurityLayer?
    /// Sees every byte as it arrives, before any security layer: lets a test
    /// check that nothing readable crosses the network.
    private var receivedBytesObserver: (@Sendable ([UInt8]) -> Void)?
    private var pending: [Int: PendingOperation] = [:]
    private var reading = false
    private var receivedAnything = false
    private var failure: LDAPError?

    private final class PendingOperation {
        let name: String
        let continuation: CheckedContinuation<[LDAPResponse], Error>
        var responses: [LDAPResponse] = []
        var timeoutTask: Task<Void, Never>?
        /// How long to wait for the next response; counted again from each one,
        /// so a long search that keeps sending entries does not time out.
        var timeout: TimeInterval = 0
        /// When the server last answered this request.
        var lastHeard = ContinuousClock.now

        init(name: String, continuation: CheckedContinuation<[LDAPResponse], Error>) {
            self.name = name
            self.continuation = continuation
        }
    }

    public init(_ options: Options) {
        self.options = options
    }

    public var isAlive: Bool { transport != nil && failure == nil }

    /// Opens the connection and, for StartTLS, negotiates TLS. The TCP connection
    /// itself is made lazily, so a wrong host or port surfaces on the first request.
    public func open() async throws {
        let transport = LDAPTransport(host: options.host, port: options.port, trust: options.trust, clientIdentity: options.clientIdentity)
        self.transport = transport
        transport.resume()
        switch options.security {
        case .none:
            break
        case .ldaps:
            transport.startTLS()
            usesTLS = true
        case .startTLS:
            do {
                let responses = try await perform(LDAPCodec.extended(oid: Self.startTLSOID), name: "StartTLS")
                guard case .extended(let result, _, _)? = responses.last?.kind else {
                    throw LDAPError.protocolError("StartTLS got no extended response")
                }
                guard result.code == .success else { throw LDAPError.server(result, operation: "StartTLS") }
                // Anything after the answer arrived before encryption, so anyone
                // on the path could have added it (STARTTLS command injection).
                guard buffer.isEmpty else { throw LDAPError.protocolError("The server sent more after agreeing to StartTLS, before encryption began.") }
            } catch {
                // The URLSession holds the transport until it is invalidated, so
                // a refused StartTLS must close it or the socket stays open.
                close()
                throw error
            }
            // The reader stops once nothing is outstanding, so no read is queued
            // that the handshake would have to wait behind.
            transport.startTLS()
            usesTLS = true
        }
    }

    /// A connection dropped without close() still lets go of its socket.
    deinit {
        transport?.close()
    }

    public func close() {
        guard let transport else { return }
        let wasHealthy = failure == nil
        fail(everything: .connectionClosed, closingTransport: false)
        self.transport = nil
        if wasHealthy {
            // Unbind is a courtesy; the server cleans up either way.
            let bytes = LDAPCodec.message(id: allocateID(), op: LDAPCodec.unbind)
            transmit(bytes, via: transport, timeout: 2) { _ in transport.close() }
        } else {
            transport.close()
        }
    }

    // MARK: Operations

    /// Simple bind. An empty password with a non-empty name is refused here:
    /// RFC 4513 calls that an unauthenticated bind, and servers that allow it
    /// report success without checking anything.
    public func bind(dn: String, password: String) async throws {
        if !dn.isEmpty && password.isEmpty { throw LDAPError.emptyPassword }
        let responses = try await perform(LDAPCodec.simpleBind(dn: dn, password: password), name: "Bind")
        guard case .bind(let result, _)? = responses.last?.kind else {
            throw LDAPError.protocolError("bind got no bind response")
        }
        guard result.code == .success else { throw LDAPError.server(result, operation: "Bind") }
        boundDN = dn.isEmpty ? nil : dn
    }

    public func search(_ request: LDAPSearchRequest) async throws -> LDAPSearchResult {
        let op = LDAPCodec.search(base: request.base, scope: request.scope, deref: request.derefAliases,
                                  sizeLimit: request.sizeLimit, timeLimit: request.timeLimit,
                                  typesOnly: request.typesOnly, filter: request.filter, attributes: request.attributes)
        let responses = try await perform(op, controls: request.controls, name: "Search")
        var result = LDAPSearchResult()
        for response in responses {
            switch response.kind {
            case .searchEntry(let entry): result.entries.append(entry)
            case .searchReference(let urls): result.references += urls
            case .searchDone(let done):
                result.result = done
                result.responseControls = response.controls
            default: break
            }
        }
        switch result.result.code {
        case .success, .sizeLimitExceeded, .timeLimitExceeded, .adminLimitExceeded:
            return result
        default:
            throw LDAPError.server(result.result, operation: "Search")
        }
    }

    /// Searches with the simple paged results control, so the server's per-query
    /// cap (1,000 in AD) does not cut the answer short. Stops after `limit`
    /// entries when given, and tells the server to release the rest.
    public func pagedSearch(_ request: LDAPSearchRequest, pageSize: Int = 500, limit: Int? = nil,
                            progress: (@Sendable (Int) -> Void)? = nil) async throws -> LDAPSearchResult {
        var cookie: [UInt8] = []
        var total = LDAPSearchResult()
        var size = pageSize
        // AD sends an empty page now and then on a slow query; a server that
        // only ever does is not making progress.
        var emptyPages = 0
        // A server that pages for ever, or answers each page with the same
        // cookie, would otherwise fill the Mac's memory.
        var repeatedCookies = 0
        var bytes = 0
        while true {
            try Task.checkCancellation()
            var page = request
            page.controls.append(.pagedResults(size: size, cookie: cookie))
            let result = try await search(page)
            // AD quietly caps a page at its MaxPageSize; OpenLDAP refuses a page
            // larger than its size.pr limit outright. Ask again for less.
            if result.result.code == .adminLimitExceeded, result.entries.isEmpty, cookie.isEmpty, size > 10 {
                size = max(10, size / 2)
                continue
            }
            total.entries += result.entries
            total.references += result.references
            total.result = result.result
            progress?(total.entries.count)
            bytes += result.entries.reduce(0) { sum, entry in
                sum + entry.dn.utf8.count + entry.attributes.reduce(0) { $0 + $1.name.utf8.count + $1.values.reduce(0) { $0 + $1.count } }
            }

            guard let next = result.responseControls.lazy.compactMap(\.pagedResultsCookie).first else {
                break // the server does not page; what it sent is everything
            }
            repeatedCookies = !next.isEmpty && next == cookie ? repeatedCookies + 1 : 0
            cookie = next
            if total.entries.count > Self.maxEntriesPerSearch || bytes > Self.maxBytesPerSearch || repeatedCookies >= 100 {
                await releasePagedSearch(request, cookie: cookie)
                throw LDAPError.protocolError(repeatedCookies >= 100
                    ? "The server kept answering with the same page; the search was stopped."
                    : "The search returned more than \(Self.maxEntriesPerSearch.formatted()) entries or \(Self.maxBytesPerSearch / 1_000_000_000) GB; it was stopped. Narrow it with a filter or a smaller base.")
            }
            if cookie.isEmpty || result.result.code != .success { break }
            emptyPages = result.entries.isEmpty && result.references.isEmpty ? emptyPages + 1 : 0
            if emptyPages >= 1_000 {
                await releasePagedSearch(request, cookie: cookie)
                throw LDAPError.protocolError("The server sent a thousand empty pages in a row; the search was stopped.")
            }
            if let limit, total.entries.count >= limit {
                total.stoppedAtLimit = true
                await releasePagedSearch(request, cookie: cookie)
                break
            }
        }
        return total
    }

    /// More results than this for one request (one page of a paged search)
    /// are refused rather than kept.
    static let maxResponsesPerRequest = 1_000_000

    /// What one paged search may gather in all, entries and bytes of values:
    /// more than any directory a person browses, less than fills a Mac.
    static let maxEntriesPerSearch = 2_000_000
    static let maxBytesPerSearch = 2_000_000_000

    /// A page size of zero with the last cookie abandons a paged search (RFC 2696 §3).
    private func releasePagedSearch(_ request: LDAPSearchRequest, cookie: [UInt8]) async {
        var release = request
        release.controls.append(.pagedResults(size: 0, cookie: cookie))
        _ = try? await search(release)
    }

    /// Reads one entry. Returns nil when it does not exist.
    public func read(_ dn: String, attributes: [String] = ["*", "+"], controls: [LDAPControl] = []) async throws -> LDAPEntry? {
        do {
            let result = try await search(LDAPSearchRequest(base: dn, scope: .base, attributes: attributes, controls: controls))
            return result.entries.first
        } catch let error as LDAPError where error.resultCode == .noSuchObject {
            return nil
        }
    }

    /// Reads each DN, several requests in flight at once (the connection
    /// pipelines them), and returns the entries that exist in the order
    /// asked. One read after another, a few thousand took minutes over a VPN.
    /// With `skippingErrors`, an entry that cannot be read counts as missing.
    public func readEach(_ dns: [String], attributes: [String], inFlight: Int = 8,
                         skippingErrors: Bool = false) async throws -> [LDAPEntry] {
        var found = [LDAPEntry?](repeating: nil, count: dns.count)
        try await withThrowingTaskGroup(of: (Int, LDAPEntry?).self) { group in
            var next = 0
            func start() {
                let index = next
                next += 1
                group.addTask {
                    do {
                        return (index, try await self.read(dns[index], attributes: attributes))
                    } catch where skippingErrors && !(error is CancellationError) {
                        return (index, nil)
                    }
                }
            }
            while next < min(max(1, inFlight), dns.count) { start() }
            while let (index, entry) = try await group.next() {
                found[index] = entry
                if next < dns.count { start() }
            }
        }
        return found.compactMap { $0 }
    }

    /// The root DSE: naming contexts, supported controls, and what kind of server this is.
    public func rootDSE() async throws -> LDAPEntry {
        let result = try await search(LDAPSearchRequest(base: "", scope: .base, attributes: ["*", "+"]))
        return result.entries.first ?? LDAPEntry(dn: "", attributes: [])
    }

    /// The identity the server associates with this connection (RFC 4532), or
    /// nil when the server does not implement "Who am I?".
    public func whoAmI() async throws -> String? {
        let responses = try await perform(LDAPCodec.extended(oid: Self.whoAmIOID), name: "Who am I")
        guard case .extended(let result, _, let value)? = responses.last?.kind, result.code == .success else { return nil }
        let identity = value.map { String(decoding: $0, as: UTF8.self) } ?? ""
        return identity.isEmpty ? "anonymous" : identity
    }

    /// Active Directory returns at most 1,500 values of a multi-valued attribute
    /// at a time, as `member;range=0-1499`. Fetches the remaining ranges and
    /// returns the entry with each such attribute whole, under its plain name.
    public func completingRangedAttributes(_ entry: LDAPEntry) async throws -> LDAPEntry {
        guard entry.attributes.contains(where: { $0.name.lowercased().contains(";range=") }) else { return entry }
        var completed = entry
        for (index, attribute) in entry.attributes.enumerated() {
            guard var range = RangedAttribute(attribute.name) else { continue }
            let firstStart = range.start
            var values = attribute.values
            var complete = true
            var guardCount = 0
            while let end = range.end {
                guardCount += 1
                // A range ending at Int.max, or one that never ends, is not a range to follow.
                guard guardCount < 10_000, end < Int.max else { complete = false; break }
                let nextName = "\(range.base);range=\(end + 1)-*"
                guard let more = try await read(entry.dn, attributes: [nextName]),
                      let piece = more.attributes.first(where: { RangedAttribute($0.name)?.base.caseInsensitiveCompare(range.base) == .orderedSame }),
                      let pieceRange = RangedAttribute(piece.name) else {
                    // The entry moved or changed between reads: what was read is
                    // kept under its range name, so it is not taken for the whole.
                    complete = false
                    break
                }
                values += piece.values
                range = pieceRange
            }
            // The server chose the numbers, so they may be anything.
            let (last, overflow) = firstStart.addingReportingOverflow(max(values.count - 1, 0))
            let name = complete ? range.base : "\(range.base);range=\(firstStart)-\(overflow ? "*" : String(last))"
            completed.attributes[index] = LDAPAttribute(name: name, values: values)
        }
        return completed
    }

    // MARK: Request plumbing

    private func allocateID() -> Int {
        let id = nextMessageID
        nextMessageID = nextMessageID == Int(Int32.max) ? 1 : nextMessageID + 1
        return id
    }

    /// Sends one request and waits for its final response (with any entries
    /// that came before it). Internal so the write operations can use it.
    /// `timeout` overrides the connection's for an operation the server
    /// answers only when it is done (AD's tree delete).
    func perform(_ op: [UInt8], controls: [LDAPControl] = [], name: String, timeout: TimeInterval? = nil) async throws -> [LDAPResponse] {
        if let failure { throw failure }
        guard let transport else { throw LDAPError.notConnected }
        try Task.checkCancellation()
        let id = allocateID()
        let bytes = LDAPCodec.message(id: id, op: op, controls: controls)
        let timeout = timeout ?? options.timeout
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[LDAPResponse], Error>) in
                let operation = PendingOperation(name: name, continuation: continuation)
                operation.timeout = timeout
                pending[id] = operation
                arm(operation, id: id)
                send(bytes, for: id, via: transport)
            }
        } onCancel: {
            Task { await self.cancel(id) }
        }
    }

    /// Starts the wait for the operation's responses: one timer for the whole
    /// request, which sleeps again for what is left since the last response
    /// rather than a new timer per response (50,000 for a big search).
    private func arm(_ operation: PendingOperation, id: Int) {
        operation.timeoutTask?.cancel()
        let timeout = operation.timeout
        guard timeout > 0 else { return }
        operation.lastHeard = .now
        operation.timeoutTask = Task { [weak self] in
            var wait = Duration.seconds(timeout)
            while true {
                try? await Task.sleep(for: wait)
                guard !Task.isCancelled, let self, let left = await self.timeLeft(id) else { return }
                if left <= .zero {
                    await self.expire(id)
                    return
                }
                wait = left
            }
        }
    }

    /// How long the operation may still wait before it has heard nothing for
    /// its whole timeout; nil once it is no longer pending.
    private func timeLeft(_ id: Int) -> Duration? {
        guard let operation = pending[id] else { return nil }
        return .seconds(operation.timeout) - (ContinuousClock.now - operation.lastHeard)
    }

    private func send(_ bytes: [UInt8], for id: Int, via transport: LDAPTransport) {
        guard pending[id] != nil else { return }
        transmit(bytes, via: transport, timeout: options.timeout) { [weak self] error in
            Task { await self?.sent(error, via: transport) }
        }
    }

    private func sent(_ error: Error?, via transport: LDAPTransport) {
        guard let error else {
            startReading()
            return
        }
        fail(everything: transport.translate(error, security: options.security, timeout: options.timeout))
    }

    /// Encrypts the message when a security layer is in force and queues it
    /// for writing, in one step on the actor: frames then go out in the order
    /// they were encrypted, which Kerberos checks by numbering them.
    private func transmit(_ message: [UInt8], via transport: LDAPTransport, timeout: TimeInterval,
                          completion: @escaping @Sendable (Error?) -> Void) {
        do {
            let wire = try securityLayer?.seal(message) ?? message
            transport.enqueueWrite(wire, timeout: timeout, completion: completion)
        } catch {
            completion(error)
        }
    }

    /// Called from a bind once the server's offer is accepted; the layer takes
    /// effect when that bind's answer arrives (`dispatch`).
    func armSecurityLayer(_ layer: SASLSecurityLayer) {
        armedSecurityLayer = layer
    }

    func disarmSecurityLayer() {
        armedSecurityLayer = nil
    }

    func observeReceivedBytes(_ observer: @escaping @Sendable ([UInt8]) -> Void) {
        receivedBytesObserver = observer
    }

    /// The most plain bytes one encrypted frame carries, with a layer in force.
    var sealedFrameLimit: Int? { securityLayer?.sendLimit }

    private func startReading() {
        guard !reading, !pending.isEmpty, let transport else { return }
        reading = true
        Task { await self.readLoop(transport) }
    }

    /// Reads only while a request is outstanding. Besides saving a parked read
    /// per idle connection, this is what lets StartTLS work: the handshake is
    /// queued behind pending reads, so one waiting for data would block it.
    private func readLoop(_ transport: LDAPTransport) async {
        defer { reading = false }
        while !pending.isEmpty, failure == nil, self.transport === transport {
            do {
                let (data, atEOF) = try await transport.read()
                if let data, !data.isEmpty {
                    receivedAnything = true
                    try ingest(data)
                }
                if atEOF {
                    fail(everything: transport.trustFailure.map(LDAPError.untrustedCertificate) ?? .connectionClosed)
                    return
                }
            } catch let error as BERError {
                fail(everything: .protocolError(error.description))
                return
            } catch let error as LDAPError {
                fail(everything: error)
                return
            } catch {
                fail(everything: transport.translate(error, security: options.security, timeout: options.timeout))
                return
            }
        }
    }

    private func ingest(_ data: Data) throws {
        receivedBytesObserver?([UInt8](data))
        if let securityLayer {
            sealedBuffer.append(contentsOf: data)
            buffer += try securityLayer.unseal(&sealedBuffer)
        } else {
            buffer.append(contentsOf: data)
        }
        var offset = 0
        while let (element, next) = try BERDecoder.element(in: buffer, at: offset) {
            offset = next
            let wasSealed = securityLayer != nil
            dispatch(try LDAPCodec.decodeResponse(element))
            if !wasSealed, let securityLayer {
                // That was the bind that agreed on the layer, the last message
                // in the clear: whatever came after it is encrypted.
                sealedBuffer = Array(buffer[offset...])
                buffer = try securityLayer.unseal(&sealedBuffer)
                offset = 0
            }
        }
        if offset > 0 { buffer.removeSubrange(0..<offset) }
    }

    private func dispatch(_ response: LDAPResponse) {
        if let armed = armedSecurityLayer, case .bind(let result, _) = response.kind, pending[response.messageID] != nil {
            armedSecurityLayer = nil
            if result.code == .success { securityLayer = armed }
        }
        if response.messageID == 0 {
            // Unsolicited notification; the only one defined is the notice of
            // disconnection (RFC 4511 §4.4.1), after which the server hangs up.
            var reason = "notice of disconnection"
            if case .extended(let result, _, _) = response.kind {
                reason = result.diagnosticMessage.isEmpty ? result.code.name : result.diagnosticMessage
            }
            fail(everything: .serverDisconnected(reason))
            return
        }
        guard let operation = pending[response.messageID] else { return }
        operation.responses.append(response)
        if operation.responses.count > Self.maxResponsesPerRequest {
            // A server that never stops sending would use up the Mac's memory.
            pending[response.messageID] = nil
            operation.timeoutTask?.cancel()
            operation.continuation.resume(throwing: LDAPError.protocolError(
                "The server sent more than \(Self.maxResponsesPerRequest.formatted()) results for one request; the rest were not read."))
            abandon(response.messageID)
            return
        }
        guard response.kind.isFinal else {
            operation.lastHeard = .now
            return
        }
        pending[response.messageID] = nil
        operation.timeoutTask?.cancel()
        operation.continuation.resume(returning: operation.responses)
    }

    private func expire(_ id: Int) {
        guard let operation = pending.removeValue(forKey: id) else { return }
        if !receivedAnything {
            // Nothing has ever come back: this is the connection, not the query.
            let error = LDAPTransport.noResponse(endpoint: "\(options.host):\(options.port)", port: options.port,
                                                 seconds: options.timeout, security: options.security)
            operation.continuation.resume(throwing: error)
            fail(everything: error)
            return
        }
        operation.continuation.resume(throwing: LDAPError.timedOut(operation.name))
        abandon(id)
    }

    private func cancel(_ id: Int) {
        guard let operation = pending.removeValue(forKey: id) else { return }
        operation.timeoutTask?.cancel()
        operation.continuation.resume(throwing: CancellationError())
        abandon(id)
    }

    /// Tells the server to stop working on a request nobody is waiting for.
    private func abandon(_ id: Int) {
        guard let transport, failure == nil else { return }
        let bytes = LDAPCodec.message(id: allocateID(), op: LDAPCodec.abandon(id))
        transmit(bytes, via: transport, timeout: 5) { _ in }
    }

    /// Marks the connection dead and fails everything waiting on it.
    private func fail(everything error: LDAPError, closingTransport: Bool = true) {
        if failure == nil { failure = error }
        let operations = pending.values
        pending.removeAll()
        for operation in operations {
            operation.timeoutTask?.cancel()
            operation.continuation.resume(throwing: error)
        }
        if closingTransport { transport?.close() }
    }
}

/// Parses AD's ranged attribute description, `member;range=1500-2999`.
struct RangedAttribute {
    var base: String
    var start: Int
    /// nil when the range ends in `*`, meaning this was the last piece.
    var end: Int?

    init?(_ name: String) {
        let parts = name.split(separator: ";")
        guard let rangePart = parts.first(where: { $0.lowercased().hasPrefix("range=") }) else { return nil }
        let bounds = rangePart.dropFirst("range=".count).split(separator: "-", maxSplits: 1)
        guard bounds.count == 2, let start = Int(bounds[0]) else { return nil }
        base = parts.filter { !$0.lowercased().hasPrefix("range=") }.joined(separator: ";")
        self.start = start
        end = bounds[1] == "*" ? nil : Int(bounds[1])
    }
}
