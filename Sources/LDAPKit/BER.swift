// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// Errors raised while decoding Basic Encoding Rules data.
public enum BERError: Error, Equatable, CustomStringConvertible {
    case truncated
    case indefiniteLength
    case lengthTooLarge(Int)
    case unsupportedTag(UInt8)
    case malformed(String)

    public var description: String {
        switch self {
        case .truncated: return "BER element is truncated"
        case .indefiniteLength: return "BER indefinite length is not allowed in LDAP"
        case .lengthTooLarge(let n): return "BER element of \(n) bytes exceeds the message limit"
        case .unsupportedTag(let t): return String(format: "Unsupported BER tag 0x%02x", t)
        case .malformed(let why): return "Malformed BER: \(why)"
        }
    }
}

/// One decoded tag-length-value element. For constructed elements `content`
/// holds the encoded children; call `children()` to decode them.
public struct BERElement: Equatable, Sendable {
    public var tag: UInt8
    public var content: [UInt8]

    public init(tag: UInt8, content: [UInt8]) {
        self.tag = tag
        self.content = content
    }

    public var isConstructed: Bool { tag & 0x20 != 0 }

    public func children() throws -> [BERElement] {
        try BERDecoder.elements(in: content)
    }

    /// Two's-complement big-endian integer. Values wider than 64 bits are rejected.
    public func integer() throws -> Int64 {
        guard !content.isEmpty else { throw BERError.malformed("empty INTEGER") }
        guard content.count <= 8 else { throw BERError.malformed("INTEGER wider than 64 bits") }
        var value: Int64 = (content[0] & 0x80) != 0 ? -1 : 0
        for byte in content {
            value = (value << 8) | Int64(byte)
        }
        return value
    }

    public func int() throws -> Int {
        Int(try integer())
    }

    public var boolean: Bool { content.first.map { $0 != 0 } ?? false }

    /// The content decoded as UTF-8. LDAP strings are UTF-8; anything else is
    /// repaired rather than dropped, since a DN that cannot be shown is worse than
    /// one with a replacement character.
    public var string: String { String(decoding: content, as: UTF8.self) }

    public var data: Data { Data(content) }
}

public enum BERDecoder {
    /// Largest single LDAP message accepted. AD's default MaxReceiveBuffer is 10 MB;
    /// a photo-heavy page of entries can approach that, so allow headroom.
    public static let maxElementLength = 64 * 1024 * 1024

    /// Decodes the element starting at `offset`. Returns `nil` when the buffer
    /// does not yet contain the whole element, which is how a stream reader knows
    /// to wait for more bytes.
    public static func element(in buffer: [UInt8], at offset: Int = 0) throws -> (element: BERElement, next: Int)? {
        var i = offset
        guard i < buffer.count else { return nil }
        let tag = buffer[i]
        // LDAP never uses tag numbers above 30, so the multi-byte tag form is refused.
        guard tag & 0x1F != 0x1F else { throw BERError.unsupportedTag(tag) }
        i += 1
        guard i < buffer.count else { return nil }
        let first = buffer[i]
        i += 1
        var length = 0
        if first < 0x80 {
            length = Int(first)
        } else if first == 0x80 {
            throw BERError.indefiniteLength
        } else {
            let count = Int(first & 0x7F)
            guard count <= 4 else { throw BERError.malformed("length of \(count) octets") }
            guard i + count <= buffer.count else { return nil }
            for _ in 0..<count {
                length = (length << 8) | Int(buffer[i])
                i += 1
            }
        }
        guard length <= maxElementLength else { throw BERError.lengthTooLarge(length) }
        guard i + length <= buffer.count else { return nil }
        let element = BERElement(tag: tag, content: Array(buffer[i..<(i + length)]))
        return (element, i + length)
    }

    /// Decodes a complete run of elements (the content of a constructed element).
    public static func elements(in buffer: [UInt8]) throws -> [BERElement] {
        var result: [BERElement] = []
        var offset = 0
        while offset < buffer.count {
            guard let (element, next) = try element(in: buffer, at: offset) else {
                throw BERError.truncated
            }
            result.append(element)
            offset = next
        }
        return result
    }
}

/// Encoders for the BER subset LDAP uses (RFC 4511 §5.1: definite lengths only).
public enum BER {
    public static func length(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 {
            bytes.insert(UInt8(v & 0xFF), at: 0)
            v >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    public static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        [tag] + length(content.count) + content
    }

    /// Minimal two's-complement encoding of an integer's content octets.
    public static func integerContent(_ value: Int64) -> [UInt8] {
        var v = value
        var out: [UInt8] = []
        repeat {
            out.insert(UInt8(truncatingIfNeeded: v), at: 0)
            v >>= 8
        } while !((v == 0 && out[0] & 0x80 == 0) || (v == -1 && out[0] & 0x80 != 0))
        return out
    }

    public static func integer(_ value: Int, tag: UInt8 = 0x02) -> [UInt8] {
        tlv(tag, integerContent(Int64(value)))
    }

    public static func enumerated(_ value: Int) -> [UInt8] {
        integer(value, tag: 0x0A)
    }

    public static func boolean(_ value: Bool, tag: UInt8 = 0x01) -> [UInt8] {
        tlv(tag, [value ? 0xFF : 0x00])
    }

    public static func octetString(_ value: String, tag: UInt8 = 0x04) -> [UInt8] {
        tlv(tag, Array(value.utf8))
    }

    public static func octetString(_ value: [UInt8], tag: UInt8 = 0x04) -> [UInt8] {
        tlv(tag, value)
    }

    public static func sequence(_ parts: [[UInt8]], tag: UInt8 = 0x30) -> [UInt8] {
        tlv(tag, parts.flatMap { $0 })
    }

    public static func set(_ parts: [[UInt8]], tag: UInt8 = 0x31) -> [UInt8] {
        tlv(tag, parts.flatMap { $0 })
    }

    public static func null(tag: UInt8 = 0x05) -> [UInt8] {
        [tag, 0x00]
    }
}
