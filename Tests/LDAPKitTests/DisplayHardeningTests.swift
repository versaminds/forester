// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import CoreGraphics
import Foundation
import ImageIO
import Testing
@testable import LDAPKit

/// What directory data written by someone else must not do on screen:
/// reach an image decoder it was not meant for, take gigabytes of pixels,
/// or hide characters in a name someone is asked to confirm.
@Suite struct DisplayHardeningTests {
    /// A picture of `width` by `height` in `type` (public.png, public.jpeg…).
    static func picture(_ width: Int, _ height: Int, type: String) throws -> Data {
        let context = try #require(CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
                                             space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue))
        context.setFillColor(red: 0.2, green: 0.5, blue: 0.8, alpha: 1)
        context.fill(CGRect(x: 0, y: 0, width: width, height: height))
        let image = try #require(context.makeImage())
        let data = NSMutableData()
        let destination = try #require(CGImageDestinationCreateWithData(data, type as CFString, 1, nil))
        CGImageDestinationAddImage(destination, image, nil)
        #expect(CGImageDestinationFinalize(destination))
        return data as Data
    }

    static func be32(_ v: UInt32) -> [UInt8] { [UInt8(v >> 24), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)] }

    /// A PNG chunk: its length, type, data and CRC-32.
    static func chunk(_ type: String, _ data: [UInt8]) -> [UInt8] {
        let body = Array(type.utf8) + data
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in body {
            crc ^= UInt32(byte)
            for _ in 0..<8 { crc = crc & 1 != 0 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1 }
        }
        return be32(UInt32(data.count)) + body + be32(crc ^ 0xFFFF_FFFF)
    }

    /// A black square `side` pixels across, one bit each: a few kilobytes
    /// that a decoder would turn into `side` squared pixels.
    static func bomb(side: UInt32) throws -> Data {
        let raw = Data(count: (1 + Int(side) / 8) * Int(side))
        let deflated = try (raw as NSData).compressed(using: .zlib) as Data
        var a: UInt32 = 1, b: UInt32 = 0
        for byte in raw { a = (a + UInt32(byte)) % 65_521; b = (b + a) % 65_521 }
        let zlib = [0x78, 0x9C] + [UInt8](deflated) + be32(b << 16 | a)
        return Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] + chunk("IHDR", be32(side) + be32(side) + [1, 0, 0, 0, 0])
                    + chunk("IDAT", zlib) + chunk("IEND", []))
    }

    @Test func photosDecodeAtTheSizeShown() throws {
        for type in ["public.png", "public.jpeg", "com.compuserve.gif"] {
            let data = try Self.picture(300, 200, type: type)
            let image = try #require(DirectoryImage.thumbnail(data, maxPixelSize: 60), "\(type)")
            #expect(max(image.width, image.height) <= 60 && image.width > image.height, "\(type)")
        }
    }

    /// Only JPEG, PNG and GIF, by their first bytes and to the decoder alike.
    @Test func otherFormatsAreNotDecoded() throws {
        for type in ["com.microsoft.bmp", "public.tiff", "public.heic"] {
            guard let data = try? Self.picture(40, 40, type: type) else { continue }
            #expect(DirectoryImage.thumbnail(data, maxPixelSize: 40) == nil, "\(type) was decoded")
        }
        // A TIFF behind a JPEG's first bytes is not taken for one.
        let tiff = try Self.picture(40, 40, type: "public.tiff")
        #expect(DirectoryImage.thumbnail(Data([0xFF, 0xD8, 0xFF]) + tiff, maxPixelSize: 40) == nil)
        #expect(DirectoryImage.thumbnail(Data("GIF89a not really".utf8), maxPixelSize: 40) == nil)
    }

    /// A picture of more pixels than a photo has (8 KB here, 64 million
    /// pixels decoded), or a value larger than one, is refused before a
    /// pixel is decoded.
    @Test func hugeImagesAreRefused() throws {
        let png = try Self.bomb(side: 8_000)
        #expect(png.count < 20_000)
        // The system's decoder would make a thumbnail of it.
        let source = try #require(CGImageSourceCreateWithData(png as CFData, nil))
        #expect(CGImageSourceCreateThumbnailAtIndex(source, 0, [kCGImageSourceCreateThumbnailFromImageAlways: true,
                                                                 kCGImageSourceThumbnailMaxPixelSize: 64] as CFDictionary) != nil)
        #expect(DirectoryImage.thumbnail(png, maxPixelSize: 64) == nil)
        #expect(DirectoryImage.thumbnail(try Self.bomb(side: 64), maxPixelSize: 64) != nil)
        let big = try Self.picture(16, 16, type: "public.png") + Data(count: DirectoryImage.maxBytes)
        #expect(DirectoryImage.thumbnail(big, maxPixelSize: 64) == nil)
    }

    /// Bidi controls and invisible characters are written out wherever a
    /// name is confirmed, and the name can still be typed to confirm it.
    @Test func hiddenCharactersAreShown() {
        let name = "admin\u{202E}txt.exe"
        #expect(VisibleText.reveal(name) == "admin⟨U+202E⟩txt.exe")
        #expect(VisibleText.reveal("a\u{200B}b\u{2066}c\u{FEFF}d\u{00AD}e\u{3164}f\u{061C}g\nh") ==
                "a⟨U+200B⟩b⟨U+2066⟩c⟨U+FEFF⟩d⟨U+00AD⟩e⟨U+3164⟩f⟨U+061C⟩g⟨U+000A⟩h")
        #expect(VisibleText.reveal("Ünïcödé Name, 日本") == "Ünïcödé Name, 日本")
        #expect(VisibleText.confirms(name, name))
        #expect(VisibleText.confirms("admin⟨U+202E⟩txt.exe", name))
        #expect(VisibleText.confirms("admin<u+202e>txt.exe", name))
        #expect(!VisibleText.confirms("admintxt.exe", name))
        #expect(!VisibleText.confirms("ADMIN<U+202E>TXT.EXE", name))
        #expect(!VisibleText.confirms("admin", "Admin"))
        #expect(VisibleText.confirms("Sales", "Sales"))
    }

    /// One huge value is shown cut short in a table, whole on request.
    @Test func longValuesAreCutForCells() {
        let long = String(repeating: "x", count: 5_000_000)
        let cell = AttributeFormatter.cellText(long)
        #expect(cell.count <= AttributeFormatter.cellLimit + 40)
        #expect(cell.hasSuffix("(5 MB)") || cell.contains("more"), "\(cell.suffix(40))")
        #expect(AttributeFormatter.cellText("short") == "short")
        #expect(AttributeFormatter.cellText("line one\nline two") == "line one\nline two")
    }
}
