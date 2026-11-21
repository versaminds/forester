// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import CoreGraphics
import Foundation
import ImageIO

/// Pictures stored in the directory (thumbnailPhoto, jpegPhoto), which
/// anyone who may write their own entry can set. Each is decoded only if
/// it is what it says, a JPEG, PNG or GIF by its first bytes and to the
/// decoder, of a size a photo has, and only as large as it is shown: handed
/// whole to a general image decoder, one crafted value could reach any of
/// the formats it reads, or ask for gigabytes of pixels.
public enum DirectoryImage {
    public enum Format: String, Sendable {
        case jpeg = "public.jpeg", png = "public.png", gif = "com.compuserve.gif"
    }

    /// Larger than any photo a directory keeps (AD's thumbnailPhoto is at
    /// most 100 KB, jpegPhoto a few MB).
    public static let maxBytes = 10 << 20
    /// Width or height, and the two multiplied, as the image's header says.
    public static let maxSide = 16_384
    public static let maxPixels = 50_000_000

    /// The format by the value's first bytes, or nil for anything else.
    public static func format(_ data: Data) -> Format? {
        let b = [UInt8](data.prefix(8))
        if b.starts(with: [0xFF, 0xD8, 0xFF]) { return .jpeg }
        if b.starts(with: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) { return .png }
        if b.starts(with: Array("GIF87a".utf8)) || b.starts(with: Array("GIF89a".utf8)) { return .gif }
        return nil
    }

    /// The picture at most `maxPixelSize` pixels on its longer side, or nil
    /// when it is not one Forester shows.
    public static func thumbnail(_ data: Data, maxPixelSize: Int) -> CGImage? {
        guard data.count <= maxBytes, let format = format(data) else { return nil }
        let options = [kCGImageSourceShouldCache: false, kCGImageSourceTypeIdentifierHint: format.rawValue] as CFDictionary
        guard let source = CGImageSourceCreateWithData(data as CFData, options),
              CGImageSourceGetType(source) as String? == format.rawValue, CGImageSourceGetCount(source) >= 1,
              let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, options) as? [CFString: Any],
              let width = (properties[kCGImagePropertyPixelWidth] as? NSNumber)?.intValue,
              let height = (properties[kCGImagePropertyPixelHeight] as? NSNumber)?.intValue,
              (1...maxSide).contains(width), (1...maxSide).contains(height), width * height <= maxPixels else { return nil }
        let thumbnail = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceThumbnailMaxPixelSize: min(max(maxPixelSize, 1), 4_096),
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceShouldCacheImmediately: true,
        ] as CFDictionary
        return CGImageSourceCreateThumbnailAtIndex(source, 0, thumbnail)
    }
}
