// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import AppKit
import LDAPKit

/// A photo from the directory, decoded only through `DirectoryImage`: a
/// JPEG, PNG or GIF of a photo's size, at the size it is shown, never the
/// value handed whole to NSImage.
enum DirectoryImages {
    /// For a frame `points` across, sharp on a Retina screen.
    static func image(_ data: Data, points: CGFloat) -> NSImage? {
        let scale = NSScreen.main?.backingScaleFactor ?? 2
        guard let image = DirectoryImage.thumbnail(data, maxPixelSize: Int((points * scale).rounded(.up))) else { return nil }
        return NSImage(cgImage: image, size: NSSize(width: CGFloat(image.width) / scale, height: CGFloat(image.height) / scale))
    }

    /// Onto the pasteboard as a picture, at most 2,048 pixels across.
    @MainActor
    static func copy(_ data: Data) {
        guard let image = DirectoryImage.thumbnail(data, maxPixelSize: 2_048) else { return }
        let picture = NSImage(cgImage: image, size: NSSize(width: image.width, height: image.height))
        NSPasteboard.general.clearContents()
        NSPasteboard.general.writeObjects([picture])
    }
}
