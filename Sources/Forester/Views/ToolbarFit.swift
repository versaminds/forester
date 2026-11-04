// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import AppKit

/// How wide each column must be for its part of the toolbar.
///
/// The toolbar is split in parts that line up with the columns below them, but
/// only while each part fits its column. When one does not, AppKit moves the
/// toolbar's divider into the next column instead of hiding anything, and the
/// column line then runs straight through a control. So each column has a
/// minimum width that holds its toolbar items, and the title, the one part
/// whose width depends on the user's data, is shortened to the room the
/// middle column has left. The automation's toolbar check measures the real
/// layout at many sizes.
enum ToolbarFit {
    /// The detail column holds Read-only or Editing, enable or disable,
    /// Actions, Show in Tree, Refresh, and the search field, which keeps its
    /// full width while it holds text: 544 points as measured, and some room.
    /// In glass the entry's six tabs, kept at their full width, are the wider
    /// part: 597 points, and a margin either side.
    static var detailMinimum: CGFloat { glass ? 640 : 560 }

    /// The middle column holds back and forward, the title, Browse and Search
    /// and Server Info. AppKit keeps 158 points for the title however short it
    /// is, so this is 415 points as measured for any title up to about 156
    /// points wide, and a little room; 434 points in glass.
    static var contentMinimum: CGFloat { glass ? 440 : 420 }

    /// With the sidebar hidden, the window's buttons and the sidebar button
    /// are in the middle column's part of the toolbar too.
    static func contentMinimum(sidebarShown: Bool) -> CGFloat {
        contentMinimum + (sidebarShown ? 0 : windowButtons)
    }

    /// Room for the title in a middle column this wide: 140 points at the
    /// narrowest, and everything the column has beyond what the other items
    /// take besides the title's own area (257 points, 274 in glass).
    static func titleRoom(column width: CGFloat, sidebarShown: Bool) -> CGFloat {
        width - (glass ? 300 : 280) - (sidebarShown ? 0 : windowButtons)
    }

    /// The close, minimise and zoom buttons and the sidebar button.
    static var windowButtons: CGFloat { glass ? 140 : 130 }

    /// From macOS 26, an app linked with its SDK or a later one draws its
    /// toolbar items as glass capsules, which take more room than the
    /// borderless items before them; on earlier macOS it looks as it did.
    static let glass = ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 26 && linkedSDKMajor >= 26

    /// The major version of the macOS SDK this binary was linked with, from
    /// its own build version load command.
    static let linkedSDKMajor: Int = {
        guard let header = _dyld_get_image_header(0) else { return 0 }
        var command = UnsafeRawPointer(header).advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<header.pointee.ncmds {
            let load = command.load(as: load_command.self)
            if load.cmd == UInt32(LC_BUILD_VERSION) {
                return Int(command.load(as: build_version_command.self).sdk >> 16)
            }
            command = command.advanced(by: Int(load.cmdsize))
        }
        return 0
    }()

    static func title(_ text: String, room: CGFloat) -> String { shortened(text, titleFont, room) }
    static func subtitle(_ text: String, room: CGFloat) -> String { shortened(text, subtitleFont, room) }

    private static let titleFont = NSFont.boldSystemFont(ofSize: 13)
    private static let subtitleFont = NSFont.systemFont(ofSize: 11)

    static func width(_ text: String, _ font: NSFont) -> CGFloat {
        (text as NSString).size(withAttributes: [.font: font]).width
    }

    /// The text, cut at the end with an ellipsis when it is wider than the room.
    private static func shortened(_ text: String, _ font: NSFont, _ room: CGFloat) -> String {
        guard width(text, font) > room else { return text }
        var kept = text
        while !kept.isEmpty {
            kept.removeLast()
            let candidate = kept.trimmingCharacters(in: .whitespaces) + "…"
            if width(candidate, font) <= room { return candidate }
        }
        return "…"
    }
}
