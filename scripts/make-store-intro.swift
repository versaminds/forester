// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

// Draws the first App Store screenshot, 2880 by 1800: the website's sharing
// picture (make-og-image.swift) at the App Store's size, the app beside the name.
//   swift scripts/make-store-intro.swift <app icon png> <screenshot png> <output png>
import AppKit

let arguments = CommandLine.arguments
guard arguments.count == 4,
      let icon = NSImage(contentsOfFile: arguments[1]),
      let shot = NSImage(contentsOfFile: arguments[2]) else {
    FileHandle.standardError.write(Data("usage: make-store-intro.swift <icon.png> <screenshot.png> <out.png>\n".utf8))
    exit(1)
}

// Laid out in points, drawn at twice that.
let size = NSSize(width: 1440, height: 900)
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width) * 2, pixelsHigh: Int(size.height) * 2, bitsPerSample: 8,
                           samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
rep.size = size
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let ctx = NSGraphicsContext.current!.cgContext

// The icon's own colours, deep navy to sea blue, as on the website's picture.
let background = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: [
    NSColor(red: 0.07, green: 0.20, blue: 0.44, alpha: 1).cgColor,
    NSColor(red: 0.06, green: 0.44, blue: 0.68, alpha: 1).cgColor,
] as CFArray, locations: [0, 1])!
ctx.drawLinearGradient(background, start: CGPoint(x: 0, y: size.height), end: CGPoint(x: size.width, y: 0), options: [])

icon.draw(in: NSRect(x: 86, y: 600, width: 190, height: 190))

let title: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 100, weight: .bold), .foregroundColor: NSColor.white, .kern: -2.5]
NSAttributedString(string: "Forester", attributes: title).draw(at: NSPoint(x: 110, y: 450))
let paragraph = NSMutableParagraphStyle()
paragraph.lineSpacing = 6
let tagline: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 44, weight: .medium),
                                              .foregroundColor: NSColor.white.withAlphaComponent(0.88), .paragraphStyle: paragraph]
NSAttributedString(string: "The LDAP and Active Directory\nbrowser for Mac.", attributes: tagline)
    .draw(in: NSRect(x: 112, y: 270, width: 640, height: 150))
let small: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 28, weight: .regular),
                                            .foregroundColor: NSColor.white.withAlphaComponent(0.7)]
NSAttributedString(string: "Browse, search and edit your directory.", attributes: small).draw(at: NSPoint(x: 112, y: 150))

// The app window, running off the right and bottom edges.
let window = NSRect(x: 780, y: -70, width: 1140, height: 712)
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -16), blur: 54, color: NSColor.black.withAlphaComponent(0.45).cgColor)
NSBezierPath(roundedRect: window, xRadius: 18, yRadius: 18).fill()
ctx.restoreGState()
NSGraphicsContext.saveGraphicsState()
NSBezierPath(roundedRect: window, xRadius: 18, yRadius: 18).addClip()
shot.draw(in: window)
NSGraphicsContext.restoreGraphicsState()

NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: arguments[3]))
