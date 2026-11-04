// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

// Draws the 1200 by 630 picture shown when the website is shared, as a JPEG.
//   swift scripts/make-og-image.swift <app icon png> <screenshot png> <output jpg>
import AppKit

let arguments = CommandLine.arguments
guard arguments.count == 4,
      let icon = NSImage(contentsOfFile: arguments[1]),
      let shot = NSImage(contentsOfFile: arguments[2]) else {
    FileHandle.standardError.write(Data("usage: make-og-image.swift <icon.png> <screenshot.png> <out.jpg>\n".utf8))
    exit(1)
}

let size = NSSize(width: 1200, height: 630)
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width), pixelsHigh: Int(size.height), bitsPerSample: 8,
                           samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let ctx = NSGraphicsContext.current!.cgContext

// The icon's own colours, deep navy to sea blue.
let background = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: [
    NSColor(red: 0.07, green: 0.20, blue: 0.44, alpha: 1).cgColor,
    NSColor(red: 0.06, green: 0.44, blue: 0.68, alpha: 1).cgColor,
] as CFArray, locations: [0, 1])!
ctx.drawLinearGradient(background, start: CGPoint(x: 0, y: size.height), end: CGPoint(x: size.width, y: 0), options: [])

icon.draw(in: NSRect(x: 64, y: 400, width: 150, height: 150))

let title: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 76, weight: .bold), .foregroundColor: NSColor.white, .kern: -2.0]
NSAttributedString(string: "Forester", attributes: title).draw(at: NSPoint(x: 84, y: 290))
let paragraph = NSMutableParagraphStyle()
paragraph.lineSpacing = 4
let tagline: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 34, weight: .medium),
                                              .foregroundColor: NSColor.white.withAlphaComponent(0.88), .paragraphStyle: paragraph]
NSAttributedString(string: "The LDAP and Active Directory\nbrowser for Mac.", attributes: tagline)
    .draw(in: NSRect(x: 86, y: 150, width: 520, height: 120))
let small: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 22, weight: .regular),
                                            .foregroundColor: NSColor.white.withAlphaComponent(0.7)]
NSAttributedString(string: "Free · source on GitHub · by VersaMinds", attributes: small).draw(at: NSPoint(x: 86, y: 76))

// The app window, running off the right and bottom edges.
let window = NSRect(x: 620, y: -150, width: 880, height: 550)
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 40, color: NSColor.black.withAlphaComponent(0.45).cgColor)
NSBezierPath(roundedRect: window, xRadius: 14, yRadius: 14).fill()
ctx.restoreGState()
NSGraphicsContext.saveGraphicsState()
NSBezierPath(roundedRect: window, xRadius: 14, yRadius: 14).addClip()
shot.draw(in: window)
NSGraphicsContext.restoreGraphicsState()

NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .jpeg, properties: [.compressionFactor: 0.86])!.write(to: URL(fileURLWithPath: arguments[3]))
