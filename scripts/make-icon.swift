// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

// Draws the app icon and writes an .iconset next to the given path.
//   swift scripts/make-icon.swift build/AppIcon.iconset
import AppKit

let output = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.iconset")
try? FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

func draw(size: CGFloat) -> NSBitmapImageRep {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size), bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let s = size / 1024
    let ctx = NSGraphicsContext.current!.cgContext

    // The macOS icon grid: an 824-point rounded square centred on 1024.
    let tile = CGRect(x: 100 * s, y: 100 * s, width: 824 * s, height: 824 * s)
    let tilePath = CGPath(roundedRect: tile, cornerWidth: 185 * s, cornerHeight: 185 * s, transform: nil)
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -10 * s), blur: 24 * s, color: NSColor.black.withAlphaComponent(0.3).cgColor)
    ctx.addPath(tilePath)
    ctx.setFillColor(NSColor.black.cgColor)
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(tilePath)
    ctx.clip()
    let gradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: [
        NSColor(red: 0.07, green: 0.20, blue: 0.45, alpha: 1).cgColor,
        NSColor(red: 0.06, green: 0.47, blue: 0.70, alpha: 1).cgColor,
    ] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(gradient, start: CGPoint(x: 0, y: 100 * s), end: CGPoint(x: 0, y: 924 * s), options: [])
    // A soft highlight across the top.
    ctx.setFillColor(NSColor.white.withAlphaComponent(0.06).cgColor)
    ctx.fillEllipse(in: CGRect(x: -100 * s, y: 560 * s, width: 1224 * s, height: 600 * s))
    ctx.restoreGState()

    // A directory tree: one root, a rail, three children.
    let white = NSColor.white.cgColor
    ctx.setStrokeColor(NSColor.white.withAlphaComponent(0.85).cgColor)
    ctx.setLineWidth(26 * s)
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    let railX = 330 * s
    ctx.move(to: CGPoint(x: railX, y: 690 * s))
    ctx.addLine(to: CGPoint(x: railX, y: 270 * s))
    for y in [530, 400, 270] as [CGFloat] {
        ctx.move(to: CGPoint(x: railX, y: y * s))
        ctx.addLine(to: CGPoint(x: 450 * s, y: y * s))
    }
    ctx.strokePath()

    func node(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat, _ alpha: CGFloat) {
        let rect = CGRect(x: x * s, y: y * s, width: w * s, height: h * s)
        ctx.addPath(CGPath(roundedRect: rect, cornerWidth: 26 * s, cornerHeight: 26 * s, transform: nil))
        ctx.setFillColor(NSColor.white.withAlphaComponent(alpha).cgColor)
        ctx.fillPath()
    }
    node(240, 650, 180, 120, 1)       // root
    node(450, 480, 320, 100, 0.95)    // children
    node(450, 350, 260, 100, 0.8)
    node(450, 220, 300, 100, 0.65)
    _ = white
    NSGraphicsContext.restoreGraphicsState()
    return rep
}

for (name, size) in [("16x16", 16), ("16x16@2x", 32), ("32x32", 32), ("32x32@2x", 64), ("128x128", 128),
                     ("128x128@2x", 256), ("256x256", 256), ("256x256@2x", 512), ("512x512", 512), ("512x512@2x", 1024)] {
    let data = draw(size: CGFloat(size)).representation(using: .png, properties: [:])!
    try! data.write(to: output.appendingPathComponent("icon_\(name).png"))
}
print("Wrote \(output.path)")
