// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors
//
// Draws the Airlock app icon, a sealed pressure hatch holding a parcel, at every macOS icon size and writes
// the asset catalog. The icon is code so it stays reviewable and reproducible:
//
//   swift scripts/make-icon.swift            # writes App/Assets.xcassets/AppIcon.appiconset
//   swift scripts/make-icon.swift preview.png  # also writes a 1024 px preview to the given path

import AppKit

/// All geometry is in a 1024-point canvas, following Apple's macOS icon grid (an 824-point body, 100 points in).
enum Icon {
    static let canvas: CGFloat = 1024
    static let body = CGRect(x: 100, y: 100, width: 824, height: 824)
    static let cornerRadius: CGFloat = 185
    static let center = CGPoint(x: 512, y: 512)

    static let bodyTop = NSColor(srgbRed: 0.13, green: 0.58, blue: 0.61, alpha: 1)
    static let bodyBottom = NSColor(srgbRed: 0.04, green: 0.28, blue: 0.31, alpha: 1)
    static let seal = NSColor(srgbRed: 0.87, green: 0.95, blue: 0.95, alpha: 1)
    static let chamberTop = NSColor(srgbRed: 0.02, green: 0.17, blue: 0.19, alpha: 1)
    static let chamberBottom = NSColor(srgbRed: 0.05, green: 0.27, blue: 0.29, alpha: 1)
    static let parcel = NSColor(srgbRed: 0.95, green: 0.72, blue: 0.29, alpha: 1)
    static let parcelShade = NSColor(srgbRed: 0.84, green: 0.58, blue: 0.20, alpha: 1)
    static let tape = NSColor(srgbRed: 0.69, green: 0.47, blue: 0.15, alpha: 1)

    static func draw(in context: CGContext) {
        let bodyPath = CGPath(roundedRect: body, cornerWidth: cornerRadius, cornerHeight: cornerRadius, transform: nil)

        // Drop shadow under the body, as on Apple's own icons.
        context.saveGState()
        context.setShadow(offset: CGSize(width: 0, height: -10), blur: 24, color: NSColor(white: 0, alpha: 0.35).cgColor)
        context.addPath(bodyPath)
        context.setFillColor(bodyBottom.cgColor)
        context.fillPath()
        context.restoreGState()

        // Body gradient, lighter at the top.
        context.saveGState()
        context.addPath(bodyPath)
        context.clip()
        fillLinear(context, from: bodyTop, to: bodyBottom, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100))
        context.restoreGState()

        // Chamber: the inside of the hatch, darker towards the top so it reads as recessed.
        let chamberRadius: CGFloat = 214
        context.saveGState()
        context.addEllipse(in: circle(radius: chamberRadius))
        context.clip()
        fillLinear(context, from: chamberTop, to: chamberBottom,
                   start: CGPoint(x: 512, y: 512 + chamberRadius), end: CGPoint(x: 512, y: 512 - chamberRadius))
        context.restoreGState()

        // Seal ring, wide enough to carry the rivets.
        let ringRadius: CGFloat = 252
        context.setStrokeColor(seal.cgColor)
        context.setLineWidth(60)
        context.addEllipse(in: circle(radius: ringRadius))
        context.strokePath()

        // Eight rivets set into the ring, starting off-axis so the mark never reads as a crosshair.
        context.setFillColor(bodyBottom.withAlphaComponent(0.55).cgColor)
        for index in 0..<8 {
            let angle = (22.5 + Double(index) * 45) * .pi / 180
            let point = CGPoint(x: center.x + ringRadius * cos(angle), y: center.y + ringRadius * sin(angle))
            context.fillEllipse(in: CGRect(x: point.x - 11, y: point.y - 11, width: 22, height: 22))
        }

        drawParcel(in: context)
    }

    /// The parcel (the app being checked), seen slightly from above: a front face, a lid and a tape band.
    private static func drawParcel(in context: CGContext) {
        let front = CGRect(x: 412, y: 418, width: 200, height: 136)
        let lid = CGRect(x: 402, y: 540, width: 220, height: 58)

        context.saveGState()
        context.setShadow(offset: CGSize(width: 0, height: -8), blur: 16, color: NSColor(white: 0, alpha: 0.4).cgColor)
        context.addPath(CGPath(roundedRect: front, cornerWidth: 16, cornerHeight: 16, transform: nil))
        context.setFillColor(parcelShade.cgColor)
        context.fillPath()
        context.restoreGState()

        context.addPath(CGPath(roundedRect: lid, cornerWidth: 14, cornerHeight: 14, transform: nil))
        context.setFillColor(parcel.cgColor)
        context.fillPath()

        context.setFillColor(tape.cgColor)
        context.fill(CGRect(x: 496, y: 418, width: 32, height: 136))
        context.fill(CGRect(x: 494, y: 540, width: 36, height: 58))
    }

    private static func circle(radius: CGFloat) -> CGRect {
        CGRect(x: center.x - radius, y: center.y - radius, width: radius * 2, height: radius * 2)
    }

    private static func fillLinear(_ context: CGContext, from top: NSColor, to bottom: NSColor, start: CGPoint, end: CGPoint) {
        let colors = [top.cgColor, bottom.cgColor] as CFArray
        guard let gradient = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB), colors: colors, locations: [0, 1])
        else { return }
        context.drawLinearGradient(gradient, start: start, end: end, options: [])
    }
}

func render(pixels: Int) -> Data {
    let space = CGColorSpace(name: CGColorSpace.sRGB)!
    let context = CGContext(data: nil, width: pixels, height: pixels, bitsPerComponent: 8, bytesPerRow: 0,
                            space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    context.interpolationQuality = .high
    context.scaleBy(x: CGFloat(pixels) / Icon.canvas, y: CGFloat(pixels) / Icon.canvas)
    Icon.draw(in: context)
    let bitmap = NSBitmapImageRep(cgImage: context.makeImage()!)
    return bitmap.representation(using: .png, properties: [:])!
}

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
let catalog = root.appendingPathComponent("App/Assets.xcassets")
let iconSet = catalog.appendingPathComponent("AppIcon.appiconset")
try FileManager.default.createDirectory(at: iconSet, withIntermediateDirectories: true)

var images: [[String: String]] = []
for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = "icon_\(points)x\(points)\(scale == 2 ? "@2x" : "").png"
        try render(pixels: points * scale).write(to: iconSet.appendingPathComponent(name))
        images.append(["idiom": "mac", "size": "\(points)x\(points)", "scale": "\(scale)x", "filename": name])
    }
}

func writeJSON(_ object: Any, to url: URL) throws {
    let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    try (data + Data("\n".utf8)).write(to: url)
}

let info = ["author": "xcode", "version": 1] as [String: Any]
try writeJSON(["images": images, "info": info], to: iconSet.appendingPathComponent("Contents.json"))
try writeJSON(["info": info], to: catalog.appendingPathComponent("Contents.json"))

if CommandLine.arguments.count > 1 {
    try render(pixels: 1024).write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
}
print("Wrote \(images.count) icon images to \(iconSet.path)")
