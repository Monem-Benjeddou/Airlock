// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import CoreGraphics
import CoreImage
import CoreImage.CIFilterBuiltins
import Foundation

/// One QR pairing attempt: the phone scans the QR, advertises `serviceName` over mDNS, and accepts
/// `password` as the pairing code (the same scheme Android Studio uses).
public struct PairingSession: Hashable, Sendable {
    public let serviceName: String
    public let password: String

    public init(serviceName: String, password: String) {
        self.serviceName = serviceName
        self.password = password
    }

    /// Letters and digits only, so the QR payload needs no escaping.
    public static func random() -> PairingSession {
        let alphabet = Array("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        var generator = SystemRandomNumberGenerator()
        func token(_ length: Int) -> String {
            String((0..<length).map { _ in alphabet.randomElement(using: &generator) ?? "a" })
        }
        return PairingSession(serviceName: "airlock-" + token(8), password: token(12))
    }

    /// `WIFI:T:ADB;S:<name>;P:<password>;;`
    public var qrPayload: String { "WIFI:T:ADB;S:\(serviceName);P:\(password);;" }
}

public enum QRCodeRenderer {
    /// Renders `text` as a QR code, each module `scale` pixels wide.
    public static func image(for text: String, scale: CGFloat = 10) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: scale, y: scale)) else { return nil }
        return CIContext(options: [.useSoftwareRenderer: true]).createCGImage(output, from: output.extent)
    }
}
