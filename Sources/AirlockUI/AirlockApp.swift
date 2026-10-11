// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AppKit
import SwiftUI

/// The SwiftUI scene graph, shared by the Xcode app target and `swift run AirlockDev`.
public struct AirlockScenes: Scene {
    private let environment: AppEnvironment

    @MainActor
    public init(environment: AppEnvironment = .fromLaunchArguments()) {
        self.environment = environment
    }

    public var body: some Scene {
        WindowGroup("Airlock") {
            RootView(environment: environment)
        }
        .windowToolbarStyle(.unified)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Airlock") { AboutPanel.show() }
            }
        }
        Settings {
            SettingsView(model: environment.settings)
        }
    }
}

/// The standard About panel with the licence, the UAD-ng credit and a link to the source.
enum AboutPanel {
    static let sourceURL = "https://github.com/Monem-Benjeddou/Airlock"

    @MainActor
    static func show() {
        NSApplication.shared.orderFrontStandardAboutPanel(options: [.credits: credits()])
        NSApplication.shared.activate()
    }

    static func credits() -> NSAttributedString {
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = .center
        let base: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
            .foregroundColor: NSColor.secondaryLabelColor,
            .paragraphStyle: paragraph,
        ]
        let text = NSMutableAttributedString(
            string: "Free software under the GNU GPL 3.0.\nDebloat lists build on UAD-ng.\n", attributes: base
        )
        var link = base
        link[.link] = URL(string: sourceURL)
        text.append(NSAttributedString(string: "Source code", attributes: link))
        return text
    }
}
