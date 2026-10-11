// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockUI
import AppKit
import SwiftUI

/// Development entry point: `swift run AirlockDev` opens the real UI without an Xcode project.
struct AirlockDevApp: App {
    init() {
        // A SwiftPM executable is not an app bundle; make it a regular foreground app.
        NSApplication.shared.setActivationPolicy(.regular)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    var body: some Scene { AirlockScenes() }
}

AirlockDevApp.main()
