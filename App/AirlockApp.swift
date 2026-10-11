// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockInspection
import AirlockUI
import SwiftUI

/// The shipping app: every archive is parsed in the sandboxed AirlockParser helper.
@main
struct AirlockApp: App {
    private let environment: AppEnvironment

    @MainActor
    init() {
        // Demo mode simulates the phone but still parses real files in the helper, so UI tests cover it.
        environment = .fromLaunchArguments(ProcessInfo.processInfo.arguments, inspector: XPCPackageInspector())
    }

    var body: some Scene {
        AirlockScenes(environment: environment)
    }
}
