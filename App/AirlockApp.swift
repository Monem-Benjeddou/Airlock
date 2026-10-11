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
        let arguments = ProcessInfo.processInfo.arguments
        environment = arguments.contains(where: { $0.hasPrefix("--demo") })
            ? .fromLaunchArguments(arguments)
            : .live(inspector: XPCPackageInspector())
    }

    var body: some Scene {
        AirlockScenes(environment: environment)
    }
}
