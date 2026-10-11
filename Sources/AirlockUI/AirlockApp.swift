// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import SwiftUI

/// The SwiftUI scene graph, shared by the Xcode app target and `swift run AirlockDev`.
public struct AirlockScenes: Scene {
    private let environment: AppEnvironment

    @MainActor
    public init(environment: AppEnvironment = .live()) {
        self.environment = environment
    }

    public var body: some Scene {
        WindowGroup("Airlock") {
            RootView(environment: environment)
        }
        .windowToolbarStyle(.unified)
        Settings {
            SettingsView(model: environment.settings)
        }
    }
}
