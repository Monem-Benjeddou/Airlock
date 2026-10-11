// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// A change Airlock can make to an installed package.
public enum DeviceOperation: String, Hashable, Sendable, Codable, CaseIterable {
    /// `pm uninstall <pkg>`: removes a user app with its data. Not restorable from the journal.
    case uninstall
    /// `pm uninstall --user 0 <pkg>`: hides a system app for the main user. Restorable.
    case uninstallForUser
    /// `pm disable-user --user 0 <pkg>`. Restorable.
    case disableForUser
    /// `pm enable <pkg>`. Restore operation.
    case enable
    /// `cmd package install-existing <pkg>`. Restore operation.
    case installExisting

    public var isDestructive: Bool {
        switch self {
        case .uninstall, .uninstallForUser, .disableForUser: true
        case .enable, .installExisting: false
        }
    }
}

public enum DenylistReason: String, Hashable, Sendable, CaseIterable {
    case criticalSystemComponent
    case onlyLauncher
    case onlyKeyboard

    public var explanation: String {
        switch self {
        case .criticalSystemComponent:
            "This is a core part of Android. Removing or disabling it can stop the phone from starting."
        case .onlyLauncher:
            "This is the only home screen app on the phone. Install another launcher before removing it."
        case .onlyKeyboard:
            "This is the only keyboard on the phone. Install another keyboard before removing it."
        }
    }
}

public enum DenylistVerdict: Hashable, Sendable {
    case allowed
    case blocked(DenylistReason)
}

/// Device facts that make otherwise-removable packages critical.
public struct DenylistContext: Hashable, Sendable {
    /// Installed and enabled packages that handle the HOME intent.
    public var launchers: Set<PackageName>
    /// Installed and enabled input methods.
    public var inputMethods: Set<PackageName>

    public init(launchers: Set<PackageName> = [], inputMethods: Set<PackageName> = []) {
        self.launchers = launchers
        self.inputMethods = inputMethods
    }
}

/// Packages that must never be removed or disabled. Cannot be overridden in v1.0.
///
/// Checked by the app manager before every destructive operation, after user confirmation and
/// independently of presets, so a bad preset cannot bypass it.
public struct CriticalDenylist: Sendable {
    public let packages: Set<String>

    public init(packages: Set<String>) {
        self.packages = packages
    }

    public static let standard = CriticalDenylist(packages: [
        // AOSP core
        "android",
        "com.android.systemui",
        "com.android.phone",
        "com.android.settings",
        "com.android.providers.settings",
        "com.android.shell", // also breaks adb itself
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
        "com.android.permissioncontroller",
        "com.google.android.permissioncontroller",
        "com.android.server.telecom",
        "com.android.providers.telephony",
        "com.android.providers.media",
        "com.android.providers.media.module",
        "com.google.android.providers.media.module",
        "com.android.networkstack",
        "com.google.android.networkstack",
        "com.android.keychain",
        "com.android.externalstorage",
        "com.android.inputdevices",
        "com.android.location.fused",
        "com.android.se",
        "com.android.extservices",
        "com.google.android.ext.services",
        "com.android.modulemetadata",
        "com.google.android.modulemetadata",
        // OEM components known to boot-loop when removed
        "com.miui.securitycenter",
        "com.lbe.security.miui",
        "com.miui.core",
        "com.miui.system",
        "com.samsung.android.providers.context",
        "com.sec.android.app.servicemodeapp",
        "com.oneplus.security",
    ])

    public func check(_ package: PackageName, operation: DeviceOperation, context: DenylistContext) -> DenylistVerdict {
        if case .blocked(let reason) = check(rawPackage: package.rawValue, operation: operation) {
            return .blocked(reason)
        }
        guard operation.isDestructive else { return .allowed }
        if context.launchers.contains(package), context.launchers.count <= 1 {
            return .blocked(.onlyLauncher)
        }
        if context.inputMethods.contains(package), context.inputMethods.count <= 1 {
            return .blocked(.onlyKeyboard)
        }
        return .allowed
    }

    /// Raw-name check, for names such as `android` that are not valid application IDs.
    public func check(rawPackage: String, operation: DeviceOperation) -> DenylistVerdict {
        guard operation.isDestructive else { return .allowed }
        return packages.contains(rawPackage.lowercased()) ? .blocked(.criticalSystemComponent) : .allowed
    }
}
