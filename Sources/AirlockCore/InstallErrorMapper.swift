// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import Foundation

/// A failure reported by the package manager, e.g. `Failure [INSTALL_FAILED_OLDER_SDK: ...]`.
public struct InstallFailure: Hashable, Sendable, Codable {
    public let code: String
    public let detail: String?

    public init(code: String, detail: String? = nil) {
        self.code = code
        self.detail = detail
    }

    /// Extracts the first `INSTALL_FAILED_*` / `INSTALL_PARSE_FAILED_*` code from adb or pm output.
    public static func parse(_ output: String) -> InstallFailure? {
        guard let codeStart = output.range(of: "INSTALL_", options: .literal) else { return nil }
        let tail = output[codeStart.lowerBound...]
        let code = String(tail.prefix { $0.isUppercase || $0 == "_" || $0.isNumber })
        guard code.hasPrefix("INSTALL_FAILED_") || code.hasPrefix("INSTALL_PARSE_FAILED_") else { return nil }

        var detail: String?
        let afterCode = tail.dropFirst(code.count)
        if afterCode.hasPrefix(":") {
            let body = afterCode.dropFirst().prefix { $0 != "]" && $0 != "\n" }
            let trimmed = body.trimmingCharacters(in: .whitespaces)
            detail = trimmed.isEmpty ? nil : trimmed
        }
        return InstallFailure(code: code, detail: detail)
    }
}

/// A one-click remedy the UI can offer next to an explained failure.
public enum FixAction: String, Hashable, Sendable, Codable, CaseIterable {
    /// Back up accessible data, uninstall the installed copy, then install. Destructive: needs confirmation.
    case uninstallExistingThenInstall
    /// Open the app manager sorted by size so the user can free space.
    case freeUpSpace
    case retry
    case reconnectDevice
    /// Ask the user to turn off "Verify apps over USB" in Developer options.
    case turnOffVerifyAppsOverUSB
    /// Ask the user to turn on "Install via USB" (Xiaomi) or remove a device-policy restriction.
    case allowInstallViaUSB
    /// Go back to split selection and include the missing splits.
    case addMissingSplits
    /// Nothing Airlock can change; the user needs a build made for this device.
    case chooseCompatibleFile

    public var isDestructive: Bool { self == .uninstallExistingThenInstall }

    public var buttonTitle: String {
        switch self {
        case .uninstallExistingThenInstall: "Back Up, Uninstall and Install"
        case .freeUpSpace: "Free Up Space"
        case .retry: "Try Again"
        case .reconnectDevice: "Reconnect"
        case .turnOffVerifyAppsOverUSB: "Show Me How"
        case .allowInstallViaUSB: "Show Me How"
        case .addMissingSplits: "Choose Splits"
        case .chooseCompatibleFile: "Choose Another File"
        }
    }
}

public struct ExplainedFailure: Hashable, Sendable {
    public let code: String
    public let title: String
    public let explanation: String
    public let fix: FixAction?
    /// False when the code is not in Airlock's table and a generic message was used.
    public let isKnown: Bool
}

/// Maps package-manager failure codes to plain-English causes and fixes.
public enum InstallErrorMapper {
    private struct Entry {
        let title: String
        let explanation: String
        let fix: FixAction?
    }

    public static func explain(_ failure: InstallFailure) -> ExplainedFailure {
        if let entry = table[failure.code] {
            return ExplainedFailure(
                code: failure.code, title: entry.title, explanation: entry.explanation, fix: entry.fix, isKnown: true
            )
        }
        return ExplainedFailure(
            code: failure.code,
            title: "Android refused the install",
            explanation: "The phone reported \(failure.code), which Airlock does not recognise yet. "
                + "Copy the details below when reporting the problem.",
            fix: nil,
            isKnown: false
        )
    }

    public static var knownCodes: [String] { table.keys.sorted() }

    // swiftlint:disable line_length
    private static let table: [String: Entry] = [
        "INSTALL_FAILED_ALREADY_EXISTS": Entry(
            title: "App is already installed",
            explanation: "The same app is already on the phone and this install did not allow replacing it.",
            fix: .retry
        ),
        "INSTALL_FAILED_INVALID_APK": Entry(
            title: "The file is not a valid app",
            explanation: "Android could not read this package. It may be damaged, incomplete or built incorrectly.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_FAILED_INVALID_URI": Entry(
            title: "The phone could not find the file",
            explanation: "The copy of the file on the phone was missing when Android tried to install it.",
            fix: .retry
        ),
        "INSTALL_FAILED_INSUFFICIENT_STORAGE": Entry(
            title: "Not enough storage on the phone",
            explanation: "The phone does not have enough free space to unpack and install this app.",
            fix: .freeUpSpace
        ),
        "INSTALL_FAILED_DUPLICATE_PACKAGE": Entry(
            title: "Duplicate app on the phone",
            explanation: "Another app with the same identity is already installed in a way that blocks this one.",
            fix: nil
        ),
        "INSTALL_FAILED_NO_SHARED_USER": Entry(
            title: "Required companion app is missing",
            explanation: "This app expects to share data with another app that is not installed.",
            fix: nil
        ),
        "INSTALL_FAILED_UPDATE_INCOMPATIBLE": Entry(
            title: "Signed by a different developer",
            explanation: "The installed copy of this app was signed with a different key, so Android will not update it. Updating means uninstalling the current copy first, which deletes its data.",
            fix: .uninstallExistingThenInstall
        ),
        "INSTALL_FAILED_SHARED_USER_INCOMPATIBLE": Entry(
            title: "Conflicts with a related app",
            explanation: "This app shares an identity with an installed app that was signed by a different developer.",
            fix: nil
        ),
        "INSTALL_FAILED_MISSING_SHARED_LIBRARY": Entry(
            title: "Phone lacks a required library",
            explanation: "The app needs a system library this phone does not have, so it cannot run here.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_FAILED_REPLACE_COULDNT_DELETE": Entry(
            title: "Could not replace the old version",
            explanation: "Android could not remove the previous version of this app. Restarting the phone usually helps.",
            fix: .retry
        ),
        "INSTALL_FAILED_DEXOPT": Entry(
            title: "Android could not optimise the app",
            explanation: "The phone failed while preparing the app's code. Free some space and try again.",
            fix: .retry
        ),
        "INSTALL_FAILED_OLDER_SDK": Entry(
            title: "Needs a newer Android version",
            explanation: "This app requires a newer version of Android than the phone runs.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_FAILED_NEWER_SDK": Entry(
            title: "Made for an older Android version",
            explanation: "This app only supports older versions of Android than the phone runs.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_FAILED_DEPRECATED_SDK_VERSION": Entry(
            title: "App is too old for this phone",
            explanation: "This app targets an Android version so old that the phone blocks it for security reasons.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_FAILED_CONFLICTING_PROVIDER": Entry(
            title: "Conflicts with an installed app",
            explanation: "Another installed app already uses a data provider name this app needs.",
            fix: nil
        ),
        "INSTALL_FAILED_TEST_ONLY": Entry(
            title: "This is a test build",
            explanation: "The app is marked as a developer test build, which Android does not install normally.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_FAILED_CPU_ABI_INCOMPATIBLE": Entry(
            title: "Built for a different processor",
            explanation: "The app's native code does not match the phone's processor type.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_FAILED_NO_MATCHING_ABIS": Entry(
            title: "Built for a different processor",
            explanation: "The app contains native code only for processor types this phone does not support. Look for a build marked for this phone's processor, for example arm64-v8a.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_FAILED_MISSING_FEATURE": Entry(
            title: "Phone lacks a required feature",
            explanation: "The app requires hardware or software features this phone does not have.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_FAILED_CONTAINER_ERROR": Entry(
            title: "Storage error on the phone",
            explanation: "Android could not write the app to storage. Free some space or restart the phone.",
            fix: .retry
        ),
        "INSTALL_FAILED_INVALID_INSTALL_LOCATION": Entry(
            title: "Cannot install to that location",
            explanation: "The app asked to be installed on storage the phone cannot use.",
            fix: nil
        ),
        "INSTALL_FAILED_MEDIA_UNAVAILABLE": Entry(
            title: "Storage is unavailable",
            explanation: "The storage the app needs is not mounted, for example a removed SD card.",
            fix: .retry
        ),
        "INSTALL_FAILED_VERIFICATION_TIMEOUT": Entry(
            title: "Verification took too long",
            explanation: "The phone's app verifier did not answer in time. Check the phone's screen and try again.",
            fix: .retry
        ),
        "INSTALL_FAILED_VERIFICATION_FAILURE": Entry(
            title: "Blocked by the phone's verifier",
            explanation: "The phone's app verifier rejected this app. You can turn off \"Verify apps over USB\" in Developer options if you trust it.",
            fix: .turnOffVerifyAppsOverUSB
        ),
        "INSTALL_FAILED_PACKAGE_CHANGED": Entry(
            title: "The app changed during install",
            explanation: "The package was modified while it was being installed. Try again.",
            fix: .retry
        ),
        "INSTALL_FAILED_UID_CHANGED": Entry(
            title: "Leftover data from an old install",
            explanation: "Old data from a previous install of this app conflicts with the new one. Restarting the phone often clears it.",
            fix: .retry
        ),
        "INSTALL_FAILED_VERSION_DOWNGRADE": Entry(
            title: "A newer version is installed",
            explanation: "The phone already has a newer version of this app. Installing an older version means uninstalling the current one first, which deletes its data.",
            fix: .uninstallExistingThenInstall
        ),
        "INSTALL_FAILED_PERMISSION_MODEL_DOWNGRADE": Entry(
            title: "Older permission model",
            explanation: "This version uses an older permission system than the installed one, so Android will not replace it.",
            fix: .uninstallExistingThenInstall
        ),
        "INSTALL_FAILED_SANDBOX_VERSION_DOWNGRADE": Entry(
            title: "Older security sandbox",
            explanation: "This version uses an older security sandbox than the installed one, so Android will not replace it.",
            fix: .uninstallExistingThenInstall
        ),
        "INSTALL_FAILED_ABORTED": Entry(
            title: "Install was cancelled",
            explanation: "The install was stopped before it finished. Nothing was changed on the phone.",
            fix: .retry
        ),
        "INSTALL_FAILED_INTERNAL_ERROR": Entry(
            title: "The phone hit an internal error",
            explanation: "Android failed for an internal reason. Restarting the phone and trying again often helps.",
            fix: .retry
        ),
        "INSTALL_FAILED_USER_RESTRICTED": Entry(
            title: "Installs from a computer are blocked",
            explanation: "The phone does not allow installing apps over USB. On Xiaomi phones turn on \"Install via USB\" in Developer options; on work phones a policy may block it.",
            fix: .allowInstallViaUSB
        ),
        "INSTALL_FAILED_DUPLICATE_PERMISSION": Entry(
            title: "Conflicts with an installed app",
            explanation: "Another installed app already defines a permission this app wants to define.",
            fix: nil
        ),
        "INSTALL_FAILED_MISSING_SPLIT": Entry(
            title: "Part of the app is missing",
            explanation: "This app is split into several parts and at least one required part was not included.",
            fix: .addMissingSplits
        ),
        "INSTALL_FAILED_SESSION_INVALID": Entry(
            title: "The install session expired",
            explanation: "The phone discarded the install before it finished. Try again.",
            fix: .retry
        ),
        "INSTALL_FAILED_BAD_SIGNATURE": Entry(
            title: "The app's signature is invalid",
            explanation: "The app's signature is broken, so Android cannot confirm who made it or that it is unmodified.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_FAILED_WRONG_INSTALLED_VERSION": Entry(
            title: "Installed version changed",
            explanation: "The installed version of this app changed during the install. Try again.",
            fix: .retry
        ),
        "INSTALL_FAILED_MULTIPACKAGE_INCONSISTENCY": Entry(
            title: "The app's parts do not match",
            explanation: "The parts of this app do not belong together, for example a split from a different version.",
            fix: .addMissingSplits
        ),
        "INSTALL_FAILED_PROCESS_NOT_DEFINED": Entry(
            title: "The app is built incorrectly",
            explanation: "The app refers to a process it never declares, so Android rejects it.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_FAILED_HADOOP_SPLIT_VERSION_MISMATCH": Entry(
            title: "The app's parts do not match",
            explanation: "The parts of this app come from different versions.",
            fix: .addMissingSplits
        ),
        "INSTALL_PARSE_FAILED_NOT_APK": Entry(
            title: "The file is not an Android app",
            explanation: "Android expected an app package but the file is something else.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_PARSE_FAILED_BAD_MANIFEST": Entry(
            title: "The app's manifest is broken",
            explanation: "The file that describes the app is damaged or invalid.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION": Entry(
            title: "Android could not read the app",
            explanation: "Android hit an unexpected problem reading the app. The file may be damaged.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_PARSE_FAILED_NO_CERTIFICATES": Entry(
            title: "The app is not signed",
            explanation: "Android only installs signed apps, and this one has no valid signature.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES": Entry(
            title: "Signed by a different developer",
            explanation: "This app or one of its parts is signed with a different key than the installed copy or the other parts. Updating means uninstalling the current copy first, which deletes its data.",
            fix: .uninstallExistingThenInstall
        ),
        "INSTALL_PARSE_FAILED_CERTIFICATE_ENCODING": Entry(
            title: "The app's signature is damaged",
            explanation: "The certificate in the app could not be read, which usually means the file is corrupted.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_PARSE_FAILED_BAD_PACKAGE_NAME": Entry(
            title: "The app has an invalid name",
            explanation: "The app's internal name is not valid, so Android rejects it.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_PARSE_FAILED_BAD_SHARED_USER_ID": Entry(
            title: "The app is built incorrectly",
            explanation: "The app declares an invalid shared identity, so Android rejects it.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_PARSE_FAILED_MANIFEST_MALFORMED": Entry(
            title: "The app's manifest is broken",
            explanation: "The file that describes the app has invalid structure.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_PARSE_FAILED_MANIFEST_EMPTY": Entry(
            title: "The app's manifest is empty",
            explanation: "The file that describes the app has no content.",
            fix: .chooseCompatibleFile
        ),
        "INSTALL_PARSE_FAILED_SKIPPED": Entry(
            title: "Android skipped this app",
            explanation: "Android skipped installing the package because a newer copy is already on the phone.",
            fix: nil
        ),
    ]
    // swiftlint:enable line_length
}
