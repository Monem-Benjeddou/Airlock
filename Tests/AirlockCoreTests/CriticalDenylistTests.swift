// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Testing

@Suite("CriticalDenylist")
struct CriticalDenylistTests {
    private let denylist = CriticalDenylist.standard

    private func pkg(_ raw: String) -> PackageName { try! PackageName(raw) } // swiftlint:disable:this force_try

    @Test(arguments: [
        "android",
        "com.android.systemui",
        "com.android.phone",
        "com.android.settings",
        "com.android.providers.settings",
        "com.android.shell",
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
        "com.android.permissioncontroller",
        "com.google.android.permissioncontroller",
        "com.android.server.telecom",
        "com.android.providers.telephony",
        "com.android.providers.media.module",
        "com.google.android.providers.media.module",
        "com.android.networkstack",
        "com.google.android.networkstack",
        "com.android.keychain",
        "com.miui.securitycenter",
        "com.lbe.security.miui",
    ])
    func blocksDestructiveActionsOnCriticalPackages(_ raw: String) throws {
        // "android" is not a valid two-segment application ID but must still be denied by raw name.
        let verdict = denylist.check(rawPackage: raw, operation: .uninstallForUser)
        #expect(verdict == .blocked(.criticalSystemComponent))
        let disable = denylist.check(rawPackage: raw, operation: .disableForUser)
        #expect(disable == .blocked(.criticalSystemComponent))
        let uninstall = denylist.check(rawPackage: raw, operation: .uninstall)
        #expect(uninstall == .blocked(.criticalSystemComponent))
    }

    @Test func allowsOrdinaryPackages() {
        let verdict = denylist.check(pkg("com.facebook.katana"), operation: .uninstallForUser, context: .init())
        #expect(verdict == .allowed)
    }

    @Test(arguments: [DeviceOperation.enable, .installExisting])
    func neverBlocksRestoreOperations(_ operation: DeviceOperation) {
        let verdict = denylist.check(pkg("com.android.systemui"), operation: operation, context: .init())
        #expect(verdict == .allowed)
    }

    @Test func blocksOnlyLauncherWhenNoAlternative() {
        let launcher = pkg("com.sec.android.app.launcher")
        let alone = DenylistContext(launchers: [launcher])
        #expect(denylist.check(launcher, operation: .disableForUser, context: alone) == .blocked(.onlyLauncher))

        let withAlternative = DenylistContext(launchers: [launcher, pkg("com.teslacoilsw.launcher")])
        #expect(denylist.check(launcher, operation: .disableForUser, context: withAlternative) == .allowed)
    }

    @Test func blocksOnlyKeyboardWhenNoAlternative() {
        let keyboard = pkg("com.google.android.inputmethod.latin")
        let alone = DenylistContext(inputMethods: [keyboard])
        #expect(denylist.check(keyboard, operation: .uninstallForUser, context: alone) == .blocked(.onlyKeyboard))
        let withAlternative = DenylistContext(inputMethods: [keyboard, pkg("com.touchtype.swiftkey")])
        #expect(denylist.check(keyboard, operation: .uninstallForUser, context: withAlternative) == .allowed)
    }

    @Test func criticalWinsOverLauncherRule() {
        // A critical package listed as the only launcher still reports the stronger reason.
        let settings = pkg("com.android.settings")
        let context = DenylistContext(launchers: [settings])
        #expect(denylist.check(settings, operation: .disableForUser, context: context) == .blocked(.criticalSystemComponent))
    }

    @Test func customDenylistIsRespected() {
        let custom = CriticalDenylist(packages: ["com.example.critical"])
        #expect(custom.check(pkg("com.example.critical"), operation: .uninstall, context: .init())
            == .blocked(.criticalSystemComponent))
        #expect(custom.check(pkg("com.android.systemui"), operation: .uninstall, context: .init()) == .allowed)
    }

    @Test func standardListIsNotEmptyAndAllEntriesAreLowercaseASCII() {
        #expect(CriticalDenylist.standard.packages.count >= 19)
        for name in CriticalDenylist.standard.packages {
            #expect(name == name.lowercased())
            let ascii = name.allSatisfy(\.isASCII)
            #expect(ascii)
        }
    }

    @Test(arguments: DenylistReason.allCases)
    func everyReasonHasAnExplanation(_ reason: DenylistReason) {
        #expect(!reason.explanation.isEmpty)
        #expect(reason.explanation.hasSuffix("."))
    }

    @Test func destructiveClassification() {
        #expect(DeviceOperation.uninstall.isDestructive)
        #expect(DeviceOperation.uninstallForUser.isDestructive)
        #expect(DeviceOperation.disableForUser.isDestructive)
        #expect(!DeviceOperation.enable.isDestructive)
        #expect(!DeviceOperation.installExisting.isDestructive)
    }
}
