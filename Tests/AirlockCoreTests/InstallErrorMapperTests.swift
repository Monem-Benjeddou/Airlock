// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import Testing

@Suite("InstallFailure parsing")
struct InstallFailureParsingTests {
    @Test func parsesCodeAndDetail() throws {
        let output = """
        Performing Streamed Install
        adb: failed to install game.apk: Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: Package com.x signatures do not \
        match previously installed version; ignoring!]
        """
        let failure = try #require(InstallFailure.parse(output))
        #expect(failure.code == "INSTALL_FAILED_UPDATE_INCOMPATIBLE")
        #expect(failure.detail == "Package com.x signatures do not match previously installed version; ignoring!")
    }

    @Test func parsesCodeWithoutDetail() throws {
        let failure = try #require(InstallFailure.parse("Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]"))
        #expect(failure.code == "INSTALL_FAILED_INSUFFICIENT_STORAGE")
        #expect(failure.detail == nil)
    }

    @Test func parsesSessionCommitFailure() throws {
        // `pm install-commit` prints the same shape.
        let failure = try #require(InstallFailure.parse("Failure [INSTALL_FAILED_VERSION_DOWNGRADE: Downgrade detected]\n"))
        #expect(failure.code == "INSTALL_FAILED_VERSION_DOWNGRADE")
        #expect(failure.detail == "Downgrade detected")
    }

    @Test func parsesParseFailureCodes() throws {
        let failure = try #require(InstallFailure.parse("Failure [INSTALL_PARSE_FAILED_NO_CERTIFICATES: no certs]"))
        #expect(failure.code == "INSTALL_PARSE_FAILED_NO_CERTIFICATES")
    }

    @Test func parsesBareCodeInAdbError() throws {
        let failure = try #require(InstallFailure.parse("adb: failed to install x.apk: INSTALL_FAILED_NO_MATCHING_ABIS"))
        #expect(failure.code == "INSTALL_FAILED_NO_MATCHING_ABIS")
        #expect(failure.detail == nil)
    }

    @Test(arguments: ["Success", "", "Performing Streamed Install\nSuccess\n", "Failure []", "Failure [lowercase]"])
    func returnsNilWithoutCode(_ output: String) {
        #expect(InstallFailure.parse(output) == nil)
    }
}

@Suite("InstallErrorMapper")
struct InstallErrorMapperTests {
    /// The plan names these explicitly; each must have a specific explanation.
    @Test(arguments: [
        "INSTALL_FAILED_UPDATE_INCOMPATIBLE",
        "INSTALL_FAILED_INSUFFICIENT_STORAGE",
        "INSTALL_FAILED_VERSION_DOWNGRADE",
        "INSTALL_FAILED_NO_MATCHING_ABIS",
    ])
    func namedCodesAreKnown(_ code: String) {
        #expect(InstallErrorMapper.knownCodes.contains(code))
        let explained = InstallErrorMapper.explain(InstallFailure(code: code))
        #expect(explained.isKnown)
    }

    @Test(arguments: InstallErrorMapper.knownCodes)
    func everyKnownCodeHasPlainEnglish(_ code: String) {
        let explained = InstallErrorMapper.explain(InstallFailure(code: code))
        #expect(explained.code == code)
        #expect(explained.isKnown)
        #expect(!explained.title.isEmpty)
        #expect(!explained.explanation.isEmpty)
        // Plain English: the explanation must not just echo the code.
        #expect(!explained.title.contains("INSTALL_"))
        #expect(!explained.explanation.contains("INSTALL_"))
        #expect(explained.title.count <= 60)
        #expect(explained.explanation.hasSuffix("."))
    }

    @Test func knownCodesAreUnique() {
        #expect(Set(InstallErrorMapper.knownCodes).count == InstallErrorMapper.knownCodes.count)
    }

    @Test func signatureMismatchOffersUninstallWithBackup() {
        let explained = InstallErrorMapper.explain(InstallFailure(code: "INSTALL_FAILED_UPDATE_INCOMPATIBLE"))
        #expect(explained.fix == .uninstallExistingThenInstall)
        #expect(explained.fix?.isDestructive == true)
        #expect(explained.explanation.localizedCaseInsensitiveContains("signed"))
    }

    @Test func inconsistentCertificatesAlsoOffersUninstall() {
        let explained = InstallErrorMapper.explain(InstallFailure(code: "INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES"))
        #expect(explained.fix == .uninstallExistingThenInstall)
    }

    @Test func storageOffersFreeingSpace() {
        let explained = InstallErrorMapper.explain(InstallFailure(code: "INSTALL_FAILED_INSUFFICIENT_STORAGE"))
        #expect(explained.fix == .freeUpSpace)
        #expect(explained.fix?.isDestructive == false)
    }

    @Test func downgradeOffersUninstall() {
        let explained = InstallErrorMapper.explain(InstallFailure(code: "INSTALL_FAILED_VERSION_DOWNGRADE"))
        #expect(explained.fix == .uninstallExistingThenInstall)
    }

    @Test func abiMismatchHasNoAutomaticFix() {
        let explained = InstallErrorMapper.explain(InstallFailure(code: "INSTALL_FAILED_NO_MATCHING_ABIS"))
        #expect(explained.fix == .chooseCompatibleFile)
    }

    @Test func verificationFailureSuggestsVerifySetting() {
        let explained = InstallErrorMapper.explain(InstallFailure(code: "INSTALL_FAILED_VERIFICATION_FAILURE"))
        #expect(explained.fix == .turnOffVerifyAppsOverUSB)
    }

    @Test func missingSplitSuggestsAddingSplits() {
        let explained = InstallErrorMapper.explain(InstallFailure(code: "INSTALL_FAILED_MISSING_SPLIT"))
        #expect(explained.fix == .addMissingSplits)
    }

    @Test func userRestrictedSuggestsInstallViaUSBSetting() {
        let explained = InstallErrorMapper.explain(InstallFailure(code: "INSTALL_FAILED_USER_RESTRICTED"))
        #expect(explained.fix == .allowInstallViaUSB)
    }

    @Test func abortedSuggestsRetry() {
        let explained = InstallErrorMapper.explain(InstallFailure(code: "INSTALL_FAILED_ABORTED"))
        #expect(explained.fix == .retry)
    }

    @Test func unknownCodeFallsBackToGenericButKeepsCode() {
        let explained = InstallErrorMapper.explain(InstallFailure(code: "INSTALL_FAILED_SOMETHING_NEW", detail: "x"))
        #expect(explained.isKnown == false)
        #expect(explained.code == "INSTALL_FAILED_SOMETHING_NEW")
        #expect(explained.explanation.contains("INSTALL_FAILED_SOMETHING_NEW"))
        #expect(explained.fix == nil)
    }

    @Test(arguments: FixAction.allCases)
    func everyFixHasAButtonTitle(_ fix: FixAction) {
        #expect(!fix.buttonTitle.isEmpty)
    }

    @Test func onlyUninstallFixIsDestructive() {
        let destructive = FixAction.allCases.filter(\.isDestructive)
        #expect(destructive == [.uninstallExistingThenInstall])
    }
}
