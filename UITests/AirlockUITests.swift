// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import XCTest

/// One or more tests per user story, run against the app's in-memory demo services (`--demo`).
final class AirlockUITests: XCTestCase {
    private let app = XCUIApplication()

    override func setUp() {
        continueAfterFailure = false
    }

    override func tearDown() {
        app.terminate()
    }

    private func launch(_ arguments: [String] = ["--demo"], queue: [String] = []) {
        app.launchArguments = arguments
        if !queue.isEmpty { app.launchEnvironment["AIRLOCK_DEMO_QUEUE"] = queue.joined(separator: ",") }
        app.launch()
    }

    // MARK: F1 Device connection and onboarding

    func testOnboardingExplainsHowToConnectWhenNoPhoneIsAttached() {
        launch(["--demo-no-device"])
        XCTAssertTrue(app.staticTexts["onboardingTitle"].waitForExistence(timeout: 5))
        XCTAssertEqual(app.staticTexts["onboardingTitle"].label, "Connect your Android phone")
        XCTAssertTrue(app.staticTexts["No phone connected"].exists)
    }

    func testOnboardingShowsBrandSpecificSteps() {
        launch(["--demo-no-device"])
        let picker = app.radioGroups["brandPicker"]
        XCTAssertTrue(picker.waitForExistence(timeout: 5))
        picker.radioButtons["Samsung Galaxy"].click()
        XCTAssertTrue(app.staticTexts["3. Turn off Auto Blocker"].waitForExistence(timeout: 2))
        picker.radioButtons["Xiaomi, Redmi or POCO"].click()
        XCTAssertTrue(app.staticTexts["3. Turn on Install via USB"].waitForExistence(timeout: 2))
    }

    func testReadyPhoneShowsModelAndBattery() {
        launch()
        XCTAssertTrue(app.staticTexts["Pixel 9 (demo)"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Android 16 · 82%"].exists)
        XCTAssertTrue(app.otherElements["dropZone"].exists || app.buttons["chooseFiles"].exists)
    }

    // MARK: F2 Installer and F3 safety report

    func testLowRiskFileInstallsWithoutQuestions() {
        launch(queue: ["notes.apk"])
        XCTAssertTrue(app.staticTexts["Installed version 3"].waitForExistence(timeout: 10))
    }

    func testHighRiskFileShowsTheReportAndCanBeDeclined() {
        launch(queue: ["risky.apk"])
        let badge = app.staticTexts["riskBadge"]
        XCTAssertTrue(badge.waitForExistence(timeout: 10))
        XCTAssertEqual(badge.label, "High risk")
        XCTAssertFalse(app.staticTexts.containing(NSPredicate(format: "label CONTAINS[c] 'safe'")).firstMatch.exists,
                       "the report never calls an app safe")
        app.buttons["skipInstall"].click()
        XCTAssertTrue(app.staticTexts["Not installed"].waitForExistence(timeout: 5))
    }

    func testHighRiskFileCanBeInstalledAfterReview() {
        launch(queue: ["risky.apk"])
        XCTAssertTrue(app.buttons["approveInstall"].waitForExistence(timeout: 10))
        app.buttons["approveInstall"].click()
        XCTAssertTrue(app.staticTexts["Installed version 3"].waitForExistence(timeout: 10))
    }

    func testQueueInstallsSeveralFilesInOrder() {
        launch(queue: ["one.apk", "two.apk", "three.apk"])
        let predicate = NSPredicate(format: "label == 'Installed version 3'")
        let installed = app.staticTexts.matching(predicate)
        let deadline = Date().addingTimeInterval(15)
        while installed.count < 3, Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.2)) }
        XCTAssertEqual(installed.count, 3)
    }

    // MARK: F4 App manager and debloat

    func testDisablingAnAppNeedsConfirmationAndCanBeRestored() {
        launch()
        app.outlineRows.staticTexts["Apps"].click()
        let row = app.tables["appsTable"].staticTexts["com.example.bloat"]
        XCTAssertTrue(row.waitForExistence(timeout: 5))
        row.click()
        app.toolbars.buttons["Disable"].click()
        XCTAssertTrue(app.buttons["confirmChange"].waitForExistence(timeout: 3), "nothing changes without confirmation")
        app.buttons["confirmChange"].click()
        XCTAssertTrue(app.otherElements["resultsBanner"].waitForExistence(timeout: 5)
            || app.staticTexts["Done: 1 change(s) applied."].waitForExistence(timeout: 5))

        app.outlineRows.staticTexts["History"].click()
        let restore = app.buttons["restoreButton"]
        XCTAssertTrue(restore.waitForExistence(timeout: 5))
        restore.click()
    }

    func testCriticalSystemAppsCannotBeDisabled() {
        launch()
        app.outlineRows.staticTexts["Apps"].click()
        let row = app.tables["appsTable"].staticTexts["com.android.settings"]
        XCTAssertTrue(row.waitForExistence(timeout: 5))
        row.click()
        app.toolbars.buttons["Disable"].click()
        app.buttons["confirmChange"].click()
        XCTAssertTrue(app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'core part of Android'")).firstMatch
            .waitForExistence(timeout: 5))
    }

    func testDebloatPresetsOpen() {
        launch()
        app.outlineRows.staticTexts["Apps"].click()
        XCTAssertTrue(app.toolbars.buttons["Debloat Presets"].waitForExistence(timeout: 5))
        app.toolbars.buttons["Debloat Presets"].click()
        XCTAssertTrue(app.staticTexts["Debloat presets"].waitForExistence(timeout: 3))
        XCTAssertTrue(app.staticTexts["com.example.bloat"].exists)
    }

    // MARK: F5 Wireless pairing

    func testQRPairingShowsACode() {
        launch()
        app.outlineRows.staticTexts["Wireless"].click()
        app.buttons["showQR"].click()
        XCTAssertTrue(app.images["pairingQR"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Waiting for your phone…"].exists)
    }
}
