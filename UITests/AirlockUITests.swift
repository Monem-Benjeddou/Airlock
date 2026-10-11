// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import XCTest

/// One or more tests per user story, run against the app's in-memory demo services (`--demo`).
///
/// SwiftUI on macOS exposes a `Text` as a static text whose string is its *value*, while buttons and combined
/// elements carry it as their *label*, so lookups match either. `launch()` replaces any running copy of the
/// app, so each test starts clean without a tearDown.
@MainActor
final class AirlockUITests: XCTestCase {
    private lazy var app = XCUIApplication()
    private var printedTree = false

    private func launch(_ arguments: [String] = ["--demo"], queue: [String] = []) {
        continueAfterFailure = false
        // App Nap can freeze a background app's timers on CI runners; keep it out of the picture. The defaults
        // pair goes first: after "--demo", AppKit would read it as that flag's value and treat "YES" as a file.
        app.launchArguments = ["-NSAppSleepDisabled", "YES"] + arguments
        if !queue.isEmpty { app.launchEnvironment["AIRLOCK_DEMO_QUEUE"] = queue.joined(separator: ",") }
        app.launch()
        app.activate()
    }

    // MARK: Queries

    /// Any element whose identifier, label or value is exactly `text`.
    private func element(_ text: String) -> XCUIElement {
        let byLabel = NSPredicate(format: "identifier == %@ OR label == %@", text, text)
        let label = app.descendants(matching: .any).matching(byLabel).firstMatch
        if label.exists { return label }
        return app.staticTexts.matching(NSPredicate(format: "value == %@", text)).firstMatch
    }

    /// Whether some element's label, or the value of a static text, text view or text field (selectable text),
    /// contains `text`, within `timeout`.
    private func appears(containing text: String, timeout: TimeInterval) -> Bool {
        let labels = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS[c] %@", text)).firstMatch
        let values = app.staticTexts.matching(NSPredicate(format: "value CONTAINS[c] %@", text)).firstMatch
        let textViews = app.textViews.matching(NSPredicate(format: "value CONTAINS[c] %@", text)).firstMatch
        let textFields = app.textFields.matching(NSPredicate(format: "value CONTAINS[c] %@", text)).firstMatch
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if labels.exists || values.exists || textViews.exists || textFields.exists { return true }
            RunLoop.current.run(until: Date().addingTimeInterval(0.2))
        } while Date() < deadline
        return false
    }

    /// Waits for `text` and fails with the accessibility tree printed, so CI logs show what was on screen.
    @discardableResult
    private func wait(
        for text: String, timeout: TimeInterval = 10, file: StaticString = #filePath, line: UInt = #line
    ) -> XCUIElement {
        let deadline = Date().addingTimeInterval(timeout)
        var found = element(text)
        while !found.exists, Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.2))
            found = element(text)
        }
        if !found.exists { fail("\"\(text)\" never appeared", file: file, line: line) }
        return found
    }

    private func fail(_ message: String, file: StaticString, line: UInt) {
        if !printedTree {
            printedTree = true
            print("=== Accessibility tree at failure ===\n\(app.debugDescription)\n=== end ===")
        }
        XCTFail(message, file: file, line: line)
    }

    private func open(_ section: String) {
        wait(for: "section-\(section)").click()
    }

    private func text(of element: XCUIElement) -> String {
        (element.value as? String).flatMap { $0.isEmpty ? nil : $0 } ?? element.label
    }

    // MARK: F1 Device connection and onboarding

    func testOnboardingExplainsHowToConnectWhenNoPhoneIsAttached() {
        launch(["--demo-no-device"])
        XCTAssertEqual(text(of: wait(for: "onboardingTitle")), "Connect your Android phone")
        wait(for: "No phone connected")
    }

    func testOnboardingShowsBrandSpecificSteps() {
        launch(["--demo-no-device"])
        wait(for: "Samsung Galaxy").click()
        XCTAssertTrue(appears(containing: "Turn off Auto Blocker", timeout: 3))
        wait(for: "Xiaomi, Redmi or POCO").click()
        XCTAssertTrue(appears(containing: "Turn on Install via USB", timeout: 3))
    }

    func testReadyPhoneShowsModelAndBattery() {
        launch()
        wait(for: "Pixel 9 (demo)")
        wait(for: "Android 16 · 82%")
        wait(for: "chooseFiles")
    }

    // MARK: F2 Installer and F3 safety report

    func testLowRiskFileInstallsWithoutQuestions() {
        launch(queue: ["notes.apk"])
        wait(for: "Installed version 3", timeout: 30)
        XCTAssertFalse(element("approveInstall").exists, "a Low risk file is not held for review")
    }

    func testHighRiskFileShowsTheReportAndCanBeDeclined() {
        launch(queue: ["risky.apk"])
        XCTAssertEqual(text(of: wait(for: "riskBadge")), "High risk")
        XCTAssertFalse(appears(containing: "safe", timeout: 0), "the report never calls an app safe")
        XCTAssertFalse(appears(containing: "cdcdcdcd", timeout: 0), "hashes stay out of the way until asked for")
        let details = wait(for: "technicalDetails")
        XCTAssertEqual(details.label, "Technical details", "VoiceOver names the section")
        details.click()
        if !appears(containing: "cdcdcdcd", timeout: 3) {
            fail("Technical details did not show the hash", file: #filePath, line: #line)
        }
        wait(for: "skipInstall").click()
        wait(for: "Not installed")
    }

    func testReturnNeverInstallsAHighRiskFile() {
        // Regression: Install Anyway was the default button, so pressing Return installed a High risk app.
        launch(queue: ["risky.apk"])
        wait(for: "riskBadge")
        XCTAssertFalse(element("approveInstall").isEnabled, "Install Anyway waits for the acknowledgement")
        app.typeKey(.return, modifierFlags: [])
        wait(for: "Not installed")
    }

    func testHighRiskFileCanBeInstalledAfterReview() {
        launch(queue: ["risky.apk"])
        wait(for: "acknowledgeRisk").click()
        wait(for: "approveInstall").click()
        wait(for: "Installed version 3", timeout: 30)
    }

    func testQueueInstallsSeveralFilesInOrder() {
        launch(queue: ["one.apk", "two.apk", "three.apk"])
        wait(for: "3 of 3 installed", timeout: 30)
        let installed = app.staticTexts.matching(NSPredicate(format: "value == 'Installed version 3' OR label == 'Installed version 3'"))
        let deadline = Date().addingTimeInterval(20)
        while installed.count < 3, Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.2)) }
        if installed.count != 3 { fail("expected 3 installed rows, saw \(installed.count)", file: #filePath, line: #line) }
    }

    // MARK: Real files through the sandboxed parser

    private func fixture(_ name: String) throws -> URL {
        try XCTUnwrap(Bundle(for: Self.self).url(forResource: name, withExtension: "apk"), "missing UI test fixture \(name)")
    }

    func testARealAPKIsParsedByTheSandboxedHelper() throws {
        // The shipped path: the app hands the file to AirlockParser.xpc, which parses it inside its sandbox and
        // hands the extracted files back. Only the phone is simulated.
        launch(queue: [try fixture("app-v2-rsa").path])
        wait(for: "org.airlock.fixture", timeout: 30)
        wait(for: "Installed version 3", timeout: 30)
    }

    func testAFolderOfSplitAPKsIsParsedByTheSandboxedHelper() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("airlock-ui-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        try FileManager.default.copyItem(at: try fixture("app-v2-rsa"), to: folder.appendingPathComponent("base.apk"))
        try FileManager.default.copyItem(at: try fixture("split-arm64-v2-rsa"),
                                         to: folder.appendingPathComponent("split_config.arm64_v8a.apk"))
        launch(queue: [folder.path])
        wait(for: "org.airlock.fixture", timeout: 30)
        wait(for: "Installed version 3", timeout: 30)
    }

    // MARK: F4 App manager and debloat

    func testDisablingAnAppNeedsConfirmationAndCanBeRestored() {
        launch()
        open("Apps")
        wait(for: "com.example.bloat").click()
        app.buttons.matching(NSPredicate(format: "label == 'Disable'")).firstMatch.click()
        wait(for: "confirmChange", timeout: 3).click()
        wait(for: "Done: 1 change(s) applied.")

        open("History")
        wait(for: "restoreButton").click()
    }

    func testCriticalSystemAppsCannotBeDisabled() {
        launch()
        open("Apps")
        wait(for: "com.android.settings").click()
        app.buttons.matching(NSPredicate(format: "label == 'Disable'")).firstMatch.click()
        wait(for: "confirmChange", timeout: 3).click()
        if !appears(containing: "core part of Android", timeout: 5) {
            fail("the denylist reason was not shown", file: #filePath, line: #line)
        }
    }

    func testDebloatPresetsOpen() {
        launch()
        open("Apps")
        wait(for: "presetsButton").click()
        wait(for: "Debloat presets")
        wait(for: "com.example.bloat")
    }

    // MARK: Identity and accessibility

    func testAboutPanelShowsTheVersionAndLicence() {
        // Regression: Info.plist hard-coded version 1.0, so About and Finder showed the wrong version.
        launch()
        app.menuBars.menuBarItems["Airlock"].click()
        app.menuBars.menuItems["About Airlock"].click()
        if !appears(containing: "Version 0.1.0", timeout: 5) { fail("About shows the wrong version", file: #filePath, line: #line) }
        if !appears(containing: "GNU GPL 3.0", timeout: 2) { fail("About has no licence", file: #filePath, line: #line) }
    }

    func testVoiceOverNeverHearsRawSymbolNames() {
        // Regression: images exposed SF Symbol names such as "cable.connector" and "arrow.down.app".
        launch(queue: ["notes.apk"])
        wait(for: "Installed version 3", timeout: 30)
        wait(for: "USB")
        for name in ["cable.connector", "arrow.down.app", "Arrow Down Circle", "checkmark.circle.fill"] {
            let match = app.descendants(matching: .any).matching(NSPredicate(format: "label == %@", name)).firstMatch
            XCTAssertFalse(match.exists, "VoiceOver would read \(name)")
        }
    }

    func testMainScreensPassTheAccessibilityAudit() throws {
        launch(["--demo-no-device"])
        continueAfterFailure = true  // report every issue on every screen in one run
        wait(for: "onboardingTitle")
        try audit("onboarding")

        launch(queue: ["risky.apk"])
        wait(for: "riskBadge")
        try audit("review sheet", within: app.sheets.firstMatch)
        wait(for: "skipInstall").click()
        wait(for: "Not installed")
        try audit("install queue")

        open("Apps")
        wait(for: "com.example.bloat")
        try audit("apps")

        open("Wireless")
        wait(for: "showQR")
        try audit("wireless")
    }

    /// Runs Apple's audit on the active window and fails with the screen name, printing the tree once for CI logs.
    ///
    /// Three kinds of finding are framework noise and are skipped: "no description" on layout containers
    /// (SwiftUI's invisible groups, split views and the Touch Bar, which VoiceOver does not stop on), anything
    /// in the title bar, which AppKit draws, and contrast of system-coloured sidebar text.
    /// With `region`, only findings on its own elements count: under a sheet, macOS dims the window on purpose.
    private func audit(_ screen: String, within region: XCUIElement? = nil) throws {
        settleAnimations(expectingSheet: region != nil)
        let regionFrames = try region.map { try Self.frames(in: $0.snapshot()) }
        app.activate()
        let window = app.windows.firstMatch.frame
        let sidebar = app.outlines["Sidebar"].firstMatch
        try app.performAccessibilityAudit { [self] issue in
            if let element = issue.element {
                if let regionFrames, !regionFrames.contains(NSStringFromRect(element.frame)) { return true }
                // The sidebar's text uses the system's own colours on its translucent material, which the audit
                // measures against a flattened backdrop; the app does not colour it.
                if issue.auditType == .contrast, sidebar.exists, sidebar.frame.contains(element.frame) { return true }
                let containers: [XCUIElement.ElementType] = [.group, .splitGroup, .touchBar]
                if issue.auditType == .sufficientElementDescription, containers.contains(element.elementType) { return true }
                if element.frame.maxY <= window.minY + 52 { return true }
            }
            let shot = XCTAttachment(screenshot: app.screenshot())
            shot.name = "audit-\(screen)"
            shot.lifetime = .keepAlways
            add(shot)
            print("AUDIT DETAIL \(screen): \(issue.detailedDescription)")
            fail("\(screen): \(issue.auditType) \(issue.compactDescription) on \(issue.element?.debugDescription ?? "the window")",
                 file: #filePath, line: #line)
            return true
        }
    }

    /// Waits for sheet animations to finish. A sheet fades in and out over the window and dims it meanwhile, so
    /// an audit taken mid-fade measures regular-weight text against a dimmed window. A sheet's frame does not
    /// change while it fades, so this waits on the sheet's presence and then a fixed settling time.
    private func settleAnimations(expectingSheet: Bool) {
        let deadline = Date().addingTimeInterval(5)
        while app.sheets.firstMatch.exists != expectingSheet, Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        }
        RunLoop.current.run(until: Date().addingTimeInterval(1))
    }

    /// The frames of every element in a snapshot, as strings so they can go in a set.
    private static func frames(in snapshot: any XCUIElementSnapshot) -> Set<String> {
        snapshot.children.reduce(into: [NSStringFromRect(snapshot.frame)]) { $0.formUnion(frames(in: $1)) }
    }

    // MARK: F5 Wireless pairing

    func testQRPairingShowsACode() {
        launch()
        open("Wireless")
        wait(for: "showQR").click()
        wait(for: "pairingQR")
        wait(for: "Waiting for your phone…")
    }
}
