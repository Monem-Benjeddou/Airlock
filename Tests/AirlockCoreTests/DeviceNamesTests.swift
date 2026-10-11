// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockCore
import Testing

@Suite("DeviceNames")
struct DeviceNamesTests {
    @Test func theOwnersNameComesFirst() {
        let name = DeviceNames.friendlyName(ownerName: "Work phone", marketName: "Redmi Note 13 Pro", model: "SM-S928B")
        #expect(name == "Work phone")
    }

    @Test func theMarketingNameComesNext() {
        #expect(DeviceNames.friendlyName(ownerName: nil, marketName: "Redmi Note 13 Pro", model: "23090RA98G") == "Redmi Note 13 Pro")
    }

    @Test func theBundledListComesNext() {
        #expect(DeviceNames.friendlyName(ownerName: nil, marketName: nil, model: "SM-S928B") == "Galaxy S24 Ultra")
    }

    @Test func theModelCodeIsTheLastResort() {
        #expect(DeviceNames.friendlyName(ownerName: nil, marketName: nil, model: "CPH2581") == "CPH2581")
    }

    @Test(arguments: ["", "   ", "null", "\n", "\u{7}"])
    func emptyOrUnsetValuesFallThrough(_ value: String) {
        #expect(DeviceNames.friendlyName(ownerName: value, marketName: value, model: "SM-S928U") == "Galaxy S24 Ultra")
    }

    @Test func aNameThatOnlyRepeatsTheModelCodeFallsThrough() {
        let name = DeviceNames.friendlyName(ownerName: "sdk_gphone64_arm64", marketName: nil, model: "sdk_gphone64_arm64")
        #expect(name == "Android Emulator")
    }

    @Test(arguments: [
        ("SM-S928B", "Galaxy S24 Ultra"), ("SM-S928U1", "Galaxy S24 Ultra"), ("SM-S921N", "Galaxy S24"),
        ("SM-F956B", "Galaxy Z Fold6"), ("SM-A556E", "Galaxy A55"), ("sdk_gphone64_arm64", "Android Emulator"),
        ("Android SDK built for x86_64", "Android Emulator"),
    ])
    func knownModels(_ model: String, _ expected: String) {
        #expect(DeviceNames.knownName(forModel: model) == expected)
    }

    @Test(arguments: ["SM-", "SM-X999B", "Pixel 9", "CPH2581", ""])
    func unknownModels(_ model: String) {
        #expect(DeviceNames.knownName(forModel: model) == nil)
    }

    @Test func controlCharactersAreDroppedAndSpacesTrimmed() {
        #expect(DeviceNames.cleaned("  Work\u{0}\nphone \t") == "Workphone")
    }

    @Test func longNamesAreCut() throws {
        let name = try #require(DeviceNames.cleaned(String(repeating: "a", count: 200)))
        #expect(name.count == DeviceNames.maxLength)
        #expect(name.hasSuffix("…"))
    }

    @Test func displayNameDefaultsToTheModel() throws {
        let info = DeviceInfo(
            serial: try DeviceSerial("R58"), stableID: "R58", model: "SM-S928B", manufacturer: "samsung",
            brand: .samsung, androidVersion: "16",
            properties: DeviceProperties(abis: [], densityDPI: 0, locales: [], sdkLevel: 36), batteryPercent: nil
        )
        #expect(info.displayName == "SM-S928B")
    }
}
