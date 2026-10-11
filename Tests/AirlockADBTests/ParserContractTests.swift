// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

@testable import AirlockADB
import AirlockCore
import AirlockTestSupport
import Testing

/// Golden-file contract tests: every adb output Airlock parses, from real recorded devices.
@Suite("Contract: recorded devices")
struct RecordedDeviceContractTests {
    @Test(arguments: Fixture.recordedDevices)
    func everyRecordedOutputParses(_ device: String) throws {
        let devices = try DevicesParser.parse(Fixture.adb(device, "devices-l.txt"))
        #expect(devices.count == 1)
        #expect(devices.first?.state == .ready)

        let props = GetpropParser.parse(Fixture.adb(device, "getprop.txt"))
        #expect(props["ro.build.version.sdk"] != nil)
        #expect(props["ro.product.cpu.abilist"] != nil)

        #expect(BatteryParser.level(Fixture.adb(device, "dumpsys-battery.txt")) != nil)
        #expect(try DensityParser.parse(Fixture.adb(device, "wm-density.txt")) > 0)

        let packages = PackageListParser.parse(Fixture.adb(device, "pm-list-packages.txt"))
        #expect(packages.count > 100)
        let system = PackageListParser.names(Fixture.adb(device, "pm-list-system.txt"))
        let thirdParty = PackageListParser.names(Fixture.adb(device, "pm-list-third-party.txt"))
        #expect(system.count + thirdParty.count == packages.count)

        #expect(try DiskFreeParser.availableBytes(Fixture.adb(device, "df-data.txt")) > 0)
        #expect(PmPathParser.parse(Fixture.adb(device, "pm-path.txt")).count >= 1)

        let dumpsys = try DumpsysPackageParser.parse(Fixture.adb(device, "dumpsys-package.txt"), package: "com.android.settings")
        #expect(dumpsys.versionCode > 0)
        #expect(!HomeActivitiesParser.parse(Fixture.adb(device, "home-activities.txt")).isEmpty)
        #expect(!InputMethodParser.parse(Fixture.adb(device, "ime-list.txt")).isEmpty)
    }
}

@Suite("Contract: Galaxy S24 Ultra, Android 16")
struct GalaxyS24ContractTests {
    let device = "samsung-s24ultra-android16"

    @Test func devicesList() throws {
        let devices = try DevicesParser.parse(Fixture.adb(device, "devices-l.txt"))
        let s24 = try #require(devices.first)
        #expect(s24.serial.rawValue == "FIXTURESERIAL01")
        #expect(s24.state == .ready)
        #expect(s24.model == "SM_S928B")
        #expect(s24.product == "e3qxxx")
        #expect(s24.deviceName == "e3q")
        #expect(s24.transportID == "43")
    }

    @Test func properties() throws {
        let props = GetpropParser.parse(Fixture.adb(device, "getprop.txt"))
        #expect(props["ro.product.model"] == "SM-S928B")
        #expect(props["ro.product.cpu.abilist"] == "arm64-v8a")
        #expect(props["ro.product.cpu.abilist32"] == "")
        #expect(props["persist.sys.locale"] == "en-GB")
        #expect(props["ro.build.version.release"] == "16")
        #expect(props["ro.build.version.sdk"] == "36")
    }

    @Test func battery() {
        #expect(BatteryParser.level(Fixture.adb(device, "dumpsys-battery.txt")) == 95)
    }

    @Test func overrideDensityWinsOverPhysical() throws {
        #expect(try DensityParser.parse(Fixture.adb(device, "wm-density.txt")) == 560)
    }

    @Test func packageList() throws {
        let packages = PackageListParser.parse(Fixture.adb(device, "pm-list-packages.txt"))
        #expect(packages.count == 597) // 598 listed; the single-segment `android` package is skipped
        let settings = try #require(packages.first { $0.packageName.rawValue == "com.android.wallpaperbackup" })
        #expect(settings.apkPath == "/system/app/WallpaperBackup/WallpaperBackup.apk")
        #expect(settings.versionCode == 36)
        #expect(settings.installer == nil)
        #expect(settings.uid == 10404)

        // Paths under /data/app contain base64 with '=' characters; the name follows the LAST '='.
        let updated = try #require(packages.first { $0.packageName.rawValue == "com.samsung.android.inputshare" })
        #expect(updated.apkPath.hasPrefix("/data/app/~~"))
        #expect(updated.apkPath.hasSuffix("/base.apk"))
        #expect(updated.installer == "com.sec.android.app.samsungapps")
        #expect(updated.versionCode == 270_104_000)
    }

    @Test func disabledPackages() {
        let disabled = PackageListParser.names(Fixture.adb(device, "pm-list-disabled.txt"))
        #expect(disabled.count == 20)
        #expect(disabled.contains("com.mygalaxy.service"))
    }

    @Test func diskFree() throws {
        // 75619616 1K-blocks available.
        #expect(try DiskFreeParser.availableBytes(Fixture.adb(device, "df-data.txt")) == 75_032_496 * 1024)
    }

    @Test func dumpsysPackage() throws {
        let info = try DumpsysPackageParser.parse(Fixture.adb(device, "dumpsys-package.txt"), package: "com.android.settings")
        #expect(info.versionCode == 36)
        #expect(info.versionName == "16")
        #expect(info.minSdk == 36)
        #expect(info.targetSdk == 36)
        #expect(info.isSystem)
        #expect(info.codePath == "/system/priv-app/SecSettings")
        #expect(info.installer == nil)
        #expect(info.splits == ["base"])
        #expect(info.userState?.installed == true)
        #expect(info.userState?.enabledState == .default)
        #expect(info.apkSigningVersion == 3)
    }

    @Test func launcherDumpsys() throws {
        let info = try DumpsysPackageParser.parse(
            Fixture.adb(device, "dumpsys-package-launcher.txt"), package: "com.sec.android.app.launcher"
        )
        #expect(info.isSystem)
        #expect(info.versionCode > 0)
    }

    @Test func homeActivities() {
        let launchers = HomeActivitiesParser.parse(Fixture.adb(device, "home-activities.txt"))
        #expect(launchers == ["com.sec.android.app.launcher", "com.android.settings"])
    }

    @Test func inputMethods() {
        let keyboards = InputMethodParser.parse(Fixture.adb(device, "ime-list.txt"))
        #expect(keyboards == ["com.samsung.android.honeyboard", "com.google.android.tts", "com.touchtype.swiftkey"])
    }

    @Test func pmPath() {
        #expect(PmPathParser.parse(Fixture.adb(device, "pm-path.txt")).first?.hasSuffix(".apk") == true)
    }
}

@Suite("Parsers: edge cases from AOSP formats")
struct ParserEdgeCaseTests {
    @Test func devicesWithEveryState() throws {
        let output = """
        * daemon not running; starting now at tcp:5037
        * daemon started successfully
        List of devices attached
        emulator-5554          device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a transport_id:1
        R58M123ABC             unauthorized usb:1-1 transport_id:2
        0123456789ABCDEF       no permissions (missing udev rules? user is in the plugdev group); see [http://developer.android.com/tools/device.html] usb:1-2 transport_id:3
        192.168.1.20:5555      offline transport_id:4
        adb-R58M-abc._adb-tls-connect._tcp device product:p model:Pixel_9 device:d transport_id:5
        HT1234                 recovery usb:1-3 transport_id:6

        """
        let devices = try DevicesParser.parse(output)
        #expect(devices.map(\.state) == [.ready, .unauthorized, .noPermissions, .offline, .ready, .other("recovery")])
        #expect(devices[0].model == "sdk_gphone64_arm64")
        #expect(devices[2].transportID == "3")
        #expect(devices[4].serial.isWireless)
    }

    @Test func emptyDeviceList() throws {
        #expect(try DevicesParser.parse("List of devices attached\n\n").isEmpty)
    }

    @Test func devicesRejectsHostileSerials() {
        #expect(throws: ADBParseError.self) {
            try DevicesParser.parse("List of devices attached\nfoo;reboot\tdevice\n")
        }
    }

    @Test func getpropMultilineAndEmpty() {
        let output = "[a.b]: [1]\n[c.d]: []\n[multi]: [line one\nline two]\ngarbage\n[e.f]: [x]\n"
        let props = GetpropParser.parse(output)
        #expect(props["a.b"] == "1")
        #expect(props["c.d"] == "")
        #expect(props["multi"] == "line one\nline two")
        #expect(props["e.f"] == "x")
    }

    @Test func batteryScale() {
        #expect(BatteryParser.level("  level: 50\n  scale: 200\n") == 25)
        #expect(BatteryParser.level("  present: false\n") == nil)
        #expect(BatteryParser.level("  level: 50\n  scale: 0\n") == 50)
    }

    @Test func densityPhysicalOnly() throws {
        #expect(try DensityParser.parse("Physical density: 420\n") == 420)
        #expect(throws: ADBParseError.self) { try DensityParser.parse("nope") }
    }

    @Test func packageListOldFormat() throws {
        // Android 8: no versionCode/uid fields.
        let packages = PackageListParser.parse("package:/system/app/Foo/Foo.apk=com.example.foo\n")
        #expect(packages.first?.versionCode == nil)
        #expect(packages.first?.packageName.rawValue == "com.example.foo")
    }

    @Test func packageListSkipsNoiseAndSamsungSecureFolderErrors() throws {
        let output = """
        Error: java.lang.SecurityException: Shell does not have permission to access user 150
         com.android.server.am.ActivityManagerService.handleIncomingUser:8
        package:/data/app/~~ab==/com.a.b-cd==/base.apk=com.a.b versionCode:3 uid:10200
        """
        let packages = PackageListParser.parse(output)
        #expect(packages.map(\.packageName.rawValue) == ["com.a.b"])
    }

    @Test func packageListSkipsInvalidNames() {
        let output = "package:/data/app/x/base.apk=com.a;reboot versionCode:1\npackage:/system/framework/framework-res.apk=android\n"
        #expect(PackageListParser.parse(output).isEmpty)
    }

    @Test func diskFreeHumanReadableOldToolbox() throws {
        let output = "Filesystem      Size  Used  Free  Blksize\n/data          25.5G  5.1G 20.4G 4096\n"
        let bytes = try DiskFreeParser.availableBytes(output)
        #expect(bytes == Int64(20.4 * 1024 * 1024 * 1024))
    }

    @Test func diskFreeRejectsGarbage() {
        #expect(throws: ADBParseError.self) { try DiskFreeParser.availableBytes("df: /data: Permission denied\n") }
    }

    @Test func dumpsysUserStates() throws {
        let output = """
        Packages:
          Package [com.example.app] (abc):
            versionCode=12 minSdk=24 targetSdk=34
            versionName=1.2
            codePath=/data/app/~~x==/com.example.app-y==
            splits=[base, config.arm64_v8a, config.xxhdpi]
            flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
            installerPackageName=com.android.vending
            lastUpdateTime=2026-01-01 10:00:00
            User 0: ceDataInode=1 installed=false hidden=false enabled=3 instant=false
            User 10: ceDataInode=2 installed=true hidden=false enabled=0
        Queries:
          com.other.app
        """
        let info = try DumpsysPackageParser.parse(output, package: "com.example.app")
        #expect(!info.isSystem)
        #expect(info.installer == "com.android.vending")
        #expect(info.splits == ["base", "config.arm64_v8a", "config.xxhdpi"])
        #expect(info.userState?.installed == false)
        #expect(info.userState?.enabledState == .disabledUser)
        #expect(info.lastUpdateTime == "2026-01-01 10:00:00")
    }

    @Test func dumpsysMissingPackage() {
        #expect(throws: ADBParseError.packageNotFound("com.example.missing")) {
            try DumpsysPackageParser.parse("Unable to find package: com.example.missing\n", package: "com.example.missing")
        }
    }

    @Test(arguments: [
        (0, PackageEnabledState.default), (1, .enabled), (2, .disabled), (3, .disabledUser), (4, .disabledUntilUsed), (9, .default),
    ])
    func enabledStates(_ raw: Int, _ expected: PackageEnabledState) {
        #expect(PackageEnabledState(rawCode: raw) == expected)
    }

    @Test func enabledStateMeaning() {
        #expect(PackageEnabledState.default.isEnabled)
        #expect(PackageEnabledState.enabled.isEnabled)
        #expect(!PackageEnabledState.disabledUser.isEnabled)
        #expect(!PackageEnabledState.disabled.isEnabled)
        #expect(!PackageEnabledState.disabledUntilUsed.isEnabled)
    }

    @Test func pmPathMultipleSplits() {
        let output = "package:/data/app/x/base.apk\npackage:/data/app/x/split_config.arm64_v8a.apk\n\n"
        #expect(PmPathParser.parse(output) == ["/data/app/x/base.apk", "/data/app/x/split_config.arm64_v8a.apk"])
    }

    @Test func installSessionID() throws {
        #expect(try InstallSessionParser.sessionID("Success: created install session [1834567]\n") == 1_834_567)
        #expect(throws: ADBParseError.self) { try InstallSessionParser.sessionID("Error: something\n") }
    }

    @Test func success() {
        #expect(InstallSessionParser.isSuccess("Success\n"))
        #expect(!InstallSessionParser.isSuccess("Failure [INSTALL_FAILED_ABORTED]\n"))
    }

    @Test func mdnsServices() {
        let output = """
        List of discovered mdns services
        adb-R58M-AbCdEf\t_adb-tls-pairing._tcp\t192.168.1.20:37099
        adb-R58M-AbCdEf\t_adb-tls-connect._tcp\t192.168.1.20:41235
        adb-R58M-AbCdEf  _adb._tcp  192.168.1.20:5555
        garbage line
        """
        let services = MdnsServicesParser.parse(output)
        #expect(services.count == 3)
        #expect(services[0] == MdnsService(instance: "adb-R58M-AbCdEf", type: .pairing, host: "192.168.1.20", port: 37099))
        #expect(services[1].type == .connect)
        #expect(services[2].type == .legacy)
    }

    @Test func mdnsCheck() {
        #expect(MdnsServicesParser.isDiscoveryAvailable("mdns daemon version [adb discovery 0.0.0]\n"))
        #expect(!MdnsServicesParser.isDiscoveryAvailable("ERROR: mdns daemon unavailable\n"))
    }

    @Test(arguments: [
        ("Successfully paired to 192.168.1.20:37099 [guid=adb-R58M-AbCdEf]", PairResult.paired(guid: "adb-R58M-AbCdEf")),
        ("Successfully paired to 192.168.1.20:37099", .paired(guid: nil)),
        ("Failed: Wrong password or connection was dropped.", .wrongCode),
        ("error: unable to connect for pairing", .unreachable),
        ("Something else", .failed("Something else")),
    ])
    func pairOutput(_ output: String, _ expected: PairResult) {
        #expect(PairOutputParser.parse(output) == expected)
    }

    @Test(arguments: [
        ("connected to 192.168.1.20:5555", ConnectResult.connected),
        ("already connected to 192.168.1.20:5555", .connected),
        ("failed to connect to '192.168.1.20:5555': Connection refused", .refused),
        ("cannot connect to 192.168.1.20:5555: No route to host (65)", .unreachable),
        ("failed to authenticate to 192.168.1.20:5555", .unauthorized),
        ("weird", .failed("weird")),
    ])
    func connectOutput(_ output: String, _ expected: ConnectResult) {
        #expect(ConnectOutputParser.parse(output) == expected)
    }

    @Test func adbVersion() {
        let output = "Android Debug Bridge version 1.0.41\nVersion 37.0.1-15733141\nInstalled as /opt/homebrew/bin/adb\n"
        #expect(ADBVersionParser.parse(output) == "37.0.1")
        #expect(ADBVersionParser.parse("nope") == nil)
    }

    @Test func statSize() throws {
        #expect(try StatParser.size("123456\n") == 123_456)
        #expect(throws: ADBParseError.self) { try StatParser.size("stat: No such file\n") }
    }

    @Test func sha256Sum() throws {
        let hash = String(repeating: "ab", count: 32)
        #expect(try Sha256SumParser.digest("\(hash)  /sdcard/Android/obb/com.a.b/main.1.com.a.b.obb\n") == hash)
        #expect(throws: ADBParseError.self) { try Sha256SumParser.digest("sha256sum: not found\n") }
        #expect(throws: ADBParseError.self) { try Sha256SumParser.digest("XYZ  file\n") }
    }
}
