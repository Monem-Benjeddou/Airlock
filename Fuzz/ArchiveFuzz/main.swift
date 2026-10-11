// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockArchive
import CFuzzerDriver
import Foundation

/// Small caps keep each input fast; the parser's behaviour does not depend on their values.
private let limits = ExtractionLimits(
    maxTotalUncompressedBytes: 64 << 20,
    maxEntries: 512,
    maxMetadataBytes: 64 << 10
)

private let scratch = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
    .appendingPathComponent("airlock-fuzz-\(getpid())", isDirectory: true)

/// libFuzzer entry point: every input must either parse or throw `ArchiveError` (typed throws make any
/// other error impossible), without crashing, leaking or reading out of bounds under AddressSanitizer.
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzArchive(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
    let data = start.map { Data(bytes: $0, count: count) } ?? Data()
    guard let archive = try? ZipArchive(data: data, limits: limits) else { return 0 }

    for entry in archive.entries {
        _ = try? archive.data(for: entry, maxBytes: 1 << 20)
        if entry.method == .stored, !entry.isDirectory, let inner = try? archive.openNested(entry) {
            for innerEntry in inner.entries {
                try? inner.stream(innerEntry) { _ in }
            }
        }
    }

    // Archives that open also go through format detection and extraction, which touch the disk.
    let input = scratch.appendingPathComponent("input.bin")
    let extractor = SafeExtractor(jobsRoot: scratch.appendingPathComponent("jobs"), limits: limits)
    do {
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        try data.write(to: input)
    } catch {
        return 0
    }
    if let package = try? FormatDetector(limits: limits).detect(at: input),
       let result = try? extractor.extract(package) {
        extractor.removeJob(result.job)
    }
    if let result = try? extractor.extract(archive.entries, from: archive) {
        extractor.removeJob(result.job)
    }
    return 0
}

var argc = CommandLine.argc
var argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>? = CommandLine.unsafeArgv
exit(LLVMFuzzerRunDriver(&argc, &argv, fuzzArchive))
