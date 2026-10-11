// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import SwiftUI

/// Review before install: the safety report plus the split selection.
struct ReviewSheet: View {
    let plan: InstallPlan
    let queue: InstallQueueModel
    @State private var selected: Set<String>

    init(plan: InstallPlan, queue: InstallQueueModel) {
        self.plan = plan
        self.queue = queue
        _selected = State(initialValue: Set(plan.selectedSplits.map(\.fileName)))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    SafetyReportView(report: plan.report)
                    if !plan.problems.isEmpty {
                        GroupBox("Before you install") {
                            VStack(alignment: .leading, spacing: 6) {
                                ForEach(plan.problems, id: \.self) { problem in
                                    Label(PreCheckText.describe(problem), systemImage: "exclamationmark.circle")
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    if !plan.package.splits.isEmpty {
                        GroupBox("Parts to install") {
                            VStack(alignment: .leading) {
                                ForEach(plan.package.splits, id: \.fileName) { split in
                                    Toggle(split.manifest.splitName ?? split.fileName, isOn: binding(for: split.fileName))
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
                .padding(24)
            }
            Divider()
            HStack {
                Button("Don't Install", role: .cancel) { queue.skipReview() }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("skipInstall")
                Spacer()
                Button(plan.report.level == .high ? "Install Anyway" : "Install") {
                    queue.approve(plan.with(selectedSplits: plan.package.splits.filter { selected.contains($0.fileName) }))
                }
                .disabled(!plan.problems.isEmpty)
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("approveInstall")
            }
            .padding()
        }
        .frame(minWidth: 560, minHeight: 520)
    }

    private func binding(for file: String) -> Binding<Bool> {
        Binding(get: { selected.contains(file) }, set: { if $0 { selected.insert(file) } else { selected.remove(file) } })
    }
}

/// F3: the report itself. Verdicts are Low, Medium or High risk, never "safe".
struct SafetyReportView: View {
    let report: SafetyReport

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                RiskBadge(level: report.level)
                VStack(alignment: .leading) {
                    Text(report.packageName).font(.title2.bold())
                    Text("SHA-256 \(report.sha256)").font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            if report.reasons.isEmpty {
                Text("Airlock found nothing worrying. That is not a guarantee: only install apps from sources you trust.")
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(report.reasons) { reason in
                        Label(reason.message, systemImage: symbol(for: reason.level))
                            .foregroundStyle(color(for: reason.level))
                    }
                }
                .accessibilityElement(children: .contain)
                .accessibilityIdentifier("riskReasons")
            }
            GroupBox("Developer") { SignerSummary(check: report.signer, match: report.signerMatch) }
            if !report.permissions.isEmpty {
                GroupBox("What it can do") {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(report.permissions) { permission in
                            Label(permission.plainLanguage, systemImage: permission.isDangerous ? "exclamationmark.triangle" : "checkmark")
                                .foregroundStyle(permission.isDangerous ? .primary : .secondary)
                                .help(permission.permission)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            GroupBox("Tracking and advertising") {
                Group {
                    if report.trackers.isEmpty {
                        Text("No known tracker libraries found.").foregroundStyle(.secondary)
                    } else {
                        ForEach(report.trackers) { Text("\($0.name) (\($0.category))") }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            GroupBox("VirusTotal") { ReputationSummary(result: report.reputation) }
        }
    }

    private func symbol(for level: RiskLevel) -> String {
        switch level {
        case .low: "info.circle"
        case .medium: "exclamationmark.triangle"
        case .high: "exclamationmark.octagon"
        }
    }

    private func color(for level: RiskLevel) -> Color {
        switch level {
        case .low: .secondary
        case .medium: .orange
        case .high: .red
        }
    }
}

struct RiskBadge: View {
    let level: RiskLevel

    var body: some View {
        Text(level.title)
            .font(.headline)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(Capsule().fill(color.opacity(0.18)))
            .foregroundStyle(color)
            .accessibilityIdentifier("riskBadge")
    }

    private var color: Color {
        switch level {
        case .low: .green
        case .medium: .orange
        case .high: .red
        }
    }
}

struct SignerSummary: View {
    let check: SignatureCheck
    let match: SignerMatch

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(statusText).fontWeight(.semibold)
            if let certificate = check.certificates.first {
                Text(certificate.subject)
                Text(certificate.sha256).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
            }
            Text(matchText).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var statusText: String {
        switch check.status {
        case .verified: "Signature verified (scheme \(check.schemes.map(String.init).joined(separator: ", ")))"
        case .invalid: "Signature does not match the file"
        case .unsigned: "Not signed"
        case .unverifiable: "Signature could not be verified"
        }
    }

    private var matchText: String {
        switch match {
        case .matchesInstalled: "Same developer as the app already on your phone."
        case .differsFromInstalled: "A different developer from the app already on your phone."
        case .notInstalled: "Not installed on your phone yet."
        case .matchesKnownOfficial(let name): "Matches the official signer of \(name)."
        case .differsFromKnownOfficial(let name): "Does not match the official signer of \(name)."
        }
    }
}

struct ReputationSummary: View {
    let result: ReputationResult

    var body: some View {
        Group {
            switch result {
            case .found(let malicious, let suspicious, let total, let link):
                VStack(alignment: .leading, spacing: 4) {
                    Text("\(malicious) of \(total) engines flag it as malicious, \(suspicious) as suspicious.")
                    if let link { Link("Open the VirusTotal report", destination: link) }
                }
            case .unknown: Text("VirusTotal has never seen this file. New or rare files are often unknown.")
            case .notConfigured: Text("Add your VirusTotal API key in Settings to check the file's hash. Only the hash is sent.")
            case .unavailable(let message): Text(message)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .foregroundStyle(.secondary)
    }
}
