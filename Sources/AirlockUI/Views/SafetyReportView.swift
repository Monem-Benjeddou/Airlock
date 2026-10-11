// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Airlock contributors

import AirlockCore
import SwiftUI

/// Review before install: who made the app, the verdict and why, the details, and the decision.
struct ReviewSheet: View {
    let plan: InstallPlan
    let queue: InstallQueueModel
    @State private var selected: Set<String>
    /// High risk installs need this ticked, and Return never installs them.
    @State private var acknowledged = false

    init(plan: InstallPlan, queue: InstallQueueModel) {
        self.plan = plan
        self.queue = queue
        _selected = State(initialValue: Set(plan.selectedSplits.map(\.fileName)))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ReviewHeader(package: plan.package)
                .padding([.horizontal, .top], Spacing.xLarge)
                .padding(.bottom, Spacing.large)
            VerdictBanner(report: plan.report)
                .padding(.horizontal, Spacing.xLarge)
            Form {
                if !plan.problems.isEmpty {
                    SwiftUI.Section("Before you install") {
                        ForEach(plan.problems, id: \.self) { problem in
                            Label(PreCheckText.describe(problem), systemImage: "exclamationmark.circle")
                        }
                    }
                }
                ReportSections(report: plan.report, deviceName: plan.device.displayName)
                if !plan.package.splits.isEmpty {
                    SwiftUI.Section("Parts to install") {
                        ForEach(plan.package.splits, id: \.fileName) { split in
                            Toggle(split.manifest.splitName ?? split.fileName, isOn: binding(for: split.fileName))
                        }
                    }
                }
                SwiftUI.Section {
                    TechnicalDetails(report: plan.report)
                }
            }
            .formStyle(.grouped)
            Divider()
            footer
                .padding(.horizontal, Spacing.xLarge)
                .padding(.vertical, Spacing.large)
                .onExitCommand { queue.skipReview() }
        }
        .frame(minWidth: 600, idealWidth: 640, minHeight: 560, idealHeight: 660)
    }

    @ViewBuilder private var footer: some View {
        if isHighRisk {
            VStack(alignment: .leading, spacing: Spacing.medium) {
                Toggle("I understand this app could harm my phone or my data", isOn: $acknowledged)
                    .accessibilityIdentifier("acknowledgeRisk")
                HStack {
                    Spacer()
                    Button("Install Anyway", role: .destructive, action: approve)
                        .disabled(!plan.problems.isEmpty || !acknowledged)
                        .accessibilityIdentifier("approveInstall")
                    // The careful choice is the default: Return and Escape both decline.
                    Button("Don't Install") { queue.skipReview() }
                        .keyboardShortcut(.defaultAction)
                        .accessibilityIdentifier("skipInstall")
                }
            }
        } else {
            HStack {
                Spacer()
                Button("Don't Install", role: .cancel) { queue.skipReview() }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("skipInstall")
                Button("Install", action: approve)
                    .disabled(!plan.problems.isEmpty)
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("approveInstall")
            }
        }
    }

    private var isHighRisk: Bool { plan.report.level == .high }

    private func approve() {
        queue.approve(plan.with(selectedSplits: plan.package.splits.filter { selected.contains($0.fileName) }))
    }

    private func binding(for file: String) -> Binding<Bool> {
        Binding(get: { selected.contains(file) }, set: { if $0 { selected.insert(file) } else { selected.remove(file) } })
    }
}

/// The app being reviewed: tile, name, package, version and size.
struct ReviewHeader: View {
    let package: InspectedPackage

    var body: some View {
        let name = AppNaming.name(forPackage: package.packageName)
        HStack(spacing: Spacing.medium) {
            AppTile(name: name, seed: package.packageName, size: 52)
            VStack(alignment: .leading, spacing: 2) {
                Text(name).font(.title2.weight(.semibold))
                Text(ReviewHeader.subtitle(of: package))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
    }

    static func subtitle(of package: InspectedPackage) -> String {
        let manifest = package.base.manifest
        let bytes = package.base.sizeBytes + package.splits.reduce(0) { $0 + $1.sizeBytes }
        return [package.packageName, "version \(manifest.versionName ?? String(manifest.versionCode))",
                ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)].joined(separator: " · ")
    }
}

/// The verdict and its reasons, first and impossible to miss. Verdicts are Low, Medium or High risk, never "safe".
struct VerdictBanner: View {
    let report: SafetyReport

    var body: some View {
        let color = Palette.verdict(report.level)
        VStack(alignment: .leading, spacing: Spacing.small) {
            HStack(spacing: Spacing.small) {
                Image(systemName: Palette.verdictSymbol(report.level))
                    .font(.title2)
                    .foregroundStyle(color)
                    .accessibilityHidden(true)
                Text(report.level.title)
                    .font(.title3.weight(.semibold))
                    .accessibilityIdentifier("riskBadge")
            }
            if report.reasons.isEmpty {
                Text("Airlock found nothing worrying. That is not a guarantee: only install apps from sources you trust.")
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                VStack(alignment: .leading, spacing: Spacing.xSmall) {
                    ForEach(report.reasons) { reason in
                        // Readable text, with the colour on the symbol: red text fails contrast at body size.
                        Label {
                            Text(reason.message).fixedSize(horizontal: false, vertical: true)
                        } icon: {
                            Image(systemName: Palette.reasonSymbol(reason.level))
                                .foregroundStyle(Palette.reason(reason.level))
                        }
                    }
                }
                .accessibilityElement(children: .contain)
                .accessibilityLabel("Reasons")
                .accessibilityIdentifier("riskReasons")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(Spacing.large)
        .background(color.opacity(0.12), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(alignment: .leading) {
            UnevenRoundedRectangle(topLeadingRadius: 10, bottomLeadingRadius: 10, style: .continuous)
                .fill(color)
                .frame(width: 4)
                .accessibilityHidden(true)
        }
    }
}

/// Developer, permissions, trackers and VirusTotal as grouped form sections.
struct ReportSections: View {
    let report: SafetyReport
    let deviceName: String

    var body: some View {
        SwiftUI.Section("Developer") {
            LabeledContent("Signed by", value: ReportSections.signerName(report.signer))
            LabeledContent("Signature") {
                let verified = report.signer.status == .verified
                Label {
                    Text(SignerText.status(report.signer))
                } icon: {
                    Image(systemName: verified ? "checkmark.seal.fill" : "xmark.seal.fill")
                        .foregroundStyle(verified ? Palette.success : Palette.danger)
                }
                .labelStyle(StatusLabelStyle())
            }
            LabeledContent("On \(deviceName)", value: SignerText.match(report.signerMatch))
        }
        SwiftUI.Section("Permissions") {
            if report.permissions.isEmpty {
                Text("It asks for no special permissions.").foregroundStyle(.secondary)
            }
            ForEach(ReportSections.sorted(report.permissions)) { permission in
                Label {
                    Text(permission.plainLanguage)
                } icon: {
                    Image(systemName: permission.isDangerous ? "exclamationmark.triangle.fill" : "circle.fill")
                        .foregroundStyle(permission.isDangerous ? Palette.warning : Color.secondary.opacity(0.5))
                        .imageScale(permission.isDangerous ? .medium : .small)
                }
                .help(permission.permission)
                .accessibilityLabel(permission.plainLanguage + (permission.isDangerous ? ", sensitive" : ""))
            }
        }
        SwiftUI.Section("Trackers") {
            if report.trackers.isEmpty {
                Text("No known tracker libraries found.").foregroundStyle(.secondary)
            }
            ForEach(report.trackers) { tracker in
                LabeledContent(tracker.name, value: tracker.category)
            }
        }
        SwiftUI.Section("VirusTotal") {
            ReputationSummary(result: report.reputation)
        }
    }

    /// Sensitive permissions first, then alphabetical, so the ones that matter are on top.
    static func sorted(_ permissions: [PermissionFinding]) -> [PermissionFinding] {
        permissions.sorted { ($0.isDangerous ? 0 : 1, $0.plainLanguage) < ($1.isDangerous ? 0 : 1, $1.plainLanguage) }
    }

    /// The certificate's common name ("CN=Demo Studio, O=Demo" → "Demo Studio"), or the whole subject.
    static func signerName(_ check: SignatureCheck) -> String {
        guard let subject = check.certificates.first?.subject else { return "Unknown" }
        for part in subject.split(separator: ",") {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("CN=") { return String(trimmed.dropFirst(3)) }
        }
        return subject
    }
}

/// A status with its symbol after the text, as Finder's info rows do.
struct StatusLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: Spacing.xSmall) {
            configuration.title
            configuration.icon.accessibilityHidden(true)
        }
    }
}

enum SignerText {
    static func status(_ check: SignatureCheck) -> String {
        switch check.status {
        case .verified: "Verified"
        case .invalid: "Does not match the file"
        case .unsigned: "Not signed"
        case .unverifiable: "Could not be verified"
        }
    }

    static func match(_ match: SignerMatch) -> String {
        switch match {
        case .matchesInstalled: "Same developer as the installed app"
        case .differsFromInstalled: "A different developer from the installed app"
        case .notInstalled: "Not installed yet"
        case .matchesKnownOfficial(let name): "Matches the official signer of \(name)"
        case .differsFromKnownOfficial(let name): "Does not match the official signer of \(name)"
        }
    }
}

struct ReputationSummary: View {
    let result: ReputationResult

    var body: some View {
        switch result {
        case .found(let malicious, let suspicious, let total, let link):
            VStack(alignment: .leading, spacing: Spacing.xSmall) {
                Text("\(malicious) of \(total) engines flag it as malicious, \(suspicious) as suspicious.")
                if let link { Link("Open the VirusTotal report", destination: link) }
            }
        case .unknown: Text("VirusTotal has never seen this file. New or rare files are often unknown.")
        case .notConfigured:
            LabeledContent {
                SettingsLink { Text("Set Up…") }
            } label: {
                Text("Not set up. Only the file's hash would be sent.").foregroundStyle(.secondary)
            }
        case .unavailable(let message): Text(message)
        }
    }
}

/// File and certificate hashes, collapsed by default. A plain button rather than a DisclosureGroup: on macOS the
/// group only toggles from its triangle, and a custom label either lost its name or leaked it onto the rows.
struct TechnicalDetails: View {
    let report: SafetyReport
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                isExpanded.toggle()
            } label: {
                Label("Technical details", systemImage: isExpanded ? "chevron.down" : "chevron.right")
            }
            .buttonStyle(.plain)
            .accessibilityValue(isExpanded ? "Expanded" : "Collapsed")
            .accessibilityIdentifier("technicalDetails")
            if isExpanded {
                VStack(alignment: .leading, spacing: 4) {
                    // Callout size: long hex strings are hard to read at caption size.
                    LabeledContent("File SHA-256") {
                        Text(report.sha256).font(.callout.monospaced()).textSelection(.enabled)
                    }
                    if let certificate = report.signer.certificates.first {
                        LabeledContent("Certificate SHA-256") {
                            Text(certificate.sha256).font(.callout.monospaced()).textSelection(.enabled)
                        }
                    }
                    if !report.signer.schemes.isEmpty {
                        LabeledContent("Signature schemes", value: report.signer.schemes.map { "v\($0)" }.joined(separator: ", "))
                    }
                    LabeledContent("Rules version", value: report.rulesVersion)
                }
                .padding(.leading, 22)
                .padding(.top, Spacing.xSmall)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
