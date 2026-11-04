// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

/// Group memberships as rows that behave like links: click one to open it.
///
/// A lazy stack rather than a `List`: nothing here is selected, and SwiftUI's
/// list makes AppKit's table re-enter its row-height cache when it is built
/// while its rows arrive.
struct MembershipView: View {
    let session: DirectorySession
    let membership: MembershipModel
    @State private var filter = ""

    var body: some View {
        if membership.loading {
            ProgressView("Reading memberships…").frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let error = membership.error {
            ContentUnavailableView {
                Label("Cannot Read Memberships", systemImage: "exclamationmark.triangle")
            } description: {
                Text(error)
            }
        } else {
            VStack(spacing: 0) {
                if total > 15 {
                    TextField("Filter", text: $filter).textFieldStyle(.roundedBorder).padding(10)
                }
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0, pinnedViews: [.sectionHeaders]) {
                        if let dynamic = membership.dynamic {
                            Section {
                                ForEach(membership.dynamicURLs, id: \.self) { url in
                                    Text(url).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                                        .padding(.horizontal, 16).padding(.vertical, 2)
                                }
                                if let note = membership.dynamicNote {
                                    Text(note).font(.caption).foregroundStyle(.orange).padding(.horizontal, 16)
                                }
                                ForEach(keyed(dynamic, in: "dynamic")) { item in RefRow(session: session, ref: item.ref) }
                            } header: {
                                SectionHeader(title: "Dynamic members, from the member query (\(dynamic.count.formatted()))")
                            }
                        }
                        if membership.isGroup && (membership.dynamic == nil || !membership.members.isEmpty) {
                            section("Members", membership.members, empty: "No direct members.")
                        }
                        section("Member of", membership.memberOf, empty: "Not a member of any group.")
                        nestedSection
                    }
                    .padding(.bottom, 12)
                }
            }
        }
    }

    private var total: Int {
        membership.members.count + membership.memberOf.count + (membership.nested?.count ?? 0) + (membership.dynamic?.count ?? 0)
    }

    /// A group can be listed both as a member and among the nested members;
    /// ids must be unique across the whole stack, so each carries its section.
    private struct Keyed: Identifiable {
        let id: String
        let ref: MembershipModel.Ref
    }

    private func keyed(_ refs: [MembershipModel.Ref], in section: String) -> [Keyed] {
        refs.filter(matches).map { Keyed(id: "\(section)/\($0.id)", ref: $0) }
    }

    private func matches(_ ref: MembershipModel.Ref) -> Bool {
        filter.isEmpty || ref.name.localizedCaseInsensitiveContains(filter) || ref.detail.localizedCaseInsensitiveContains(filter)
            || ref.dn.localizedCaseInsensitiveContains(filter)
    }

    @ViewBuilder
    private func section(_ title: String, _ refs: [MembershipModel.Ref], empty: String) -> some View {
        Section {
            if refs.isEmpty {
                Text(empty).foregroundStyle(.secondary).padding(.horizontal, 16).padding(.vertical, 6)
            }
            ForEach(keyed(refs, in: title)) { item in
                RefRow(session: session, ref: item.ref)
            }
        } header: {
            SectionHeader(title: "\(title) (\(refs.count.formatted()))")
        }
    }

    @ViewBuilder
    private var nestedSection: some View {
        let title = membership.isGroup ? "All members, including nested groups" : "All groups, including nested"
        Section {
            if let nested = membership.nested {
                if let note = membership.nestedNote {
                    Text(note).font(.caption).foregroundStyle(.secondary).padding(.horizontal, 16).padding(.vertical, 4)
                }
                ForEach(keyed(nested, in: "nested")) { item in
                    RefRow(session: session, ref: item.ref)
                }
            } else if membership.nestedLoading {
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Following nested groups…").foregroundStyle(.secondary)
                }
                .padding(.horizontal, 16).padding(.vertical, 6)
            } else {
                Button(membership.isGroup ? "Show All Nested Members" : "Show All Nested Groups") { membership.loadNested() }
                    .help(session.isMicrosoft ? "One query with the in-chain matching rule (LDAP_MATCHING_RULE_IN_CHAIN)."
                                              : "Follows group links level by level.")
                    .padding(.horizontal, 16).padding(.vertical, 6)
            }
        } header: {
            SectionHeader(title: membership.nested.map { "\(title) (\($0.count.formatted()))" } ?? title)
        }
    }
}

private struct SectionHeader: View {
    let title: String

    var body: some View {
        Text(title)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 4)
            .background(.background)
    }
}

private struct RefRow: View {
    let session: DirectorySession
    let ref: MembershipModel.Ref
    @State private var hovering = false

    var body: some View {
        Button {
            if !ref.dn.isEmpty { session.open(ref.dn) }
        } label: {
            HStack(spacing: 8) {
                EntryIcon(kind: ref.kind ?? .other, disabled: ref.disabled)
                VStack(alignment: .leading, spacing: 1) {
                    Text(ref.name).foregroundStyle(ref.disabled ? .secondary : .primary)
                    if !ref.detail.isEmpty {
                        Text(ref.detail).font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if let note = ref.note {
                    Text(note)
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(.quaternary, in: Capsule())
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(hovering && !ref.dn.isEmpty ? Color.primary.opacity(0.06) : .clear,
                        in: RoundedRectangle(cornerRadius: 6))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 6)
        .onHover { hovering = $0 }
        .disabled(ref.dn.isEmpty)
        .help(ref.dn.isEmpty ? ref.name : ref.dn)
        .contextMenu {
            if !ref.dn.isEmpty {
                Button("Open") { session.open(ref.dn) }
                Button("Show in Tree") { session.open(ref.dn); session.reveal(ref.dn) }
                Divider()
                Button("Copy DN") { Pasteboard.copy(ref.dn) }
            }
            Button("Copy Name") { Pasteboard.copy(ref.name) }
        }
    }
}
