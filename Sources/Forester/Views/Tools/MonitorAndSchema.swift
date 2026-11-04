// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import LDAPKit
import SwiftUI

// MARK: Tool windows

/// Identifies a tool window: which tool, for which connection.
struct ToolWindowID: Codable, Hashable {
    enum Tool: String, Codable {
        case domainInfo, serverMonitor, schema

        var title: String {
            switch self {
            case .domainInfo: return "Domain Information"
            case .serverMonitor: return "Server Monitor"
            case .schema: return "Schema"
            }
        }
    }

    var profile: UUID
    var tool: Tool
}

struct ToolWindowContent: View {
    let id: ToolWindowID
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            if let session = model.existingSession(id.profile), session.phase.isConnected {
                switch id.tool {
                case .domainInfo: DomainInfoView(session: session)
                case .serverMonitor: ServerMonitorView(session: session)
                case .schema: SchemaBrowserView(session: session)
                }
            } else {
                ContentUnavailableView("Not Connected", systemImage: "bolt.horizontal.circle",
                                       description: Text("Connect in the main window, then open this again."))
            }
        }
        .navigationTitle("\(id.tool.title) · \(model.store.profile(id.profile)?.displayName ?? "")")
        .frame(minWidth: 640, minHeight: 420)
    }
}

// MARK: Server monitor

@MainActor @Observable
final class ServerMonitorModel {
    struct Metric: Identifiable {
        var id: String { label }
        let label: String
        let value: String
    }

    struct Reading: Identifiable, Hashable {
        let id: String
        let entry: String
        let attribute: String
        let value: String
    }

    var metrics: [Metric] = []
    var readings: [Reading] = []
    var agreements: [LDAPEntry] = []
    var message: String?
    var loading = false
    var lastRead: Date?

    func load(_ session: DirectorySession) async {
        loading = true
        defer { loading = false; lastRead = Date() }
        if session.server?.kind.isMicrosoft == true {
            message = "Active Directory has no cn=monitor; its counters are Windows performance counters. See Domain Information for the domain controllers and roles."
            return
        }
        let request = LDAPSearchRequest(base: "cn=monitor", scope: .subtree, attributes: ["*", "+"])
        guard let entries = try? await session.run({ try await $0.search(request) }).entries, !entries.isEmpty else {
            message = "The server publishes no cn=monitor, or this account may not read it. On OpenLDAP it needs “database monitor” in its configuration."
            return
        }
        message = nil
        readings = entries.flatMap { entry -> [Reading] in
            let path = DN.components(entry.dn).dropLast().reversed().map(DN.rdnValue).joined(separator: " › ")
            return entry.attributes.filter { !["objectclass", "structuralobjectclass", "entrydn", "subschemasubentry",
                                                "hassubordinates", "creatorsname", "modifiersname", "createtimestamp",
                                                "modifytimestamp", "cn"].contains($0.baseName.lowercased()) }
                .flatMap { attribute in
                    attribute.stringValues.enumerated().map { index, value in
                        Reading(id: "\(entry.dn)|\(attribute.name)|\(index)", entry: path.isEmpty ? "Monitor" : path,
                                attribute: attribute.name, value: value)
                    }
                }
        }
        metrics = Self.summary(entries)
        if session.server?.kind == .the389DirectoryServer {
            let agreementRequest = LDAPSearchRequest(base: "cn=config", scope: .subtree,
                                                     filter: .equality("objectClass", "nsds5replicationagreement"), attributes: ["*"])
            agreements = (try? await session.run { try await $0.search(agreementRequest) })?.entries ?? []
        }
    }

    /// The headline numbers, from OpenLDAP's back-monitor or 389's cn=monitor.
    static func summary(_ entries: [LDAPEntry]) -> [Metric] {
        func entry(_ path: String) -> LDAPEntry? {
            entries.first { DN.isSame($0.dn, "\(path),cn=Monitor") || DN.isSame($0.dn, path) }
        }
        func value(_ path: String, _ attribute: String) -> String? { entry(path)?.string(attribute) }
        var metrics: [Metric] = []
        if let root = entries.first(where: { DN.isSame($0.dn, "cn=monitor") }), root.attribute("currentconnections") != nil {
            // 389 Directory Server
            for (label, attribute) in [("Version", "version"), ("Current connections", "currentconnections"),
                                       ("Total connections", "totalconnections"), ("Threads", "threads"),
                                       ("Operations started", "opsinitiated"), ("Operations completed", "opscompleted"),
                                       ("Entries sent", "entriessent"), ("Bytes sent", "bytessent"), ("Started", "starttime")] {
                if let found = root.string(attribute) { metrics.append(Metric(label: label, value: found)) }
            }
            return metrics
        }
        if let started = value("cn=Start,cn=Time", "monitorTimestamp").flatMap(ADValues.generalizedTime) {
            metrics.append(Metric(label: "Running since", value: started.formatted(date: .abbreviated, time: .shortened)))
        }
        if let uptime = value("cn=Uptime,cn=Time", "monitoredInfo").flatMap(Double.init) {
            metrics.append(Metric(label: "Uptime", value: AttributeFormatter.duration(uptime)))
        }
        let pairs: [(String, String, String)] = [
            ("Current connections", "cn=Current,cn=Connections", "monitorCounter"),
            ("Total connections", "cn=Total,cn=Connections", "monitorCounter"),
            ("Operations started", "cn=Operations", "monitorOpInitiated"),
            ("Operations completed", "cn=Operations", "monitorOpCompleted"),
            ("Searches", "cn=Search,cn=Operations", "monitorOpCompleted"),
            ("Binds", "cn=Bind,cn=Operations", "monitorOpCompleted"),
            ("Entries sent", "cn=Entries,cn=Statistics", "monitorCounter"),
            ("Bytes sent", "cn=Bytes,cn=Statistics", "monitorCounter"),
            ("Active threads", "cn=Active,cn=Threads", "monitoredInfo"),
            ("Read waiters", "cn=Read,cn=Waiters", "monitorCounter"),
        ]
        for (label, path, attribute) in pairs {
            if let found = value(path, attribute) {
                let number = Int(found).map { $0.formatted() } ?? found
                metrics.append(Metric(label: label, value: label == "Bytes sent" ? (Int64(found).map {
                    ByteCountFormatter.string(fromByteCount: $0, countStyle: .binary) } ?? found) : number))
            }
        }
        return metrics
    }
}

struct ServerMonitorView: View {
    let session: DirectorySession
    @State private var model = ServerMonitorModel()
    @State private var autoRefresh = false
    @State private var filter = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let message = model.message {
                ContentUnavailableView("No Monitor Data", systemImage: "gauge.with.dots.needle.0percent", description: Text(message))
            } else {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 160), spacing: 10)], spacing: 10) {
                    ForEach(model.metrics) { metric in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(metric.label).font(.caption).foregroundStyle(.secondary)
                            Text(metric.value).font(.title3.weight(.semibold)).monospacedDigit().lineLimit(1).minimumScaleFactor(0.6)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
                    }
                }
                .padding(14)
                if !model.agreements.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Replication agreements").font(.headline)
                        ForEach(model.agreements, id: \.dn) { agreement in
                            HStack {
                                Text(agreement.string("cn") ?? DN.rdnValue(agreement.dn)).font(.callout.weight(.medium))
                                Text("→ \(agreement.string("nsDS5ReplicaHost") ?? "?"):\(agreement.string("nsDS5ReplicaPort") ?? "")")
                                Spacer()
                                Text(agreement.string("nsds5replicaLastUpdateStatus") ?? "No status")
                                    .foregroundStyle((agreement.string("nsds5replicaLastUpdateStatus") ?? "").contains("Error (0)") ? .green : .orange)
                                    .lineLimit(1)
                            }
                            .font(.callout)
                        }
                    }
                    .padding(.horizontal, 14)
                    .padding(.bottom, 10)
                }
                TextField("Filter", text: $filter).textFieldStyle(.roundedBorder).padding(.horizontal, 14).padding(.bottom, 8)
                Table(model.readings.filter { filter.isEmpty || $0.entry.localizedCaseInsensitiveContains(filter)
                        || $0.attribute.localizedCaseInsensitiveContains(filter) || $0.value.localizedCaseInsensitiveContains(filter) }) {
                    TableColumn("Section", value: \.entry)
                    TableColumn("Attribute", value: \.attribute)
                    TableColumn("Value") { Text($0.value).textSelection(.enabled) }
                }
                // Built afresh when the first reading arrives rather than diffed from
                // empty, which makes AppKit's row-height cache re-enter itself.
                .id(model.readings.isEmpty)
            }
        }
        .toolbar {
            ToolbarItemGroup {
                if let lastRead = model.lastRead {
                    Text("Read \(lastRead.formatted(date: .omitted, time: .standard))").font(.caption).foregroundStyle(.secondary)
                }
                Toggle(isOn: $autoRefresh) { Label("Refresh every 5 seconds", systemImage: "timer") }
                    .help("Refresh every 5 seconds")
                Button { Task { await model.load(session) } } label: { Label("Refresh", systemImage: "arrow.clockwise") }
            }
        }
        .task { await model.load(session) }
        .task(id: autoRefresh) {
            while autoRefresh, !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                if autoRefresh { await model.load(session) }
            }
        }
    }
}

// MARK: Schema browser

struct SchemaBrowserView: View {
    let session: DirectorySession
    var initialSelection: String?
    @State private var showing: Kind = .classes
    @State private var filter = ""
    @State private var selection: String?

    enum Kind: String, CaseIterable { case classes = "Object Classes", attributes = "Attributes" }

    var body: some View {
        if let schema = session.schema {
            HSplitView {
                VStack(spacing: 0) {
                    Picker("", selection: $showing) {
                        ForEach(Kind.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .padding(10)
                    TextField("Filter by name or OID", text: $filter).textFieldStyle(.roundedBorder).padding(.horizontal, 10)
                    List(names(schema), id: \.self, selection: $selection) { name in
                        Text(name).tag(name)
                    }
                    .listStyle(.inset)
                    Text("\(schema.objectClasses.count) classes, \(schema.attributeTypes.count) attributes")
                        .font(.caption).foregroundStyle(.secondary).padding(6)
                }
                .frame(minWidth: 220, idealWidth: 260, maxWidth: 360)
                ScrollView {
                    if let selection {
                        if showing == .classes, let objectClass = schema.objectClass(selection) {
                            classDetail(objectClass, schema)
                        } else if let type = schema.attributeType(selection) {
                            attributeDetail(type, schema)
                        }
                    } else {
                        Text("Choose a class or an attribute.").foregroundStyle(.secondary).padding(30)
                    }
                }
                .frame(minWidth: 380, maxWidth: .infinity, maxHeight: .infinity)
            }
            .onChange(of: showing) { selection = nil }
            .onAppear { if selection == nil { selection = initialSelection } }
        } else {
            ContentUnavailableView("No Schema", systemImage: "list.bullet.rectangle",
                                   description: Text("The server did not let this connection read its schema (subschemaSubentry)."))
        }
    }

    private func names(_ schema: LDAPSchema) -> [String] {
        let all = showing == .classes ? schema.objectClasses.map { ($0.name, $0.oid) } : schema.attributeTypes.map { ($0.name, $0.oid) }
        return all.filter { filter.isEmpty || $0.0.localizedCaseInsensitiveContains(filter) || $0.1.hasPrefix(filter) }
            .map(\.0).sorted { $0.lowercased() < $1.lowercased() }
    }

    private func link(_ name: String, kind: Kind) -> some View {
        Button(name) {
            showing = kind
            DispatchQueue.main.async { selection = name }
        }
        .buttonStyle(.link)
    }

    private func detailRow<V: View>(_ label: String, @ViewBuilder _ value: () -> V) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            value()
        }
    }

    private func classDetail(_ objectClass: LDAPSchema.ObjectClass, _ schema: LDAPSchema) -> some View {
        let own = (must: objectClass.must.map(schema.canonicalName), may: objectClass.may.map(schema.canonicalName))
        let all = schema.allowedAttributes(for: [objectClass.name])
        let inheritedMust = all.must.filter { name in !own.must.contains { $0.caseInsensitiveCompare(name) == .orderedSame } }
        let inheritedMay = all.may.filter { name in !own.may.contains { $0.caseInsensitiveCompare(name) == .orderedSame } }
        return VStack(alignment: .leading, spacing: 14) {
            Text(objectClass.name).font(.title2.weight(.semibold)).textSelection(.enabled)
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                detailRow("OID") { Text(objectClass.oid).font(.callout.monospaced()).textSelection(.enabled) }
                if objectClass.names.count > 1 { detailRow("Also called") { Text(objectClass.names.dropFirst().joined(separator: ", ")) } }
                detailRow("Kind") { Text(objectClass.kind.rawValue.lowercased().capitalizingFirst) }
                if let description = objectClass.description { detailRow("Description") { Text(description) } }
                if !objectClass.superiors.isEmpty {
                    detailRow("Inherits from") { HStack { ForEach(objectClass.superiors, id: \.self) { link($0, kind: .classes) } } }
                }
                if objectClass.obsolete { detailRow("Status") { Text("Obsolete").foregroundStyle(.orange) } }
            }
            .font(.callout)
            attributeList("Required", own.must, schema)
            attributeList("Optional", own.may, schema)
            if !inheritedMust.isEmpty { attributeList("Required, inherited", inheritedMust, schema) }
            if !inheritedMay.isEmpty { attributeList("Optional, inherited", inheritedMay, schema) }
            Button("Find Entries of This Class") {
                session.search.filterText = "(objectClass=\(objectClass.name))"
                session.mode = .search
                session.search.run()
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func attributeList(_ title: String, _ names: [String], _ schema: LDAPSchema) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("\(title) (\(names.count))").font(.headline)
            if names.isEmpty {
                Text("None").foregroundStyle(.secondary).font(.callout)
            } else {
                FlowLayout(spacing: 6) {
                    ForEach(names.sorted { $0.lowercased() < $1.lowercased() }, id: \.self) { link($0, kind: .attributes) }
                }
                .font(.callout)
            }
        }
    }

    private func attributeDetail(_ type: LDAPSchema.AttributeType, _ schema: LDAPSchema) -> some View {
        let users = schema.classes(using: type.name).map(\.name).sorted { $0.lowercased() < $1.lowercased() }
        let syntax = schema.syntax(of: type.name)
        return VStack(alignment: .leading, spacing: 14) {
            Text(type.name).font(.title2.weight(.semibold)).textSelection(.enabled)
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                detailRow("OID") { Text(type.oid).font(.callout.monospaced()).textSelection(.enabled) }
                if type.names.count > 1 { detailRow("Also called") { Text(type.names.dropFirst().joined(separator: ", ")) } }
                if let description = type.description { detailRow("Description") { Text(description) } }
                if let syntax {
                    detailRow("Syntax") {
                        Text("\(schema.syntaxDescription(syntax) ?? "Unknown") (\(syntax))\(type.syntaxLength.map { ", up to \($0)" } ?? "")")
                    }
                }
                detailRow("Values") { Text(type.singleValue ? "Single" : "Multiple") }
                if let superior = type.superior { detailRow("Inherits from") { link(superior, kind: .attributes) } }
                if let equality = type.equality { detailRow("Equality") { Text(equality) } }
                if let ordering = type.ordering { detailRow("Ordering") { Text(ordering) } }
                if let substring = type.substring { detailRow("Substrings") { Text(substring) } }
                detailRow("Usage") { Text(type.usage) }
                if type.noUserModification { detailRow("Writable") { Text("No, set by the server") } }
                if type.obsolete { detailRow("Status") { Text("Obsolete").foregroundStyle(.orange) } }
            }
            .font(.callout)
            VStack(alignment: .leading, spacing: 4) {
                Text("Used by (\(users.count))").font(.headline)
                FlowLayout(spacing: 6) { ForEach(users, id: \.self) { link($0, kind: .classes) } }.font(.callout)
            }
            Button("Find Entries with This Attribute") {
                session.search.filterText = "(\(type.name)=*)"
                session.mode = .search
                session.search.run()
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
