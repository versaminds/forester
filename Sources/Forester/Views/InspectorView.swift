// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import AppKit
import LDAPKit
import SwiftUI

struct InspectorView: View {
    @Environment(AppModel.self) private var model
    let session: DirectorySession
    @Bindable var inspector: InspectorModel

    init(session: DirectorySession) {
        self.session = session
        inspector = session.inspector
    }

    var body: some View {
        Group {
            if let error = inspector.error {
                ContentUnavailableView {
                    Label("Cannot Show Entry", systemImage: "exclamationmark.triangle")
                } description: {
                    Text(error).textSelection(.enabled)
                } actions: {
                    if let domain = inspector.otherDomain {
                        Button("Open \(domain)") { Task { await model.openDomain(domain, from: session, select: inspector.dn) } }
                    } else {
                        Button("Try Again") { inspector.reload() }
                    }
                }
            } else if let entry = inspector.entry {
                VStack(spacing: 0) {
                    EntryHeader(session: session, entry: entry, kind: inspector.kind)
                        .padding([.horizontal, .top], 16)
                        .padding(.bottom, 10)
                    Picker("View", selection: $inspector.tab) {
                        ForEach(InspectorModel.Tab.allCases.filter { tab in
                            (tab != .membership || inspector.showsMembership)
                                && (tab != .replication || session.hasADTools) && (tab != .permissions || session.hasADTools)
                        }) { tab in
                            Text(tab.label).tag(tab)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .fixedSize()
                    .padding(.bottom, 10)
                    Divider()
                    switch inspector.tab {
                    case .overview: OverviewView(session: session, entry: entry, kind: inspector.kind)
                    case .attributes: AttributesView(session: session, entry: entry)
                    case .membership: MembershipView(session: session, membership: inspector.membership)
                    case .permissions: PermissionsView(session: session, entry: entry)
                    case .replication: ReplicationView(session: session, entry: entry)
                    case .ldif: LDIFView(entry: entry)
                    }
                }
                .id(entry.dn)
            } else if inspector.loading {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ContentUnavailableView("No Entry Selected", systemImage: "sidebar.right",
                                       description: Text("Choose an entry in the tree or in the search results."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .toolbar {
            ToolbarItemGroup(placement: .navigation) {
                Button { session.goBack() } label: { Label("Back", systemImage: "chevron.left") }
                    .disabled(!session.canGoBack)
                    .help("Back (⌘[)")
                Button { session.goForward() } label: { Label("Forward", systemImage: "chevron.right") }
                    .disabled(!session.canGoForward)
                    .help("Forward (⌘])")
            }
            // Since macOS 26 neighbouring items share one glass capsule unless
            // a spacer parts them: whether changes are allowed stands alone,
            // apart from what can be done to the entry.
            ToolbarItem {
                EditingToggle(session: session)
            }
            if #available(macOS 26.0, *) {
                ToolbarSpacer(.fixed)
            }
            ToolbarItemGroup {
                if let entry = inspector.entry, let method = AccountLockMethod.method(for: entry, session: session) {
                    let disabled = method.isDisabled(entry)
                    Button {
                        Task { await AccountActions.setEnabled(disabled, entry, session: session) }
                    } label: {
                        Label(disabled ? "Enable Account" : "Disable Account",
                              systemImage: disabled ? "person.crop.circle.badge.checkmark" : "person.crop.circle.badge.xmark")
                    }
                    .help(disabled ? "Enable the account" : "Disable the account")
                    .disabled(!session.canWrite)
                }
                EntryActionsMenu(session: session)
            }
            ToolbarItemGroup {
                Button { if let dn = session.selectedDN { session.reveal(dn) } } label: {
                    Label("Show in Tree", systemImage: "list.bullet.indent")
                }
                .help("Show in tree (⌘L)")
                .disabled(session.selectedDN == nil)
                Button { inspector.reload() } label: { Label("Refresh", systemImage: "arrow.clockwise") }
                    .help("Read the entry again (⌘R)")
                    .disabled(session.selectedDN == nil)
            }
        }
        .overlay(alignment: .bottom) { NoticeBanner(session: session) }
    }
}

/// Turns editing on and off for the connection. Off, nothing is ever sent
/// that would change the directory.
struct EditingToggle: View {
    let session: DirectorySession

    var body: some View {
        let readOnly = session.profile.readOnly
        // Words as well as an icon: whether changes can be made is the one
        // thing about a connection that must never be guessed at.
        // A toolbar toggle is drawn pressed while it is on, so allowing changes
        // shows as a highlighted Editing button.
        // The icon and the word are laid out here rather than by a Label: in a
        // glass toolbar a Label keeps a full icon's width beside a narrow
        // symbol, which leaves a wide gap after it and the word against the
        // capsule's edge.
        Toggle(isOn: Binding(get: { !readOnly }, set: { session.setReadOnly(!$0) })) {
            HStack(spacing: 5) {
                Image(systemName: readOnly ? "lock.fill" : "pencil").accessibilityHidden(true)
                Text(readOnly ? "Read-only" : "Editing")
            }
        }
        .toggleStyle(.button)
        .tint(.orange)
        .help(readOnly ? "Read-only: nothing is changed in the directory. Click to allow changes (⌥⌘E)."
                       : "Changes are allowed. Click to make this connection read-only again (⌥⌘E).")
    }
}

/// Everything that can be done to the selected entry.
struct EntryActionsMenu: View {
    let session: DirectorySession

    var body: some View {
        let entry = session.inspector.entry
        let dn = session.selectedDN ?? ""
        let canChange = entry != nil && session.canChangeEntry(dn)
        Menu {
            Button("New Entry…") { if let parent = session.newEntryParent { session.sheet = .newEntry(parent: parent) } }
                .disabled(!session.canWrite)
            Button("Duplicate…") { if let entry { session.sheet = .duplicate(entry) } }
                .disabled(!canChange)
            Divider()
            Button("Rename…") { session.sheet = .renameMove(dn: dn, move: false) }.disabled(!canChange)
            Button("Move…") { session.sheet = .renameMove(dn: dn, move: true) }.disabled(!canChange)
            Button("Delete…", role: .destructive) { session.sheet = .delete(dn: dn) }.disabled(!canChange)
            if let entry, AccountLockMethod.method(for: entry, session: session) != nil {
                Divider()
                Button("Reset Password…") { session.sheet = .password(entry) }.disabled(!session.canWrite)
                if AccountActions.isLocked(entry) {
                    Button("Unlock Account") { Task { await AccountActions.unlock(entry, session: session) } }.disabled(!session.canWrite)
                }
                if session.hasADTools {
                    Button("Account Status on Each DC…") { session.sheet = .accountStatus(entry) }
                }
            }
            Divider()
            Button("Export Entry as LDIF…") { session.exportLDIF(dn, scope: .base) }.disabled(entry == nil)
            Button("Export Children as LDIF…") { session.exportLDIF(dn, scope: .oneLevel) }.disabled(entry == nil || dn.isEmpty)
            Button("Export Subtree as LDIF…") { session.exportLDIF(dn, scope: .subtree) }.disabled(entry == nil || dn.isEmpty)
            Button("Import LDIF…") { session.sheet = .importLDIF(nil) }.disabled(!session.canWrite)
        } label: {
            Label("Actions", systemImage: "ellipsis.circle")
        }
        .help("Create, rename, move, delete, passwords, export")
    }
}

/// The outcome of the last change, at the bottom of the window.
struct NoticeBanner: View {
    let session: DirectorySession

    var body: some View {
        if let notice = session.notice {
            HStack(spacing: 8) {
                Image(systemName: notice.isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                    .foregroundStyle(notice.isError ? .red : .green)
                Text(notice.message).lineLimit(3).textSelection(.enabled)
                Button { session.notice = nil } label: { Image(systemName: "xmark") }.buttonStyle(.borderless)
            }
            .font(.callout)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(notice.isError ? Color.red.opacity(0.4) : Color.secondary.opacity(0.2)))
            .shadow(radius: 6, y: 2)
            .padding(16)
            .frame(maxWidth: 560)
            .transition(.move(edge: .bottom).combined(with: .opacity))
            .animation(.snappy, value: notice.id)
        }
    }
}

/// Presents whichever editing sheet the session asks for.
struct EntrySheetHost: ViewModifier {
    let session: DirectorySession?

    func body(content: Content) -> some View {
        content.sheet(item: Binding(get: { session?.sheet }, set: { session?.sheet = $0 })) { sheet in
            if let session {
                switch sheet {
                case .newEntry(let parent): NewEntrySheet(session: session, parentDN: parent)
                case .duplicate(let entry): NewEntrySheet(session: session, parentDN: DN.parent(entry.dn) ?? "", source: entry)
                case .renameMove(let dn, let move): RenameMoveSheet(session: session, dn: dn, startWithMove: move)
                case .delete(let dn): DeleteEntrySheet(session: session, dn: dn)
                case .password(let entry): PasswordSheet(session: session, entry: entry)
                case .accountStatus(let entry): AccountStatusSheet(session: session, entry: entry)
                case .importLDIF(let file): LDIFImportSheet(session: session, initialFile: file)
                case .history: ChangeHistorySheet(session: session)
                }
            }
        }
    }
}

// MARK: Header

struct EntryHeader: View {
    let session: DirectorySession
    let entry: LDAPEntry
    let kind: ObjectKind

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            photo
            VStack(alignment: .leading, spacing: 5) {
                Text(title)
                    .font(.title2.weight(.semibold))
                    .textSelection(.enabled)
                    .lineLimit(2)
                Text(subtitle)
                    .foregroundStyle(.secondary)
                HStack(spacing: 4) {
                    Text(entry.dn.isEmpty ? "Root DSE" : entry.dn)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .lineLimit(2)
                        .truncationMode(.middle)
                    if !entry.dn.isEmpty {
                        Button { Pasteboard.copy(entry.dn) } label: { Image(systemName: "doc.on.doc") }
                            .buttonStyle(.borderless)
                            .controlSize(.small)
                            .help("Copy DN")
                    }
                }
                let badges = StatusBadge.badges(for: entry, kind: kind)
                if !badges.isEmpty {
                    FlowLayout(spacing: 5) {
                        ForEach(badges) { badge in badge }
                    }
                    .padding(.top, 2)
                }
            }
            Spacer(minLength: 0)
        }
    }

    @ViewBuilder
    private var photo: some View {
        if let data = entry.values("thumbnailPhoto").first ?? entry.values("jpegPhoto").first,
           let image = NSImage(data: data) {
            Image(nsImage: image)
                .resizable()
                .aspectRatio(contentMode: .fill)
                .frame(width: 56, height: 56)
                .clipShape(Circle())
                .overlay(Circle().stroke(.separator))
        } else {
            EntryIcon(kind: kind, disabled: isDisabled(entry), size: 30)
                .frame(width: 56, height: 56)
                .background(kind.tint.opacity(0.12), in: Circle())
        }
    }

    private var title: String {
        if entry.dn.isEmpty { return session.server?.dnsHostName ?? session.profile.host }
        if kind == .groupPolicy, let name = entry.string("displayName") { return name }
        if kind == .foreignSecurityPrincipal, let name = ADValues.wellKnownName(DN.rdnValue(entry.dn)) { return name }
        // An entry named by uid (uid=alovelace) usually has its person's name in cn.
        return entry.string("displayName") ?? entry.string("cn") ?? DN.displayName(entry.dn)
    }

    private var subtitle: String {
        var parts = [kind.label]
        switch kind {
        case .user, .serviceAccount:
            if let account = entry.string("userPrincipalName") ?? entry.string("sAMAccountName") ?? entry.string("uid") { parts.append(account) }
            if let title = entry.string("title") { parts.append(title) }
        case .computer, .domainController:
            if let host = entry.string("dNSHostName") { parts.append(host) }
            if let os = entry.string("operatingSystem") { parts.append(os) }
        case .group:
            if let type = entry.int("groupType") { parts[0] = ADValues.groupTypeDescription(type).capitalizingFirst }
            if entry.attribute("memberURL") != nil || entry.attribute("memberQueryURL") != nil {
                parts[0] = "Dynamic group"
                parts.append("members found by a query")
            } else {
                let count = entry.values("member").count + entry.values("uniqueMember").count + entry.values("memberUid").count
                parts.append("\(count.formatted()) direct member\(count == 1 ? "" : "s")")
            }
        case .rootDSE:
            parts = [session.server?.kind.label ?? "LDAP server"]
            if let version = session.server?.vendorVersion { parts.append(version) }
        default:
            if let parent = DN.parent(entry.dn) { parts.append("in \(DN.canonicalName(parent))") }
        }
        return parts.joined(separator: " · ")
    }
}

struct StatusBadge: View, Identifiable {
    let text: String
    let color: Color
    let help: String

    var id: String { text }

    var body: some View {
        Text(text)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .foregroundStyle(color)
            .background(color.opacity(0.13), in: Capsule())
            .help(help)
    }

    static func badges(for entry: LDAPEntry, kind: ObjectKind, now: Date = Date()) -> [StatusBadge] {
        var badges: [StatusBadge] = []
        let uac = entry.int("userAccountControl") ?? 0
        let computed = entry.int("msDS-User-Account-Control-Computed") ?? 0
        let isAccount = [.user, .computer, .domainController, .serviceAccount].contains(kind)
        if isAccount, entry.attribute("userAccountControl") != nil {
            if uac & 0x2 != 0 {
                badges.append(StatusBadge(text: "Disabled", color: .red, help: "The account is disabled (userAccountControl 0x2)."))
            } else {
                badges.append(StatusBadge(text: "Enabled", color: .green, help: "The account is enabled."))
            }
            let lockout = entry.int("lockoutTime") ?? 0
            if computed & 0x10 != 0 || (entry.attribute("msDS-User-Account-Control-Computed") == nil && (uac & 0x10 != 0 || lockout > 0)) {
                badges.append(StatusBadge(text: "Locked out", color: .orange, help: "Too many failed sign-ins."))
            }
            if computed & 0x800000 != 0 {
                badges.append(StatusBadge(text: "Password expired", color: .orange, help: "The password has expired."))
            }
            if kind == .user, entry.int("pwdLastSet") == 0 {
                badges.append(StatusBadge(text: "Must change password", color: .orange, help: "pwdLastSet is 0: the password must be changed at the next sign-in."))
            }
            if kind == .user, uac & 0x10000 != 0 {
                badges.append(StatusBadge(text: "Password never expires", color: .yellow, help: "DONT_EXPIRE_PASSWORD is set."))
            }
            if let expires = entry.int("accountExpires"), case .date(let date) = ADValues.fileTime(expires) {
                if date < now {
                    badges.append(StatusBadge(text: "Account expired", color: .red, help: "The account expired \(date.formatted())."))
                } else if date.timeIntervalSince(now) < 30 * 86400 {
                    badges.append(StatusBadge(text: "Expires soon", color: .yellow, help: "The account expires \(date.formatted())."))
                }
            }
            if uac & 0x20 != 0 { badges.append(StatusBadge(text: "Password not required", color: .red, help: "PASSWD_NOTREQD is set.")) }
            if uac & 0x400000 != 0 {
                badges.append(StatusBadge(text: "No Kerberos pre-auth", color: .red, help: "DONT_REQ_PREAUTH: anyone can request a ticket to crack offline (AS-REP roasting)."))
            }
            if uac & 0x80000 != 0, kind != .domainController {
                badges.append(StatusBadge(text: "Unconstrained delegation", color: .red, help: "TRUSTED_FOR_DELEGATION on an account that is not a domain controller."))
            }
            if uac & 0x40000 != 0 { badges.append(StatusBadge(text: "Smart card required", color: .blue, help: "SMARTCARD_REQUIRED is set.")) }
            if kind == .user, !entry.values("servicePrincipalName").isEmpty {
                badges.append(StatusBadge(text: "Has SPN", color: .yellow, help: "A user account with a service principal name can be Kerberoasted; it needs a long, random password."))
            }
        } else if isDisabled(entry) {
            badges.append(StatusBadge(text: "Disabled", color: .red, help: "The account is disabled."))
        }
        if entry.int("adminCount") == 1 {
            badges.append(StatusBadge(text: "Privileged", color: .purple, help: "adminCount=1: this object is or was protected by AdminSDHolder."))
        }
        if kind == .group, entry.attribute("member") == nil, entry.attribute("uniqueMember") == nil, entry.attribute("memberUid") == nil,
           entry.attribute("memberURL") == nil, entry.attribute("memberQueryURL") == nil {
            badges.append(StatusBadge(text: "No members", color: .secondary, help: "The group has no direct members (primary-group members are not counted)."))
        }
        return badges
    }
}

extension String {
    var capitalizingFirst: String { prefix(1).uppercased() + dropFirst() }
}

/// Lays children out left to right, wrapping onto new lines.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0, widest: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > 0 && x + size.width > width {
                y += rowHeight + spacing
                x = 0
                rowHeight = 0
            }
            x += size.width + spacing
            widest = max(widest, x - spacing)
            rowHeight = max(rowHeight, size.height)
        }
        return CGSize(width: min(widest, width), height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowHeight: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > bounds.minX && x + size.width > bounds.maxX {
                y += rowHeight + spacing
                x = bounds.minX
                rowHeight = 0
            }
            view.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}

// MARK: LDIF

struct LDIFView: View {
    let entry: LDAPEntry
    /// Written away from the main thread: a group of 50,000 members is
    /// megabytes of LDIF.
    @State private var text: String?

    var body: some View {
        Group {
            if let text {
                ReadOnlyText(text: text, accessibilityLabel: "LDIF")
            } else {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .task(id: entry) {
            let entry = entry
            text = await Task.detached(priority: .userInitiated) { LDIF.entry(entry) }.value
        }
        .safeAreaInset(edge: .bottom) {
            HStack {
                Spacer()
                Button("Copy") { if let text { Pasteboard.copy(text) } }.disabled(text == nil)
                Button("Save…") { Exporter.saveLDIF([entry], suggestedName: DN.displayName(entry.dn)) }
            }
            .padding(10)
            .background(.bar)
        }
    }
}

/// Selectable monospaced text that scrolls both ways without wrapping.
///
/// An `NSTextView` rather than SwiftUI's `Text`, which lays out every line
/// first and held up the window for seconds on a big group's LDIF. And on
/// TextKit 1: TextKit 2 also lays out everything when lines do not wrap, to
/// find the widest (1.2 s for 50,000 lines, against 10 ms).
struct ReadOnlyText: NSViewRepresentable {
    let text: String
    let accessibilityLabel: String

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.drawsBackground = false
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        let textView = NSTextView(usingTextLayoutManager: false)
        textView.autoresizingMask = [.width, .height]
        textView.minSize = .zero
        textView.isVerticallyResizable = true
        scroll.documentView = textView
        textView.isEditable = false
        textView.isSelectable = true
        textView.drawsBackground = false
        textView.font = .monospacedSystemFont(ofSize: NSFont.preferredFont(forTextStyle: .callout).pointSize, weight: .regular)
        textView.textColor = .labelColor
        textView.textContainerInset = NSSize(width: 10, height: 14)
        textView.isHorizontallyResizable = true
        textView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        textView.textContainer?.widthTracksTextView = false
        textView.textContainer?.containerSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        textView.setAccessibilityLabel(accessibilityLabel)
        textView.string = text
        context.coordinator.shown = text
        return scroll
    }

    /// The text last given to the view: comparing with it is cheap when it is
    /// the same string, where reading the view's own back would copy megabytes.
    final class Coordinator {
        var shown = ""
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let textView = scroll.documentView as? NSTextView, context.coordinator.shown != text else { return }
        textView.string = text
        context.coordinator.shown = text
    }
}
