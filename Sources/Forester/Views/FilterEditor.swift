// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import AppKit
import LDAPKit
import SwiftUI

/// A filter text field that completes attribute names (and object class names
/// after `objectClass=`) from the server's schema as you type, with AppKit's own
/// completion popup. Line breaks and spaces between parts are allowed.
struct FilterEditor: NSViewRepresentable {
    @Binding var text: String
    var attributes: [String]
    var classes: [String]
    var invalid: Bool
    var onSubmit: () -> Void

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        guard let textView = scroll.documentView as? NSTextView else { return scroll }
        let field = CompletingTextView(frame: textView.frame, textContainer: textView.textContainer)
        field.autoresizingMask = textView.autoresizingMask
        field.minSize = textView.minSize
        field.maxSize = textView.maxSize
        field.isVerticallyResizable = true
        field.isHorizontallyResizable = false
        field.textContainer?.widthTracksTextView = true
        field.isRichText = false
        field.allowsUndo = true
        field.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        field.isAutomaticQuoteSubstitutionEnabled = false
        field.isAutomaticDashSubstitutionEnabled = false
        field.isAutomaticTextReplacementEnabled = false
        field.isContinuousSpellCheckingEnabled = false
        field.isGrammarCheckingEnabled = false
        field.smartInsertDeleteEnabled = false
        field.textContainerInset = NSSize(width: 4, height: 5)
        field.delegate = context.coordinator
        field.string = text
        field.setAccessibilityLabel("Filter")
        scroll.documentView = field
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .noBorder
        scroll.drawsBackground = false
        context.coordinator.textView = field
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        context.coordinator.parent = self
        guard let field = context.coordinator.textView else { return }
        if field.string != text { field.string = text }
    }

    /// Completion range covers the whole attribute name: letters, digits,
    /// hyphens and dots (msDS-User-Account-Control-Computed, 2.5.4.3).
    final class CompletingTextView: NSTextView {
        override var rangeForUserCompletion: NSRange {
            let selected = selectedRange()
            let text = string as NSString
            var start = selected.location
            while start > 0 {
                let character = text.character(at: start - 1)
                guard let scalar = UnicodeScalar(character), CharacterSet.alphanumerics.contains(scalar) || scalar == "-" || scalar == "." else { break }
                start -= 1
            }
            return NSRange(location: start, length: selected.location - start)
        }
    }

    @MainActor
    final class Coordinator: NSObject, NSTextViewDelegate {
        var parent: FilterEditor
        weak var textView: NSTextView?
        private var completing = false

        init(_ parent: FilterEditor) { self.parent = parent }

        func textDidChange(_ notification: Notification) {
            guard let textView else { return }
            parent.text = textView.string
            guard !completing, let event = NSApp.currentEvent, event.type == .keyDown,
                  let typed = event.characters?.unicodeScalars.first,
                  CharacterSet.alphanumerics.contains(typed) || typed == "-" else { return }
            let range = textView.rangeForUserCompletion
            guard range.length >= 2, !candidates(for: range, in: textView).isEmpty else { return }
            completing = true
            textView.complete(nil)
            completing = false
        }

        func textView(_ textView: NSTextView, doCommandBy selector: Selector) -> Bool {
            // Return searches; Option-Return inserts a line break for long filters.
            if selector == #selector(NSResponder.insertNewline(_:)) {
                parent.onSubmit()
                return true
            }
            return false
        }

        func textView(_ textView: NSTextView, completions words: [String], forPartialWordRange charRange: NSRange,
                      indexOfSelectedItem index: UnsafeMutablePointer<Int>?) -> [String] {
            index?.pointee = -1
            return candidates(for: charRange, in: textView)
        }

        /// Attribute names where an attribute goes: after `(`, `&`, `|` or `!`.
        /// Class names after `objectClass=`.
        private func candidates(for range: NSRange, in textView: NSTextView) -> [String] {
            let text = textView.string as NSString
            guard range.location != NSNotFound, NSMaxRange(range) <= text.length else { return [] }
            let partial = text.substring(with: range).lowercased()
            let before = text.substring(to: range.location).replacingOccurrences(of: " ", with: "")
            let pool: [String]
            if before.lowercased().hasSuffix("objectclass=") {
                pool = parent.classes
            } else if before.isEmpty || before.hasSuffix("(") || before.hasSuffix("&") || before.hasSuffix("|") || before.hasSuffix("!") {
                pool = parent.attributes
            } else {
                return []
            }
            return Array(pool.filter { $0.lowercased().hasPrefix(partial) && $0.lowercased() != partial }.prefix(60))
        }
    }
}

/// Builds a filter from conditions, for people who would rather not type
/// RFC 4515: attribute (picked from the schema), test, value.
struct FilterBuilder: View {
    let session: DirectorySession
    @Binding var filterText: String
    @State private var conditions: [Condition] = [Condition()]
    @State private var matchAll = true

    struct Condition: Identifiable, Equatable {
        let id = UUID()
        var attribute = "cn"
        var test: Test = .contains
        var value = ""
    }

    enum Test: String, CaseIterable, Identifiable {
        case equals = "is", contains = "contains", startsWith = "starts with", endsWith = "ends with"
        case present = "is present", absent = "is not present", greater = "≥", less = "≤", not = "is not"
        var id: String { rawValue }
        var needsValue: Bool { self != .present && self != .absent }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Picker("", selection: $matchAll) {
                Text("Match all of").tag(true)
                Text("Match any of").tag(false)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            ForEach($conditions) { $condition in
                HStack(spacing: 6) {
                    AttributeField(session: session, name: $condition.attribute)
                        .frame(width: 180)
                    Picker("", selection: $condition.test) {
                        ForEach(Test.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .labelsHidden()
                    .fixedSize()
                    if condition.test.needsValue {
                        TextField("value", text: $condition.value).textFieldStyle(.roundedBorder)
                    } else {
                        Spacer()
                    }
                    Button { conditions.removeAll { $0.id == condition.id } } label: { Image(systemName: "minus.circle") }
                        .buttonStyle(.borderless)
                        .disabled(conditions.count == 1)
                }
            }
            Button { conditions.append(Condition()) } label: { Label("Add Condition", systemImage: "plus") }
                .buttonStyle(.borderless)
        }
        .onChange(of: conditions) { filterText = built }
        .onChange(of: matchAll) { filterText = built }
        .onAppear { filterText = built }
    }

    private var built: String {
        let parts = conditions.compactMap { condition -> String? in
            let attribute = condition.attribute.trimmingCharacters(in: .whitespaces)
            guard !attribute.isEmpty else { return nil }
            let value = LDAPFilter.escape(condition.value)
            switch condition.test {
            case .equals: return "(\(attribute)=\(value))"
            case .contains: return "(\(attribute)=*\(value)*)"
            case .startsWith: return "(\(attribute)=\(value)*)"
            case .endsWith: return "(\(attribute)=*\(value))"
            case .present: return "(\(attribute)=*)"
            case .absent: return "(!(\(attribute)=*))"
            case .greater: return "(\(attribute)>=\(value))"
            case .less: return "(\(attribute)<=\(value))"
            case .not: return "(!(\(attribute)=\(value)))"
            }
        }
        if parts.count == 1 { return parts[0] }
        return "(\(matchAll ? "&" : "|")\(parts.joined()))"
    }
}

/// An attribute name field with the schema's names in a menu beside it.
struct AttributeField: View {
    let session: DirectorySession
    @Binding var name: String

    static let common = ["cn", "sAMAccountName", "userPrincipalName", "displayName", "givenName", "sn", "mail", "uid",
                         "description", "title", "department", "memberOf", "objectClass", "userAccountControl", "ou"]

    var body: some View {
        HStack(spacing: 2) {
            TextField("attribute", text: $name).textFieldStyle(.roundedBorder).font(.callout)
            Menu {
                Section("Common") {
                    ForEach(Self.common, id: \.self) { item in Button(item) { name = item } }
                }
                if let schema = session.schema {
                    Menu("All Attributes") {
                        ForEach(schema.attributeNames.filter { $0.first?.isLetter == true }.prefix(2000), id: \.self) { item in
                            Button(item) { name = item }
                        }
                    }
                }
            } label: { Image(systemName: "chevron.down") }
                .menuIndicator(.hidden)
                .fixedSize()
        }
    }
}
