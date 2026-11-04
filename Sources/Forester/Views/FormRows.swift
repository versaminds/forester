// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import SwiftUI

// Shared building blocks for forms and sheets, so every form in the app has
// the same shape: labels in a column on the left, fields starting at one edge
// and filling the rest, text that starts where you type, and the same title
// and button bar on every sheet.
//
// A grouped Form on its own puts a text field's text against the right edge,
// with the empty part of the field in front of it, and sets labels a few
// points above their fields. These rows avoid both.

private struct FormLabelWidthKey: EnvironmentKey {
    static let defaultValue: CGFloat = 110
}

extension EnvironmentValues {
    /// The width of the label column; set once per form so its fields line up.
    var formLabelWidth: CGFloat {
        get { self[FormLabelWidthKey.self] }
        set { self[FormLabelWidthKey.self] = newValue }
    }
}

extension View {
    func formLabelWidth(_ width: CGFloat) -> some View {
        environment(\.formLabelWidth, width)
    }
}

/// A label in the form's label column and any control beside it, aligned on
/// the first line of text.
struct FieldRow<Content: View>: View {
    let label: String
    var required = false
    var help: String?
    @ViewBuilder var content: () -> Content
    @Environment(\.formLabelWidth) private var labelWidth

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            HStack(spacing: 2) {
                Text(label).lineLimit(1).truncationMode(.middle)
                if required {
                    Text("*").foregroundStyle(.red).accessibilityLabel("required")
                }
            }
            .frame(width: labelWidth, alignment: .leading)
            .help(help ?? label)
            content()
                .frame(maxWidth: .infinity, alignment: .leading)
                .multilineTextAlignment(.leading)
        }
    }
}

/// A text field with its label, filling the row. `width` fixes it for short
/// values such as a port number.
struct TextFieldRow: View {
    let label: String
    @Binding var text: String
    var prompt: String?
    var required = false
    var help: String?
    var width: CGFloat?

    var body: some View {
        FieldRow(label: label, required: required, help: help) {
            TextField(label, text: $text, prompt: prompt.map { Text($0) })
                .labelsHidden()
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .accessibilityIdentifier(label)
                .frame(width: width)
        }
    }
}

/// A password field with a button to show what was typed.
struct PasswordFieldRow: View {
    let label: String
    @Binding var text: String
    var prompt: String?
    /// Shared by a password and its confirmation, so both show or hide together.
    @Binding var reveal: Bool
    var showsRevealButton = true
    var required = false

    var body: some View {
        FieldRow(label: label, required: required) {
            HStack(spacing: 6) {
                Group {
                    if reveal {
                        TextField(label, text: $text, prompt: prompt.map { Text($0) })
                            .autocorrectionDisabled()
                    } else {
                        SecureField(label, text: $text, prompt: prompt.map { Text($0) })
                    }
                }
                .labelsHidden()
                .textFieldStyle(.roundedBorder)
                // Without its button, the field still leaves the button's room,
                // so it ends where the password field above it ends.
                Button { reveal.toggle() } label: {
                    Image(systemName: reveal ? "eye.slash" : "eye").frame(width: 18)
                }
                .buttonStyle(.borderless)
                .help(reveal ? "Hide the password" : "Show the password")
                .accessibilityLabel(reveal ? "Hide password" : "Show password")
                .opacity(showsRevealButton ? 1 : 0)
                .disabled(!showsRevealButton)
                .accessibilityHidden(!showsRevealButton)
            }
        }
    }
}

/// A DN, typed or chosen from the directory.
struct DNFieldRow: View {
    let label: String
    @Binding var dn: String
    var prompt = "OU=…,DC=…"
    let choose: () -> Void

    var body: some View {
        FieldRow(label: label) {
            HStack(spacing: 8) {
                TextField(label, text: $dn, prompt: Text(prompt))
                    .labelsHidden()
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                Button("Choose…", action: choose)
            }
        }
    }
}

/// A pop-up menu that starts at the field edge, like the text fields around it.
struct PickerRow<Value: Hashable, Options: View>: View {
    let label: String
    @Binding var selection: Value
    var help: String?
    @ViewBuilder var options: () -> Options

    var body: some View {
        FieldRow(label: label, help: help) {
            Picker(label, selection: $selection, content: options)
                .labelsHidden()
                .fixedSize()
        }
    }
}

/// A read-only value in the field column: a computed DN, the method a sheet
/// will use, and the like.
struct ValueRow: View {
    let label: String
    let value: String
    var monospaced = false

    var body: some View {
        FieldRow(label: label) {
            Text(value)
                .font(monospaced ? .callout.monospaced() : .body)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// A number with a stepper beside it, typed or stepped.
struct NumberFieldRow: View {
    let label: String
    @Binding var value: Int
    let range: ClosedRange<Int>
    var step = 1
    var unit: String?

    var body: some View {
        FieldRow(label: label) {
            HStack(spacing: 6) {
                TextField(label, value: Binding(get: { value }, set: { value = min(max($0, range.lowerBound), range.upperBound) }),
                          format: .number.grouping(.never))
                    .labelsHidden()
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 72)
                Stepper(label, value: $value, in: range, step: step).labelsHidden()
                if let unit { Text(unit).foregroundStyle(.secondary) }
            }
        }
    }
}

/// Every sheet's frame: a title (and optional subtitle) at the top, the
/// content, and a bar of buttons at the bottom with an optional status on the
/// left. The content decides the height unless `height` is given.
struct SheetLayout<Content: View, Status: View, Buttons: View>: View {
    let title: String
    var subtitle: String?
    var width: CGFloat = 520
    var height: CGFloat?
    @ViewBuilder var content: () -> Content
    @ViewBuilder var status: () -> Status
    @ViewBuilder var buttons: () -> Buttons

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline).lineLimit(2)
                if let subtitle {
                    Text(subtitle).font(.callout).foregroundStyle(.secondary).lineLimit(2).truncationMode(.middle)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 20)
            .padding(.top, 18)
            .padding(.bottom, 4)
            content()
                .frame(maxHeight: height == nil ? nil : .infinity, alignment: .top)
            Divider()
            HStack(spacing: 10) {
                status().font(.callout)
                Spacer(minLength: 12)
                buttons()
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
        }
        .frame(width: width, height: height)
    }
}

extension SheetLayout where Status == EmptyView {
    init(title: String, subtitle: String? = nil, width: CGFloat = 520, height: CGFloat? = nil,
         @ViewBuilder content: @escaping () -> Content, @ViewBuilder buttons: @escaping () -> Buttons) {
        self.init(title: title, subtitle: subtitle, width: width, height: height,
                  content: content, status: { EmptyView() }, buttons: buttons)
    }
}

/// Explanatory text under a form section, aligned with the rows above it
/// (a grouped form puts footers against the right edge).
struct FormFooter: View {
    let text: String
    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.leading)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

extension View {
    /// A grouped form that is as tall as its content, for short sheets that
    /// should not open with a screen of empty space under the last row.
    func hugsContent() -> some View {
        scrollDisabled(true).fixedSize(horizontal: false, vertical: true)
    }
}

/// The left of a sheet's button bar: what is still missing, or what went wrong.
struct SheetStatus: View {
    var problem: String?
    var error: String?

    var body: some View {
        if let error {
            Label { Text(error).textSelection(.enabled).lineLimit(3) } icon: {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
            }
            .foregroundStyle(.red)
        } else if let problem {
            Text(problem).foregroundStyle(.secondary).lineLimit(2)
        }
    }
}

extension View {
    /// A switch in a grouped form keeps its label to itself for VoiceOver,
    /// which then announces only "switch, off": the label is given again.
    func formSwitch(_ label: String, hint: String? = nil) -> some View {
        accessibilityLabel(Text(label))
            .accessibilityHint(hint.map { Text($0) } ?? Text(""))
    }
}
