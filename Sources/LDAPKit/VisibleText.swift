// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import Foundation

/// Names and DNs as a person must see them before agreeing to change
/// something: a directory name can hold characters that are not drawn but
/// change what is (a right-to-left override turns "nimda" around, a
/// zero-width space makes two names look the same). Each is written out as
/// ⟨U+202E⟩ wherever a name is confirmed, picked or typed.
public enum VisibleText {
    /// Not drawn, or drawn as nothing, while changing the text around them:
    /// format characters (bidi controls and isolates, zero-width spaces and
    /// joiners, the soft hyphen, tags), controls, line and paragraph
    /// separators, and the letters and marks that render empty.
    public static func isHidden(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.properties.generalCategory {
        case .format, .control, .lineSeparator, .paragraphSeparator: return true
        default: return invisibleOthers.contains(scalar.value)
        }
    }

    /// Hangul fillers, Khmer inherent vowels and the combining grapheme
    /// joiner: letters or marks that are drawn as nothing.
    private static let invisibleOthers: Set<UInt32> = [0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0]

    /// `text` with each hidden character written out, as ⟨U+202E⟩.
    public static func reveal(_ text: String) -> String {
        guard text.unicodeScalars.contains(where: isHidden) else { return text }
        var out = ""
        for scalar in text.unicodeScalars {
            if isHidden(scalar) {
                out += String(format: "⟨U+%04X⟩", scalar.value)
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
        return out
    }

    /// Whether `typed` confirms `name`: the name itself, or the name as it
    /// is shown (hidden characters written out, the brackets also typed as
    /// < and >), since a hidden character cannot be typed.
    public static func confirms(_ typed: String, _ name: String) -> Bool {
        if typed == name { return true }
        func plain(_ text: String) -> String {
            text.replacingOccurrences(of: "⟨", with: "<").replacingOccurrences(of: "⟩", with: ">")
        }
        let shown = reveal(name)
        return shown != name && plain(typed).uppercased() == plain(shown).uppercased() && plain(typed).count == plain(shown).count
            && caseKeptOutsideMarks(plain(typed), plain(shown))
    }

    /// Only the U+ codes may differ in case; the name's own letters must match.
    private static func caseKeptOutsideMarks(_ typed: String, _ shown: String) -> Bool {
        func outside(_ text: String) -> String {
            var out = ""
            var inMark = false
            for character in text {
                if character == "<" { inMark = true } else if character == ">" { inMark = false } else if !inMark { out.append(character) }
            }
            return out
        }
        return outside(typed) == outside(shown)
    }
}
