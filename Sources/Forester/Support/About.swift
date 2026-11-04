// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

import AppKit

/// Who makes Forester and where to find it, for the About window, the Help
/// menu and anything else that names them.
enum ForesterInfo {
    static let name = "Forester"
    static let tagline = "The LDAP and Active Directory browser for Mac."
    static let website = URL(string: "https://forester.versaminds.live")!
    static let company = "VersaMinds"
    static let companyWebsite = URL(string: "https://www.versaminds.live")!
    static let copyright = "© 2026 VersaMinds"
    static let licenseURL = URL(string: "https://polyformproject.org/licenses/shield/1.0.0")!

    /// The Mac App Store build (scripts/make-appstore.sh): sandboxed, so it
    /// reaches only its own container, and updated by the App Store, whose
    /// rules allow no other way.
    #if APP_STORE
    static let fromAppStore = true
    #else
    static let fromAppStore = false
    #endif

    static var version: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "development build"
    }

    @MainActor
    static func showAboutPanel() {
        NSApp.orderFrontStandardAboutPanel(options: [
            .applicationName: name,
            .applicationVersion: version,
            .version: "",
            .credits: credits,
            NSApplication.AboutPanelOptionKey(rawValue: "Copyright"): copyright,
        ])
        NSApp.activate()
    }

    /// The text under the name and version: what it is, who makes it, where
    /// to find them, and the licence.
    static var credits: NSAttributedString {
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = .center
        paragraph.paragraphSpacing = 6
        let base: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
            .foregroundColor: NSColor.labelColor,
            .paragraphStyle: paragraph,
        ]
        let text = NSMutableAttributedString()
        func add(_ string: String, link: URL? = nil, secondary: Bool = false) {
            var attributes = base
            if let link { attributes[.link] = link }
            if secondary { attributes[.foregroundColor] = NSColor.secondaryLabelColor }
            text.append(NSAttributedString(string: string, attributes: attributes))
        }
        add(tagline + "\n")
        add("Made by ")
        add(company, link: companyWebsite)
        add(", the company behind Stackbridge and Wayfinder.\n")
        add("forester.versaminds.live", link: website)
        add("   ")
        add("versaminds.live", link: companyWebsite)
        add("\n")
        add("Free to use. Source code under the ", secondary: true)
        add("PolyForm Shield License", link: licenseURL)
        add(".", secondary: true)
        // The download's updates come through Sparkle, whose licence travels
        // with every copy (scripts/build-app.sh puts it in the bundle).
        if let sparkleLicense = Bundle.main.url(forResource: "Sparkle-LICENSE", withExtension: "txt") {
            add("\nUpdates through Sparkle, under its ", secondary: true)
            add("MIT licence", link: sparkleLicense)
            add(".", secondary: true)
        }
        return text
    }
}
