// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Copyright © 2026 VersaMinds

#if !APP_STORE
import Foundation
import Sparkle

/// Updates of the download, through Sparkle: a feed of releases on Forester's
/// website, each signed with VersaMinds' key and checked against it before it
/// is installed. Only a build that names the feed and the key (scripts/build-app.sh
/// puts both in the Info.plist) has them; any other build, such as a debug
/// build, has no update menu at all rather than one that cannot work.
///
/// Sparkle asks on the second launch whether to check automatically, so
/// nothing is fetched before the person has said yes or chosen Check for
/// Updates. The Mac App Store version is built without Sparkle: the App Store
/// updates it.
@MainActor
enum Updates {
    private(set) static var controller: SPUStandardUpdaterController?

    static var isAvailable: Bool { controller != nil }

    /// At launch: starts the updater when the build is set up for one.
    static func start() {
        guard controller == nil else { return }
        let info = Bundle.main.infoDictionary ?? [:]
        guard let feed = info["SUFeedURL"] as? String, URL(string: feed)?.scheme == "https",
              let key = info["SUPublicEDKey"] as? String, !key.isEmpty else { return }
        controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
    }

    static func checkNow() {
        controller?.checkForUpdates(nil)
    }

    static var checksAutomatically: Bool {
        get { controller?.updater.automaticallyChecksForUpdates ?? false }
        set { controller?.updater.automaticallyChecksForUpdates = newValue }
    }
}
#endif
