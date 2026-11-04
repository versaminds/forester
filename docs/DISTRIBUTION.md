# Getting Forester to people

How to ship Forester: the website, a download that opens without warnings,
Homebrew, and the Mac App Store. Written in October 2026; Apple's and
Homebrew's rules change, so check the linked pages before relying on a number.

**The order chosen**

1. Join the Apple Developer Program. Everything else needs it.
2. **The Mac App Store first**, with the website live:
   [APP-STORE.md](APP-STORE.md) walks through submitting it, and
   `scripts/check-release.sh` lists what is still missing. The website's
   Download buttons lead there (`site/_redirects`). The App Store updates it.
3. Then the signed, notarized download from GitHub Releases, which updates
   itself through Sparkle (see Updates below), and a Homebrew cask from
   VersaMinds' own tap. Admins who install by download, Homebrew or their MDM
   get it there; until then the website offers only the App Store.

---

## 1. Apple Developer Program

<https://developer.apple.com/programs/enroll/>

- Enroll as an **organization**, in the name of the legal entity that owns
  VersaMinds, so the App Store and Gatekeeper show "VersaMinds" rather than a
  person's name. Apple asks for a **D-U-N-S number** (free from Dun & Bradstreet;
  getting one can take a couple of weeks, so start now), the legal entity name,
  a website on your own domain, and a work email address on that domain.
- 99 USD a year, or the local equivalent.
- The person who enrolls becomes the Account Holder. Only the Account Holder
  can create **Developer ID** certificates.

Once enrolled, create in Xcode › Settings › Accounts › Manage Certificates:

| Certificate | For |
|---|---|
| Developer ID Application | the download (step 2) |
| Developer ID Installer | a .pkg for MDM tools, if a customer asks for one |
| Apple Distribution and Mac Installer Distribution | the Mac App Store (step 4) |

`scripts/build-app.sh` finds a Developer ID Application or Apple Development
certificate by itself (or takes `FORESTER_SIGN_IDENTITY`). A stable signature also
ends the keychain prompts after every build that an ad hoc signature causes.

---

## 2. The download

### Build, sign, notarize

Store the notarization credentials once (an app-specific password from
appleid.apple.com, or an App Store Connect API key):

```bash
xcrun notarytool store-credentials forester-notary --apple-id you@versaminds.live --team-id TEAMID
```

Then, for every release:

```bash
FORESTER_NOTARY_PROFILE=forester-notary scripts/make-release.sh
```

`scripts/make-release.sh` builds for Apple silicon and Intel, signs the app with
the hardened runtime, notarizes and staples it, wraps it in `build/Forester.dmg`
(with an Applications shortcut to drag it to), then signs, notarizes and staples
the disk image too, and prints its SHA-256. It refuses rather than produce a
release it cannot vouch for: uncommitted changes, a `VERSION` that differs from
the tag on `HEAD`, a binary missing either architecture or linking a library
through `@rpath`, a signature without the hardened runtime, no notary profile,
or a refused notarization (whose log it prints). `FORESTER_ALLOW_ADHOC=1`
makes an image signed ad hoc for trying on this Mac only, and
`FORESTER_ALLOW_DIRTY=1` builds from uncommitted changes. `build/Forester.dSYM`
is kept beside the app, outside the image: keep it with each release, so crash
reports people send can be read. Only the ad hoc path has been run so far: the
signing and notarizing steps need the certificate before they can be tried.

The Intel half is for Intel Macs, which run macOS 14 to 26; Apple silicon runs
the native half. To try the Intel half on Apple silicon, `arch -x86_64
build/Forester.app/Contents/MacOS/Forester` runs it under Rosetta, and macOS 27
then shows "App Update Required", because macOS 28 drops Rosetta for apps. That
notice is about the test, not the release. Drop `--arch x86_64` from
`build-app.sh` once Intel Macs no longer matter.

Before publishing, on a Mac that has never seen Forester:

```bash
spctl --assess --type open --context context:primary-signature --verbose build/Forester.dmg
```

then open the image, drag the app to Applications and open it. There should be
no warning beyond "downloaded from the internet".

### Version numbers

`VERSION` holds the version shown in About Forester (`CFBundleShortVersionString`
and `CFBundleVersion`). Raise it before each release. The App Store requires
`CFBundleVersion` to grow with every upload.

### GitHub

The website links to `github.com/versaminds/forester`, and the update feed
and the Homebrew cask to its releases, so:

1. Make `versaminds/forester` public (Settings › General › Danger Zone ›
   Change visibility). While it is private, the source link, the updates and
   Homebrew all get "not found" for everyone but its members.
2. Tag the release and push the tag: `git tag -a v1.0.0 -m "Forester 1.0.0"`,
   then `git push origin v1.0.0`. The tag must match `VERSION`, and be
   annotated: the release workflow counts two weeks from its date.
3. Publish it with the disk image attached under exactly the name
   `Forester.dmg`: on GitHub, Releases › Draft a new release › the tag ›
   attach `build/Forester.dmg` › Publish. Or with the GitHub CLI
   (`brew install gh`, then `gh auth login`):

```bash
gh release create v1.0.0 build/Forester.dmg --title "Forester 1.0" --generate-notes
```

4. Commit `site/updates/appcast.xml`, which `make-release.sh` added the
   release to, and deploy the site: copies already out there are offered the
   update from then on. When the download is offered on the website, add it
   next to the App Store button.

### The website

The site is `site/`: plain HTML and CSS, no build step, no scripts, nothing
loaded from other companies. It is served by Cloudflare Pages (free), with
strict security headers from `site/_headers`. To put it live at
forester.versaminds.live, with versaminds.live's DNS on the same Cloudflare
account:

1. `wrangler pages deploy` from the repository (`wrangler.toml` names the project
   and the folder), or in the dashboard, Workers & Pages › Create › Pages ›
   connect the GitHub repository, with no build command and `site` as the
   output folder.
2. Under the project's Custom domains, add `forester.versaminds.live`.
   Cloudflare adds the DNS record and issues the HTTPS certificate.

The pictures come from the real app. After a change to the app's look, retake
them, with the test directory running (TESTING.md) and the Mac left alone for
the minute it takes:

```bash
scripts/app-store-screenshots.sh
```

It refreshes the site's images and the App Store's screenshots together, and
gives every link to a picture a new version, so no browser keeps showing the
old one. `cwebp` comes from `brew install webp`.

### Homebrew

Homebrew's own cask list only takes software with public interest beyond its
author; for a project its owner submits, that currently means 225 GitHub stars,
90 forks or 90 watchers, and a repository at least 30 days old
(<https://docs.brew.sh/Acceptable-Casks>, <https://docs.brew.sh/Package-Acceptance-Policy>).
Until then, publish from VersaMinds' own tap:

1. Create the public repository `versaminds/homebrew-tap` (the name must start
   with `homebrew-`) with `Casks/forester.rb`. `make-release.sh` writes this
   file, with the release's version and SHA-256, to `build/forester.rb`:

```ruby
cask "forester" do
  version "1.0.0"
  sha256 "SHA-256 printed by make-release.sh"

  url "https://github.com/versaminds/forester/releases/download/v#{version}/Forester.dmg"
  name "Forester"
  desc "LDAP and Active Directory browser"
  homepage "https://forester.versaminds.live/"

  depends_on macos: :sonoma

  app "Forester.app"

  zap trash: [
    "~/Library/Application Support/Forester",
    "~/Library/Preferences/live.versaminds.Forester.plist",
    "~/Library/Saved Application State/live.versaminds.Forester.savedState",
  ]
end
```

2. Check it before pushing, from the tap's folder:

```bash
brew audit --cask --new ./Casks/forester.rb
```

```bash
brew install --cask ./Casks/forester.rb
```

3. People then install it with `brew install --cask versaminds/tap/forester`.
   For every release, publish the GitHub release first, then copy the new
   `build/forester.rb` over the tap's and push it; `brew upgrade` brings it to
   everyone who installed through the tap.

### Updates

The App Store version is updated by the App Store, and is built without any
updater of its own: App Review refuses one, and `Package.swift` leaves Sparkle
out when `FORESTER_APP_STORE=1` (`make-appstore.sh` checks).

The download updates itself through [Sparkle](https://sparkle-project.org)
2.10.1 (MIT; its licence ships in the app and About links to it). The feed
is `site/updates/appcast.xml`, served at
https://forester.versaminds.live/updates/appcast.xml; each release in it points
at its disk image on GitHub Releases and carries an EdDSA signature that the
app checks against the public key it was built with before installing
anything. Sparkle asks on the second launch whether to check automatically
(Settings › Updates changes it later), so nothing is fetched before the person
says yes or chooses Forester › Check for Updates.

Once, before the first download:

1. Make the update key, kept in this Mac's login keychain:

```bash
.build/artifacts/sparkle/Sparkle/bin/generate_keys --account forester
```

2. Put the public key it prints in `Resources/sparkle-public-key` and commit
   it. Back up the private key (`generate_keys --account forester -x
   forester-update-key`) somewhere safe and offline: without it no copy out
   there can ever be updated again, and anyone holding it can sign an update.

`build-app.sh` then gives the download its feed and key (`FORESTER_FEED_URL`
names another feed), and a build without the key has no update menu at all.
`make-release.sh` refuses a release without the updater, signs the notarized
image with the key in the keychain (`FORESTER_UPDATE_KEY_FILE` names a key
file instead), checks the signature against `Resources/sparkle-public-key` as
the app will, and adds the release to the feed. Publish the GitHub release
first and the feed second, so it never names a file that is not there yet.
Homebrew users get updates with `brew upgrade` as well.

---

## 3. Before the first release

- Run the full test list in TESTING.md (unit and integration tests, and the
  self-driving run), on the build that will ship.
- Run the checks against the Samba domain controller (TESTING.md step 6), then
  try it against your own Active Directory, read-only (step 7).
- Open the notarized disk image on a second Mac.
- Check the website on a phone and in dark mode, and that the Download
  buttons lead to Forester on the Mac App Store.

---

## 4. The Mac App Store

[APP-STORE.md](APP-STORE.md) has all of it: the account, certificates and
profile, the demo directory App Review connects to, the build
(`scripts/make-appstore.sh`), the store listing's text and the review notes.

---

## 5. Releases every two weeks

After the first release, GitHub Actions keeps Forester current and releases
it every other week. What runs, all on GitHub's macOS runners:

| Workflow | When | What it does |
|---|---|---|
| Tests (`ci.yml`) | every push to main and pull request | `scripts/test-all.sh`: unit and integration tests, release builds of both variants, the app driving itself, the App Store variant in its sandbox |
| Weekly (`weekly.yml`) | Mondays, 05:00 UTC | every test of main with the big directory; a failure opens an issue. A newer Sparkle is tested and proposed, and merged when every test passes and the major version is the same |
| Release (`release.yml`) | Tuesdays, 06:00 UTC | when the last release is two weeks old and the app changed: every test, the version raised (1.1.0, 1.2.0, …), the App Store package uploaded to App Store Connect, the DMG built, the tag pushed and a GitHub release drafted |
| Publish (`publish.yml`) | when you publish a release | the update feed, the website and the Homebrew cask |
| Website (`site.yml`) | a push to main that touches `site/` | deploys the website |

Dependabot keeps the workflows' own actions current.

**Your part of each release:** in App Store Connect, once Apple has processed
the build (TestFlight shows it), create the version, add the build and press
Submit for Review. On GitHub, read the draft release, edit its notes and
publish it. Before submitting a release that changes how Forester treats
Active Directory, run the AD checks (TESTING.md step 6) on your Mac: CI has no
domain controller.

A fix in between: Actions › Release › Run workflow, part `patch`, force on.

### Set up once

In the repository's Settings:

1. **Actions › General › Workflow permissions:** "Read and write
   permissions", and "Allow GitHub Actions to create and approve pull
   requests". The weekly update and the release push with the workflow's own
   token; a rule on main that requires reviews or checks stops them (the
   update pull request then waits for you).
2. **Secrets and variables › Actions**, as repository secrets:

| Secret | What | How |
|---|---|---|
| `APPLE_CERTIFICATES_P12` | the signing certificates with their private keys | Keychain Access: select Apple Distribution, Mac Installer Distribution and (for the download) Developer ID Application, File › Export Items… as a .p12 with a password; then `base64 -i Certificates.p12 \| pbcopy` |
| `APPLE_CERTIFICATES_PASSWORD` | that .p12's password | |
| `APPSTORE_PROFILE` | the Mac App Store provisioning profile | `base64 -i Forester_App_Store.provisionprofile \| pbcopy` |
| `ASC_KEY_ID`, `ASC_ISSUER_ID`, `ASC_KEY_P8` | an App Store Connect API key with the App Manager role: it uploads and notarizes | App Store Connect › Users and Access › Integrations › Team Keys; the .p8 downloads once, paste its whole text |
| `SPARKLE_PRIVATE_KEY` | the update key's private half (the download only) | `generate_keys --account forester -x key.txt`, paste the file's text, delete the file |
| `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` | the website | see `site.yml` |
| `HOMEBREW_TAP_TOKEN` | the cask (optional) | a fine-grained token with Contents: write on `versaminds/homebrew-tap` only |

Without the App Store secrets the release stops before changing anything,
and says what is missing; without the download's (the Developer ID
certificate, `SPARKLE_PRIVATE_KEY` and `Resources/sparkle-public-key` in the
repository) it releases the App Store package only.

The certificates and the profile expire (a year, and with the certificate);
when one does, the release fails at signing: export and paste it again.

### On GitHub's minutes

macOS runners are free for a public repository, which is why
`versaminds/forester` stays public. In a private one each macOS minute counts
ten times against the organisation's allowance: a full test run takes about
half an hour, which counts as some 300 minutes, so the weekly check alone
would use about 1,200 a month (the free plan includes 2,000), and every push
to main another 300. A workflow can be paused under Actions › the workflow ›
⋯ › Disable.

