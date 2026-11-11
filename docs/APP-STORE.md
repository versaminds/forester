<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<!-- Copyright © 2026 VersaMinds -->

# The Mac App Store

Everything needed to put Forester in the Mac App Store, in the order it is
done. The App Store build is the same app with four things left out for the
sandbox and App Review's rules (see "What differs" at the end); the download
from GitHub stays as it is.

Steps 1 to 6 take an evening; review usually takes one to two days after it.

## 1. The Apple Developer account

Sign in at <https://developer.apple.com/account> and check **Membership
details**:

- **Entity type.** An *Individual* account sells under the person's name, so
  the App Store would show "Lennert Mertens" as the seller. To show
  "VersaMinds", the account has to be an *Organization* (with a D-U-N-S number;
  see docs/DISTRIBUTION.md § 1). A team can later be moved from individual to
  organization through Apple's support, and the app moves with it.
- **Agreements.** In App Store Connect › Business, the Free Apps agreement is
  enough for a free app; no banking or tax forms are needed.
- **EU trader status** (App Store Connect › Business, required since 2025 to
  be listed in the EU): a company distributing its own product is a trader,
  and the address, phone number and email address it gives are shown on the
  App Store page in the EU. Give the same details the website's legal notice
  (`site/legal.html`) states: VersaMinds BV, Petrus Van Bavegemstraat 17, 9200
  Dendermonde, enterprise number 0804.360.325, and support@versaminds.live.
  Apple also asks for a phone number, which the website does not publish.

## 2. Certificates, App ID and provisioning profile

1. **Certificates**: Xcode › Settings › Accounts › (the team) › Manage
   Certificates › **+** › **Apple Distribution**, then **+** › **Mac Installer
   Distribution**. Both go into the keychain with their private keys.
2. **App ID**: developer.apple.com › Certificates, Identifiers & Profiles ›
   Identifiers › **+** › App IDs › App. Platform macOS, Bundle ID **Explicit**:
   `live.versaminds.Forester`. No capabilities.
3. **Provisioning profile**: Profiles › **+** › Distribution › **Mac App Store
   Connect** › the App ID above › the Apple Distribution certificate › name it
   "Forester App Store" › Download. Keep the `.provisionprofile` file; the build
   script takes its path.

## 3. A directory for App Review

Reviewers must be able to use the app, and Forester needs a directory to
connect to. Forum Systems has run a public, read-only OpenLDAP test server
for years, `ldap.forumsys.com`, and the review notes below send reviewers
there through Try a Sample Directory (in the empty window and the Help menu):
plain LDAP on port 389, read anonymously, about twenty people and groups.
Nothing of ours has to stay up for it; `scripts/check-release.sh` checks
that it answers.

It cannot show editing, TLS or Active Directory. Should App Review ask to see
those, `demo-server/` runs a directory of our own instead: the test
directory's made-up company (about 1,650 people, groups and computers) on
OpenLDAP behind a Let's Encrypt certificate, with an account that may change
entries in one OU.

1. Create a small Linux machine: Hetzner Cloud CX22 (2 vCPU, 4 GB, EU, about
   4 euros a month) with **Debian 13** and your SSH key is plenty. In its
   firewall, allow TCP 22, 80, 389 and 636 in.
2. In Cloudflare, add an **A** record `demo.forester` → the machine's IPv4
   address, **DNS only** (grey cloud): Cloudflare's proxy does not carry LDAP.
3. Copy the repository over and run the setup as root:

   ```bash
   rsync -a --exclude .build --exclude build ~/Documents/LDAPExplorer/ root@demo.forester.versaminds.live:/opt/forester/
   ```

   ```bash
   ssh root@demo.forester.versaminds.live sh /opt/forester/demo-server/setup.sh demo.forester.versaminds.live you@versaminds.live
   ```

   It prints the review account's password at the end. It is kept on the
   machine (`/etc/forester-demo/env`), never in the repository.
4. From the Mac, check it the way App Review will reach it:

   ```bash
   demo-server/check.sh demo.forester.versaminds.live
   ```

5. Try it in Forester itself with the values from the review notes below.

The review account reads everything and may change entries only in
`OU=Playground,DC=corp,DC=example`; the directory is rebuilt every night at
04:00 UTC and on every restart. Signing in without TLS is refused. Keep the
machine running for as long as the review notes name it: every update is
reviewed again. The review notes then name host `demo.forester.versaminds.live`,
LDAPS, the user `CN=App Review,CN=Users,DC=corp,DC=example` and the password
`setup.sh` printed.

## 4. The website

App Store Connect needs a privacy policy URL and a support URL that load.
`site/` has both, and the rest of what an EU publisher's site needs: terms of
use (`terms.html`, the source licence and Apple's standard licence side by side) and a
legal notice (`legal.html`) naming VersaMinds BV, its registered office and
its enterprise number, which every page's footer repeats, as Belgian law asks.
Deploy it to Cloudflare Pages (docs/DISTRIBUTION.md, "The website") and point
`forester.versaminds.live` at it before submitting. The pages use support@ and
privacy@versaminds.live, which must reach someone before submitting.

Every Download button on the site links to `/app-store`, which
`site/_redirects` sends to Forester's page on the Mac App Store: put Forester's
Apple ID in it once the App Store Connect record exists (step 6), then deploy.
The page answers as soon as the app is released. The site's GitHub links (the
source, and issues on the support page) work once the repository is public;
App Review may open the marketing URL, so make it public first or expect that
question.

`scripts/check-release.sh` checks all of this from outside, with the
certificates, the App Store build and the review directory, and lists what is
still to do.

## 5. Build and upload

First run the checks inside the sandbox the App Store build lives in
(TESTING.md § 5, the test directory running), then build:

```bash
scripts/automation-sandboxed.sh
```

```bash
scripts/make-appstore.sh ~/Downloads/Forester_App_Store.provisionprofile
```

It builds the App Store variant for Apple silicon and Intel, signs it with
Apple Distribution and the profile, checks that it is sandboxed and built with
this Mac's SDK, and writes `build/AppStore/Forester-<version>.pkg` signed with
Mac Installer Distribution. Every upload needs a higher build number than any
before, across versions, and at most three numbers: the build number is the
time of the build in UTC (`20261112.0930`), so a new build always has one.

Upload it with **Transporter** (free in the Mac App Store): sign in with the
developer account, drag the .pkg in, **Deliver**. Processing takes 10 to 30
minutes; App Store Connect emails when the build is ready, or what is wrong
with it.

`scripts/make-appstore.sh --sandbox-test` signs the same build with an Apple
Development certificate and no profile, to try the sandbox on this Mac.

## 6. The App Store Connect record

Apps › **+** › New App: platform **macOS**, name **Forester: LDAP Browser**,
primary language **English (U.K.)**, bundle ID `live.versaminds.Forester`, SKU
`forester-mac`. If the name is taken, try "Forester for LDAP". The new app's
**Apple ID** (App Information) goes in `site/_redirects` (step 4).

| Field | Value |
|---|---|
| Name (30) | Forester: LDAP Browser |
| Subtitle (30) | Active Directory and LDAP |
| Primary category | Developer Tools |
| Secondary category | Utilities |
| Price | Free (Pricing and Availability › all countries) |
| Copyright | 2026 VersaMinds BV |
| Keywords (100) | ldap,active directory,openldap,ldif,ldaps,kerberos,directory,admin,users,groups,ad lds |
| Marketing URL | https://forester.versaminds.live |
| Support URL | https://forester.versaminds.live/support.html |
| Privacy policy URL | https://forester.versaminds.live/privacy.html |
| App Privacy | Data Not Collected |
| Age rating | answer None or No to every question: 4+ |
| Content rights | does not contain third-party content |
| Export compliance | answered by the build (`ITSAppUsesNonExemptEncryption` = NO: only TLS and Kerberos through macOS) |
| License agreement | Apple's standard (the terms page says the PolyForm Shield License applies to the source as well) |
| Version release | Manually release this version, so the website can link it the same day |

**Screenshots** (Mac, 2880 × 1800): nine, taken from the screen so they show
the app as macOS 26 and later draw it. With the test directory running, and
the Mac left alone for the minute it takes (Forester must stay in front):

```bash
scripts/app-store-screenshots.sh
```

It writes them to `build/AppStore/Screenshots/` in upload order and refreshes
the website's pictures. Check each window looks active (coloured close
buttons) before uploading. The terminal needs the Screen Recording permission.

**Promotional text** (170)

> Browse, search and look after Active Directory and LDAP in a native Mac app. Every connection is read-only until you allow changes, and changes can be undone.

**Description**

> Forester is a native Mac app for browsing, searching and administering Active Directory and other LDAP directories.
>
> Every connection is read-only until you allow changes, so you can open a production directory without worrying about a stray click. The toolbar always says in words whether you are in Read-only or Editing, and most changes can be undone.
>
> Browse: a fast outline of your directory that loads one level at a time, with icons for each kind of object and disabled accounts dimmed.
>
> Inspect: SIDs, GUIDs, timestamps and account options in plain words, with badges for accounts that need attention: passwords that never expire, service principal names, unconstrained delegation, privileged accounts.
>
> Permissions: who may do what with an entry, read from its security descriptor and said in words, such as Reset Password or Create user objects, and what you yourself may change.
>
> Edit: the right editor for every value, chosen from your server's own schema. Enable, disable and unlock accounts, reset passwords, create users and groups from templates, rename, move and delete with care.
>
> Active Directory: domain information, operations masters, domain controllers and sites, password policies including fine-grained ones, account status on every domain controller, replication metadata and nested group membership. Search the whole forest through a global catalog, and open its other domains.
>
> Search: LDAP filters checked as you type, with names completed from the schema, a filter builder and ready-made searches such as stale computers and Kerberoastable accounts. Export results to CSV or LDIF.
>
> Import and export LDIF, with a summary before anything is sent and a log of every record.
>
> Sign in with the Kerberos ticket your Mac already has, over LDAPS or StartTLS, and no password is typed at all. Or use a name and password, kept in your keychain and tied to the server it was saved for.
>
> Private by design: no account, no analytics, no crash reports. Forester talks only to the directory servers you add.
>
> Free, with every line of its source code public. Made by VersaMinds.

**App Review Information**: your name, phone number and email; **Sign-in
required**: off (Forester has no account; the test server's sign-in is in the notes).

**Notes**:

> Forester is a client for LDAP directory servers, such as Microsoft Active Directory, that organisations run on their own networks. No account or sign-in is needed to review it:
>
> 1. Open Forester. The empty window offers Try a Sample Directory (it is also in the Help menu).
> 2. Click it. Forester connects to a public, read-only test directory that Forum Systems runs for this purpose (ldap.forumsys.com), without signing in, and shows its people (such as einstein) and groups (such as scientists).
> 3. Choose any entry for its overview, attributes and LDIF. Click Search in the toolbar and search with a filter such as (objectClass=person).
>
> Every connection in Forester is read-only until the person allows changes with the Read-only button in the toolbar; this test directory is read-only itself, so a change sent to it is refused with the server's own message. The test server offers no TLS, so the status bar says the connection is unencrypted. Active Directory features and Kerberos sign-in need an organisation's own domain and cannot be tried here.
>
> Forester collects no data and has no account. Its source code is public under the PolyForm Shield License; VersaMinds holds the copyright to all of it.
>
> About NSAllowsArbitraryLoads: Forester connects over TLS to organisations' own directory servers, which use certificates from the organisation's own certificate authority and, on older domain controllers, older TLS versions. Forester checks every certificate itself and asks the person before trusting one the Mac does not. The App Store version makes no web requests of its own.

Then **Add for Review** › **Submit to App Review**.

## 7. After approval

- Release it (Version release was set to manual): the website's Download
  buttons lead to it from then on. Apple's "Download on the Mac App Store"
  badge can replace their text
  (<https://developer.apple.com/app-store/marketing/guidelines/>).
- A rejection names the guideline it cites; answer it in App Store Connect,
  or fix it and upload a new build with a higher build number.
- **TestFlight** (App Store Connect › TestFlight) can give a build to testers
  before release, for instance for the field test in docs/FIELD-TEST.md.

## What differs in the App Store build

`scripts/build-app.sh` builds it with `FORESTER_APP_STORE=1`, which compiles
with `APP_STORE` (`ForesterInfo.fromAppStore`):

| Left out | Why |
|---|---|
| Sparkle, the download's updater, and Check for Updates | App Review allows no update mechanism but the App Store's; `Package.swift` leaves Sparkle out of this build |
| Keep connections in iCloud Drive | the sandbox keeps the app out of iCloud Drive's folder; doing it properly takes an iCloud container |
| Write a log file next to the LDIF | the sandbox grants the LDIF, not its folder; Save Log… asks where instead |
| Carrying over data from the name "LDAP Explorer" | outside the sandbox, and no App Store user ever had that name |

The sandbox allows outgoing connections and the files a person picks in an
open or save panel (`Resources/AppStore.entitlements`). Connections and
preferences live in the app's container, and keychain items belong to the App
Store signature, so someone moving from the download exports their connections
there (sidebar › Export) and imports them here, and types each password once.

The app also carries a privacy manifest (`Resources/PrivacyInfo.xcprivacy`):
no data collected, no tracking, user defaults for its own settings (CA92.1),
and its own connections file's modification date (C617.1).

## Licensing

Forester's source is published under the PolyForm Shield License 1.0.0
(LICENSE), which binds those who receive the code, not its copyright holder.
VersaMinds publishes the app in the App Store under Apple's standard licence,
which it may do as long as it holds the rights to all of it: CONTRIBUTING.md
("Licensing of contributions") has every contributor grant VersaMinds the
right to distribute their work under any terms. The names Forester and
VersaMinds and the icon are trademarks of VersaMinds BV (TRADEMARKS.md). This
is a reading of the situation, not legal advice.
