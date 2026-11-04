# Contributing to Forester

Thank you for helping. Bug reports, ideas and pull requests are all welcome.

## Reporting a problem

Open an issue with what you did, what you expected and what happened, and the
Forester and macOS versions. Say which directory server it was (Active Directory,
OpenLDAP, 389 Directory Server…). Please leave real names, addresses and other
data from your directory out of public issues. Security problems go through
[SECURITY.md](SECURITY.md) instead.

## Changing the code

[README.md](README.md) shows how to build and run Forester, and
[TESTING.md](TESTING.md) how to test it, including a local test directory you
can change freely.

- Keep the app native: SwiftUI and AppKit, and no third-party dependencies.
  LDAPKit, the LDAP client, uses only Apple's Foundation, Security and CryptoKit.
- New files start with the licence header:
  `// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0` and `// Copyright © 2026 VersaMinds`.
- A change that sends anything to a directory must respect read-only
  connections, and should be covered by a test against the test directory.
- Run `swift test` and, with the test directory running,
  `FORESTER_TEST_SERVER=1 swift test` before opening a pull request.
- Words on screen are plain and specific (say what will happen), and follow the
  macOS conventions, such as title case on buttons and menu items.

## Licensing of contributions

Forester's source is published under the PolyForm Shield License 1.0.0
([LICENSE](LICENSE)), and VersaMinds distributes the app under other terms too,
for example through the Mac App Store. So that this stays possible, by
submitting a contribution you agree that:

1. you grant VersaMinds a perpetual, worldwide, non-exclusive, royalty-free and
   irrevocable licence to use, change, sublicense and distribute your
   contribution under any licence terms, the PolyForm Shield License included;
   and
2. you wrote the contribution yourself, or otherwise have the right to submit it
   under these terms.

Show that you agree by adding a `Signed-off-by: Your Name <you@example.com>` line
to each commit (`git commit -s` does this).
