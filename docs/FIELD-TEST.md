<!-- SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0 -->
<!-- Copyright © 2026 VersaMinds -->

# A first week in the field

Forester is tested against OpenLDAP and against a Samba Active Directory
domain controller (TESTING.md). What those cannot show is a real company's
directory: its size, its certificates, its policies, its forest. This is a
one-week, read-only trial with one friendly team, and what to bring back
from it.

## What it has not met yet

Knowing these is the point of the week:

- **A Windows Server domain controller.** Samba behaves like AD, not exactly
  as AD. In particular "LDAP signing" and "LDAP channel binding" set to
  required, which Kerberos sign-in is built for but has only been tried
  against Samba.
- **A forest with more than one domain.** Searching the whole forest and
  opening another domain were tested against a single-domain forest only.
- **A large directory.** The test directory holds about 1,650 entries, and
  the performance check fills an OU with 50,000 made-up users (TESTING.md,
  "A big directory"); a real one has its own shape, such as deep trees, huge
  groups and slow links.
- **macOS 14, and an Intel Mac.** It was built and tested on macOS 27 on
  Apple silicon; the Intel half has only been started under Rosetta.
- **A signed and notarized build.** The trial needs one (docs/DISTRIBUTION.md),
  so it is the first time that build is run anywhere.

## Setting up

1. Install the signed disk image on the tester's own Mac.
2. Add a connection to a domain controller by its full DNS name, with
   StartTLS or LDAPS. It is read-only, and stays read-only for the week.
3. Sign in with **Kerberos ticket** if the Mac has one (Ticket Viewer, or the
   company's single sign-on), otherwise with a name and password.
4. If the certificate is not trusted, look at it with **Show Certificate…**
   before trusting it, and note which it was: the company's own CA missing
   from the Mac is worth knowing about.

## During the week

Use it for what the tester would otherwise use ADUC or PowerShell for, and
try at least these once:

- Browse the largest OU, and a group with thousands of members.
- **Find by name** for a person, an account name, and part of a group name.
- The search presets (stale computers, disabled users, Kerberoastable
  accounts), and an export to CSV.
- **Search › Whole forest**, if the forest has more than one domain, and
  **Domain Information › Domains in this forest › Open**.
- The **Permissions** tab on a user, a group and an OU.
- **Domain Information**, and **Account Status on Each DC** for one account.
- Leave Forester open over lunch, then carry on: the connection should come
  back by itself. The same after a VPN drop.

Not this week: turning editing on against production, or importing LDIF.

## When something is wrong

**Help › Copy Diagnostics** copies the app and macOS versions, the kind of
server and how the connection is made, and the last errors. It leaves out
host names, user names and passwords, but an error can name an entry, so the
tester reads it before sending it. Send it with:

- what they did, step by step;
- what they expected, and what happened instead;
- how long it took, if slowness is the problem;
- a screenshot, with names covered.

## What to ask at the end

- What did you still open ADUC or PowerShell for?
- Was anything slow? Which screen, and roughly how long?
- Did Kerberos sign-in work the first time? If not, what did Forester say?
- Was a certificate prompt confusing, or did a trusted certificate get asked
  about anyway?
- Did anything say more, or less, than you wanted?
