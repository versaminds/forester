# Testing Forester

Five ways to test, from quickest to most thorough. Run all commands from the
project folder.

| | What | Needs | Takes |
|---|---|---|---|
| 1 | Unit tests | Swift | seconds |
| 2 | A local test directory | Python 3.11+ | seconds |
| 3 | Integration tests against it | step 2 | seconds |
| 4 | The app against it, by hand | step 2 | 30 minutes |
| 5 | The app driving itself: every screen and sheet, then real clicks and typing | step 2 | 5 minutes |

Then, when you have one, [an Active Directory domain controller](#6-against-an-active-directory-domain-controller).

`scripts/test-all.sh` runs steps 1, 3 and 5 in a row, with the release builds
and the App Store variant in its sandbox, as CI does on every push
(`.github/workflows/ci.yml`); `--performance` adds the big-directory part.
Each Monday CI runs it all, with a newer Sparkle when there is one, and once
a month, on a Tuesday, it makes a release (docs/DISTRIBUTION.md, step 5).

## What you need

- macOS 14 or later.
- Xcode, or the Command Line Tools with Swift 6 or later (`swift --version`).
- For the test directory: **Python 3.11 or later**. The `python3` that comes with
  macOS is 3.9, which is too old for the TLS proxy. Install a newer one with:

  ```bash
  brew install python
  ```

  The start script finds it by itself. To use a specific one, set
  `LDAP_TEST_PYTHON=/path/to/python3`.
- Nothing else is downloaded. The test server is the `slapd` that macOS ships in
  `/usr/libexec`, and the certificates come from the system `openssl`.
- For the Active Directory domain controller in step 6, and the SASL server
  at the end of step 3, only: Podman (`brew install podman`, then
  `podman machine init` and `podman machine start`). They download Alpine
  Linux with Samba, or with OpenLDAP, when they build their images the first
  time.

## 1. Unit tests

```bash
swift test
```

This runs 117 unit tests. The 27 tests that need a server are reported as
*skipped* (step 3), and so are the 10 that need the SASL server (the end of
step 3), the 8 Kerberos tests and the 5 permission tests, which need the domain
controller of step 6, the 4 that time the LDAP client against a big
directory (step 5, "A big directory"), and the one that needs servers of an
old TLS version (the end of step 3). The unit tests cover:

- **BER encoding**: integers, lengths, partial reads.
- **Filters**: every example from RFC 4515, plus malformed filters and the error
  each one reports.
- **AD values**: SIDs, GUIDs, FILETIME timestamps, flags, AD's bind error codes.
- **DN parsing**: escaped commas, hex escapes, comparison.
- **LDIF**: output (parents before children, so an export imports again), and
  reading it back: content and change records, base64, folded lines, and the
  sample file in `TestDirectory/sample-import.ldif`.
- **Schema**: parsing RFC 4512 definitions, including names that look like
  keywords, and which attributes a set of classes allows.
- **Security descriptors**: reading one, and adding and removing the "cannot
  change password" deny entries in the order AD expects.
- **Changing permissions**: where a new rule goes (denials, then allowances,
  then inherited rules), and what is refused: changing an inherited rule, a
  rule that is gone, adding to, removing from or changing a list out of
  order, emptying the list, a rule that applies to nothing or carries the
  wrong flags, a rule of a kind Forester does not read (named as one, with
  its type), an owner changed by someone else since. Only a descriptor that
  encodes back to its own bytes is written. The rule editor's drafts, which
  give back every rule's flags as they were (object inherit alone, 0x01,
  0x05 and 0x09, never gains container inherit), a typed SID kept as it
  reads back, a RID named only in this domain's SIDs, the read-back after a
  write judged rather than thrown, and the change in words. And 3,000 random
  access lists, each given a random change: the inherited rules never move,
  the list stays in order, and undoing the change gives back the very bytes
  it started from (`FORESTER_FUZZ` makes it more).
- **AD metadata**: replication metadata XML and LDAP URLs of dynamic groups.
- The **attribute formatter**.
- **Regressions** found by reviewing the code: DNs whose value ends in an
  escaped space, escaped commas in DN comparisons, older filter escapes (`\*`,
  `\(`) and DNs pasted into a filter, text starting with "BM" taken for an
  image, a malformed security descriptor, and times with a zone but no seconds.
- **Security**: what a file, a server or someone else's directory data must not
  be able to do. An LDIF file reads no file from the Mac without consent, and
  with it only regular files beside the LDIF, up to 10 MB, never through `..` or
  a symbolic link; an LDIF record with controls is refused rather than run
  without them; an attribute name with a line break cannot add a record to an
  export; a combining mark cannot hide a comma from DN escaping; a filter nested
  past 64 levels is refused rather than crashing the app; and an access list
  past 64 KB is refused rather than written wrongly.
- **LDIF hardening**: an exported attribute named `changetype`, `control` or
  `dn` stays a comment, so the file imports again as the entry; the review
  before an import lists each record that is not a plain add or lands
  outside the expected container, with its DN and changes, and warns about
  administrators' groups' members, permissions, account flags, service
  principal names, delegation and passwords, without showing a password;
  the import log keeps a line break in a DN on its record's line, and a new
  log is numbered beside an earlier one.
- **Display hardening**: a photo is decoded only as a JPEG, PNG or GIF by
  its first bytes and to the decoder alike, at the size shown; a BMP, TIFF
  or HEIC, a TIFF behind a JPEG's first bytes, a value past 10 MB and an
  8 KB PNG of 64 million pixels are not; bidirectional controls and
  invisible characters in a name are written out (⟨U+202E⟩) and the name can
  still be typed to confirm; a value of megabytes is cut short in a cell.
- **Sign-in**: SCRAM against the examples in RFC 5802 and RFC 7677, and what
  a server's challenge may not ask for (step 3 has the details); the framing
  of Kerberos-encrypted messages, which refuses a frame outside the agreed
  sizes before Kerberos sees it. And what a sign-in must not do: name a
  character of the password in an error (only the field), mix right-to-left
  and left-to-right text in SASLprep, send a nonce without the system's
  random numbers, compare the server's proof in time that depends on it,
  use SCRAM with "Accept any certificate", show a client certificate nobody
  chose, use TLS older than 1.2, take a Kerberos server named other than
  `ldap/` and the host, or seal without numbered messages.
- **Domains of a forest**: which connection answers for a DN when two
  domains are browsed in one window. This domain's entries, its configuration
  and its DNS zones stay on its own connection; a browsed domain's go to that
  domain's; a domain listed but not open, one that failed, and a child domain
  the forest does not list are refused, with the reason; a connection refuses
  before anything is sent, for reads, searches, changes, additions, deletions
  and password changes; and moving an entry between domains is refused.
- **Access rules**: an access control entry in words (full control, read,
  extended rights, property sets, attributes and classes named, where it
  applies, inherited or not, denials), in the order AD applies them.
- **Fuzzing**: the BER decoder, the response decoder, filters, DNs, LDIF, schema
  definitions and security descriptors are fed random and corrupted input, and
  must answer or throw, never crash; escaped DNs and filters and exported LDIF
  must come back exactly as they went in. It runs 3,000 inputs per parser; set
  `FORESTER_FUZZ=150000` (or any number) for a longer run.

To run one suite:

```bash
swift test --filter FilterTests
```

### Saved connections

The unit tests are LDAPKit's; the app's saved connections are checked by a
small program built from the app's own `ConnectionProfile.swift` and
`CannotChangePassword.swift` in a temporary folder:

```bash
scripts/check-connections.sh
```

Forester 1.1 reads `connections.json` whole, and on a Mac sharing it through
iCloud Drive a connection it cannot read would make it save its own list over
everyone's. Connections that sign in with SCRAM or a certificate therefore
live in `connections-1.2.json` beside it. Eleven checks use 1.1.1's own
decoder and encoder (taken from the `v1.1.1` tag): 1.1.1 reads the
connections it knows; after it changes one, adds one and reorders them, every
connection is still there in the order last saved here, its change kept and
its new one last; a connection written by a newer Forester that this one
cannot read survives a save; a connection changed back to a simple bind
moves to where 1.1.1 reads it.

Twelve more check what the file may not decide. Pinned certificates,
accepting any certificate, allowing changes and the client certificate are
this Mac's (`connection-settings.json`, beside the local connections file,
never in iCloud Drive): upgrading keeps them from the file once; a file
written later changes none of them, and a connection that arrives in it
starts read-only, trusting the system's certificates only. A client
certificate is shown only to the server, port, security and certificate
checking it was chosen for in the editor. An import never replaces a
connection here. The global catalog and other servers get the system's
certificates, and on the same host this connection's pins, never "accept
any". Another domain reuses a saved connection only with the same kind of
sign-in, user and certificate. The password prompt warns of clear text and of
any certificate accepted. And "User cannot change password" changes only its
own rules: undone, they come back where they were, with a rule added
meanwhile kept, and with nothing added the very bytes return.

With `FORESTER_TEST_AD=1` and the domain controller of step 6 running, three
more do the last against it: turned on, AD refuses the user's own password
change; undone after another administrator added a rule, the rule stays and
the user may change the password again.

## 2. Start the test directory

```bash
TestDirectory/start.sh
```

```
slapd is up: ldap://127.0.0.1:10389  ldaps://127.0.0.1:10636
CA certificate: …/TestDirectory/.run/ca.crt
```

This starts a throwaway OpenLDAP server holding an **Active Directory-shaped**
domain, `corp.example`, with 1,667 entries:

- users, groups, computers and OUs with binary `objectSid` and `objectGUID`
- FILETIME timestamps, `userAccountControl` and `groupType`
- `memberOf`, `directReports` and nested groups
- Group Policy links, and photos
- security descriptors on users, one of them denying "change password"
- per-attribute replication metadata, and when each group member was added
- a configuration partition: sites, two domain controllers, FSMO role holders,
  the Recycle Bin and the tombstone lifetime
- two fine-grained password policies, and a forest trust
- dynamic groups (`groupOfURLs`)
- a second, plain LDAP naming context, `example.org` (`inetOrgPerson`,
  `posixGroup` and `groupOfNames`)
- the server's own `cn=Monitor`
- a child domain, `child.corp.example` (`DC=child,DC=corp,DC=example`), served
  by a second `slapd` the way another domain's controller would be, with
  three people, a team and its own Domain Users; the forest's configuration
  lists both domains (crossRefs with `systemFlags` 3), and
  *UG-Forest-Readers* in `CN=Users` of corp.example holds a member from each

Dates are relative to the day you start it, so "expires soon" and "not seen for
90 days" are always true for the same entries.

| | |
|---|---|
| Plain LDAP and StartTLS | `localhost`, port **10389** |
| LDAPS | `localhost`, port **10636** |
| Bind DN | `CN=admin,DC=corp,DC=example` |
| Password | `secret` |
| Or | anonymous (everything is readable, nothing writable) |
| The child domain | `localhost`, port **10489** (StartTLS) and **10637** (LDAPS), the same administrator |

Bound as admin you may change anything. Every start rebuilds the directory from
scratch, so stopping and starting it undoes all your changes.

The server caps a page at 200 entries and an unpaged search at 500, the way AD
caps both at 1,000. That makes the app's paging visible: the *Bulk Import* OU
holds 1,500 users.

TLS uses a private certificate authority that your Mac does not trust. So the
first connection over StartTLS or LDAPS shows the app's certificate prompt.
That is intended: it is one of the things to test.

To stop the server:

```bash
TestDirectory/stop.sh
```

Starting it again also makes a new CA, so the app will ask you to trust the
certificate again. Logs are in `TestDirectory/.run/` (`slapd.log`,
`proxy.log`).

To use other ports, set them when starting. The integration tests read the same
variables:

```bash
LDAP_TEST_PORT=11389 LDAPS_TEST_PORT=11636 TestDirectory/start.sh
```

Ports 10388 and 10488 are also used, internally (see the note at the end).
The child domain's ports are set with `LDAP_TEST_CHILD_PORT` and
`LDAPS_TEST_CHILD_PORT`.

## 3. Integration tests

With the test directory running:

```bash
FORESTER_TEST_SERVER=1 swift test
```

144 tests run, in about 7 seconds (the SASL tests wait for their own server,
the Kerberos and permission tests for step 6, and the timing tests for a big
directory). The 27 against the server are in three suites.

**IntegrationTests** (14) checks reading:

- **Root DSE and binds**: reading the root DSE, a simple bind, and "Who am I?".
- **Bind errors**: a wrong password is reported as *invalid credentials*, and an
  empty password is refused before it reaches the server.
- **Paging**:
  - an unpaged search stops at the server's limit of 500
  - a paged search returns all 1,500 entries
  - a search stopped at a limit leaves the connection usable
  - a request whose answer passes its byte limit (64 KB in the test, 512 MB
    in the app) fails as it arrives, and pages under it come through
- **Pipelining**: four searches sent at once each get their own answer.
- **Binary values**: searching by binary SID.
- **TLS**: for both StartTLS and LDAPS, an untrusted certificate is reported with
  its fingerprint, pinning that fingerprint connects, and "accept any
  certificate" connects.
- **Error paths**, each with the exact message a person sees:
  - an unknown host
  - a refused connection
  - plain LDAP sent to the LDAPS port
  - LDAPS sent to the plain port (this one waits out a 5-second timeout)
  - cancelling a search midway

**WriteTests** (9) checks changing, and the newer read paths:

- add, modify, rename, move and delete, each read back, and deleting a subtree
- password and binary values written and read back intact
- a security descriptor survives a round trip through the server, with "cannot
  change password" set and cleared; and a rule added and removed, and the
  owner changed and back, leave its bytes as they were
- the schema is read and answers "which attributes may this entry have?"
- a dynamic group's URL runs as a search
- `cn=Monitor` is readable
- `sample-import.ldif` applies as described in step 4: seven records succeed
  and the seventh fails
- an anonymous write is refused with a message that says to sign in, not to
  encrypt

The write tests work in their own OU, and put back anything else they change.

**ForestIntegrationTests** (4) checks two domains of one forest over two
connections, the parent's routed as the app routes it:

- the forest's configuration lists both domains, as the app reads them
- asked of the parent's connection, the child domain's entries are read,
  searched (paged), changed, added, renamed and deleted on the child's server,
  each read back from that server, while not one byte about them crosses the
  parent's connection
- a corp.example group's members from both domains are read together, each
  from its own server; and from the child's side, the parent's entries go to
  the parent
- with the child domain not open, its entries are refused and the parent's
  server never hears of them, while the parent's own entries are read as before

To run one suite:

```bash
FORESTER_TEST_SERVER=1 swift test --filter WriteTests
```

### SCRAM and certificate sign-in

The test directory's TLS is a proxy in front of Apple's `slapd`, which offers
neither SCRAM nor sign-in with a client certificate. A second server does:
OpenLDAP with its own TLS and Cyrus SASL, in a Podman container (about 30 MB).

```bash
TestDirectory/start-sasl.sh
```

```bash
FORESTER_TEST_SASL=1 swift test --filter SASLServerTests
```

It answers on `ldap://localhost:12389` (StartTLS) and `ldaps://localhost:12636`,
asks every TLS client for a certificate, and binds SCRAM to the TLS
connection (SCRAM-SHA-256-PLUS). The script makes a test CA, the server's
certificate and two client certificates as `.p12` files in
`TestDirectory/.run/sasl/` (password `forester`); the tests read them into
memory, so nothing is added to a keychain. **SASLServerTests** (10) checks:

- SCRAM-SHA-256 signs in over StartTLS and LDAPS, bound to the TLS
  connection, and over plain LDAP; a password typed with accents in another
  Unicode form signs in too; a wrong password is *invalid credentials*
- the server refuses a sign-in bound to another certificate (someone in
  between), and one that says the server cannot bind when it can (the -PLUS
  mechanism hidden), though the password is right
- the client certificate signs in over StartTLS and LDAPS as the entry the
  server maps it to; a certificate from another issuer ends the handshake
- without TLS, or without a certificate chosen, nothing is sent; a server
  that never asks for a certificate (step 2's test directory, with
  `FORESTER_TEST_SERVER=1`) and one that asks but cannot sign in with it (the
  domain controller of step 6, with `FORESTER_TEST_AD=1`) are each named as
  such
- with no certificate chosen, this server, which asks for one, gets none:
  the handshake goes on, and it has nothing to sign in as

**SCRAMTests**, among the unit tests, checks the arithmetic against the
examples in RFC 5802 and RFC 7677, the channel-binding headers, escaped user
names, SASLprep, and the challenges refused: fewer than 4,096 rounds (a
recorded sign-in is then quick to guess against), a nonce that is not this
sign-in's, a mandatory extension, an empty salt, a server error.

To try it in the app, import `TestDirectory/.run/sasl/client.p12` into your
login keychain, connect to `localhost` port 12636 (LDAPS), Sign in
**Certificate**, and choose *Forester Client*; or Sign in **Name and password
(SCRAM)** as `scram.user` with `Scram-Test-Password-2026!`. Trust the test
CA's certificate when asked. Remove the certificate from the keychain
afterwards. `TestDirectory/stop-sasl.sh` removes the server and its files.

### TLS older than 1.2

Forester connects with TLS 1.2 or newer only. To see an older server
refused, start two throwaway TLS servers with Homebrew's Python, one that
speaks only TLS 1.1 and one only TLS 1.2, each answering the first search
with an empty success (with a self-signed certificate: the test accepts any):

```bash
python3 TestDirectory/old_tls_server.py 14611 1.1 & python3 TestDirectory/old_tls_server.py 14612 1.2 &
```

```bash
FORESTER_TEST_TLS11_PORT=14611 FORESTER_TEST_TLS12_PORT=14612 swift test --filter tlsOlderThan12IsRefused
```

The 1.1 server gets no connection, the 1.2 one does. Recent macOS refuses
TLS 1.1 to such a stream by itself; the floor is set for the older versions
Forester runs on, and the unit tests check it is. Stop the two servers with
`kill %1 %2` in the same shell.

## 4. The app against the test directory

Build and open the app:

```bash
scripts/build-app.sh && open "build/Forester.app"
```

Or, for a quicker edit-and-run loop, run a debug build:

```bash
swift run Forester
```

### Connect

1. Click **+** at the bottom of the sidebar (or press ⌘N) and fill in:

   | Field | Value |
   |---|---|
   | Name | Corp test |
   | Host | `localhost` |
   | Security | StartTLS |
   | Port | `10389` |
   | Sign in | Name and password |
   | User | `CN=admin,DC=corp,DC=example` |
   | Password | `secret` |

   Every field starts where you type, and the bottom of the form explains each
   option. Leave **Read-only** on for now.
2. Click **Test Connection**. You should see that the certificate is not trusted,
   with its SHA-256 fingerprint. **Show Certificate…** opens the system
   certificate viewer. Click **Trust This Certificate**. The test runs again and
   reports *Connected to OpenLDAP over TLS, bound as cn=admin,…* just above the
   buttons.
3. Click **Add**, then **Connect**. The tree opens on `corp.example`; the
   toolbar and the status bar say **Read-only**. The password you typed is used
   even with **Remember the password in the keychain** off; it is then kept
   only until you quit.

If "Remember the password" is on, macOS may ask for your Mac's password before
Forester can use the keychain item, twice: once to let this copy of the app read
it, and once for the item's partition list. Choose **Always Allow** both times.
An app signed ad hoc (no certificate, see the README) asks again after each
rebuild; while the app runs, it reads each password from the keychain only once.

### Things to look at

Each line is a place in the tree, or a search, and what you should see. None of
these change anything.

**Accounts and badges**

| Where | Expect |
|---|---|
| Corp › Users › Engineering › **Pieter Van Damme** | A photo. Overview with *Direct reports* as links (click one to go there). Password last set and last sign-in shown as dates ("3 days ago"). |
| Same user, **Membership** tab | *Domain Users* marked **Primary group** (resolved from `primaryGroupID` and the domain SID), then the direct groups. **Show All Nested Groups** adds *DL-VPN-Users* and *GG-Workstation-Admins*. |
| Same user, **Attributes** tab | `objectSid` as `S-1-5-21-…`, `objectGUID` as a GUID, timestamps as dates. Untick **Decode values** to see the raw form. Double-click a value to view it in full. |
| Same user, **Replication** tab | When `cn`, `pwdLastSet`, `userAccountControl` and `title` last changed, on which DC, and how many times. |
| Corp › Users › Sales › **Thomas Wouters** | **Locked out** badge. |
| Corp › Users › Engineering › **Ines Goossens** | **Expires soon** badge, account expires in about 3 weeks. |
| Corp › Users › Finance › **Bram Maes** | **Smart card required**. |
| Corp › Service Accounts › **svc_sql** | **Password never expires** and **Has SPN**. |
| Corp › Service Accounts › **svc_backup** | In the *Account* panel, **User cannot change password** is ticked (read from its security descriptor). |
| Corp › Servers › **LEGACY01** | **Unconstrained delegation** in red. Domain controllers have the same flag and are not warned about. |
| Users › **Guest**, Corp › **Disabled Users** | Greyed-out icons, **Disabled** badge. |

**Groups**

| Where | Expect |
|---|---|
| Corp › Groups › **DL-VPN-Users** | Domain local security group. 3 direct members, all groups. **Show All Nested Members** lists 29. The *Replication* tab lists when each member was added. |
| Corp › Groups › **UG-All-Staff** | More than 1,500 direct members. |
| Corp › Groups › **GG-Empty-Legacy** | **No members** badge. |
| Corp › Groups › **DYN-Engineering** | A **dynamic group**: its rule (`(objectClass=user)` one level under Engineering) and the 17 people it matches today. |
| **example.org** › groups › **everyone** | A dynamic group in the plain LDAP part: the four people. |

**Structure and paging**

| Where | Expect |
|---|---|
| Corp › **Workstations** | *Linked policies* shows **Workstation Baseline** by name; the link opens the GPO. |
| Corp › **Bulk Import** | 1,500 children. They arrive in pages of 200, because the server refuses larger pages. |
| Corp › Workstations › **WKS-0001** | Expandable: a computer can hold child objects (a BitLocker-style container here). |
| Right-click any node › **Show Containers Only** | The tree hides users, groups and computers, leaving the OU structure. |

**Tools**

| Where | Expect |
|---|---|
| **Tools › Domain Information** (⇧⌘I) | NetBIOS name *CORP*, the domain SID, DC01 and DC02 in two sites, the five FSMO roles (three on DC01, two on DC02), Recycle Bin on, tombstone lifetime 180 days, the default password policy, the trust with *partner.example*, and the two password policies *PSO-Admins* and *PSO-ServiceAccounts* with who they apply to. |
| Thomas Wouters › **Actions › Account Status on Each DC…** | One row per DC. Both say the DC cannot be reached, because `dc01.corp.example` does not exist. Against real AD this shows bad-password counts and last sign-in per DC. |
| **Tools › Server Monitor** (⌃⌘M) | Connections, operations and threads from `cn=Monitor`. Turn on **Refresh every 5 seconds** in its toolbar to watch them move. |
| **Tools › Schema** (⌥⌘S) | Every class and attribute. Select *user*: what it inherits from, then its required and optional attributes, its own and inherited. Click a name to go to it. |
| **Root DSE** (bottom of the tree), or the ⓘ toolbar button | Server type, naming contexts, and supported controls listed by name. |

**Other parts of the app**

| Where | Expect |
|---|---|
| **example.org** › people › **alovelace** | Ada Lovelace, a plain `inetOrgPerson`. The tree shows the entry's RDN, here a `uid`. Membership is found by searching, since this part has no `memberOf`: *scientists* (groupOfNames), *staff* (posixGroup, by `memberUid`) and *everyone* (dynamic). |

**Search** (⌘2)

| Try | Expect |
|---|---|
| **Presets** › Locked-out users | Thomas Wouters. |
| **Presets** › Users with a service principal name | svc_sql. |
| **Presets** › Computers › Not seen for 90 days | WKS-0007, WKS-0019 and LEGACY01 among them. |
| **Presets** › Empty groups | GG-Empty-Legacy. |
| Type `bulk01` in the toolbar search field, press Return | 100 matches. |
| Edit the filter so a `)` is missing | A red message naming the character position; **Search** is disabled. |
| Type `(user` in the filter | A completion list of attribute names from the schema appears as you type; after `(objectClass=` it offers class names. |
| Switch the filter to **Builder** | Rows of attribute, condition and value under **Match all of** or **Match any of**. The filter it makes is shown underneath. |
| Base `OU=Bulk Import,OU=Corp,DC=corp,DC=example`, scope One level, filter `(objectClass=user)` | 1,500 entries, gathered across pages. |
| Results › **Export** › CSV… | Opens in Numbers or Excel with SIDs and dates as text. |
| Results › **Export** › LDIF, All Attributes… | Every attribute of every result. |

**Navigation**

- ⌘[ and ⌘] go back and forward.
- ⌘L shows the current entry in the tree.
- ⇧⌘G goes to a DN you type.
- ⇧⌘C copies the DN.
- Right-click a tree node for **Search Beneath…**, **Refresh**, export and the
  copy actions.
- Option-click a disclosure triangle to expand everything below it.

### Making changes

Everything here really changes the test directory. Run `TestDirectory/stop.sh`
and `TestDirectory/start.sh` to put it all back.

First, check that read-only holds: on Pieter Van Damme's **Attributes** tab
there is no way to edit a value, and the context menu says to turn editing on.

Then press **⌥⌘E** (or click **Read-only** in the toolbar). It now reads
**Editing**, in orange, and so does the status bar.

**Attributes and entries**

| Do | Expect |
|---|---|
| Pieter Van Damme › Attributes › double-click `description`, change it, **Save** | The new value, read back from the server. |
| **+** above the attribute table | Only attributes his classes allow, with the schema's description of each. Add `mobile`. |
| `userAccountControl` › Edit | Checkboxes, not a number. |
| A `manager` value › Edit | A DN field with a button that opens the directory: a tree to browse, opened where the current value is, and a search. |
| Right-click Corp › Users › Engineering › **New Entry Here…** (⌃⌘N) | Templates: user, group, computer and contact (Active Directory), organizational unit, and plain LDAP ones. The attributes the schema requires are asked for; an AD user also gets a password, over StartTLS. |
| Select a user › **Duplicate…** (⌘D) | A new user with a choice of what to copy (department, title, manager and the like; never names, SIDs or passwords) and **Add to the same groups**. |
| **Rename…** (⇧⌘R) | A new name; the tree and the inspector follow it. |
| **Move…** (⇧⌘M), or drag a user onto another OU in the tree | A confirmation, then the entry in its new place. |
| **Delete…** an OU that holds entries | It counts what is beneath and asks you to type the OU's name before deleting all of it. |

**Accounts** (the *Account* panel on a user's Overview)

| Do | Expect |
|---|---|
| Untick **Account enabled** (or ⇧⌘E) | The icon greys and a **Disabled** badge appears. Tick it again. |
| Thomas Wouters › **Unlock** | The *Locked out* badge goes. |
| svc_backup › untick **User cannot change password** | Read back from its security descriptor: unticked. Tick it again. |
| Tick **User must change password at next sign-in** | `pwdLastSet` reads *Must change at next sign-in* (0). |
| **Reset Password…** (⇧⌘P) | Asks for the password twice, or **Generate**s one. Over StartTLS or LDAPS it is sent; on a plain connection the app refuses. |

**Permissions** (a user's *Permissions* tab; the test directory keeps the
descriptor but enforces none of it, step 6 does)

| Do | Expect |
|---|---|
| Pieter Van Damme › **Add Rule…**: Choose › Authenticated Users, Allow, To *A property or property set*, find and pick `description`, tick Write, **Review…** | The rule in words, *Allow Authenticated Users: Write description, on this object only*, and that only this rule changes. **Add Rule**: it is listed among the rules set here, after the other allowances and before the inherited one. |
| Edit › **Undo** | The rule is gone again; Change History lists both. |
| Select the inherited rule (*Pre-Windows 2000 Compatible Access*) | **Change…** and **Remove** are off: it is changed where it is set. |
| Select *Domain Admins, Full control* › **Change…** › Deny | The review says *Change the rule Allow … to Deny …*. Cancel. |
| **Change Owner…** › Choose › Administrators › **Review…** › **Change Owner** | The owner reads Administrators. Undo puts it back. |
| Turn changes off (⌥⌘E) | The buttons give way to a note that the connection is read-only. |

**Import and export**

| Do | Expect |
|---|---|
| **Tools › Import LDIF…** (⇧⌘O), choose `TestDirectory/sample-import.ldif`, keep **Continue after an error** on | Eight records. Seven succeed; the seventh fails (`gidNumber` is not allowed on a user) and the import carries on. **Save Log…** writes the log. Corp › **Imported** now holds Ada Import, *Grace Hopper Import* (renamed) and GG-Imported; Pieter Van Damme's title is *VP Engineering*; GG-Empty-Legacy is gone. |
| Import the same file again | Entries that already exist are logged as *already exists, skipped* (the **If an entry exists** setting can also replace their values, after listing which ones and asking, or report an error). Records whose change was already made fail with the server's reason. |
| Right-click Corp › Users › **Export as LDIF › The Whole Subtree…** | Every entry below it, parents before children, so the file can be imported again. |

**Connections**

| Do | Expect |
|---|---|
| Sidebar **⋯ › Export Selected Connection…** or **Export All Connections…** | A `.forester` file. It holds no passwords. |
| **Import Connections…** of that file | Nothing added: the same connections are here already. Change one first, and the import adds it as a connection of its own beside it, read-only and trusting no certificate, since a connection file can come from anyone; nothing here is replaced. A saved password is used only while the server, port, security, user and certificate checking are what it was saved with; otherwise Forester asks for it. |
| **Forester › Settings…** › **Keep connections in iCloud Drive** | The connections move to iCloud Drive and appear on your other Macs signed in to the same account. Passwords stay in each Mac's keychain. |

### Things that should fail cleanly

| Do | Expect |
|---|---|
| Right-click the connection › **Disconnect**, then **Edit…** it with a wrong password, and connect | *Bind failed: Invalid credentials (49).*, and the password prompt again. |
| Make a second profile: Security **LDAPS**, port **10636**, Sign in **Anonymous** | Its own certificate prompt, now with **Trust Once** as well as **Always Trust**. Trust is pinned per connection. |
| On the anonymous connection, turn editing on and change a value | *Modify failed: Stronger authentication required (8). Modifications require authentication. Connect with a name and password to make changes.* |
| Set Security to **LDAPS** on port **10389** | After the timeout (30 seconds by default; lower it under Advanced): *No response from localhost:10389 … For LDAPS, 10389 must be a TLS port: usually 636…* |
| Host `localhost`, port `10999` | *Could not connect to localhost:10999. The server refused the connection; check the host and port.* |
| Host `no-such-host.invalid` | *The host “no-such-host.invalid” could not be found. Check the name, or your VPN.* |
| Run `TestDirectory/stop.sh` while connected, then click an entry | An error. Start the server again and connect: the app asks to trust the new certificate, then carries on. |

The test server reports itself as **OpenLDAP**. The app recognises the
AD-shaped data and offers the Active Directory tools, but some lookups still
take their portable path: substring search instead of ambiguous name
resolution, and following group links level by level instead of AD's one-query
nested lookup. Those are covered in step 6.

## 5. The app driving itself

A debug build can drive itself through the app and save a picture of every
screen and sheet. It renders its own windows, so it needs no screen-recording
permission, and it reads only its own windows and controls, so it needs no
Accessibility permission either. With a freshly started test directory:

```bash
scripts/automation.sh
```

The script links the debug build with this Mac's SDK, as every release is.
That matters: the SDK an app was built with decides how macOS 26 and later
draw it (in glass, or as before), and a plain `swift build` says it was built
with the macOS 14 SDK. It takes an output folder (`/tmp/forester-shots` by
default) and the parts to run, for example
`scripts/automation.sh /tmp/forester-layout layout`.

Drawing the view hierarchy leaves out the glass of macOS 26 and later, so the
pictures miss the sidebar and parts of the toolbar there. For pictures that
show what a person sees, such as the App Store screenshots, add
`FORESTER_SCREEN_CAPTURE=1`; it needs the Screen Recording permission of the
terminal it is started from.

It runs six parts, about ten minutes in all, then quits, with exit status 1
if anything failed (the log says what, and `FAILED.png` shows the window). Look at the
pictures with:

```bash
open /tmp/forester-shots
```

**The walkthrough** (pictures `01`–`39`) steps through the main screens and
makes 13 changes, reading each one back from the server (`verified: …`), then
takes changes back:

- a new connection is read-only, and a change is refused while it is
- a description saved; the account disabled and enabled again; Thomas Wouters
  unlocked; "cannot change password" cleared and set; "must change password" set
- an entry created, renamed, moved, and an OU deleted with everything in it
- undo: Edit › Undo puts a value back and Redo sets it again; undoing an
  added group member removes only that member, and is refused until confirmed
  when someone else changed the group since; a rename goes back and forward,
  and is refused until confirmed once the entry changed since; a creation
  whose details are not kept (a password) is undone and not redone; a change
  of case in a list comes back; an unlock is listed as not undoable, with the
  reason

It also checks, from a picture of the window, that the toolbar meets the line
between the sidebar and the middle column, browsing and searching, and that no
toolbar control sits on a column line; that nested
groups asked for on one entry are not shown on the next; that re-running a
search keeps it running and shows the second search's results; that
switching between two connections shows each one's own tree; and, with a
throwaway keychain item it removes again, that a saved password is read from
the keychain once per run and not at all to show that one is saved (each read
can make macOS ask for the Mac's password), and only for the server, port,
encryption, user and certificate checking it was saved with. It checks that
the update check reads only a version number and opens only Forester's release
page, and that Help › Copy Diagnostics names the server and the errors but never
the host, the user or the password.

**VoiceOver.** Every window the parts picture is also read the way VoiceOver
reads it, and the run fails on any control without a name. SwiftUI makes its
accessibility elements only while an assistive app asks for them, so the run
switches them on as such an app does; and before trusting a clean result it
shows the audit a sheet with a deliberately unnamed button and checks it is
caught. `FORESTER_A11Y_NAMES=1` lists every name as well, to read them for
sense.

Its screens: not connected, the certificate prompt, the domain; a user's
overview, attributes, membership and replication metadata; nested group
members, a dynamic group, a computer; a search preset, quick find, a filter
error, the filter builder, a paged search, a large OU, containers only; the
root DSE, light mode, and declining a certificate; the editing sheets; domain
information, the server monitor and the schema browser.

**The toolbar at many sizes** (pictures `T-…`, 8 of them). The toolbar is
split in parts over the columns, and each part must stay inside its column: when
one does not fit, macOS moves the toolbar's divider instead, and the column
line runs through a control (it did, through **Search**, with text in the
search field and a wide middle column). It tries 72 layouts: the window at its
narrowest, 1316 and 1800 points wide; the middle column as laid out, dragged
as narrow and as wide as it goes; the search field empty and holding text; a
short connection name and a long one; the sidebar shown and hidden. Each must
have every control and the title clear of the column lines, and the toolbar's
divider over the line between the middle column and the detail. A failure names
the control and the layout, and lists where each toolbar item was.
`FORESTER_LAYOUT_LOG=1` lists them for every layout.

**The entry's sheets as the app presents them** (pictures `E-…`, 9 of them):
new entry, duplicate, rename, move, delete, password reset, LDIF import,
account status and the change history, each opened through SwiftUI's own
presentation, as a click opens it. Each must appear at its own size, keep the
app answering, and close again.

**Every sheet** (pictures `S-…`, 38 of them) opened the way a person opens it,
at its real size: new and existing connections, the password prompt, Go to DN,
Settings, the container picker, new entries of each kind, duplicate, rename,
move, delete, password reset, LDIF import empty and with a file, account status,
the attribute editor for text, a DN, an expiry date, a photo, a read-only
attribute, the group type and a member list, the attribute picker, and the value
viewer; and the main window. Seven of them again in dark mode (`…-dark`).

**Real clicks and typing** (pictures `U-…`, 26 checks printed as
`verified (UI): …`). Starting with no saved connections, it uses the app's own
controls: menu commands from the menu bar, text typed key by key into the
fields, Return and Escape for a sheet's default and cancel buttons, and
buttons, checkboxes and the toolbar's **Read-only** pressed as VoiceOver
presses them. Built with the macOS 26 SDK or later, SwiftUI draws its buttons
and checkboxes itself, so they are found by their names in the accessibility
tree, not as AppKit buttons. In order: it types a new connection into the
editor, tests it, trusts the certificate and adds it; connects; goes to Pieter
by typing his DN; allows changes with the toolbar's **Read-only** button;
renames him and back; creates a user by typing a name, first and last name and
a password (checking that Create waits for a name and for matching passwords,
and that the account names fill in by themselves); resets that password with
**Generate**; disables and enables the account with its checkbox; deletes it;
imports the sample LDIF; deletes the imported OU by typing its name; types a
filter, checking that attribute names are offered as you type; and makes the
connection read-only again from the Entry menu. Every result is read back from
the server.

This part needs Forester in front, because menu commands follow the
focused window. It asks macOS to bring it forward, so do not type into other
apps while it runs. If macOS keeps another app in front, it does the menu
commands it could not reach directly, and says so at the end
(`note: the app was in the background…`).

**Another domain in the window** (16 checks printed as `verified (forest): …`).
The test forest has no DNS of its own, so the debug build is told where
child.corp.example answers (`FORESTER_TEST_DOMAIN_HOSTS`, which the script
sets and a release build never reads). The forest lists both domains; an
entry of the child domain is offered, not read, until the domain is browsed;
browsed, it is one more root of the tree, listing its own containers and
protected from rename and delete; its entry is read and shown, with its
primary group found in its own domain and its permissions read there; read-only
holds for it; a change goes to the child's server and Change History undoes it
there; a search beneath its root finds its three people, and an export of its
subtree reads all eight entries; a corp.example group shows its member from
the child domain; stopped, its root and connection go and its entries are no
longer read; and a domain whose controllers do not answer shows why on its
own root while the rest of the window carries on.

**Inside the App Store sandbox.** The Mac App Store variant runs sandboxed,
and what the sandbox refuses (a connection, the keychain, a file) shows only
there. Before every upload:

```bash
scripts/automation-sandboxed.sh
```

builds the debug App Store variant, puts it in an app bundle of its own
(`live.versaminds.Forester.sandboxcheck`, so it never touches the real app's
connections), signs it with the App Store's entitlements and runs the
walkthrough, the entry sheets and the UI tour in its container. A sandbox
reads only the files the person chose, so the sample LDIF is handed over in
the environment. The pictures stay in the container, which macOS keeps even
from the terminal; the log says what was checked.

To run some parts only, list them in `FORESTER_AUTOMATION_ONLY`, for example
`FORESTER_AUTOMATION_ONLY=sheets` (also `walkthrough`, `layout`, `entrysheets`
and `ui`), or pass them after the output folder:
`scripts/automation.sh /tmp/forester-shots ui`.
`marketing` is not part of the default run: it takes the pictures for the
website and the App Store (`M-…`, 2880 by 1800, light and dark), which
`scripts/make-site-images.sh` turns into the website's images. Nor is
`sample`, which needs the internet: from an empty sidebar it presses Try a
Sample Directory and checks that Forum Systems' public test server is added
once and opens read-only, without signing in
(`scripts/automation.sh /tmp/forester-shots sample`, and inside the App
Store's sandbox with `scripts/automation-sandboxed.sh sample`).

### A big directory

`performance` is not part of the default run either. It needs the test
directory with a big *Bulk Import* OU, whose users are all members of
*UG-All-Staff*:

```sh
LDAP_TEST_BULK=50000 TestDirectory/start.sh
scripts/automation.sh /tmp/forester-perf performance
```

`automation.sh` builds it optimised, as a release is. It opens the OU in the
tree, searches for all of it, sorts and selects the results, searches again,
and opens the group on each tab. Each step prints how long it took, the
longest the app went without answering (the window hanging), and the memory
in use, also in `performance.txt` in the output folder. It fails when any step
keeps the app from answering for more than half a second. On an M-series Mac
every step answers within about 0.4 s; the tree shows the first 5,000 entries
of the OU and the search all 50,000, at about 200 MB.

The memory figures go up and down by tens of megabytes as the allocator keeps
and returns freed memory. Whether replaced results are let go is counted with
`heap` while it runs: after the fifth search there is one
`_ContiguousArrayStorage<LDAPKit.LDAPEntry>` and one
`_ContiguousArrayStorage<Forester.SearchRow>`, the shown results.

```sh
heap $(pgrep -f 'automation-release/.*/Forester$') | grep -E 'LDAPEntry>|SearchRow>'
```

The LDAP client on its own, without the app, is timed by
`FORESTER_BENCH=1 swift test -c release --filter PerformanceTests` against the
same directory.

`FORESTER_PROFILE_DIR` keeps your own saved connections out of it, and the
test connection's password is not saved in your keychain. The parts
change the test directory, so restart it before running them again, and before
running the integration tests (step 3). Progress is printed as
`[automation] …`; a step or check that fails prints `FAILED:` and quits. All of
this is compiled into debug builds only; the app built by
`scripts/build-app.sh` does not contain it.

## 6. Against an Active Directory domain controller

The test directory in step 2 is OpenLDAP dressed as Active Directory: it holds
AD's data but enforces none of AD's rules. This step uses a real domain
controller, Samba's, in a container, with the same `corp.example` directory.
It enforces what AD enforces: the password policy, unique account names, rights
on password changes, locking out after failed sign-ins, and values the server
assigns itself. It needs Podman, and about 400 MB for the image.

```bash
TestDirectory/start-ad.sh
```

provisions the domain, loads the 1,608 entries over LDAPS and locks Thomas
Wouters out with wrong passwords. It answers on `ldaps://localhost:11636` and
`ldap://localhost:11389` (StartTLS), as `Administrator@corp.example` with the
password `Forester-Lab-Admin-2026!`. Its global catalog answers on
`localhost:13268`, and its Kerberos KDC on `localhost:10088`: the script gets a
ticket for Administrator into `TestDirectory/.run/krb5cc`, with its own
`TestDirectory/.run/krb5.conf`, so the Mac's own Kerberos settings and tickets
are not touched. The Kerberos tests run with them:

```bash
FORESTER_TEST_AD=1 KRB5_CONFIG=$PWD/TestDirectory/.run/krb5.conf KRB5CCNAME=FILE:$PWD/TestDirectory/.run/krb5cc \
  swift test --filter KerberosTests
```

They sign in with the ticket over StartTLS and LDAPS, are refused with any
certificate accepted, and are refused with a channel binding for another
certificate (Samba checks it, as a Windows domain controller with channel
binding required does). Over plain LDAP on 11389 they sign in only to a
server Kerberos names `ldap/localhost`, the host connected to (asked for
that name while connecting to 127.0.0.1, as DNS could make it, the sign-in
is refused), with every message numbered and Kerberos
encrypting every message: what crosses the network holds none of the names
read (the 1,500 entries of *Bulk Import*, paged, arrive in many encrypted
frames), 300 reads in flight at once and a search abandoned midway leave the
connection working (Kerberos numbers each message, and the server refuses one
out of order), and an account is created with a password and a photo larger
than one frame, so the request goes out in several. Every seeded account has
`Corp-Example-Test-Password-2026!`. Each start begins a new domain;
`TestDirectory/stop-ad.sh` removes it.

Changing permissions is checked against it too:

```bash
FORESTER_TEST_AD=1 swift test --filter ADPermissionTests
```

**ADPermissionTests** (5) reads the security descriptor of every object in
the domain and the configuration partition (over 2,000 each time), as the
owner alone, the access list alone, owner, group and access list, and all of
it with the SACL, and each encodes back to exactly the bytes read. Then, on
objects of their own: a rule letting Pieter Van Damme write a contact's
description is added, and Pieter, signed in, can; removed, he cannot, and the
access list is the very bytes it was, with the SACL untouched throughout. A
denial goes before the allowances and outweighs them, changed into an
allowance it lets him, and each change undone restores the bytes. The owner
changes alone (group, access list and SACL keep their bytes), an owner
changed by someone else since is not overwritten, and changing it back
restores the descriptor exactly. A rule for descendant contacts set on an OU
reaches a contact created beneath it as an inherited rule the server obeys,
cannot be removed there, and removed from the OU is gone from the contact.
It takes about 30 seconds, most of it reading every descriptor four times.

Then the app drives itself against it, twice:

```bash
KRB5_CONFIG=$PWD/TestDirectory/.run/krb5.conf KRB5CCNAME=FILE:$PWD/TestDirectory/.run/krb5cc \
FORESTER_TEST_AD=1 FORESTER_TEST_PASSWORD='Forester-Lab-Admin-2026!' scripts/automation.sh /tmp/forester-ad ad
```

```bash
FORESTER_TEST_AD=1 FORESTER_TEST_PASSWORD='Forester-Lab-Admin-2026!' scripts/automation.sh /tmp/forester-ad-ui ui
```

**`ad`** (72 checks, `verified (AD): …`) goes through everything Forester does
to AD, with the functions the app's controls call, and reads every result back.
Where AD keeps the result to itself, it signs in as the account instead: AD
answers "must change password" only to the right password, so that proves both.
It covers: recognising AD; signing in by user principal name, `CORP\user` and
DN, and a wrong password reported as one; the schema; a 1,500-entry OU past AD's
1,000-entry page and a 1,544-member group past its 1,500-value limit; memberOf,
nested membership in one query, name resolution and five presets; domain
information and the fine-grained password policies; and then, in an OU of its
own, creating an OU, a user with a password, a group, a computer and a contact,
"must change password", a reset, a password the policy refuses, a change
knowing the current one, "user cannot change password" (written, and AD then
refusing the user's own change), disabling, the account options, unlocking,
group membership, groups nested in a circle (each listed once, also when the
in-chain query fails and the groups are walked one by one), a group's members at
any depth, Find by name matching inside a name (`K8S_MINFRA` finds
`GRP_GSU_APP_K8S_MINFRA_ADMIN`), converting a group to universal, rename, move,
delete and tree delete. Then undoing "user cannot change password" (the
security descriptor comes back) and an account option; a user's permissions
read and named (its owner, Domain Admins, AD's extended rights and property
sets) with what the signed-in account may do; a rule added to them and undone
from the change history (the access list comes back byte for byte), and the
owner changed and undone, the rules left alone; the forest's domains, a search
of the whole forest through the global catalog, an entry of another domain
not offered unless the forest lists its domain, a domain the forest does not
list refused, and one it lists opened read-only with the password lent; and, with the ticket from `start-ad.sh`, a connection
that signs in with Kerberos and no password.

**`ui`** is step 5's tour of real clicks and typing, against AD: the
connection typed in, the certificate trusted, a user created with the New Entry
form, its password reset with Generate, disabled with its checkbox, the smart
card question, the sample LDIF imported and its OU deleted by typing its name.

Two things AD does that are easy to take for a bug, and are not:

- After a password reset or change, AD keeps accepting the **previous
  password** for an hour ("old password allowed period"). The checks prove a
  new password by signing in with it.
- Turning on **Smart card is required** makes AD replace the password with a
  random one, for good. Forester asks before it does that.

One thing Samba does not do: it does not compute `msDS-ReplAttributeMetaData`,
so on a Samba domain the Replication tab says it has no metadata. Windows AD
provides it.

## 7. Against your own Active Directory

A new connection is read-only, so it is safe to point at production with an
ordinary account. Turn editing on only on a connection, and with an account,
where you mean to make changes.

- **Host**: a domain controller, or the domain name.
- **Security**: StartTLS on 389, or LDAPS on 636 (3269 for the global catalog).
- **User**: `you@corp.example`, `CORP\you` or your DN.

These parts only run against real AD, so they are the ones worth checking:

- **Server info** says *Active Directory* and shows the domain and forest
  functional levels.
- The toolbar search uses AD's **ambiguous name resolution**: type part of a
  name, an account name or an email address.
- **Show All Nested Groups** answers in a single query (`LDAP_MATCHING_RULE_IN_CHAIN`).
- A group with **more than 1,500 members** shows all of them. AD sends them in
  ranges and the app fetches the rest.
- A **wrong password** reads *The user name or password is wrong (AD code 52e)*.
- **Domain Information** reads the real configuration partition, and **Account
  Status on Each DC** reaches every domain controller.
- With editing on, in a test OU: **reset a password** (AD needs StartTLS or
  LDAPS, and a password that meets the policy), **delete a subtree** (AD's tree
  delete control), and **User cannot change password**, which should then show
  as ticked in Active Directory Users and Computers too.
- If your organisation's root CA is in Keychain Access, LDAPS connects without
  asking. If not, compare the fingerprint the app shows with what your
  administrators expect before trusting it.

## Troubleshooting

| Symptom | Fix |
|---|---|
| *The test server needs Python 3.11 or later* | `brew install python`, or set `LDAP_TEST_PYTHON`. |
| *slapd did not come up* | Read `TestDirectory/.run/slapd.log`. Most often a port is taken: `lsof -nP -iTCP:10389`, or use other ports. |
| Integration tests all *skipped* | Set `FORESTER_TEST_SERVER=1` and start the test directory first. |
| A walkthrough check fails, or entries look changed | An earlier run or your own edits changed the directory. Stop and start it. |
| `start-ad.sh` fails, or Podman reports no space | Check the Podman machine's disk: `podman machine ssh df -h /var`. `podman system check --repair` removes layers no image or container uses. |
| An `ad` check fails after an interrupted run | Start the domain again with `TestDirectory/start-ad.sh`; it begins from scratch. |
| *the UI tour needs Forester in front* | macOS kept another app active the whole time. Run it again and leave the keyboard alone while it runs. |
| *no structuralObjectClass* when changing an entry | The server is still running data from an older version of the start script. Stop and start it. |
| Certificate prompt after restarting the server | Expected: each start makes a new CA. |
| Keychain prompt after rebuilding the app | Expected with an ad-hoc signed build; choose Always Allow. |
| A change does nothing and the status bar says *Read-only* | Allow changes: ⌥⌘E, or click Read-only in the toolbar. |
| Only `CN=admin` can bind to the test server | Apple's slapd sends every other simple bind to Open Directory. Use the admin account or connect anonymously. |

A note on the test server's internals: Apple's `slapd` only accepts a TLS
certificate from a keychain. Rather than install one in yours,
`TestDirectory/tls_proxy.py` handles TLS in front of it, for both LDAPS and the
StartTLS upgrade. `slapd` itself listens on port 10388, and the child domain's on 10488.
