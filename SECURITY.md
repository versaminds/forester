# Security

Forester handles directory credentials, often those of administrators, so
security reports are taken seriously and handled before anything else.

## Reporting a vulnerability

Please report it privately, not in a public issue:

- On GitHub, open the repository's **Security** tab and choose **Report a
  vulnerability**. Only VersaMinds sees the report.

Include what you found, how to reproduce it, and which version of Forester and
macOS you used. Leave out real names, addresses and other data from your
directory; a made-up example is enough.

We will confirm that we received the report, keep you informed while we work on
a fix, and credit you in the release notes unless you would rather not be named.

## What counts

Anything that could expose credentials or directory data, or change a directory
without the user meaning to. For example:

- a password or bind credential written somewhere other than the macOS keychain,
  or included in an export
- a change sent while a connection is read-only
- a certificate accepted without the user trusting it (the certificate
  question trusts nothing on Return or Escape), TLS silently not used, or TLS
  older than 1.2 used
- a crafted server response that crashes Forester or makes it misbehave,
  including one answer large enough to fill the Mac's memory (each request's
  responses are capped at 512 MB) or a photo that is not a JPEG, PNG or GIF
  of a photo's size reaching an image decoder
- an LDIF file that does something other than what the import summary shows:
  a record other than a plain add, or one outside the expected container,
  not listed with its DN and changes before the import; a change to an
  administrators' group's members, permissions, account flags, service
  principal names, delegation or passwords not warned about; or an exported
  entry that imports again as a change record
- a name or DN in a confirmation, a picker or the type-to-confirm field that
  hides characters (bidirectional controls, zero-width or format characters)
  instead of showing them
- a saved password sent to a server, port, user or certificate setting other
  than the one it was saved for. By design, and only over TLS to certificates
  this Mac trusts, the password in use also goes to the same domain's global
  catalog (ports 3268 and 3269), to its other domain controllers when you ask
  for an account's status on each, and to another domain of the forest you
  browse in the window or open from it
- a request about an entry of one domain of a forest sent to another
  domain's server, when several domains are browsed in one window, whichever
  domain is the parent; an entry named by `<GUID=…>` or `<SID=…>` (which says
  nothing of its domain) sent anywhere while another domain is about; or a
  domain connected to by a DNS name other than the one its naming context
  spells (a crossRef whose dnsRoot points elsewhere is no domain)
- a Kerberos sign-in whose ticket could be relayed to another connection (the
  TLS channel binding), or, without TLS, a message sent or taken on that
  connection without Kerberos encryption and numbering, or a sign-in kept
  with a server Kerberos names other than `ldap/` and the host connected to.
  That name is the one the macOS Kerberos library reports for the server the
  exchange authenticated (`gss_inquire_context`). The tests show a ticket for
  another name is refused (asked for `ldap/localhost` while connected to
  127.0.0.1); that the library reports a name it reached through a DNS alias
  rather than the name it was given has not been shown here, since the test
  realm's Kerberos would not follow one without changing this Mac's
  resolver
- a SCRAM sign-in kept without the server's proof that it knows the
  password, with fewer than 4,096 rounds of hashing, not bound to the TLS
  connection when the server offers that, or made with "Accept any
  certificate"; a password saved for SCRAM sent in a simple bind; or a
  character of the password in an error message or Diagnostics
- a client certificate shown to a server other than the one it was chosen
  for, one the person did not choose shown at all, or after the connection's
  server, port, security or certificate checking changed without it being
  chosen again; or a certificate sign-in
  that goes on as something else when it fails. By design, and only over TLS
  to certificates this Mac trusts (or, on the same host, the ones pinned for
  the connection), it is also shown to the same domain's global catalog and
  other domain controllers, and to another domain of the forest browsed or
  opened from it, as the password is
- a certificate trusted, any certificate accepted, changes allowed or a client
  certificate chosen because the connections file said so (on this Mac or in
  iCloud Drive), rather than by you on this Mac; or an imported connection
  replacing one already here. By design, the first start of this version on
  a Mac takes them from the file once, as earlier versions kept them there;
  never again after that, also when this Mac's settings file is removed or
  cannot be read (every connection is then read-only, trusting the system's
  certificates only)
- a permissions change that writes more than it says: another part of the
  security descriptor (the SACL above all, or the access list when changing
  the owner), an inherited rule, a rule's inheritance widened (object
  inherit turned into container inherit), a list out of Windows' order
  reordered, or anything in the descriptor besides the change shown in
  words; a principal shown by a name that is not its own (a RID named as
  this domain's group in another domain's SID); or a change the server took
  that is missing from the change history or cannot be undone
- an update installed, or unpacked, that is not signed with VersaMinds'
  update key, or the update feed read before you chose to check for updates

## Supported versions

Fixes go into the latest release. Please check that the problem still exists
there before reporting it.
