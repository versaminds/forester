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
- a certificate accepted without the user trusting it, or TLS silently not used
- a crafted server response that crashes Forester or makes it misbehave
- an LDIF file that does something other than what the import summary shows
- a saved password sent to a server, port, user or certificate setting other
  than the one it was saved for. By design, and only over TLS to certificates
  this Mac trusts, the password in use also goes to the same domain's global
  catalog (ports 3268 and 3269), to its other domain controllers when you ask
  for an account's status on each, and to another domain of the forest you
  open from it
- a Kerberos sign-in whose ticket could be relayed to another connection (the
  TLS channel binding), or, without TLS, a message sent or taken on that
  connection without Kerberos encryption
- a SCRAM sign-in kept without the server's proof that it knows the
  password, with fewer than 4,096 rounds of hashing, or not bound to the TLS
  connection when the server offers that; or a password saved for SCRAM
  sent in a simple bind
- a client certificate shown to a server other than the one it was chosen
  for, or a certificate sign-in that goes on as something else when it fails
- an update installed that is not signed with VersaMinds' update key, or the
  update feed read before you chose to check for updates

## Supported versions

Fixes go into the latest release. Please check that the problem still exists
there before reporting it.
