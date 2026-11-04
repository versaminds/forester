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
  than the one it was saved for
- a Kerberos sign-in without TLS, or one whose ticket could be relayed to
  another connection (the TLS channel binding)
- an update installed that is not signed with VersaMinds' update key, or the
  update feed read before you chose to check for updates

## Supported versions

Fixes go into the latest release. Please check that the problem still exists
there before reporting it.
