# Security policy

## Reporting a vulnerability in Namazu

Please do not open a public issue. Use GitHub's private vulnerability reporting
on this repository (Security tab, "Report a vulnerability"), which goes only to
the maintainers.

Include what you were doing, what happened, and the smallest reproduction you
have. You will get an acknowledgement within a few days.

## Scope

Namazu is a local tool that sends requests to targets you choose. The parts most
worth attention:

- **Host and origin guard** (`namazu/app.py`). The service binds to loopback and
  rejects requests arriving with an unrecognised Host header or a cross-site
  origin. A bypass of that guard is in scope, because it would let a web page
  you visit drive the tool against your internal network.
- **The write gate** (`namazu/audit/transport.py`). Any path that sends a
  state-changing request without `allow_mutating` is a serious bug.
- **Credential handling.** Tokens are held in memory and masked in exports. A
  path that writes a credential to disk, logs it, or leaks it into an export is
  in scope.
- **The OAuth callback** (`/oauth/callback`). It accepts only a `state` value
  Namazu issued, and hands a token to the browser exactly once.

## Not in scope

Namazu makes requests to wherever you point it, including hosts on your own
network. That is the purpose of the tool, not a vulnerability. The same applies
to the OAuth and URL-fetch features: they are deliberately not restricted by an
allow-list, because an operator testing an internal API needs to reach it.

Running with `--host 0.0.0.0` removes the loopback protection by design. Reports
about that configuration being reachable are not treated as vulnerabilities.

## Using Namazu

Only run it against systems you are authorised to test. The `writes` profile
creates and modifies data on the target.
