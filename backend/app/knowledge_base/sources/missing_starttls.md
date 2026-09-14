# Missing STARTTLS Negotiation

## Overview

STARTTLS is an opportunistic-upgrade mechanism (RFC 3207 for SMTP, RFC 2595
for IMAP/POP3) that lets a client open a connection on the traditional
plaintext port and then upgrade the same connection to TLS before any
sensitive data is exchanged. When a session on port 25/587/110/143
completes its protocol exchange without ever negotiating STARTTLS, all
subsequent traffic — including `AUTH` credentials and message bodies —
remains in cleartext for the entire session.

## Why It's Dangerous

- **STARTTLS stripping**: an active on-path attacker can intercept the
  plaintext connection and simply delete or corrupt the server's
  `250-STARTTLS` advertisement in the EHLO response, causing a
  misconfigured client to silently continue in plaintext instead of
  aborting — the client believes it tried to upgrade and has no user-facing
  indication that the upgrade was blocked.
- Servers that advertise STARTTLS but don't *require* it before accepting
  `AUTH` or `MAIL FROM` leave a downgrade path open even when the
  capability is technically present.
- This is a distinct finding from full plaintext-protocol usage: STARTTLS
  may be supported and even used most of the time, but its absence in a
  specific observed session indicates either a misconfigured client, a
  misconfigured server, or an active downgrade attack in progress.

## Standards & Compliance References

- RFC 3207 (SMTP STARTTLS) and RFC 2595 (IMAP/POP3 STARTTLS).
- RFC 8314 recommends implicit TLS (SMTPS/993/995-style ports) as
  preferable to opportunistic STARTTLS specifically because it removes the
  plaintext negotiation window that stripping attacks exploit.

## Remediation

- Configure the MTA to require STARTTLS before accepting authentication or
  mail submission (`AUTH` and `MAIL FROM` rejected pre-TLS).
- Where feasible, migrate to implicit-TLS ports (465/993/995) which never
  expose a plaintext negotiation phase at all.
- Deploy MTA-STS (RFC 8461) to let receiving domains publish an enforceable
  policy that senders must use TLS, closing the silent-downgrade gap.
