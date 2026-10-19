# Deprecated TLS/SSL Protocol Versions (SSL 3.0, TLS 1.0, TLS 1.1)

## Overview

SSL 3.0 and TLS 1.0/1.1 are legacy transport-encryption protocol versions
that predate modern cryptographic design practices. All three have been
formally deprecated by standards bodies and are considered unsafe for
production use, even though the session is nominally "encrypted."

## Why It's Dangerous

- **SSL 3.0** is vulnerable to POODLE (CVE-2014-3566), a padding-oracle
  attack against CBC-mode ciphers that allows an active MITM attacker to
  decrypt session content one byte at a time.
- **TLS 1.0** is vulnerable to BEAST (CVE-2011-3389) and lacks support for
  modern AEAD cipher suites, forcing reliance on weaker CBC/RC4 constructs.
- **TLS 1.1** carries the same weak cipher-suite limitations as TLS 1.0 and
  offers no meaningful security improvement over it.
- All three lack forward-secrecy guarantees comparable to modern
  ECDHE-based TLS 1.2/1.3 handshakes in typical deployments, and none
  support TLS 1.3's simplified, hardened handshake.

## Standards & Compliance References

- RFC 8996 formally deprecates TLS 1.0 and TLS 1.1 across the IETF
  ecosystem (March 2021).
- RFC 7568 formally deprecates SSL 3.0 (June 2015).
- PCI DSS explicitly disallows "early TLS" (TLS 1.0) and SSL for
  cardholder-data environments.
- NIST SP 800-52r2 mandates TLS 1.2 as the minimum acceptable version for
  federal systems, recommending TLS 1.3.

## Remediation

- Disable SSL 3.0, TLS 1.0, and TLS 1.1 at the server/mail-transfer-agent
  configuration level; require TLS 1.2 as a floor, TLS 1.3 where supported.
- Re-test client compatibility after disabling legacy versions — very old
  mail clients may need to be upgraded or retired.
