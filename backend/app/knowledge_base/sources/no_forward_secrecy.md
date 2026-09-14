# TLS Session Without Forward Secrecy

## Overview

Forward secrecy (also called Perfect Forward Secrecy, PFS) is the property
that a session's traffic-encryption key cannot be recovered even if the
server's long-term private key is later compromised. TLS achieves this by
using an ephemeral Diffie-Hellman key exchange (DHE or ECDHE) instead of a
static key exchange (plain RSA key transport, or static (EC)DH) to derive
the session key.

## Why It's Dangerous

Without forward secrecy, an adversary who passively records encrypted
traffic today gains a standing incentive to compromise the server's private
key at any point in the future -- doing so retroactively decrypts every
past session that used that key, not just future ones ("harvest now,
decrypt later"). This matters even for organizations with strong current
key hygiene, because it removes any time limit on the value of a future key
compromise or legal compulsion to disclose a private key. TLS 1.0-1.2
deployments that still permit static RSA key exchange (`TLS_RSA_WITH_*`
cipher suites) or static (EC)DH key exchange are exposed to this. TLS 1.3
removes the non-ephemeral key-exchange modes entirely, so a session
negotiated over TLS 1.3 is always forward-secret by construction.

## Standards & Compliance References

- NIST SP 800-52r2 recommends cipher suites using ECDHE key exchange and
  explicitly discourages static RSA/DH key exchange for new TLS
  deployments.
- Mozilla's Server Side TLS guidance (Intermediate and Modern
  compatibility profiles) excludes all static-RSA-key-exchange cipher
  suites specifically for this reason.
- RFC 7525 (TLS recommendations, BCP 195) recommends implementations
  support and prefer cipher suites that provide forward secrecy.

## Remediation

- Configure the mail server to prefer ECDHE (or DHE) cipher suites ahead of
  static RSA/(EC)DH suites in its cipher preference order.
- Remove `TLS_RSA_WITH_*` and static `TLS_ECDH_*`/`TLS_DH_*` cipher suites
  from the server's enabled cipher list where legacy client compatibility
  does not require them.
- Prefer TLS 1.3 where client support allows -- it removes the
  non-ephemeral key-exchange modes from the protocol entirely, so this
  class of finding cannot occur on a TLS 1.3 session.
