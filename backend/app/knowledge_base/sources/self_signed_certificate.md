# Self-Signed / Untrusted Certificate

## Overview

A self-signed certificate is signed by its own private key rather than by a
Certificate Authority the connecting client already trusts. It can still
provide encryption for the session, but it provides no independent
identity assurance — anyone can generate a self-signed certificate
claiming to be any hostname.

## Why It's Dangerous

Without a trusted third party vouching for the certificate, the connecting
client has no cryptographic basis to distinguish the legitimate mail
server's self-signed certificate from an attacker-generated self-signed
certificate presented during a man-in-the-middle interception. The
encryption itself is real, but the *identity* guarantee TLS is supposed to
provide is absent — an MITM proxy can transparently substitute its own
self-signed certificate and the client has no way to detect it unless it
has separately pinned the expected certificate/key.

## Standards & Compliance References

- RFC 5280 defines the certificate chain-of-trust model that self-signed
  leaf certificates deliberately bypass.
- Public CA/Browser Forum trust programs exist specifically to prevent this
  class of impersonation for internet-facing services; self-signed
  certificates are appropriate only for closed, explicitly-pinned internal
  contexts, not for general mail transport.

## Remediation

- Issue certificates from a trusted public CA (or an internal CA that all
  connecting clients are explicitly configured to trust) instead of
  self-signing.
- Where self-signing is unavoidable (isolated lab/test environments),
  distribute and pin the exact expected certificate/public key out-of-band
  rather than relying on opportunistic trust-on-first-use.
