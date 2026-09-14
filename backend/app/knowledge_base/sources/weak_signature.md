# Weak Certificate Signature Algorithm

## Overview

An X.509 certificate is itself signed by its issuing Certificate Authority
using a hash-and-sign algorithm (e.g. `sha256WithRSAEncryption`,
`ecdsa-with-SHA384`). If the hash function underlying that signature is
cryptographically broken, the signature no longer reliably proves the
certificate's contents haven't been tampered with.

## Why It's Dangerous

Certificates signed with **MD5** or **SHA-1** are vulnerable to collision
attacks. Researchers have demonstrated practical chosen-prefix collisions
against both algorithms, meaning an attacker with sufficient compute can, in
principle, construct a second certificate with different (attacker-chosen)
key material that shares the same CA signature as a legitimately issued
certificate — undermining the entire chain-of-trust guarantee that
signatures exist to provide.

## Standards & Compliance References

- CVE-2004-2761 documents practical MD5 collision attacks.
- Major CAs and browser root programs (CA/Browser Forum Baseline
  Requirements) have prohibited issuance of SHA-1-signed certificates
  since 2016-2017; SHA-1 has been publicly demonstrated as
  collision-broken (the "SHAttered" attack, 2017).
- NIST SP 800-131A deprecates SHA-1 for digital signature generation.

## Remediation

- Re-issue any certificate signed with MD5 or SHA-1 using a
  SHA-256-or-stronger signature algorithm.
- Verify the full certificate chain (not just the leaf) — an
  otherwise-modern leaf certificate can still chain to a weakly-signed
  intermediate.
