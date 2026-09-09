# Insufficient Certificate Public-Key Size

## Overview

A certificate's public key (typically RSA or, less commonly, DSA) must be
large enough that brute-force or number-field-sieve factorization attacks
remain computationally infeasible for the certificate's validity period.
RSA keys below 2048 bits (e.g. 512-bit or 1024-bit) fall below this bar.

## Why It's Dangerous

- 512-bit RSA keys have been practically factored in hours using cloud
  compute (the basis of the 2015 FREAK attack, CVE-2015-0204, which forced
  servers down to export-grade 512-bit keys).
- 1024-bit RSA is considered within reach of well-resourced adversaries
  (nation-state-level compute) and is no longer recommended for any new
  issuance; its long-term security margin has been shrinking for over a
  decade.
- A factored private key allows an attacker to fully impersonate the
  server and passively decrypt any session that used non-forward-secret
  key exchange.

## Standards & Compliance References

- NIST SP 800-57 Part 1 specifies 2048-bit RSA as the minimum for security
  through 2030, with 3072-bit recommended for longer-lived keys.
- CA/Browser Forum Baseline Requirements have mandated a 2048-bit RSA
  minimum for publicly trusted certificates since 2014.

## Remediation

- Re-issue certificates with RSA keys of at least 2048 bits (3072-bit or
  ECDSA P-256/P-384 preferred for new deployments).
- Audit any internal/private CA issuance templates that may still default
  to legacy key sizes.
