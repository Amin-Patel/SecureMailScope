# Weak Cipher Suite Negotiation

## Overview

A TLS handshake negotiates a cipher suite that determines the key exchange,
bulk encryption algorithm, and MAC/AEAD construction used for the session.
Legacy cipher suites built on RC4, 3DES (Triple DES), static RSA key
exchange, or CBC-mode block ciphers without AEAD are considered weak by
current standards, even when layered inside an otherwise-current TLS
version.

## Why It's Dangerous

- **RC4** has known statistical biases in its keystream that allow partial
  plaintext recovery given enough observed ciphertext (RFC 7465 prohibits
  its use in TLS entirely).
- **3DES** has a 64-bit block size vulnerable to birthday-bound collision
  attacks in long-lived sessions transferring large volumes of data
  (the "Sweet32" attack, CVE-2016-2183).
- **CBC-mode ciphers without AEAD** (e.g. AES-CBC combined with HMAC in the
  older non-encrypt-then-MAC construction) are susceptible to
  padding-oracle attacks such as BEAST and Lucky 13.
- **Static RSA key exchange** provides no forward secrecy — if the
  server's private key is ever compromised, every past session recorded by
  an eavesdropper becomes retroactively decryptable.

## Standards & Compliance References

- RFC 7465 bans RC4 in TLS.
- NIST SP 800-52r2 recommends AEAD cipher suites (AES-GCM, ChaCha20-Poly1305)
  with ECDHE key exchange for forward secrecy.
- PCI DSS and most modern browser TLS policies reject 3DES and RC4 suites.

## Remediation

- Restrict the server's cipher suite list to AEAD constructions with
  ECDHE/DHE key exchange (forward secrecy).
- Remove RC4, 3DES, and static-RSA-key-exchange suites from the TLS
  configuration entirely.
- Prefer TLS 1.3, which removes weak cipher suites from the protocol by
  design.
