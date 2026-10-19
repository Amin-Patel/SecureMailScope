# PKI Certificate Chain & Trust Validation Issues

## Overview

Beyond a single certificate's own properties (signature algorithm, key
size, validity dates), a TLS session's trust depends on the *chain* of
certificates presented during the handshake being valid end-to-end: each
certificate correctly signed by the next one up, ending in a certificate
this client actually trusts, with hostname, validity period, and
certificate-purpose constraints all satisfied along the way. A single
break anywhere in that chain undermines the identity guarantee TLS is
supposed to provide, even if every individual certificate looks fine in
isolation.

## Why It's Dangerous

- **Expired or not-yet-valid certificates** (`CERT_EXPIRED`,
  `CERT_NOT_YET_VALID`) break automated validation and train users/clients
  to click through trust warnings, which also masks genuine substitution
  attacks presenting an entirely different certificate.
- **Hostname mismatch** (`CERT_HOSTNAME_MISMATCH`) means the certificate
  wasn't issued for the server actually being connected to -- a hallmark
  of a misconfigured server or an active MITM presenting the wrong
  certificate.
- **Invalid signature** (`CERT_SIGNATURE_INVALID`) means a certificate in
  the chain was not actually signed by its claimed issuer's private key --
  the chain is cryptographically broken, not just administratively messy.
- **Invalid chain order** (`CERT_INVALID_CHAIN_ORDER`) can cause some
  clients to fail validation while others succeed, producing inconsistent
  security behavior across the client population.
- **Self-signed** (`CERT_SELF_SIGNED`) and **untrusted CA**
  (`CERT_UNTRUSTED_CA`) certificates provide encryption but no independent
  identity assurance -- a client has no cryptographic basis to distinguish
  the legitimate server's certificate from an attacker-generated one signed
  by the same untrusted/self-issued authority.
- **Invalid Extended Key Usage or Basic Constraints**
  (`CERT_INVALID_EKU`, `CERT_INVALID_BASIC_CONSTRAINTS`) mean a
  certificate is being used outside the purpose it was actually issued
  for -- e.g. a non-CA certificate being used to sign other certificates,
  or a certificate without server-auth EKU being used for TLS server
  authentication.

## Standards & Compliance References

- RFC 5280 defines the X.509 certificate chain-of-trust model, path
  validation algorithm, and the semantics of Basic Constraints and
  Extended Key Usage that a conformant validator must enforce.
- RFC 6125 defines hostname verification rules for TLS server
  certificates.
- CA/Browser Forum Baseline Requirements govern what public CAs may
  issue and are the basis most trust-store validators (including browser
  and OS root programs) build their path-validation logic against.

## Remediation

- Renew certificates before expiry and automate renewal (ACME/Let's
  Encrypt) rather than relying on manual tracking.
- Ensure the server presents the complete, correctly-ordered chain
  (leaf -> intermediate(s) -> root) rather than relying on clients to
  fetch missing intermediates.
- Issue certificates from a CA in the client's actual trust store, with
  the correct hostname(s) in the Subject Alternative Name field.
- Verify Basic Constraints (`CA:TRUE`/`CA:FALSE`) and Extended Key Usage
  are set correctly for each certificate's actual role in the chain.
