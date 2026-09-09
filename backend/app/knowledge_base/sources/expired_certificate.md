# Expired Certificate

## Overview

Every X.509 certificate carries a `notBefore`/`notAfter` validity window.
Once the current date passes `notAfter`, the certificate is no longer
considered valid by any strictly-conforming TLS client, regardless of
whether the underlying key material is otherwise sound.

## Why It's Dangerous

- Mail clients and MTAs that strictly enforce certificate validation will
  refuse the connection or fall back to an insecure/unencrypted transport,
  silently degrading confidentiality until an operator notices.
- Some deployments configure clients to ignore expiry warnings for
  operational convenience — this trains users and automated systems to
  click through certificate errors, which also masks genuine MITM
  substitution attacks presenting an entirely different, attacker-controlled
  certificate.
- Automated mail-exchange validation (e.g. MTA-STS, DANE) that depends on a
  valid certificate chain will fail closed, potentially causing legitimate
  mail delivery failures.

## Standards & Compliance References

- RFC 5280 §4.1.2.5 defines certificate validity period semantics and
  requires relying parties to reject expired certificates.
- CA/Browser Forum Baseline Requirements cap maximum certificate lifetime
  (currently 398 days for publicly trusted certificates) specifically to
  force regular rotation and reduce the blast radius of key compromise.

## Remediation

- Automate certificate renewal (e.g. ACME/Let's Encrypt, or an internal PKI
  renewal job) well ahead of expiry rather than relying on manual tracking.
- Alert on certificates approaching expiry (30/14/7-day thresholds) rather
  than discovering the failure after it has already caused an outage or a
  forced insecure fallback.
