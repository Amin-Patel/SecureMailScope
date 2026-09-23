# Email Authentication Weaknesses (SPF, DKIM, DMARC)

## Overview

SPF, DKIM and DMARC are the DNS-published controls that let a receiving
server decide whether mail claiming to be from a domain is really
authorized by it. SPF lists the hosts allowed to send for a domain. DKIM
attaches a cryptographic signature that receivers check against a public
key published in DNS. DMARC ties them together: it requires SPF or DKIM to
pass *and align with the visible From domain*, and tells receivers what to
do on failure (none, quarantine, reject). Evidence of these controls
appears passively in captured traffic as Authentication-Results,
Received-SPF and DKIM-Signature message headers, and as SPF/DMARC/DKIM TXT
records in plaintext DNS responses.

## Why It's Dangerous

- An SPF record ending in `+all` or `?all` authorizes every sender, so it
  gives no protection against spoofing; `~all` only soft-fails.
- A DMARC policy of `p=none` only monitors, so spoofed mail is still
  delivered. Without DMARC, receivers have no domain policy at all.
- A DKIM signature that does not cover the From header (h= omits `from`)
  lets an attacker change the visible sender without breaking the
  signature. A body-length limit (`l=`) lets content be appended after the
  signed portion. A signing domain (`d=`) that does not align with the From
  domain does nothing for DMARC.
- `rsa-sha1` signatures are deprecated (RFC 8301) and DKIM RSA keys below
  1024 bits can be factored; 1024-bit keys are below current guidance.
- Recorded SPF, DKIM or DMARC failures on real messages are direct evidence
  of spoofing attempts, forwarding breakage, or misconfiguration.

## Standards & Compliance References

- RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 8301 (DKIM
  cryptographic algorithm and key requirements), RFC 8601
  (Authentication-Results header).
- NIST SP 800-177r1 "Trustworthy Email" recommends deploying SPF, DKIM and
  DMARC together with an enforcing DMARC policy and 2048-bit DKIM keys.

## Remediation

- Publish one SPF record ending in `-all` (use `~all` only while rolling
  out), staying within the 10-DNS-lookup limit.
- Sign outbound mail with DKIM using rsa-sha256 (or ed25519-sha256) and a
  2048-bit key; include From in the signed headers, omit `l=`, and sign with
  a `d=` domain aligned with the From domain.
- Publish DMARC starting at `p=none` with `rua=` reporting, then move to
  `p=quarantine` and `p=reject` once legitimate senders align.
- Rotate DKIM keys periodically and revoke retired selectors.
