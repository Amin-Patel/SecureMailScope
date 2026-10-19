# Certificate Matches Known-Malicious Threat Intelligence

## Overview

Not every cryptographic risk is a property of how a certificate or TLS
session is configured. A certificate can be validly signed, use a strong
key, and negotiate TLS 1.3 with an AEAD cipher, and still terminate at
infrastructure that is actively malicious — for example, a botnet's
command-and-control (C2) server using TLS to blend in with legitimate
traffic and evade plaintext-signature detection. Threat intelligence feeds
close this gap by tracking the SHA1 fingerprints of certificates observed
in the wild on known-bad infrastructure, independent of the certificate's
own cryptographic soundness.

## Why It's Dangerous

- A session flagged this way passed every local, deterministic check —
  the danger is entirely in *who is on the other end*, not in the
  handshake parameters. Configuration hardening alone cannot catch this.
- C2 operators increasingly use valid, even publicly-trusted, TLS
  certificates specifically to defeat network defenders who only inspect
  cipher/protocol/cert-validity, not endpoint reputation.
- A match indicates the observed host has already been confirmed malicious
  by external researchers, not merely suspected — this is evidence of
  contact with known-bad infrastructure, not a configuration weakness to
  remediate over time.

## Standards & Compliance References

- abuse.ch SSLBL (SSL Certificate Blacklist) — a community-maintained feed
  of SHA1 fingerprints for certificates observed on botnet C2 servers,
  used here as the source of match data.
- NIST SP 800-150 ("Guide to Cyber Threat Information Sharing") recommends
  incorporating external threat intelligence alongside local detection
  controls precisely because configuration-based checks cannot detect
  known-bad endpoints on their own.

## Remediation

- Treat the host as compromised immediately: terminate the connection and
  do not allow further traffic to or from the matched IP/certificate.
- Isolate the endpoint that initiated the connection and investigate it
  for signs of malware or C2 beaconing beyond this single session.
- Block the certificate's SHA1 fingerprint and the associated IP address(es)
  at the network perimeter (firewall/proxy) to prevent recurrence.
- Preserve the session's packet capture and certificate as forensic
  evidence before remediating, since this indicates an active or
  attempted compromise rather than a misconfiguration to simply fix.
