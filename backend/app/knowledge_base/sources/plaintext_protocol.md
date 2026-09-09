# Plaintext Email Protocol Transmission

## Overview

SMTP (port 25), POP3 (port 110), and IMAP (port 143) were originally designed
without transport encryption. When a mail session negotiates none of the
available upgrade mechanisms, every byte of the session — including
authentication credentials (`AUTH LOGIN`/`AUTH PLAIN` are base64-encoded, not
encrypted) and full message bodies — is transmitted as cleartext on the wire.

## Why It's Dangerous

Any party with visibility into the network path (a shared Wi-Fi segment, a
compromised switch, a malicious upstream router, or a lawful/unlawful
interception point) can passively capture full email content and credentials
with a simple packet capture — no active attack is required. Captured
credentials are frequently reused across other services, turning a single
sniffed session into a broader account-compromise incident.

## Standards & Compliance References

- RFC 5321 (SMTP) and RFC 3501 (IMAP4) define these protocols without
  mandatory encryption; RFC 3207 (STARTTLS for SMTP) and RFC 2595
  (STARTTLS for IMAP/POP3) define the opportunistic upgrade path.
- Regulatory frameworks that treat unencrypted transmission of personal or
  financial data as a compliance failure: GDPR Art. 32, HIPAA Security Rule
  (45 CFR §164.312(e)), PCI DSS Requirement 4.

## Remediation

- Enforce STARTTLS or implicit TLS (SMTPS/587, IMAPS/993, POP3S/995) and
  reject connections that fall back to plaintext.
- Disable legacy plaintext listener ports (25 for submission, 110, 143)
  where they are not required for MX-to-MX relay.
- Monitor for STARTTLS-stripping downgrade attempts at the network boundary.
