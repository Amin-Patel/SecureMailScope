"""
SPF / DKIM / DMARC checks for a domain.

IMPORTANT: this is an ACTIVE check. It issues live DNS TXT lookups and is
not derived from the captured traffic. It is a user-initiated feature and
is deliberately kept out of the passive PCAP findings/risk score (results
carry check_type="active_dns_lookup"). The passive counterpart, which reads
the same kinds of evidence out of a capture, is email_auth_analyzer.py.

Each result also carries `alerts`: dangerous-looking published records
(permissive SPF, non-enforcing DMARC, weak DKIM keys, ...).
"""

import re
from typing import Callable, Dict, List, Optional

import dns.exception
import dns.resolver

from services.email_auth_analyzer import _rsa_bits_from_dkim

CHECK_TYPE = "active_dns_lookup"
DNS_TIMEOUT_SECONDS = 5.0

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)
_SELECTOR_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?$")

# DKIM selectors can't be enumerated from DNS; these are common defaults
# tried only when the caller doesn't supply one.
COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2"]

# (query_name, record_type) -> list of TXT strings; raises LookupError-like via DNSLookupError
TxtResolver = Callable[[str], List[str]]


class DNSLookupError(Exception):
    """A lookup failed for a reason other than 'no such record' (timeout, SERVFAIL...)."""


def normalize_domain(domain: str) -> str:
    d = (domain or "").strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(d):
        raise ValueError(f"Not a valid domain name: {domain!r}")
    return d


def default_txt_resolver(name: str) -> List[str]:
    """Return the TXT record strings at `name`; [] if the name/record doesn't exist."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT_SECONDS
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.exception.DNSException) as e:
        raise DNSLookupError(f"{type(e).__name__} looking up {name}") from e
    # A TXT record may be split into multiple <=255-byte strings; they concatenate.
    return ["".join(part.decode("utf-8", "replace") for part in rdata.strings) for rdata in answer]


def _result(status: str, summary: str, record: Optional[str] = None, **extra) -> Dict:
    return {"status": status, "summary": summary, "record": record, **extra}


# ─── SPF ───

def check_spf(domain: str, resolve: TxtResolver = default_txt_resolver) -> Dict:
    try:
        records = [r for r in resolve(domain) if r.lower().startswith("v=spf1")]
    except DNSLookupError as e:
        return _result("error", str(e))

    if not records:
        return _result("missing", "No SPF record published; anyone can spoof this domain's envelope sender without an SPF fail.")
    if len(records) > 1:
        return _result("fail", "Multiple SPF records published; receivers treat this as a permanent error (RFC 7208 §4.5).", records[0])

    record = records[0]
    terms = record.lower().split()
    qualifier = next((t for t in reversed(terms) if t.lstrip("+-~?") == "all"), None)
    if qualifier == "-all":
        return _result("pass", "SPF ends in -all: unauthorized senders are rejected.", record)
    if qualifier == "~all":
        return _result("warn", "SPF ends in ~all (soft fail): spoofed mail is flagged but usually still delivered.", record)
    if qualifier in ("?all", "all", "+all"):
        return _result("fail", f"SPF ends in {qualifier}: it authorizes or ignores unauthorized senders, offering no protection.", record)
    if any(t.startswith("redirect=") for t in terms):
        return _result("pass", "SPF delegates to another domain via redirect=; policy is defined there.", record)
    return _result("warn", "SPF record has no terminating 'all' mechanism, so unlisted senders get a neutral result.", record)


# ─── DMARC ───

def check_dmarc(domain: str, resolve: TxtResolver = default_txt_resolver) -> Dict:
    try:
        records = [r for r in resolve(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
    except DNSLookupError as e:
        return _result("error", str(e))

    if not records:
        return _result("missing", "No DMARC record published; receivers have no policy for spoofed mail from this domain.")

    record = records[0]
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip().lower()
    policy = tags.get("p", "")

    if policy == "reject":
        return _result("pass", "DMARC policy is p=reject: failing mail is rejected.", record, policy=policy)
    if policy == "quarantine":
        return _result("pass", "DMARC policy is p=quarantine: failing mail is sent to spam.", record, policy=policy)
    if policy == "none":
        return _result("warn", "DMARC policy is p=none (monitoring only): spoofed mail is still delivered.", record, policy=policy)
    return _result("fail", "DMARC record has no valid p= policy tag, so it is ignored by receivers.", record, policy=policy or None)


# ─── DKIM ───

def check_dkim(domain: str, selector: Optional[str] = None, resolve: TxtResolver = default_txt_resolver) -> Dict:
    """DKIM public keys live at <selector>._domainkey.<domain>, and selectors are
    chosen by the sender and cannot be discovered from DNS. With no selector we
    probe common defaults, so a 'not_found' result means 'none of those selectors',
    NOT 'DKIM is not deployed'."""
    if selector:
        if not _SELECTOR_RE.match(selector.strip().lower()):
            raise ValueError(f"Not a valid DKIM selector: {selector!r}")
        candidates = [selector.strip().lower()]
    else:
        candidates = COMMON_DKIM_SELECTORS

    errors = 0
    for sel in candidates:
        try:
            records = [r for r in resolve(f"{sel}._domainkey.{domain}") if "p=" in r.lower() or r.lower().startswith("v=dkim1")]
        except DNSLookupError:
            errors += 1
            continue
        if records:
            record = records[0]
            revoked = re.search(r"\bp=\s*(;|$)", record.replace(" ", "")) is not None
            if revoked:
                return _result("fail", f"DKIM key for selector '{sel}' is published with an empty p= (revoked).", record, selector=sel)
            return _result("pass", f"DKIM public key found for selector '{sel}'.", record, selector=sel,
                           rsa_bits=_rsa_bits_from_dkim(record))

    if errors == len(candidates):
        return _result("error", "DNS lookups failed for every DKIM selector tried.")
    tried = ", ".join(candidates)
    if selector:
        return _result("missing", f"No DKIM key at selector '{selector}'.", selector=selector, selectors_tried=candidates)
    return _result(
        "not_found",
        f"No DKIM key found at common selectors ({tried}). This does not prove DKIM is absent; "
        "the sender's selector is unknown. Supply one (e.g. from a message's DKIM-Signature s= tag) to check it.",
        selectors_tried=candidates,
    )


# ─── ALERTS ───

_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
_SPF_LOOKUP_MECHANISMS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


def _alert(severity: str, title: str, detail: str, remediation: str) -> Dict:
    return {"severity": severity, "title": title, "detail": detail, "remediation": remediation}


def derive_alerts(spf: Dict, dkim: Dict, dmarc: Dict) -> List[Dict]:
    """Raise an alert for each dangerous-looking published record."""
    alerts: List[Dict] = []

    if spf["status"] == "missing":
        alerts.append(_alert("MEDIUM", "No SPF record",
                             "Anyone can send mail claiming this domain without failing SPF.",
                             "Publish an SPF record ending in -all."))
    elif spf["status"] == "fail":
        detail = spf["summary"]
        alerts.append(_alert("HIGH", "Dangerous SPF record", detail,
                             "Fix the record: publish exactly one v=spf1 record ending in -all (or ~all while rolling out)."))
    elif spf["status"] == "warn":
        alerts.append(_alert("LOW", "SPF is not strict", spf["summary"], "Move to -all once all senders are listed."))
    if spf.get("record"):
        terms = spf["record"].lower().split()
        lookups = sum(1 for t in terms[1:] if t.lstrip("+-~?").startswith(_SPF_LOOKUP_MECHANISMS))
        if lookups > 10:
            alerts.append(_alert("MEDIUM", "SPF exceeds the 10-DNS-lookup limit",
                                 f"At least {lookups} lookup mechanisms in the top-level record; receivers return permerror above 10, so SPF stops protecting the domain.",
                                 "Flatten includes or remove unused mechanisms."))
        if any(t.lstrip("+-~?") == "ptr" or t.lstrip("+-~?").startswith("ptr:") for t in terms):
            alerts.append(_alert("LOW", "SPF uses the deprecated ptr mechanism",
                                 "ptr is slow, unreliable and discouraged by RFC 7208.", "Replace ptr with ip4/ip6/include."))

    if dmarc["status"] == "missing":
        alerts.append(_alert("MEDIUM", "No DMARC record",
                             "Receivers have no policy for spoofed mail from this domain.", "Publish a DMARC record, starting with p=none plus rua reporting."))
    elif dmarc["status"] == "warn":
        alerts.append(_alert("MEDIUM", "DMARC is monitoring-only (p=none)", dmarc["summary"],
                             "Move to p=quarantine, then p=reject, after reviewing reports."))
    elif dmarc["status"] == "fail":
        alerts.append(_alert("MEDIUM", "DMARC record has no valid policy", dmarc["summary"], "Add a valid p= tag."))

    bits = dkim.get("rsa_bits")
    if dkim["status"] == "fail":
        alerts.append(_alert("MEDIUM", "DKIM key revoked", dkim["summary"], "Publish a new key if signing is still intended."))
    if bits:
        if bits < 1024:
            alerts.append(_alert("HIGH", "Dangerously weak DKIM key",
                                 f"Selector '{dkim.get('selector')}' publishes a {bits}-bit RSA key, which can be factored.", "Rotate to a 2048-bit key."))
        elif bits < 2048:
            alerts.append(_alert("MEDIUM", "Weak DKIM key",
                                 f"Selector '{dkim.get('selector')}' publishes a {bits}-bit RSA key.", "Rotate to a 2048-bit key."))

    alerts.sort(key=lambda a: -_SEVERITY_ORDER[a["severity"]])
    return alerts


# ─── COMBINED ───

def run_email_auth_checks(domain: str, dkim_selector: Optional[str] = None,
                          resolve: TxtResolver = default_txt_resolver) -> Dict:
    domain = normalize_domain(domain)
    spf = check_spf(domain, resolve)
    dkim = check_dkim(domain, dkim_selector, resolve)
    dmarc = check_dmarc(domain, resolve)
    alerts = derive_alerts(spf, dkim, dmarc)
    return {
        "check_type": CHECK_TYPE,
        "domain": domain,
        "note": "Active DNS lookup: reflects the domain's current public DNS, not the captured traffic.",
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "alerts": alerts,
        "alert_level": alerts[0]["severity"] if alerts else "NONE",
    }
