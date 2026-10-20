"""
Passive SPF / DKIM / DMARC analysis from captured traffic.

Everything here is derived only from what is inside the PCAP -- no DNS
queries, no network access. Two evidence sources:

1. Message headers in *unencrypted* mail streams (SMTP DATA, IMAP/POP3
   fetches): Authentication-Results, Received-SPF and DKIM-Signature.
2. Plaintext DNS responses in the capture carrying SPF/DMARC/DKIM TXT
   records (the actual published policy, when a resolver lookup was
   captured).

Limits, stated in the output rather than glossed over:
- Encrypted streams (TLS) hide message headers, so they contribute nothing.
- SPF/DKIM/DMARC *results* are what a receiving server wrote into the
  headers. We report them as asserted; we do not independently verify
  signatures (that would need the DKIM public key from live DNS).
- A message with no Authentication-Results simply has no recorded verdict
  (typical on the sending leg); that is reported as "not asserted", not
  as a failure.
"""

import base64
import re
from typing import Dict, List, Optional, Tuple

_HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):[ \t]?(.*)$")
_BLOCK_MARKERS = {"from", "received", "dkim-signature", "authentication-results", "received-spf"}
_AUTH_METHODS = ("spf", "dkim", "dmarc", "arc")
_SPF_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}
_TWO_LEVEL_SLDS = {"co", "com", "org", "net", "gov", "ac", "edu"}

LIMITATIONS = [
    "Derived only from the captured traffic; no DNS lookups were performed.",
    "Verdicts are as asserted in message headers by the servers that handled the mail; signatures are not independently verified.",
    "Encrypted (TLS) streams hide message headers, so only plaintext mail traffic can be inspected.",
]


# ─── HEADER EXTRACTION ───

def _unfold_block(lines: List[str]) -> Dict[str, List[str]]:
    fields: Dict[str, List[str]] = {}
    current: Optional[Tuple[str, List[str]]] = None
    for line in lines:
        if line[:1] in (" ", "\t") and current:
            current[1][-1] += " " + line.strip()
            continue
        m = _HEADER_RE.match(line)
        if not m:
            continue
        name = m.group(1).lower()
        fields.setdefault(name, []).append(m.group(2).strip())
        current = (name, fields[name])
    return fields


def extract_header_blocks(text: str) -> List[Dict[str, List[str]]]:
    """Find RFC 5322 header blocks in a chunk of stream text. A block needs
    several header lines including one of From/Received/DKIM/auth headers, so
    protocol chatter (MAIL FROM:, +OK, IMAP tags) is not mistaken for mail."""
    blocks: List[Dict[str, List[str]]] = []
    current: List[str] = []

    def flush():
        nonlocal current
        if len(current) >= 3:
            fields = _unfold_block(current)
            if _BLOCK_MARKERS & set(fields):
                blocks.append(fields)
        current = []

    for line in re.split(r"\r?\n", text):
        if _HEADER_RE.match(line) or (current and line[:1] in (" ", "\t") and line.strip()):
            current.append(line)
        else:
            flush()
    flush()
    return blocks


# ─── HEADER PARSING ───

def _domain_of(address: str) -> str:
    m = re.search(r"@([A-Za-z0-9.-]+)", address or "")
    return m.group(1).lower().rstrip(".") if m else ""


def _org_domain(domain: str) -> str:
    """Approximate organizational domain (no public-suffix list)."""
    labels = [l for l in domain.lower().split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _TWO_LEVEL_SLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def parse_authentication_results(value: str) -> List[Dict]:
    results = []
    for part in value.split(";")[1:]:  # first token is the authserv-id
        m = re.match(r"\s*(\w[\w-]*)\s*=\s*(\w+)", part)
        if not m or m.group(1).lower() not in _AUTH_METHODS:
            continue
        props = dict(re.findall(r"([\w]+\.[\w]+)\s*=\s*([^\s;()]+)", part))
        policy = re.search(r"\(\s*p=(\w+)", part, re.IGNORECASE)
        results.append({
            "method": m.group(1).lower(),
            "result": m.group(2).lower(),
            "properties": {k.lower(): v for k, v in props.items()},
            "policy": policy.group(1).lower() if policy else None,
        })
    return results


def parse_dkim_signature(value: str) -> Dict:
    tags: Dict[str, str] = {}
    for part in value.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = re.sub(r"\s+", "", v)
    signed = [h for h in tags.get("h", "").lower().split(":") if h]
    return {
        "domain": tags.get("d", "").lower(),
        "selector": tags.get("s", ""),
        "algorithm": tags.get("a", "").lower(),
        "canonicalization": tags.get("c", ""),
        "signed_headers": signed,
        "body_length_limit": tags.get("l"),
        "has_expiry": "x" in tags,
    }


def _aligned(from_domain: str, d: str) -> bool:
    return bool(from_domain and d and _org_domain(from_domain) == _org_domain(d))


def analyze_message(fields: Dict[str, List[str]]) -> Dict:
    from_domain = _domain_of((fields.get("from") or [""])[0])
    results = [r for v in fields.get("authentication-results", []) for r in parse_authentication_results(v)]
    signatures = [parse_dkim_signature(v) for v in fields.get("dkim-signature", [])]
    for sig in signatures:
        sig["aligned_with_from"] = _aligned(from_domain, sig["domain"])
        sig["signs_from_header"] = "from" in sig["signed_headers"]

    spf_header = (fields.get("received-spf") or [""])[0]
    spf_from_header = spf_header.split(None, 1)[0].lower() if spf_header else ""
    spf_result = next((r["result"] for r in results if r["method"] == "spf"), None)
    spf_source = "Authentication-Results" if spf_result else None
    if not spf_result and spf_from_header in _SPF_RESULTS:
        spf_result, spf_source = spf_from_header, "Received-SPF"

    dkim_results = [r["result"] for r in results if r["method"] == "dkim"]
    dmarc = next((r for r in results if r["method"] == "dmarc"), None)

    return {
        "from_domain": from_domain,
        "return_path_domain": _domain_of((fields.get("return-path") or [""])[0]),
        "spf": {"result": spf_result, "source": spf_source},
        "dkim": {"signatures": signatures, "results": dkim_results},
        "dmarc": {"result": dmarc["result"] if dmarc else None, "policy": dmarc["policy"] if dmarc else None},
        "has_arc": "arc-seal" in fields,
    }


# ─── STREAM WALKING ───

def extract_messages(tcp_streams: Dict[str, Dict]) -> Tuple[List[Dict], int, int]:
    """Returns (messages, plaintext_stream_count, encrypted_stream_count)
    over mail-protocol streams."""
    messages: List[Dict] = []
    plaintext = encrypted = 0
    for st in tcp_streams.values():
        if st.get("protocol") == "TCP":
            continue  # not a mail port
        if st.get("encrypted"):
            encrypted += 1
            continue
        plaintext += 1
        seen_blocks = set()  # the same message can appear in both directions (echoes, retransmits)
        # An SMTP server never sends message headers to the client, so only the
        # submitted (client->server) side is real; IMAP/POP3 messages arrive server->client
        # but IMAP APPEND can send them the other way, so both are read there.
        directions = ("client_to_server",) if str(st.get("protocol", "")).startswith("SMTP")             else ("client_to_server", "server_to_client")
        for direction in directions:
            text = "".join(c["payload"] for c in st.get("chunks", []) if c.get("direction") == direction)
            for fields in extract_header_blocks(text):
                message_id = (fields.get("message-id") or [""])[0]
                fingerprint = message_id or repr(sorted((k, tuple(v)) for k, v in fields.items()))
                if fingerprint in seen_blocks:
                    continue
                seen_blocks.add(fingerprint)
                msg = analyze_message(fields)
                msg.update({
                    "stream_id": st.get("stream_id"),
                    "protocol": st.get("protocol"),
                    "direction": direction,
                    "client": st.get("client"),
                    "server": st.get("server"),
                })
                messages.append(msg)
    return messages, plaintext, encrypted


# ─── DNS RECORDS ───

def _rsa_bits_from_dkim(record: str) -> Optional[int]:
    m = re.search(r"\bp=([A-Za-z0-9+/=\s]+)", record)
    if not m or not m.group(1).strip():
        return None
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = load_der_public_key(base64.b64decode(re.sub(r"\s+", "", m.group(1))))
        return key.key_size if isinstance(key, rsa.RSAPublicKey) else None
    except Exception:
        return None


def analyze_dns_records(dns_records: List[Dict]) -> List[Dict]:
    """dns_records: [{'name': qname, 'txt': [strings], 'frame': n}] from plaintext DNS responses."""
    out = []
    for rec in dns_records:
        name = (rec.get("name") or "").lower().rstrip(".")
        txts = rec.get("txt") or []
        if "._domainkey." in name:
            text = "".join(txts)
            if "p=" in text.lower():
                out.append({"kind": "dkim", "name": name, "domain": name.split("._domainkey.", 1)[1],
                            "selector": name.split("._domainkey.", 1)[0], "record": text,
                            "rsa_bits": _rsa_bits_from_dkim(text), "frame": rec.get("frame")})
            continue
        for text in txts:
            low = text.lower().strip()
            if low.startswith("v=spf1"):
                terms = low.split()
                allq = next((t for t in reversed(terms) if t.lstrip("+-~?") == "all"), None)
                out.append({"kind": "spf", "name": name, "domain": name, "record": text,
                            "all_qualifier": allq, "frame": rec.get("frame")})
            elif low.startswith("v=dmarc1") and name.startswith("_dmarc."):
                tags = {k.strip(): v.strip() for k, v in (p.split("=", 1) for p in low.split(";") if "=" in p)}
                out.append({"kind": "dmarc", "name": name, "domain": name[len("_dmarc."):], "record": text,
                            "policy": tags.get("p"), "pct": tags.get("pct"), "frame": rec.get("frame")})
    return out


# ─── ISSUES ───

def _issue(rule_id: str, severity: str, title: str, description: str, remediation: str, affected: List[str]) -> Dict:
    return {"rule_id": rule_id, "severity": severity, "title": title, "description": description,
            "remediation": remediation, "affected": sorted(set(affected))}


def derive_issues(messages: List[Dict], dns: List[Dict]) -> List[Dict]:
    buckets: Dict[str, List[str]] = {}

    def add(rule: str, label: str):
        buckets.setdefault(rule, []).append(label)

    for i, msg in enumerate(messages, 1):
        label = f"message {i} (From: {msg['from_domain'] or 'unknown'}, stream {msg['stream_id']})"
        spf = msg["spf"]["result"]
        if spf == "fail":
            add("EMAILAUTH_SPF_FAIL", label)
        elif spf in ("softfail", "permerror"):
            add("EMAILAUTH_SPF_SOFTFAIL", label)
        if any(r in ("fail", "permerror") for r in msg["dkim"]["results"]):
            add("EMAILAUTH_DKIM_FAIL", label)
        if msg["dmarc"]["result"] == "fail":
            add("EMAILAUTH_DMARC_FAIL", label)
        sigs = msg["dkim"]["signatures"]
        if not sigs:
            add("EMAILAUTH_DKIM_MISSING", label)
        for sig in sigs:
            if sig["algorithm"] == "rsa-sha1":
                add("EMAILAUTH_DKIM_WEAK_ALGORITHM", f"{label}, d={sig['domain']}")
            if not sig["signs_from_header"]:
                add("EMAILAUTH_DKIM_FROM_UNSIGNED", f"{label}, d={sig['domain']}")
            if sig["body_length_limit"] is not None:
                add("EMAILAUTH_DKIM_BODY_LENGTH_LIMIT", f"{label}, d={sig['domain']}")
            if msg["from_domain"] and not sig["aligned_with_from"]:
                add("EMAILAUTH_DKIM_MISALIGNED", f"{label}, d={sig['domain']}")

    for rec in dns:
        where = f"{rec['name']} (frame {rec['frame']})"
        if rec["kind"] == "spf" and rec["all_qualifier"] in ("+all", "all", "?all"):
            add("EMAILAUTH_DNS_SPF_PERMISSIVE", f"{where}: {rec['all_qualifier']}")
        elif rec["kind"] == "dmarc" and rec["policy"] in (None, "none"):
            add("EMAILAUTH_DNS_DMARC_WEAK", f"{where}: p={rec['policy'] or 'missing'}")
        elif rec["kind"] == "dkim" and rec["rsa_bits"] and rec["rsa_bits"] < 2048:
            sev_rule = "EMAILAUTH_DNS_DKIM_WEAK_KEY_1024" if rec["rsa_bits"] < 1024 else "EMAILAUTH_DNS_DKIM_WEAK_KEY_2048"
            add(sev_rule, f"{where}: {rec['rsa_bits']}-bit RSA")

    catalog = {
        "EMAILAUTH_SPF_FAIL": ("HIGH", "SPF Failure Recorded on Message",
            "The receiving server recorded an SPF failure: the sending host was not authorized by the sender domain.",
            "Investigate the source of these messages; if legitimate, add the sending host to the domain's SPF record."),
        "EMAILAUTH_SPF_SOFTFAIL": ("MEDIUM", "SPF Soft-Fail or Error Recorded on Message",
            "SPF returned softfail/permerror: the sender is not authorized, or the SPF record is broken.",
            "Fix the SPF record (syntax, lookup limit) or authorize the sending host; move from ~all to -all once stable."),
        "EMAILAUTH_DKIM_FAIL": ("HIGH", "DKIM Verification Failure Recorded on Message",
            "A receiving server recorded a DKIM failure: the signature did not verify, so content or headers may have been altered or the key is wrong.",
            "Check the signing selector's published key and ensure no intermediary modifies signed headers or body."),
        "EMAILAUTH_DMARC_FAIL": ("HIGH", "DMARC Failure Recorded on Message",
            "DMARC evaluation failed: neither SPF nor DKIM produced an aligned pass for the From domain, a hallmark of spoofing.",
            "Align SPF and/or DKIM with the From domain, and enforce p=quarantine or p=reject once aligned."),
        "EMAILAUTH_DKIM_WEAK_ALGORITHM": ("MEDIUM", "DKIM Signature Uses rsa-sha1",
            "rsa-sha1 is deprecated for DKIM (RFC 8301) because SHA-1 collision attacks weaken it.",
            "Sign with rsa-sha256 (or ed25519-sha256)."),
        "EMAILAUTH_DKIM_FROM_UNSIGNED": ("HIGH", "DKIM Signature Does Not Cover the From Header",
            "The signature's h= list omits From, so an attacker can change the visible sender without breaking the signature (RFC 6376 requires From to be signed).",
            "Include From in the signed header list (h=)."),
        "EMAILAUTH_DKIM_BODY_LENGTH_LIMIT": ("MEDIUM", "DKIM Signature Uses a Body Length Limit (l=)",
            "The l= tag lets anyone append content after the signed portion without invalidating the signature.",
            "Remove the l= tag from DKIM signing configuration."),
        "EMAILAUTH_DKIM_MISALIGNED": ("MEDIUM", "DKIM Signing Domain Not Aligned With From Domain",
            "The signature's d= domain differs from the From domain, so it does not help DMARC and proves nothing about the visible sender.",
            "Sign with a d= domain that matches (or is a subdomain of) the From domain."),
        "EMAILAUTH_DKIM_MISSING": ("LOW", "Message Carries No DKIM Signature",
            "No DKIM-Signature header was present, so the content's origin and integrity cannot be verified by recipients.",
            "Enable DKIM signing on the outbound mail server."),
        "EMAILAUTH_DNS_SPF_PERMISSIVE": ("HIGH", "Published SPF Record Authorizes All Senders",
            "A captured DNS response shows an SPF record ending in +all/?all, which offers no protection against spoofing.",
            "End the SPF record with -all (or ~all while rolling out)."),
        "EMAILAUTH_DNS_DMARC_WEAK": ("MEDIUM", "Published DMARC Policy Is Not Enforcing",
            "A captured DNS response shows DMARC with p=none or no policy, so spoofed mail is still delivered.",
            "Move to p=quarantine and then p=reject after reviewing aggregate reports."),
        "EMAILAUTH_DNS_DKIM_WEAK_KEY_1024": ("HIGH", "Published DKIM Key Is Under 1024 Bits",
            "A captured DKIM key record is a sub-1024-bit RSA key, which can be factored with modest resources.",
            "Rotate to a 2048-bit RSA key."),
        "EMAILAUTH_DNS_DKIM_WEAK_KEY_2048": ("MEDIUM", "Published DKIM Key Is Under 2048 Bits",
            "A captured DKIM key record is a 1024-bit RSA key, below the 2048-bit recommendation.",
            "Rotate to a 2048-bit RSA key."),
    }
    return [_issue(rule, *catalog[rule], affected) for rule, affected in buckets.items()]


# ─── ENTRY POINT ───

def analyze(tcp_streams: Dict[str, Dict], dns_txt_records: Optional[List[Dict]] = None) -> Dict:
    messages, plaintext, encrypted = extract_messages(tcp_streams or {})
    dns = analyze_dns_records(dns_txt_records or [])

    def count(getter) -> Dict[str, int]:
        tally: Dict[str, int] = {}
        for m in messages:
            v = getter(m) or "not_asserted"
            tally[v] = tally.get(v, 0) + 1
        return tally

    return {
        "passive": True,
        "source": "captured_traffic_only",
        "summary": {
            "messages_analyzed": len(messages),
            "plaintext_mail_streams": plaintext,
            "encrypted_mail_streams": encrypted,
            "dns_records_found": len(dns),
            "spf": count(lambda m: m["spf"]["result"]),
            "dmarc": count(lambda m: m["dmarc"]["result"]),
            "dkim_signed": sum(1 for m in messages if m["dkim"]["signatures"]),
        },
        "messages": messages,
        "dns_records": dns,
        "issues": derive_issues(messages, dns),
        "limitations": LIMITATIONS,
    }
