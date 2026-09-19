"""
Threat intel feed for SecureMailScope.

Downloads and caches abuse.ch's SSLBL SSL Certificate Blacklist -- a free,
no-auth-required CSV of SHA1 fingerprints for certificates observed in the
wild on botnet C2 infrastructure. This lets the security engine flag a
certificate that is cryptographically well-formed but known to belong to
malicious infrastructure, which no local/deterministic check can catch on
its own.

Mirrors risk_classifier.py's lazy-singleton, graceful-degradation shape:
if the feed can't be downloaded and no cache exists, lookups simply never
match rather than raising -- a missing feed should never break analysis.
"""

import csv
import io
import os
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Optional, Set

SSLBL_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
CACHE_PATH = Path(__file__).parent.parent.parent / "threat_intel" / "sslbl.csv"
REQUEST_TIMEOUT_SECONDS = 5


class ThreatIntelFeed:
    """In-memory lookup over the cached SSLBL SHA1 fingerprint blacklist."""

    def __init__(self):
        self.refresh_interval_hours = float(os.getenv("THREAT_INTEL_REFRESH_HOURS", "24"))
        self.fingerprints: Dict[str, Dict[str, str]] = {}
        self.available = False

        if not CACHE_PATH.exists() or self._is_stale():
            self._refresh()
        else:
            self._load_cache()

    def _is_stale(self) -> bool:
        if not CACHE_PATH.exists():
            return True
        age_hours = (time.time() - CACHE_PATH.stat().st_mtime) / 3600
        return age_hours >= self.refresh_interval_hours

    def _refresh(self) -> None:
        """Best-effort download. Falls back to whatever cache already exists
        (even if stale) on failure, and to an empty feed if there's no cache
        at all -- never raises, since threat intel is advisory, not required."""
        try:
            req = urllib.request.Request(SSLBL_URL, headers={"User-Agent": "SecureMailScope/1.0"})
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                raw = response.read().decode("utf-8", errors="replace")
            CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            CACHE_PATH.write_text(raw, encoding="utf-8")
            self._parse(raw)
            self.available = True
            print(f"[+] Threat intel feed refreshed from SSLBL ({len(self.fingerprints)} entries)")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            print(f"[*] Could not refresh SSLBL threat intel feed ({e}); trying cache.")
            if CACHE_PATH.exists():
                self._load_cache()
            else:
                print("[*] No cached threat intel feed available. Threat-intel matching disabled.")

    def _load_cache(self) -> None:
        try:
            raw = CACHE_PATH.read_text(encoding="utf-8")
            self._parse(raw)
            self.available = True
        except OSError as e:
            print(f"[!] Failed to read cached threat intel feed: {e}")

    def _parse(self, raw_csv: str) -> None:
        """SSLBL CSV: `#`-prefixed comment/header lines, then
        Listingdate,SHA1,Listingreason rows."""
        fingerprints: Dict[str, Dict[str, str]] = {}
        lines = [line for line in raw_csv.splitlines() if line and not line.startswith("#")]
        for row in csv.reader(lines):
            if len(row) < 3:
                continue
            listed_since, sha1, reason = row[0].strip(), row[1].strip().upper(), row[2].strip()
            if sha1:
                fingerprints[sha1] = {"listed_since": listed_since, "reason": reason}
        self.fingerprints = fingerprints

    def lookup(self, fingerprint_sha1: Optional[str]) -> Optional[Dict[str, str]]:
        """Returns the SSLBL listing record if this fingerprint is blacklisted, else None."""
        if not fingerprint_sha1 or not self.fingerprints:
            return None
        return self.fingerprints.get(fingerprint_sha1.strip().upper())


_feed_instance: Optional[ThreatIntelFeed] = None


def get_threat_intel_feed() -> ThreatIntelFeed:
    global _feed_instance
    if _feed_instance is None:
        _feed_instance = ThreatIntelFeed()
    return _feed_instance
