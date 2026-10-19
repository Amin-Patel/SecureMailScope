"""
IANA TLS Cipher Suite reference for SecureMailScope.

tshark reports negotiated cipher suites as raw hex codes (e.g. "0x1302"),
not human-readable names -- this registry maps the codes actually relevant
to email-server TLS deployments to their name, key-exchange mechanism,
forward-secrecy status, and known-weak status, so the security engine can
reason about them without re-deriving IANA assignments inline.

Unknown codes are deliberately left unmapped rather than guessed at --
callers should skip a cipher they can't find here rather than assume a
security property that can't be confirmed.
"""

from typing import Dict, Optional, TypedDict


class CipherSuiteInfo(TypedDict):
    name: str
    kex: str  # "RSA", "DHE", "DHE_DSS", "ECDHE", "ECDH", "DH_anon", "ECDH_anon", "NULL", "TLS1.3"
    forward_secret: bool
    weak: bool
    weak_reason: Optional[str]


def _entry(name: str, kex: str, forward_secret: bool, weak: bool, weak_reason: Optional[str] = None) -> CipherSuiteInfo:
    return {"name": name, "kex": kex, "forward_secret": forward_secret, "weak": weak, "weak_reason": weak_reason}


CIPHER_SUITE_REGISTRY: Dict[str, CipherSuiteInfo] = {
    # ─── TLS 1.3 (always ephemeral key exchange -- inherently forward-secret) ───
    "0x1301": _entry("TLS_AES_128_GCM_SHA256", "TLS1.3", True, False),
    "0x1302": _entry("TLS_AES_256_GCM_SHA384", "TLS1.3", True, False),
    "0x1303": _entry("TLS_CHACHA20_POLY1305_SHA256", "TLS1.3", True, False),
    "0x1304": _entry("TLS_AES_128_CCM_SHA256", "TLS1.3", True, False),
    "0x1305": _entry("TLS_AES_128_CCM_8_SHA256", "TLS1.3", True, False),

    # ─── NULL / no encryption ───
    "0x0000": _entry("TLS_NULL_WITH_NULL_NULL", "NULL", False, True, "no encryption (NULL cipher)"),
    "0x0001": _entry("TLS_RSA_WITH_NULL_MD5", "RSA", False, True, "no encryption (NULL cipher)"),
    "0x0002": _entry("TLS_RSA_WITH_NULL_SHA", "RSA", False, True, "no encryption (NULL cipher)"),

    # ─── Export-grade (FREAK-class weakness) ───
    "0x0003": _entry("TLS_RSA_EXPORT_WITH_RC4_40_MD5", "RSA", False, True, "export-grade (40-bit)"),
    "0x0006": _entry("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "RSA", False, True, "export-grade (40-bit)"),
    "0x0008": _entry("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "RSA", False, True, "export-grade (40-bit)"),
    "0x0014": _entry("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "DHE", True, True, "export-grade (40-bit)"),

    # ─── Static RSA key exchange (no forward secrecy) ───
    "0x0004": _entry("TLS_RSA_WITH_RC4_128_MD5", "RSA", False, True, "RC4"),
    "0x0005": _entry("TLS_RSA_WITH_RC4_128_SHA", "RSA", False, True, "RC4"),
    "0x0009": _entry("TLS_RSA_WITH_DES_CBC_SHA", "RSA", False, True, "single DES"),
    "0x000a": _entry("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", False, True, "3DES (Sweet32)"),
    "0x002f": _entry("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", False, False),
    "0x0035": _entry("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", False, False),
    "0x003c": _entry("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", False, False),
    "0x003d": _entry("TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", False, False),
    "0x009c": _entry("TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", False, False),
    "0x009d": _entry("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", False, False),

    # ─── DHE (ephemeral Diffie-Hellman -- forward-secret) ───
    "0x0013": _entry("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "DHE_DSS", True, True, "3DES (Sweet32)"),
    "0x0032": _entry("TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "DHE_DSS", True, False),
    "0x0033": _entry("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE", True, False),
    "0x0038": _entry("TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "DHE_DSS", True, False),
    "0x0039": _entry("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE", True, False),
    "0x0067": _entry("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE", True, False),
    "0x006b": _entry("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE", True, False),
    "0x009e": _entry("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", True, False),
    "0x009f": _entry("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", True, False),

    # ─── Static (EC)DH key exchange (no forward secrecy, less common) ───
    "0xc001": _entry("TLS_ECDH_ECDSA_WITH_NULL_SHA", "ECDH", False, True, "no encryption (NULL cipher)"),
    "0xc003": _entry("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDH", False, True, "3DES (Sweet32)"),
    "0xc004": _entry("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", "ECDH", False, False),
    "0xc005": _entry("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", "ECDH", False, False),
    "0xc00b": _entry("TLS_ECDH_RSA_WITH_NULL_SHA", "ECDH", False, True, "no encryption (NULL cipher)"),
    "0xc00e": _entry("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "ECDH", False, False),
    "0xc00f": _entry("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", "ECDH", False, False),

    # ─── ECDHE (ephemeral elliptic-curve Diffie-Hellman -- forward-secret; the modern default) ───
    "0xc007": _entry("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "ECDHE", True, True, "RC4"),
    "0xc009": _entry("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE", True, False),
    "0xc00a": _entry("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE", True, False),
    "0xc011": _entry("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE", True, True, "RC4"),
    "0xc012": _entry("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", True, True, "3DES (Sweet32)"),
    "0xc013": _entry("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", True, False),
    "0xc014": _entry("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE", True, False),
    "0xc023": _entry("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE", True, False),
    "0xc024": _entry("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE", True, False),
    "0xc027": _entry("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", True, False),
    "0xc028": _entry("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", True, False),
    "0xc02b": _entry("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", True, False),
    "0xc02c": _entry("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", True, False),
    "0xc02f": _entry("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", True, False),
    "0xc030": _entry("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", True, False),
    "0xcca8": _entry("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", True, False),
    "0xcca9": _entry("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", True, False),

    # ─── Anonymous Diffie-Hellman (ephemeral key exchange, but NO authentication --
    #      trivially MITM-able regardless of forward secrecy, so always weak) ───
    "0x0018": _entry("TLS_DH_anon_WITH_RC4_128_MD5", "DH_anon", True, True, "anonymous key exchange (no authentication) + RC4"),
    "0x001b": _entry("TLS_DH_anon_WITH_DES_CBC_SHA", "DH_anon", True, True, "anonymous key exchange (no authentication)"),
    "0x0034": _entry("TLS_DH_anon_WITH_AES_128_CBC_SHA", "DH_anon", True, True, "anonymous key exchange (no authentication)"),
    "0x003a": _entry("TLS_DH_anon_WITH_AES_256_CBC_SHA", "DH_anon", True, True, "anonymous key exchange (no authentication)"),
    "0xc016": _entry("TLS_ECDH_anon_WITH_RC4_128_SHA", "ECDH_anon", True, True, "anonymous key exchange (no authentication) + RC4"),
    "0xc018": _entry("TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "ECDH_anon", True, True, "anonymous key exchange (no authentication)"),
    "0xc019": _entry("TLS_ECDH_anon_WITH_AES_256_CBC_SHA", "ECDH_anon", True, True, "anonymous key exchange (no authentication)"),
}

CIPHER_SUITE_BY_NAME: Dict[str, CipherSuiteInfo] = {
    info["name"].upper(): info for info in CIPHER_SUITE_REGISTRY.values()
}


def lookup(cipher_code_or_name: str) -> Optional[CipherSuiteInfo]:
    """Look up a cipher suite by its raw tshark hex code (case-insensitive) or IANA name."""
    if not cipher_code_or_name:
        return None
    key = cipher_code_or_name.strip()
    return CIPHER_SUITE_REGISTRY.get(key.lower()) or CIPHER_SUITE_BY_NAME.get(key.upper())
