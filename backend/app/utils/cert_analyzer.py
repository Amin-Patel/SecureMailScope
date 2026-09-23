"""
Certificate Extraction, Chain Construction, and CA Trust Hierarchy Validation
Adheres strictly to deterministic X.509 cryptography and RFC 5280 PKI path validation.
Includes RSASSA-PSS and PKCS#1 v1.5 verification, multi-tier chain building, and trust status auditing.
"""

import binascii
import fnmatch
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, ed25519, ed448, rsa, dsa
from cryptography.x509.oid import ExtensionOID, NameOID, ExtendedKeyUsageOID

from app.utils.tshark_helper import TSharkHelper


class CertificateAnalyzer:
    """Extracts, inspects, and validates multi-tier X.509 certificate chains and trust paths."""

    _TRUST_STORE_CACHE: Optional[List[x509.Certificate]] = None

    @classmethod
    def get_trust_store(cls) -> List[x509.Certificate]:
        """Loads and caches Mozilla root CA trust store from certifi."""
        if cls._TRUST_STORE_CACHE is None:
            certs = []
            try:
                with open(certifi.where(), "rb") as f:
                    pem_data = f.read()
                # Load all certificates in bundle
                certs = x509.load_pem_x509_certificates(pem_data)
            except Exception as e:
                print(f"[!] Warning: Failed to load system root trust store: {e}")
            cls._TRUST_STORE_CACHE = certs
        return cls._TRUST_STORE_CACHE

    @staticmethod
    def verify_certificate_signature(child_cert: x509.Certificate, parent_cert: x509.Certificate) -> bool:
        """
        Verifies that child_cert was digitally signed by parent_cert.
        Supports RSA (PKCS#1 v1.5 and RSASSA-PSS), ECDSA, Ed25519, Ed448, and DSA.
        """
        try:
            public_key = parent_cert.public_key()
            sig_bytes = child_cert.signature
            tbs_bytes = child_cert.tbs_certificate_bytes
            sig_hash = child_cert.signature_hash_algorithm

            if isinstance(public_key, rsa.RSAPublicKey):
                if sig_hash is None:
                    return False
                # Try PKCS#1 v1.5 first
                try:
                    public_key.verify(sig_bytes, tbs_bytes, padding.PKCS1v15(), sig_hash)
                    return True
                except Exception:
                    # Fallback to RSASSA-PSS
                    try:
                        public_key.verify(
                            sig_bytes,
                            tbs_bytes,
                            padding.PSS(
                                mgf=padding.MGF1(sig_hash),
                                salt_length=padding.PSS.AUTO
                            ),
                            sig_hash
                        )
                        return True
                    except Exception:
                        return False

            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                if sig_hash is None:
                    return False
                public_key.verify(sig_bytes, tbs_bytes, ec.ECDSA(sig_hash))
                return True
            elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                public_key.verify(sig_bytes, tbs_bytes)
                return True
            elif isinstance(public_key, dsa.DSAPublicKey):
                if sig_hash is None:
                    return False
                public_key.verify(sig_bytes, tbs_bytes, sig_hash)
                return True
            return False
        except Exception:
            return False

    @classmethod
    def extract_and_analyze_chains(cls, pcap_path: str) -> List[Dict]:
        """
        Extracts presented certificate chains from PCAP, builds trust paths against the
        configured trust store, and performs deterministic PKI validation.
        """
        raw_items = TSharkHelper.extract_raw_certificates(pcap_path)
        if not raw_items:
            return []

        # Group presented certificates by TLS stream / frame
        streams_map: Dict[str, List[Dict]] = {}
        for item in raw_items:
            key = f"{item['tcp_stream']}_{item['ip_src']}_{item['ip_dst']}"
            if key not in streams_map:
                streams_map[key] = []
            streams_map[key].append(item)

        analyzed_results = []

        for group_key, items in streams_map.items():
            items.sort(key=lambda x: x['chain_position'])
            presented_certs_parsed: List[Tuple[x509.Certificate, Dict]] = []

            for it in items:
                try:
                    cert_obj = x509.load_der_x509_certificate(it['der_bytes'])
                    presented_certs_parsed.append((cert_obj, it))
                except Exception as e:
                    print(f"[!] Failed to parse X.509 DER certificate: {e}")

            if not presented_certs_parsed:
                continue

            chain_analysis = cls._analyze_single_handshake_chain(presented_certs_parsed)
            analyzed_results.append(chain_analysis)

        return analyzed_results

    @classmethod
    def _analyze_single_handshake_chain(cls, presented: List[Tuple[x509.Certificate, Dict]]) -> Dict:
        now = datetime.now(timezone.utc)
        trust_store = cls.get_trust_store()

        first_cert, first_meta = presented[0]
        sni = first_meta.get('sni') or ''
        frame_number = first_meta.get('frame_number', 0)
        tcp_stream = first_meta.get('tcp_stream', '0')

        # 1. Structure all presented certificates
        structured_presented = []
        for idx, (cert, meta) in enumerate(presented):
            struct_cert = cls._serialize_certificate(cert, is_presented=True, meta=meta, chain_pos=idx)
            structured_presented.append((cert, struct_cert))

        # 2. Build Trust Path:
        leaf_cert, leaf_struct = structured_presented[0]
        
        # Check Hostname / SAN match
        hostname_val = cls._validate_hostname(leaf_struct['subject_alternative_names'], leaf_struct['common_name'], sni)
        leaf_struct['hostname_validation'] = hostname_val

        built_path_structs: List[Dict] = [leaf_struct]
        current_cert = leaf_cert
        current_struct = leaf_struct
        chain_order_valid = True
        signature_valid_throughout = True
        is_untrusted_ca = False
        is_unbuildable_chain = False
        root_ca_found = None

        # Try to link through remaining presented certificates
        presented_pool = list(structured_presented[1:])
        visited = {leaf_cert.serial_number}

        while True:
            # Check if current cert is self-signed (Root CA)
            if current_cert.issuer == current_cert.subject:
                if cls.verify_certificate_signature(current_cert, current_cert):
                    current_struct['is_self_signed'] = True
                    if cls._is_in_trust_store(current_cert, trust_store):
                        current_struct['trust_status'] = 'TRUSTED_ROOT'
                    else:
                        current_struct['trust_status'] = 'UNTRUSTED_ROOT'
                        is_untrusted_ca = True
                    root_ca_found = current_cert
                    break

            # Find parent in presented pool
            parent_found = None
            parent_struct = None
            for idx, (p_cert, p_struct) in enumerate(presented_pool):
                if p_cert.serial_number not in visited and p_cert.subject == current_cert.issuer:
                    aki = current_struct.get('authority_key_identifier')
                    ski = p_struct.get('subject_key_identifier')
                    if aki and ski and aki != ski:
                        continue

                    if cls.verify_certificate_signature(current_cert, p_cert):
                        parent_found = p_cert
                        parent_struct = p_struct
                        if presented_pool.index((p_cert, p_struct)) != 0:
                            chain_order_valid = False
                        presented_pool.pop(idx)
                        break

            if parent_found:
                visited.add(parent_found.serial_number)
                built_path_structs.append(parent_struct)
                current_cert = parent_found
                current_struct = parent_struct
                continue

            # If not in presented pool, check local Trust Store
            trust_anchor = cls._find_in_trust_store(current_cert.issuer, current_struct.get('authority_key_identifier'), trust_store)
            if trust_anchor:
                if cls.verify_certificate_signature(current_cert, trust_anchor):
                    anchor_struct = cls._serialize_certificate(trust_anchor, is_presented=False, meta=None, chain_pos=len(built_path_structs))
                    anchor_struct['trust_status'] = 'TRUSTED_ROOT'
                    built_path_structs.append(anchor_struct)
                    root_ca_found = trust_anchor
                    break
                else:
                    signature_valid_throughout = False

            is_unbuildable_chain = True
            is_untrusted_ca = True
            break

        # 3. Deterministic PKI Findings Collection
        pki_findings = cls._evaluate_pki_rules(
            built_path_structs=built_path_structs,
            leaf_struct=leaf_struct,
            chain_order_valid=chain_order_valid,
            signature_valid=signature_valid_throughout,
            is_unbuildable=is_unbuildable_chain,
            is_untrusted=is_untrusted_ca,
            frame_number=frame_number,
            tcp_stream=tcp_stream,
            sni=sni
        )

        return {
            'frame_number': frame_number,
            'tcp_stream': tcp_stream,
            'sni': sni,
            'leaf_certificate': leaf_struct,
            'presented_chain': [s for _, s in structured_presented],
            'built_trust_path': built_path_structs,
            'chain_depth': len(built_path_structs),
            'chain_order_valid': chain_order_valid,
            'chain_complete': not is_unbuildable_chain,
            'is_trusted': not (is_untrusted_ca or is_unbuildable_chain),
            'pki_findings': pki_findings
        }

    @staticmethod
    def _serialize_certificate(cert: x509.Certificate, is_presented: bool, meta: Optional[Dict], chain_pos: int) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        
        subject_str = cert.subject.rfc4514_string()
        issuer_str = cert.issuer.rfc4514_string()
        
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = cn_attrs[0].value if cn_attrs else subject_str

        issuer_cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer_common_name = issuer_cn_attrs[0].value if issuer_cn_attrs else issuer_str

        serial_hex = f"{cert.serial_number:032X}"

        # Validity
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        is_expired = now > not_after
        not_yet_valid = now < not_before

        pub_key = cert.public_key()
        pub_algo = "UNKNOWN"
        key_size = 0
        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_algo = "RSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_algo = f"ECDSA ({pub_key.curve.name})"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            pub_algo = "Ed25519"
            key_size = 256
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            pub_algo = "Ed448"
            key_size = 448
        elif isinstance(pub_key, dsa.DSAPublicKey):
            pub_algo = "DSA"
            key_size = pub_key.key_size

        sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid.dotted_string)
        sig_hash_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "None"

        ski = None
        try:
            ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            ski = binascii.hexlify(ski_ext.value.digest).decode('ascii')
        except Exception:
            pass

        aki = None
        try:
            aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            if aki_ext.value.key_identifier:
                aki = binascii.hexlify(aki_ext.value.key_identifier).decode('ascii')
        except Exception:
            pass

        is_ca = False
        path_len = None
        try:
            bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            is_ca = bc_ext.value.ca
            path_len = bc_ext.value.path_length
        except Exception:
            pass

        key_usages = []
        try:
            ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku = ku_ext.value
            if ku.digital_signature: key_usages.append("digitalSignature")
            if ku.content_commitment: key_usages.append("nonRepudiation")
            if ku.key_encipherment: key_usages.append("keyEncipherment")
            if ku.data_encipherment: key_usages.append("dataEncipherment")
            if ku.key_agreement: key_usages.append("keyAgreement")
            if ku.key_cert_sign: key_usages.append("keyCertSign")
            if ku.crl_sign: key_usages.append("cRLSign")
        except Exception:
            pass

        ekus = []
        try:
            eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            for oid in eku_ext.value:
                if oid == ExtendedKeyUsageOID.SERVER_AUTH: ekus.append("serverAuth")
                elif oid == ExtendedKeyUsageOID.CLIENT_AUTH: ekus.append("clientAuth")
                elif oid == ExtendedKeyUsageOID.EMAIL_PROTECTION: ekus.append("emailProtection")
                elif oid == ExtendedKeyUsageOID.CODE_SIGNING: ekus.append("codeSigning")
                else: ekus.append(oid.dotted_string)
        except Exception:
            pass

        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = san_ext.value.get_values_for_type(x509.DNSName) + [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
        except Exception:
            pass

        is_self_signed = (cert.issuer == cert.subject)

        trust_status = 'TRUSTED_INTERMEDIATE' if is_ca else 'LEAF'
        if is_self_signed:
            trust_status = 'SELF_SIGNED'

        return {
            'common_name': common_name,
            'subject': subject_str,
            'issuer': issuer_str,
            'issuer_common_name': issuer_common_name,
            'serial_number': serial_hex,
            'fingerprint_sha1': cert.fingerprint(hashes.SHA1()).hex().upper(),
            'not_before': not_before.isoformat(),
            'not_after': not_after.isoformat(),
            'is_expired': is_expired,
            'not_yet_valid': not_yet_valid,
            'public_key_algorithm': pub_algo,
            'key_size': key_size,
            'signature_algorithm': sig_algo,
            'signature_hash_algorithm': sig_hash_algo,
            'subject_key_identifier': ski,
            'authority_key_identifier': aki,
            'is_ca': is_ca,
            'path_length': path_len,
            'key_usages': key_usages,
            'extended_key_usages': ekus,
            'subject_alternative_names': sans,
            'is_self_signed': is_self_signed,
            'is_presented': is_presented,
            'chain_position': chain_pos,
            'trust_status': trust_status,
            'frame_number': meta.get('frame_number') if meta else None,
            'tcp_stream': meta.get('tcp_stream') if meta else None
        }

    @staticmethod
    def _validate_hostname(sans: List[str], common_name: str, sni: str) -> str:
        if not sni:
            return "NOT_DETERMINABLE_FROM_CAPTURE"
        
        sni_clean = sni.strip().lower()
        candidates = [s.strip().lower() for s in sans]
        if common_name:
            candidates.append(common_name.strip().lower())

        for cand in candidates:
            if cand == sni_clean:
                return "MATCH"
            if cand.startswith("*.") and fnmatch.fnmatch(sni_clean, cand):
                return "MATCH"

        return "MISMATCH"

    @classmethod
    def _is_in_trust_store(cls, cert: x509.Certificate, trust_store: List[x509.Certificate]) -> bool:
        for root in trust_store:
            if root.subject == cert.subject and root.public_key() == cert.public_key():
                return True
        return False

    @classmethod
    def _find_in_trust_store(cls, issuer: x509.Name, aki: Optional[str], trust_store: List[x509.Certificate]) -> Optional[x509.Certificate]:
        for root in trust_store:
            if root.subject == issuer:
                if aki:
                    try:
                        ski_ext = root.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                        root_ski = binascii.hexlify(ski_ext.value.digest).decode('ascii')
                        if root_ski == aki:
                            return root
                    except Exception:
                        pass
                return root
        return None

    @staticmethod
    def _evaluate_pki_rules(
        built_path_structs: List[Dict],
        leaf_struct: Dict,
        chain_order_valid: bool,
        signature_valid: bool,
        is_unbuildable: bool,
        is_untrusted: bool,
        frame_number: int,
        tcp_stream: str,
        sni: str
    ) -> List[Dict]:
        findings = []

        # 1. CERT_EXPIRED
        for c in built_path_structs:
            if c['is_expired']:
                findings.append({
                    'rule_id': 'CERT_EXPIRED',
                    'severity': 'HIGH',
                    'title': f"Certificate Expired: {c['common_name']}",
                    'description': f"Certificate for '{c['common_name']}' expired on {c['not_after']}.",
                    'evidence': {
                        'frame': frame_number,
                        'tcp_stream': tcp_stream,
                        'subject': c['subject'],
                        'not_after': c['not_after'],
                        'serial': c['serial_number']
                    },
                    'remediation': "Renew and redeploy the expired certificate."
                })

        # 2. CERT_NOT_YET_VALID
        for c in built_path_structs:
            if c.get('not_yet_valid'):
                findings.append({
                    'rule_id': 'CERT_NOT_YET_VALID',
                    'severity': 'HIGH',
                    'title': f"Certificate Not Yet Valid: {c['common_name']}",
                    'description': f"Certificate for '{c['common_name']}' is not valid until {c['not_before']}.",
                    'evidence': {
                        'frame': frame_number,
                        'tcp_stream': tcp_stream,
                        'subject': c['subject'],
                        'not_before': c['not_before']
                    },
                    'remediation': "Verify system clock synchronization and certificate issuance start timestamp."
                })

        # 3. CERT_HOSTNAME_MISMATCH
        if leaf_struct.get('hostname_validation') == 'MISMATCH':
            findings.append({
                'rule_id': 'CERT_HOSTNAME_MISMATCH',
                'severity': 'HIGH',
                'title': f"Certificate Hostname Mismatch (SNI: {sni})",
                'description': f"The presented certificate does not match the observed TLS SNI '{sni}'.",
                'evidence': {
                    'frame': frame_number,
                    'tcp_stream': tcp_stream,
                    'sni': sni,
                    'certificate_sans': leaf_struct['subject_alternative_names'],
                    'common_name': leaf_struct['common_name']
                },
                'remediation': f"Issue certificate including '{sni}' in Subject Alternative Names (SAN)."
            })

        # 4. CERT_SIGNATURE_INVALID
        if not signature_valid:
            findings.append({
                'rule_id': 'CERT_SIGNATURE_INVALID',
                'severity': 'CRITICAL',
                'title': "Invalid Certificate Cryptographic Signature",
                'description': "Cryptographic signature verification failed between parent and child certificates in the chain.",
                'evidence': {
                    'frame': frame_number,
                    'tcp_stream': tcp_stream
                },
                'remediation': "Inspect CA hierarchy and re-issue the certificate chain."
            })

        # 5. CERT_INVALID_CHAIN_ORDER
        if not chain_order_valid:
            findings.append({
                'rule_id': 'CERT_INVALID_CHAIN_ORDER',
                'severity': 'MEDIUM',
                'title': "Invalid Certificate Chain Order in TLS Handshake",
                'description': "Certificates were presented out of sequence (RFC 5246 requires Leaf followed by successive Intermediate CAs).",
                'evidence': {
                    'frame': frame_number,
                    'tcp_stream': tcp_stream
                },
                'remediation': "Reorder the intermediate certificates bundle on the mail server."
            })

        # 6. CERT_CHAIN_UNBUILDABLE / CERT_UNTRUSTED_CA
        if is_unbuildable or is_untrusted:
            if leaf_struct.get('is_self_signed'):
                findings.append({
                    'rule_id': 'CERT_SELF_SIGNED',
                    'severity': 'MEDIUM',
                    'title': f"Self-Signed Certificate Detected ({leaf_struct['common_name']})",
                    'description': "The endpoint presented a self-signed certificate rather than one signed by a trusted CA.",
                    'evidence': {
                        'frame': frame_number,
                        'tcp_stream': tcp_stream,
                        'subject': leaf_struct['subject']
                    },
                    'remediation': "Deploy certificates issued by a publicly trusted CA (e.g. Let's Encrypt)."
                })
            else:
                findings.append({
                    'rule_id': 'CERT_UNTRUSTED_CA',
                    'severity': 'HIGH',
                    'title': "Untrusted Certificate Authority / Incomplete Chain",
                    'description': "Certificate chain could not be anchored to a known trusted Root CA in the trust store.",
                    'evidence': {
                        'frame': frame_number,
                        'tcp_stream': tcp_stream,
                        'issuer': leaf_struct['issuer']
                    },
                    'remediation': "Ensure all intermediate certificates are installed on the server and use a trusted CA."
                })

        # 7. CERT_INVALID_EKU
        if leaf_struct.get('extended_key_usages') and 'serverAuth' not in leaf_struct['extended_key_usages']:
            findings.append({
                'rule_id': 'CERT_INVALID_EKU',
                'severity': 'MEDIUM',
                'title': "Missing serverAuth in Extended Key Usage",
                'description': "Leaf certificate Extended Key Usage does not allow TLS Server Authentication ('serverAuth').",
                'evidence': {
                    'frame': frame_number,
                    'tcp_stream': tcp_stream,
                    'ekus': leaf_struct['extended_key_usages']
                },
                'remediation': "Include 'serverAuth' (OID 1.3.6.1.5.5.7.3.1) in Extended Key Usage extension."
            })

        # 8. CERT_INVALID_BASIC_CONSTRAINTS
        for idx, c in enumerate(built_path_structs[1:], 1):
            if not c.get('is_ca'):
                findings.append({
                    'rule_id': 'CERT_INVALID_BASIC_CONSTRAINTS',
                    'severity': 'CRITICAL',
                    'title': f"Intermediate CA Missing Basic Constraints CA:TRUE ({c['common_name']})",
                    'description': f"Certificate at position {idx} acted as an intermediate signer but has CA:FALSE.",
                    'evidence': {
                        'frame': frame_number,
                        'tcp_stream': tcp_stream,
                        'subject': c['subject']
                    },
                    'remediation': "Ensure signing certificates have Basic Constraints CA:TRUE and keyCertSign usage."
                })

        return findings

    @staticmethod
    def extract_certificates(pcap_path: str) -> List[Dict]:
        """Backward compatibility wrapper returning flat list of parsed certificates."""
        chains = CertificateAnalyzer.extract_and_analyze_chains(pcap_path)
        flat_certs = []
        seen = set()
        for ch in chains:
            for c in ch['presented_chain']:
                if c['serial_number'] not in seen:
                    seen.add(c['serial_number'])
                    flat_certs.append(c)
        return flat_certs