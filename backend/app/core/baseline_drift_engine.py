"""
Cryptographic Drift & Baseline Analysis Engine for SecureMailScope (USP 6)

Provides:
1. Baseline management: Creation, versioning, persistence, and retrieval of reference baselines.
2. Normalized observation extraction from packet capture analysis.
3. Multi-property drift comparison with granular diff classification.
4. Security significance evaluation (Weakened vs Strengthened vs Policy Violation vs Benign).
5. Drift history recording and temporal trend tracking.
"""

import os
import json
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
BASELINES_DIR = DATA_DIR / "baselines"
DRIFT_HISTORY_DIR = DATA_DIR / "drift_history"

BASELINES_DIR.mkdir(parents=True, exist_ok=True)
DRIFT_HISTORY_DIR.mkdir(parents=True, exist_ok=True)


class DiffClassification:
    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    UNKNOWN = "UNKNOWN"
    INCOMPARABLE = "INCOMPARABLE"


class SecuritySignificance:
    POTENTIALLY_WEAKENED = "POTENTIALLY_WEAKENED"
    POTENTIALLY_STRENGTHENED = "POTENTIALLY_STRENGTHENED"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    POLICY_COMPLIANT = "POLICY_COMPLIANT"
    BENIGN_CHANGE = "BENIGN_CHANGE"
    UNRESOLVED = "UNRESOLVED"


class BaselineDriftEngine:
    """
    Core engine for establishing cryptographic baselines and computing
    forensically grounded drift comparisons against subsequent captures.
    """

    def __init__(self):
        self._seed_default_baselines()

    def _seed_default_baselines(self):
        """Seed standard industrial & RFC baselines if none exist"""
        default_nist = BASELINES_DIR / "nist_sp800_52r2.json"
        if not default_nist.exists():
            baseline_data = {
                "baseline_id": "nist_sp800_52r2",
                "name": "NIST SP 800-52 Rev 2 Federal Baseline",
                "description": "Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations in Federal Systems.",
                "version": "1.0",
                "baseline_type": "SECURITY_POLICY",
                "target_endpoint": "ALL_EMAIL_SERVICES",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "properties": {
                    "min_tls_version": "TLS 1.2",
                    "allowed_tls_versions": ["TLS 1.2", "TLS 1.3"],
                    "disallowed_tls_versions": ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"],
                    "approved_ciphers": ["GCM", "POLY1305", "CCM"],
                    "disallowed_ciphers": ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5", "CBC"],
                    "min_rsa_key_size": 2048,
                    "min_ec_key_size": 224,
                    "allow_self_signed": False,
                    "allow_expired": False,
                    "enforce_starttls": True
                },
                "version_history": []
            }
            with open(default_nist, "w") as f:
                json.dump(baseline_data, f, indent=2)

        default_ent = BASELINES_DIR / "secure_enterprise_default.json"
        if not default_ent.exists():
            ent_data = {
                "baseline_id": "secure_enterprise_default",
                "name": "Modern Enterprise Secure Mail Transport Baseline",
                "description": "Standard corporate baseline mandating TLS 1.2+, modern CA-signed certificates, and mandatory STARTTLS.",
                "version": "1.0",
                "baseline_type": "SECURITY_POLICY",
                "target_endpoint": "smtp.enterprise.local:587",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "properties": {
                    "min_tls_version": "TLS 1.2",
                    "allowed_tls_versions": ["TLS 1.2", "TLS 1.3"],
                    "disallowed_tls_versions": ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"],
                    "approved_ciphers": ["AES-GCM", "CHACHA20-POLY1305"],
                    "disallowed_ciphers": ["RC4", "DES", "3DES", "NULL", "EXPORT"],
                    "min_rsa_key_size": 2048,
                    "min_ec_key_size": 224,
                    "allow_self_signed": False,
                    "allow_expired": False,
                    "enforce_starttls": True
                },
                "version_history": []
            }
            with open(default_ent, "w") as f:
                json.dump(ent_data, f, indent=2)

    def create_baseline_from_analysis(
        self,
        analysis_data: Dict[str, Any],
        name: str,
        description: str,
        target_endpoint: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Creates an observed empirical baseline directly from actual capture analysis results.
        """
        capture_id = analysis_data.get("capture_id") or "unknown"
        norm = self.extract_normalized_observation(analysis_data, target_endpoint)

        baseline_id = f"baseline_{uuid.uuid4().hex[:8]}"
        now = datetime.now().isoformat()

        baseline_record = {
            "baseline_id": baseline_id,
            "name": name or f"Observed Baseline from #{capture_id}",
            "description": description or f"Empirical cryptographic baseline established from capture {analysis_data.get('original_filename', capture_id)}.",
            "version": "1.0",
            "baseline_type": "OBSERVED_TRAFFIC",
            "source_capture_id": capture_id,
            "target_endpoint": target_endpoint or norm.get("primary_endpoint") or "Default Mail Service",
            "created_at": now,
            "updated_at": now,
            "properties": {
                "min_tls_version": norm.get("lowest_tls_version") or "TLS 1.2",
                "allowed_tls_versions": norm.get("observed_tls_versions", []),
                "disallowed_tls_versions": ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"],
                "approved_ciphers": norm.get("observed_ciphers", []),
                "disallowed_ciphers": ["RC4", "DES", "3DES", "NULL", "EXPORT"],
                "min_rsa_key_size": norm.get("lowest_rsa_key_size") or 2048,
                "min_ec_key_size": norm.get("lowest_ec_key_size") or 224,
                "allow_self_signed": False,
                "allow_expired": False,
                "enforce_starttls": norm.get("starttls_status") == "UPGRADED_SUCCESSFUL",
                "observed_fingerprints": norm.get("cert_fingerprints", []),
                "observed_subjects": norm.get("cert_subjects", [])
            },
            "raw_observation_snapshot": norm,
            "version_history": []
        }

        file_path = BASELINES_DIR / f"{baseline_id}.json"
        with open(file_path, "w") as f:
            json.dump(baseline_record, f, indent=2)

        return baseline_record

    def update_baseline(
        self,
        baseline_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Updates an existing baseline and archives the previous version in version_history.
        """
        baseline = self.get_baseline(baseline_id)
        if not baseline:
            raise ValueError(f"Baseline '{baseline_id}' not found.")

        # Archive old version
        old_version_record = {
            "version": baseline.get("version", "1.0"),
            "archived_at": datetime.now().isoformat(),
            "properties": baseline.get("properties", {}),
            "description": baseline.get("description", "")
        }
        baseline.setdefault("version_history", []).append(old_version_record)

        # Increment version (e.g. 1.0 -> 1.1)
        try:
            curr_v = float(baseline.get("version", "1.0"))
            new_v = f"{curr_v + 0.1:.1f}"
        except Exception:
            new_v = "2.0"

        baseline["version"] = new_v
        baseline["updated_at"] = datetime.now().isoformat()
        if name:
            baseline["name"] = name
        if description:
            baseline["description"] = description
        if properties:
            baseline["properties"].update(properties)

        file_path = BASELINES_DIR / f"{baseline_id}.json"
        with open(file_path, "w") as f:
            json.dump(baseline, f, indent=2)

        return baseline

    def get_baseline(self, baseline_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a baseline by ID"""
        file_path = BASELINES_DIR / f"{baseline_id}.json"
        if not file_path.exists():
            return None
        with open(file_path, "r") as f:
            return json.load(f)

    def list_baselines(self) -> List[Dict[str, Any]]:
        """Lists summary metadata of all available baselines"""
        self._seed_default_baselines()
        baselines = []
        for p in BASELINES_DIR.glob("*.json"):
            try:
                with open(p, "r") as f:
                    b = json.load(f)
                    baselines.append({
                        "baseline_id": b.get("baseline_id"),
                        "name": b.get("name"),
                        "description": b.get("description"),
                        "version": b.get("version", "1.0"),
                        "baseline_type": b.get("baseline_type", "SECURITY_POLICY"),
                        "target_endpoint": b.get("target_endpoint"),
                        "created_at": b.get("created_at"),
                        "updated_at": b.get("updated_at")
                    })
            except Exception:
                continue
        baselines.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)
        return baselines

    def delete_baseline(self, baseline_id: str) -> bool:
        """Deletes a custom baseline (default baselines protected)"""
        if baseline_id in ("nist_sp800_52r2", "secure_enterprise_default"):
            return False  # Protected default
        file_path = BASELINES_DIR / f"{baseline_id}.json"
        if file_path.exists():
            file_path.unlink()
            return True
        return False

    def extract_normalized_observation(
        self,
        analysis_data: Dict[str, Any],
        target_endpoint: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Extracts standardized cryptographic properties from capture analysis data.
        """
        sessions = analysis_data.get("sessions", [])
        handshakes = analysis_data.get("tls_handshakes", [])
        certs = analysis_data.get("certificates", [])
        summary = analysis_data.get("summary", {})

        # Filter by endpoint if specified
        if target_endpoint and ":" in target_endpoint:
            target_ip, target_port = target_endpoint.split(":")
            filtered_sessions = [
                s for s in sessions
                if target_ip in str(s.get("dst")) or target_ip in str(s.get("src"))
            ]
            if filtered_sessions:
                sessions = filtered_sessions

        tls_versions = list(summary.get("tls_versions", {}).keys())
        if not tls_versions and handshakes:
            tls_versions = list(set(h.get("tls_version") for h in handshakes if h.get("tls_version")))

        all_ciphers = []
        for h in handshakes:
            all_ciphers.extend(h.get("cipher_suites", []))
        all_ciphers = sorted(list(set(all_ciphers)))

        rsa_sizes = [c.get("key_size") for c in certs if c.get("key_size") and (c.get("public_key_algorithm") or "").upper() == "RSA"]
        ec_sizes = [c.get("key_size") for c in certs if c.get("key_size") and (c.get("public_key_algorithm") or "").upper() == "EC"]

        primary_ep = "N/A"
        if sessions:
            s0 = sessions[0]
            primary_ep = f"{s0.get('dst')}:{s0.get('dst_port')}"

        starttls_statuses = list(set(s.get("starttls_status", "NOT_ATTEMPTED") for s in sessions if s.get("starttls_status")))
        primary_starttls = "UPGRADED_SUCCESSFUL" if "UPGRADED_SUCCESSFUL" in starttls_statuses else (starttls_statuses[0] if starttls_statuses else "NOT_ATTEMPTED")

        return {
            "capture_id": analysis_data.get("capture_id"),
            "primary_endpoint": primary_ep,
            "observed_tls_versions": tls_versions,
            "lowest_tls_version": sorted(tls_versions)[0] if tls_versions else None,
            "observed_ciphers": all_ciphers,
            "lowest_rsa_key_size": min(rsa_sizes) if rsa_sizes else None,
            "lowest_ec_key_size": min(ec_sizes) if ec_sizes else None,
            "cert_fingerprints": [c.get("fingerprint_sha256") for c in certs if c.get("fingerprint_sha256")],
            "cert_subjects": [c.get("subject") for c in certs if c.get("subject")],
            "has_expired_cert": any(c.get("is_expired") for c in certs),
            "has_self_signed_cert": any(c.get("is_self_signed") for c in certs),
            "starttls_status": primary_starttls,
            "is_encrypted": any(s.get("encrypted") for s in sessions),
            "plaintext_packets": summary.get("plaintext_packets", 0),
            "total_packets": summary.get("total_packets", 0)
        }

    def compare_analysis_against_baseline(
        self,
        analysis_data: Dict[str, Any],
        baseline_id: str,
        target_endpoint: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes formal cryptographic drift comparison between observed capture data
        and the specified baseline.
        """
        baseline = self.get_baseline(baseline_id)
        if not baseline:
            raise ValueError(f"Baseline '{baseline_id}' does not exist.")

        observed = self.extract_normalized_observation(analysis_data, target_endpoint)
        base_props = baseline.get("properties", {})
        diffs = []

        # 1. TLS Version Evaluation
        base_allowed_tls = set(base_props.get("allowed_tls_versions", ["TLS 1.2", "TLS 1.3"]))
        base_disallowed_tls = set(base_props.get("disallowed_tls_versions", ["SSL 3.0", "TLS 1.0", "TLS 1.1"]))
        obs_tls = observed.get("observed_tls_versions", [])

        if not obs_tls:
            diffs.append({
                "property": "TLS Protocol Versions",
                "baseline_value": list(base_allowed_tls),
                "current_value": "No TLS handshakes observed",
                "diff_type": DiffClassification.UNKNOWN,
                "security_significance": SecuritySignificance.POLICY_VIOLATION if observed.get("plaintext_packets", 0) > 0 else SecuritySignificance.UNRESOLVED,
                "explanation": "No TLS versions could be observed. Plaintext communication detected." if observed.get("plaintext_packets", 0) > 0 else "Capture lacks TLS handshake records.",
                "evidence_ref": "sessions"
            })
        else:
            disallowed_found = [v for v in obs_tls if v in base_disallowed_tls]
            if disallowed_found:
                diffs.append({
                    "property": "TLS Protocol Versions",
                    "baseline_value": list(base_allowed_tls),
                    "current_value": obs_tls,
                    "diff_type": DiffClassification.CHANGED,
                    "security_significance": SecuritySignificance.POLICY_VIOLATION,
                    "explanation": f"Observed deprecated/disallowed protocol version(s): {', '.join(disallowed_found)} (POODLE/BEAST risk).",
                    "evidence_ref": "handshakes"
                })
            elif set(obs_tls) == base_allowed_tls or all(v in base_allowed_tls for v in obs_tls):
                diffs.append({
                    "property": "TLS Protocol Versions",
                    "baseline_value": list(base_allowed_tls),
                    "current_value": obs_tls,
                    "diff_type": DiffClassification.UNCHANGED,
                    "security_significance": SecuritySignificance.POLICY_COMPLIANT,
                    "explanation": "All observed TLS protocol versions comply with baseline mandates.",
                    "evidence_ref": "handshakes"
                })
            else:
                diffs.append({
                    "property": "TLS Protocol Versions",
                    "baseline_value": list(base_allowed_tls),
                    "current_value": obs_tls,
                    "diff_type": DiffClassification.CHANGED,
                    "security_significance": SecuritySignificance.BENIGN_CHANGE,
                    "explanation": f"Observed versions ({obs_tls}) differ from baseline ({list(base_allowed_tls)}) but are not explicitly prohibited.",
                    "evidence_ref": "handshakes"
                })

        # 2. Cipher Suites
        obs_ciphers = observed.get("observed_ciphers", [])
        base_disallowed_ciphers = base_props.get("disallowed_ciphers", ["RC4", "DES", "3DES", "NULL", "EXPORT"])
        weak_ciphers = [c for c in obs_ciphers if any(w.upper() in c.upper() for w in base_disallowed_ciphers)]

        if weak_ciphers:
            diffs.append({
                "property": "Cryptographic Cipher Suites",
                "baseline_value": "Zero weak ciphers (AES-GCM / ChaCha20-Poly1305 only)",
                "current_value": weak_ciphers,
                "diff_type": DiffClassification.CHANGED,
                "security_significance": SecuritySignificance.POTENTIALLY_WEAKENED,
                "explanation": f"Weak or legacy cipher suites negotiated: {', '.join(weak_ciphers[:3])}.",
                "evidence_ref": "handshakes"
            })
        elif obs_ciphers:
            diffs.append({
                "property": "Cryptographic Cipher Suites",
                "baseline_value": "Modern AEAD Ciphers",
                "current_value": obs_ciphers[:3],
                "diff_type": DiffClassification.UNCHANGED,
                "security_significance": SecuritySignificance.POLICY_COMPLIANT,
                "explanation": "All observed cipher suites satisfy approved baseline cipher standards.",
                "evidence_ref": "handshakes"
            })
        else:
            diffs.append({
                "property": "Cryptographic Cipher Suites",
                "baseline_value": "Modern AEAD Ciphers",
                "current_value": "Unobserved / Absent",
                "diff_type": DiffClassification.UNKNOWN,
                "security_significance": SecuritySignificance.UNRESOLVED,
                "explanation": "No cipher suites could be extracted from capture handshake frames.",
                "evidence_ref": "handshakes"
            })

        # 3. Public Key Size (RSA)
        base_rsa_min = base_props.get("min_rsa_key_size", 2048)
        obs_rsa_min = observed.get("lowest_rsa_key_size")

        if obs_rsa_min is None:
            diffs.append({
                "property": "RSA Public Key Length",
                "baseline_value": f">={base_rsa_min}-bit",
                "current_value": "No RSA certificates observed",
                "diff_type": DiffClassification.UNKNOWN,
                "security_significance": SecuritySignificance.UNRESOLVED,
                "explanation": "No RSA public keys present in certificate evidence to evaluate bit strength.",
                "evidence_ref": "certificates"
            })
        elif obs_rsa_min < base_rsa_min:
            diffs.append({
                "property": "RSA Public Key Length",
                "baseline_value": f">={base_rsa_min}-bit",
                "current_value": f"{obs_rsa_min}-bit",
                "diff_type": DiffClassification.CHANGED,
                "security_significance": SecuritySignificance.POLICY_VIOLATION,
                "explanation": f"Sub-standard RSA key length ({obs_rsa_min}-bit) falls below baseline threshold ({base_rsa_min}-bit). Factorization risk.",
                "evidence_ref": "certificates"
            })
        else:
            diffs.append({
                "property": "RSA Public Key Length",
                "baseline_value": f">={base_rsa_min}-bit",
                "current_value": f"{obs_rsa_min}-bit",
                "diff_type": DiffClassification.UNCHANGED,
                "security_significance": SecuritySignificance.POLICY_COMPLIANT,
                "explanation": f"All examined RSA keys ({obs_rsa_min}-bit) meet or exceed baseline security bit strength.",
                "evidence_ref": "certificates"
            })

        # 4. Certificate Validity & Expiration
        if observed.get("has_expired_cert"):
            diffs.append({
                "property": "Certificate Expiration Status",
                "baseline_value": "Active valid certificate within notBefore/notAfter interval",
                "current_value": "Expired certificate(s) presented",
                "diff_type": DiffClassification.CHANGED,
                "security_significance": SecuritySignificance.POLICY_VIOLATION,
                "explanation": "Presented certificate has expired, breaking trust chains.",
                "evidence_ref": "certificates"
            })
        else:
            diffs.append({
                "property": "Certificate Expiration Status",
                "baseline_value": "Active valid certificate",
                "current_value": "Valid unexpired certificate(s)",
                "diff_type": DiffClassification.UNCHANGED,
                "security_significance": SecuritySignificance.POLICY_COMPLIANT,
                "explanation": "Presented certificates are within active validity lifespans.",
                "evidence_ref": "certificates"
            })

        # 5. CA Trust & Self-Signed
        if observed.get("has_self_signed_cert"):
            diffs.append({
                "property": "Public CA Trust Root",
                "baseline_value": "CA-signed certificate",
                "current_value": "Self-signed certificate presented",
                "diff_type": DiffClassification.CHANGED,
                "security_significance": SecuritySignificance.POLICY_VIOLATION,
                "explanation": "Self-signed certificate cannot be authenticated via public trust roots.",
                "evidence_ref": "certificates"
            })
        else:
            diffs.append({
                "property": "Public CA Trust Root",
                "baseline_value": "CA-signed certificate",
                "current_value": "CA-signed certificates presented",
                "diff_type": DiffClassification.UNCHANGED,
                "security_significance": SecuritySignificance.POLICY_COMPLIANT,
                "explanation": "Certificates are signed by distinct issuing authorities.",
                "evidence_ref": "certificates"
            })

        # 6. STARTTLS Enforcement
        base_starttls_req = base_props.get("enforce_starttls", True)
        obs_starttls = observed.get("starttls_status")

        if base_starttls_req and obs_starttls != "UPGRADED_SUCCESSFUL":
            diffs.append({
                "property": "STARTTLS Negotiation Enforcement",
                "baseline_value": "Mandatory STARTTLS Upgrade (UPGRADED_SUCCESSFUL)",
                "current_value": obs_starttls,
                "diff_type": DiffClassification.CHANGED,
                "security_significance": SecuritySignificance.POLICY_VIOLATION,
                "explanation": f"STARTTLS upgrade requirement failed. Session status: {obs_starttls}.",
                "evidence_ref": "sessions"
            })
        else:
            diffs.append({
                "property": "STARTTLS Negotiation Enforcement",
                "baseline_value": "Mandatory STARTTLS Upgrade",
                "current_value": obs_starttls,
                "diff_type": DiffClassification.UNCHANGED,
                "security_significance": SecuritySignificance.POLICY_COMPLIANT,
                "explanation": "STARTTLS negotiation successfully established transport encryption.",
                "evidence_ref": "sessions"
            })

        # Compile metrics
        unchanged_count = sum(1 for d in diffs if d["diff_type"] == DiffClassification.UNCHANGED)
        changed_count = sum(1 for d in diffs if d["diff_type"] == DiffClassification.CHANGED)
        weakened_count = sum(1 for d in diffs if d["security_significance"] in (SecuritySignificance.POTENTIALLY_WEAKENED, SecuritySignificance.POLICY_VIOLATION))
        strengthened_count = sum(1 for d in diffs if d["security_significance"] == SecuritySignificance.POTENTIALLY_STRENGTHENED)

        if weakened_count > 0:
            overall_status = "SECURITY_DEGRADATION_DRIFT"
            badge_color = "#ef4444"
            summary_desc = f"Critical security drift detected: {weakened_count} property/policy violation(s) relative to {baseline.get('name')}."
        elif changed_count > 0:
            overall_status = "ACCEPTABLE_DRIFT"
            badge_color = "#f59e0b"
            summary_desc = f"Moderate configuration drift observed: {changed_count} property change(s) without critical cryptographic weakness."
        else:
            overall_status = "BASELINE_ADHERENT"
            badge_color = "#10b981"
            summary_desc = f"Complete baseline compliance: 100% adherence to {baseline.get('name')} across all inspected properties."

        comparison_id = f"cmp_{uuid.uuid4().hex[:10]}"
        comparison_record = {
            "comparison_id": comparison_id,
            "baseline_id": baseline_id,
            "baseline_name": baseline.get("name"),
            "baseline_version": baseline.get("version", "1.0"),
            "capture_id": analysis_data.get("capture_id"),
            "filename": analysis_data.get("original_filename") or analysis_data.get("filename"),
            "target_endpoint": target_endpoint or observed.get("primary_endpoint"),
            "compared_at": datetime.now().isoformat(),
            "overall_status": overall_status,
            "badge_color": badge_color,
            "summary_description": summary_desc,
            "metrics": {
                "total_properties": len(diffs),
                "unchanged_count": unchanged_count,
                "changed_count": changed_count,
                "weakened_count": weakened_count,
                "strengthened_count": strengthened_count
            },
            "property_diffs": diffs,
            "observed_snapshot": observed
        }

        # Persist comparison to history
        comp_file = DRIFT_HISTORY_DIR / f"{comparison_id}.json"
        with open(comp_file, "w") as f:
            json.dump(comparison_record, f, indent=2)

        return comparison_record

    def get_comparison(self, comparison_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a comparison record by ID"""
        comp_file = DRIFT_HISTORY_DIR / f"{comparison_id}.json"
        if not comp_file.exists():
            return None
        with open(comp_file, "r") as f:
            return json.load(f)

    def list_comparisons(self, capture_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists historical comparisons, optionally filtered by capture ID"""
        comps = []
        for p in DRIFT_HISTORY_DIR.glob("*.json"):
            try:
                with open(p, "r") as f:
                    c = json.load(f)
                    if not capture_id or c.get("capture_id") == capture_id:
                        comps.append({
                            "comparison_id": c.get("comparison_id"),
                            "baseline_id": c.get("baseline_id"),
                            "baseline_name": c.get("baseline_name"),
                            "capture_id": c.get("capture_id"),
                            "filename": c.get("filename"),
                            "target_endpoint": c.get("target_endpoint"),
                            "compared_at": c.get("compared_at"),
                            "overall_status": c.get("overall_status"),
                            "badge_color": c.get("badge_color"),
                            "metrics": c.get("metrics")
                        })
            except Exception:
                continue
        comps.sort(key=lambda x: str(x.get("compared_at") or ""), reverse=True)
        return comps


_drift_engine_instance: Optional[BaselineDriftEngine] = None


def get_drift_engine() -> BaselineDriftEngine:
    global _drift_engine_instance
    if _drift_engine_instance is None:
        _drift_engine_instance = BaselineDriftEngine()
    return _drift_engine_instance


# Alias for backward compatibility
CryptographicDriftEngine = BaselineDriftEngine

