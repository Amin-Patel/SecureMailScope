"""
Test Suite for Authentication, Ownership, IDOR Protection, PCAP Validation,
Path Traversal, and Rate Limiting on SecureMailScope Backend.
"""

import pytest
import jwt
import time
import uuid
from pathlib import Path
from fastapi.testclient import TestClient

from main import app, RESULTS_DIR, UPLOAD_DIR
from app.core.auth import SUPABASE_JWT_SECRET

client = TestClient(app)

# Test User Fixtures
USER_A_ID = "11111111-1111-4111-8111-111111111111"
USER_B_ID = "22222222-2222-4222-8222-222222222222"

SECRET = SUPABASE_JWT_SECRET or "test-suite-fixture-jwt-secret-at-least-32-bytes"
import os
if not os.getenv("SUPABASE_JWT_SECRET"):
    os.environ["JWT_SECRET"] = SECRET


def create_test_jwt(user_id: str, email: str = "user@test.com", expired: bool = False, bad_alg: bool = False, bad_iss: bool = False) -> str:
    now = int(time.time())
    payload = {
        "sub": user_id,
        "email": email,
        "role": "authenticated",
        "iss": "https://invalid-issuer.com" if bad_iss else "https://ymwflcngyzawphnvezmr.supabase.co/auth/v1",
        "iat": now - 3600 if expired else now,
        "exp": now - 60 if expired else now + 3600
    }
    alg = "none" if bad_alg else "HS256"
    if bad_alg:
        return jwt.encode(payload, key="", algorithm=alg)
    return jwt.encode(payload, key=SECRET, algorithm=alg)


@pytest.fixture
def auth_header_user_a():
    token = create_test_jwt(USER_A_ID, "user_a@securemailscope.com")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def auth_header_user_b():
    token = create_test_jwt(USER_B_ID, "user_b@securemailscope.com")
    return {"Authorization": f"Bearer {token}"}


# ─── TEST 1: JWT AUTHENTICATION & CLAIM VALIDATION ───
def test_jwt_auth_required_for_protected_routes():
    # Attempt upload without token
    pcap_bytes = b"\xa1\xb2\xc3\xd4" + b"\x00" * 20
    res = client.post("/api/upload", files={"file": ("test.pcap", pcap_bytes, "application/octet-stream")})
    assert res.status_code == 401
    assert "detail" in res.json()


def test_jwt_expired_token_rejected():
    expired_token = create_test_jwt(USER_A_ID, expired=True)
    res = client.get("/api/analyses", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401
    assert "expired" in res.json()["detail"].lower()


def test_jwt_invalid_signature_rejected():
    fake_token = jwt.encode({"sub": USER_A_ID, "exp": int(time.time()) + 3600}, "wrong-secret-key", algorithm="HS256")
    res = client.get("/api/analyses", headers={"Authorization": f"Bearer {fake_token}"})
    assert res.status_code == 401


def test_jwt_invalid_algorithm_rejected():
    token = create_test_jwt(USER_A_ID, bad_alg=True)
    res = client.get("/api/analyses", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401


def test_jwt_invalid_issuer_rejected():
    token = create_test_jwt(USER_A_ID, bad_iss=True)
    res = client.get("/api/analyses", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401


# ─── TEST 2: PCAP UPLOAD SECURITY & MAGIC BYTE VALIDATION ───
def test_pcap_magic_byte_validation_rejects_fake_pcap(auth_header_user_a):
    fake_bytes = b"MZ\x90\x00" + b"This is an executable not a pcap"
    res = client.post("/api/upload", headers=auth_header_user_a, files={"file": ("fake.pcap", fake_bytes, "application/octet-stream")})
    assert res.status_code == 400
    assert "magic numbers" in res.json()["detail"].lower()


def test_pcap_extension_validation(auth_header_user_a):
    pcap_bytes = b"\xa1\xb2\xc3\xd4" + b"\x00" * 20
    res = client.post("/api/upload", headers=auth_header_user_a, files={"file": ("script.exe", pcap_bytes, "application/octet-stream")})
    assert res.status_code == 400
    assert "Invalid file type" in res.json()["detail"]


# ─── TEST 3: CAPTURE OWNERSHIP & IDOR PROTECTION ───
def test_user_ownership_and_idor_isolation(auth_header_user_a, auth_header_user_b):
    # Setup test analysis records for User A
    cap_a_id = f"test_own_a_{uuid.uuid4().hex[:6]}"
    res_a_file = RESULTS_DIR / f"{cap_a_id}.json"
    data_a = {
        "capture_id": cap_a_id,
        "owner_user_id": USER_A_ID,
        "original_filename": "secret_user_a.pcap",
        "summary": {"risk_score": 10, "risk_level": "LOW", "session_count": 1},
        "findings": [],
        "tcp_streams": {"1": {"stream_id": 1, "protocol": "SMTP", "chunks": []}}
    }
    with open(res_a_file, "w") as f:
        import json
        json.dump(data_a, f)

    try:
        # 1. User A can retrieve their own analysis
        res_a = client.get(f"/api/analysis/{cap_a_id}/results", headers=auth_header_user_a)
        assert res_a.status_code == 200
        assert res_a.json()["capture_id"] == cap_a_id

        # 2. User B CANNOT retrieve User A's analysis (IDOR Check -> 403)
        res_b = client.get(f"/api/analysis/{cap_a_id}/results", headers=auth_header_user_b)
        assert res_b.status_code == 403
        assert "access denied" in res_b.json()["detail"].lower()

        # 3. Unauthenticated request to private capture is rejected (401)
        res_unauth = client.get(f"/api/analysis/{cap_a_id}/results")
        assert res_unauth.status_code == 401

        # 4. User B cannot access User A's stream details (403)
        res_stream = client.get(f"/api/analysis/{cap_a_id}/stream/1", headers=auth_header_user_b)
        assert res_stream.status_code == 403

        # 5. User B cannot generate User A's report (403)
        res_report = client.get(f"/api/analysis/{cap_a_id}/report", headers=auth_header_user_b)
        assert res_report.status_code == 403

        # 6. User B cannot delete User A's capture (403)
        res_del = client.delete(f"/api/analysis/{cap_a_id}", headers=auth_header_user_b)
        assert res_del.status_code == 403

        # 7. User A can delete their own capture (200)
        res_del_ok = client.delete(f"/api/analysis/{cap_a_id}", headers=auth_header_user_a)
        assert res_del_ok.status_code == 200
        assert not res_a_file.exists()

    finally:
        if res_a_file.exists():
            res_a_file.unlink()


# ─── TEST 4: PATH TRAVERSAL ATTEMPTS REJECTED ACROSS ALL ENDPOINTS ───
def test_path_traversal_protection(auth_header_user_a):
    traversal_ids = [
        "../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "test/capture",
        "test\\capture",
        "capture..id",
        "..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//etc/passwd"
    ]
    for tid in traversal_ids:
        # Results endpoint
        res = client.get(f"/api/analysis/{tid}/results", headers=auth_header_user_a)
        assert res.status_code in [400, 404]

        # Stream endpoint
        res_stream = client.get(f"/api/analysis/{tid}/stream/1", headers=auth_header_user_a)
        assert res_stream.status_code in [400, 404]

        # Report endpoint
        res_rep = client.get(f"/api/analysis/{tid}/report", headers=auth_header_user_a)
        assert res_rep.status_code in [400, 404]

        # Delete endpoint
        res_del = client.delete(f"/api/analysis/{tid}", headers=auth_header_user_a)
        assert res_del.status_code in [400, 404]

        # Demo load endpoint
        res_demo = client.post(f"/api/demo/load/{tid}")
        assert res_demo.status_code in [400, 404]


# ─── TEST 5: DEMO PRESET PUBLIC ACCESSIBILITY ───
def test_demo_preset_accessible_without_auth():
    # Samples list is public
    res = client.get("/api/demo/samples")
    assert res.status_code == 200
    assert "samples" in res.json()


# ─── TEST 6: RAG ADMIN ROLE AUTHORIZATION ───
ADMIN_USER_ID = "00000000-0000-4000-8000-000000000001"

def create_admin_jwt(user_id: str = ADMIN_USER_ID) -> str:
    now = int(time.time())
    payload = {
        "sub": user_id,
        "email": "admin@securemailscope.com",
        "role": "admin",
        "app_metadata": {"role": "admin"},
        "is_admin": True,
        "iss": "https://ymwflcngyzawphnvezmr.supabase.co/auth/v1",
        "iat": now,
        "exp": now + 3600
    }
    return jwt.encode(payload, key=SECRET, algorithm="HS256")


def test_rag_admin_role_authorization_and_kb_management():
    admin_token = create_admin_jwt()
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Admin can create new Knowledge Base / RAG article
    new_article = {
        "title": "Automated DNSSEC & DANE Enforcement Guide",
        "category": "DNS Security",
        "content": "Deploy TLSA records with DANE to pin TLS certificates and eliminate CA compromise vectors.",
        "tags": ["DANE", "DNSSEC", "TLSA"]
    }
    create_res = client.post("/api/admin/kb/articles", json=new_article, headers=admin_headers)
    assert create_res.status_code == 200
    created_data = create_res.json()
    assert created_data["success"] is True
    article_id = created_data["article"]["id"]
    assert created_data["article"]["title"] == new_article["title"]

    # 2. Admin can approve KB article
    approve_res = client.put(f"/api/admin/kb/articles/{article_id}/approve", headers=admin_headers)
    assert approve_res.status_code == 200
    assert approve_res.json()["article"]["status"] == "APPROVED"

    # 3. Admin can delete KB article
    del_res = client.delete(f"/api/admin/kb/articles/{article_id}", headers=admin_headers)
    assert del_res.status_code == 200
    assert del_res.json()["deleted_id"] == article_id


# ─── TEST 7: NON-ADMIN CANNOT MODIFY/APPROVE/DELETE KB ───
def test_non_admin_cannot_modify_approve_delete_kb(auth_header_user_a):
    new_article = {
        "title": "Unauthorized KB Injection",
        "category": "Exploit",
        "content": "Malicious payload injection test",
        "tags": ["Exploit"]
    }

    # Non-admin user receives 403 on CREATE
    res_create = client.post("/api/admin/kb/articles", json=new_article, headers=auth_header_user_a)
    assert res_create.status_code == 403
    assert "Forbidden" in res_create.json()["detail"] or "privileges required" in res_create.json()["detail"].lower()

    # Non-admin user receives 403 on APPROVE
    res_approve = client.put("/api/admin/kb/articles/kb_001/approve", headers=auth_header_user_a)
    assert res_approve.status_code == 403

    # Non-admin user receives 403 on DELETE
    res_delete = client.delete("/api/admin/kb/articles/kb_001", headers=auth_header_user_a)
    assert res_delete.status_code == 403

    # Unauthenticated user receives 401 on CREATE
    res_unauth_create = client.post("/api/admin/kb/articles", json=new_article)
    assert res_unauth_create.status_code == 401

    # Unauthenticated user receives 401 on APPROVE
    res_unauth_approve = client.put("/api/admin/kb/articles/kb_001/approve")
    assert res_unauth_approve.status_code == 401

    # Unauthenticated user receives 401 on DELETE
    res_unauth_del = client.delete("/api/admin/kb/articles/kb_001")
    assert res_unauth_del.status_code == 401


# ─── TEST 8: RATE LIMITING EXHAUSTION (429) ───
def test_rate_limit_exhaustion_returns_429():
    from main import limiter
    try:
        hit_429 = False
        for i in range(150):
            res = client.get("/api/demo/samples")
            if res.status_code == 429:
                hit_429 = True
                assert "detail" in res.json() or "Too Many Requests" in res.text or res.status_code == 429
                break
        assert hit_429, "Rate limiter failed to trigger HTTP 429 Too Many Requests after exceeding threshold."
    finally:
        limiter.reset()


# ─── TEST 9: ES256 ASYMMETRIC JWT VERIFICATION ───
def test_jwt_es256_valid_token_accepted():
    from unittest.mock import MagicMock, patch
    from cryptography.hazmat.primitives.asymmetric import ec
    from app.core.auth import decode_and_verify_supabase_jwt

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    now = int(time.time())

    payload = {
        "sub": USER_A_ID,
        "email": "user_a@securemailscope.com",
        "role": "authenticated",
        "iss": "https://ymwflcngyzawphnvezmr.supabase.co/auth/v1",
        "iat": now,
        "exp": now + 3600
    }
    token = jwt.encode(payload, private_key, algorithm="ES256", headers={"kid": "mock-es256-key"})

    mock_signing_key = MagicMock()
    mock_signing_key.key = public_key
    mock_jwks = MagicMock()
    mock_jwks.get_signing_key_from_jwt.return_value = mock_signing_key

    with patch("app.core.auth.get_jwks_client", return_value=mock_jwks):
        user = decode_and_verify_supabase_jwt(token)
        assert user["user_id"] == USER_A_ID
        assert user["email"] == "user_a@securemailscope.com"


def test_jwt_es256_invalid_signature_rejected():
    from unittest.mock import MagicMock, patch
    from cryptography.hazmat.primitives.asymmetric import ec
    from fastapi import HTTPException
    from app.core.auth import decode_and_verify_supabase_jwt

    key1 = ec.generate_private_key(ec.SECP256R1())
    key2 = ec.generate_private_key(ec.SECP256R1())
    now = int(time.time())

    token = jwt.encode({"sub": USER_A_ID, "exp": now + 3600}, key1, algorithm="ES256", headers={"kid": "mock-key"})

    mock_signing_key = MagicMock()
    mock_signing_key.key = key2.public_key() # Wrong public key
    mock_jwks = MagicMock()
    mock_jwks.get_signing_key_from_jwt.return_value = mock_signing_key

    with patch("app.core.auth.get_jwks_client", return_value=mock_jwks):
        with pytest.raises(HTTPException) as exc_info:
            decode_and_verify_supabase_jwt(token)
        assert exc_info.value.status_code == 401



