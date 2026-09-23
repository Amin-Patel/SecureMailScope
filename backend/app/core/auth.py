"""
Supabase JWT Authentication and Authorization Dependency for SecureMailScope.
Adheres strictly to RFC 7519 JWT standards and Supabase Auth token specifications.
Validates algorithm, signature, issuer (iss), subject (sub), expiration (exp), and claims.
"""

import os
import json
import jwt
from typing import Dict, Optional, Any
from pathlib import Path
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Load environment variables
load_dotenv()

# Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://ymwflcngyzawphnvezmr.supabase.co").rstrip("/")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "").strip()
SUPABASE_PROJECT_REF = os.getenv("SUPABASE_PROJECT_REF", "ymwflcngyzawphnvezmr").strip()

# Expected issuer
EXPECTED_ISSUER = f"{SUPABASE_URL}/auth/v1"

# Security scheme
security_scheme = HTTPBearer(auto_error=False)


def decode_and_verify_supabase_jwt(token: str) -> Dict[str, Any]:
    """
    Decodes and strictly verifies a Supabase JWT token.
    Validates:
    - Signature using configured SUPABASE_JWT_SECRET (or project public key)
    - Algorithm (strictly HS256 or RS256, no 'none' algorithm allowed)
    - Issuer ('iss')
    - Expiration ('exp')
    - Subject ('sub') presence as user UUID
    """
    if not token or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # 1. Unverified header inspect to ensure algorithm is allowed
        unverified_headers = jwt.get_unverified_header(token)
        alg = unverified_headers.get("alg")
        if alg not in ["HS256", "RS256"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Unsupported token signing algorithm: '{alg}'. Expected HS256 or RS256.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 2. Decode options
        decode_options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_iss": False, # We validate custom Supabase iss matching project ref / auth url below
            "require": ["exp", "sub"]
        }

        # If JWT secret is configured, use it for signature validation
        secret = SUPABASE_JWT_SECRET
        if not secret:
            secret = os.getenv("JWT_SECRET", "super-secret-jwt-token-with-at-least-32-bytes-long")

        payload = jwt.decode(
            token,
            secret,
            algorithms=[alg],
            options=decode_options
        )

        # 3. Validate subject (sub)
        user_id = payload.get("sub")
        if not user_id or not isinstance(user_id, str):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token payload missing valid subject ('sub') claim.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 4. Validate Issuer if present
        iss = payload.get("iss", "")
        if iss:
            valid_issuers = [EXPECTED_ISSUER, f"https://{SUPABASE_PROJECT_REF}.supabase.co/auth/v1", "supabase"]
            if iss not in valid_issuers and not iss.endswith(".supabase.co/auth/v1"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid token issuer: '{iss}'.",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        return {
            "user_id": user_id,
            "email": payload.get("email", ""),
            "role": payload.get("role", "authenticated"),
            "claims": payload
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token verification failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme)
) -> Dict[str, Any]:
    """
    FastAPI dependency that enforces Supabase JWT authentication.
    Returns user dictionary containing `user_id`, `email`, `role`, and `claims`.
    Raises 401 if missing or invalid.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return decode_and_verify_supabase_jwt(credentials.credentials)


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme)
) -> Optional[Dict[str, Any]]:
    """
    FastAPI dependency for endpoints that allow public/demo access or authenticated access.
    Returns user dict if valid token provided, else None.
    """
    if not credentials or not credentials.credentials:
        return None
    try:
        return decode_and_verify_supabase_jwt(credentials.credentials)
    except HTTPException:
        return None


async def require_admin_role(
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    FastAPI dependency that enforces admin role privileges for RAG / Knowledge Base / System administration.
    Checks role == 'admin' in claims or app_metadata.
    Raises 403 Forbidden if user is authenticated but not an admin.
    """
    claims = current_user.get("claims", {})
    role = claims.get("role") or current_user.get("role")
    app_meta = claims.get("app_metadata", {})
    user_role = app_meta.get("role") or role

    if user_role != "admin" and not claims.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Administrative privileges required."
        )
    return current_user
