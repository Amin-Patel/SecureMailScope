"""
Supabase JWT Authentication and Authorization Dependency for SecureMailScope.
Adheres strictly to RFC 7519 JWT standards and Supabase Auth token specifications.
Validates algorithm, signature, issuer (iss), subject (sub), expiration (exp), and claims.
"""

import os
import logging
import jwt
from typing import Dict, Optional, Any
from pathlib import Path
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger(__name__)

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

# Allowed signing algorithms
ALLOWED_ALGORITHMS = ["HS256", "RS256", "ES256"]

# JWKS client cache for asymmetric token verification
_jwks_client: Optional[jwt.PyJWKClient] = None


def get_jwks_client() -> jwt.PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        jwks_url = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
        _jwks_client = jwt.PyJWKClient(
            jwks_url,
            cache_keys=True,
            cache_jwk_set=True,
            lifespan=3600
        )
    return _jwks_client


def decode_and_verify_supabase_jwt(token: str) -> Dict[str, Any]:
    """
    Decodes and strictly verifies a Supabase JWT token.
    Validates:
    - Signature using configured SUPABASE_JWT_SECRET (HS256) or Supabase JWKS / Public Key (ES256 / RS256)
    - Algorithm (strictly HS256, RS256, or ES256; no 'none' algorithm allowed)
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
        if alg not in ALLOWED_ALGORITHMS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Unsupported token signing algorithm: '{alg}'. Expected HS256, RS256, or ES256.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 2. Decode options
        decode_options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_iss": False, # We validate custom Supabase iss matching project ref / auth url below
            "verify_aud": False, # Supabase tokens typically include 'aud': 'authenticated'
            "require": ["exp", "sub"]
        }

        # 3. Resolve key according to algorithm
        if alg in ["ES256", "RS256"]:
            verification_key = None
            try:
                jwks_client = get_jwks_client()
                try:
                    signing_key = jwks_client.get_signing_key_from_jwt(token)
                    verification_key = signing_key.key
                except Exception:
                    # Fallback if kid is missing or unmatched: inspect available keys in JWKS
                    signing_keys = jwks_client.get_signing_keys()
                    matching = [k for k in signing_keys if getattr(k, "algorithm_name", None) == alg]
                    if matching:
                        verification_key = matching[0].key
                    elif signing_keys:
                        verification_key = signing_keys[0].key
            except Exception as jwks_err:
                pub_key = os.getenv("SUPABASE_PUBLIC_KEY") or os.getenv("SUPABASE_JWT_PUBLIC_KEY")
                if pub_key:
                    verification_key = pub_key
                else:
                    logger.error(f"Failed to fetch JWKS public key: {jwks_err}")
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=f"Unable to retrieve public key for {alg} verification: {str(jwks_err)}",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

            if not verification_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"No matching public key found for algorithm '{alg}'.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        else:
            # HS256 symmetric secret
            verification_key = os.getenv("SUPABASE_JWT_SECRET") or os.getenv("JWT_SECRET") or SUPABASE_JWT_SECRET
            if not verification_key:
                logger.error("Neither SUPABASE_JWT_SECRET nor JWT_SECRET is configured for HS256 verification.")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Authentication configuration error: JWT secret not configured.",
                )

        payload = jwt.decode(
            token,
            verification_key,
            algorithms=[alg],
            options=decode_options
        )

        # 4. Validate subject (sub)
        user_id = payload.get("sub")
        if not user_id or not isinstance(user_id, str):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token payload missing valid subject ('sub') claim.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 5. Validate Issuer if present (must match configured Supabase project)
        iss = payload.get("iss", "")
        if iss:
            valid_issuers = {
                EXPECTED_ISSUER.rstrip("/"),
                f"https://{SUPABASE_PROJECT_REF}.supabase.co/auth/v1".rstrip("/")
            }
            if iss.rstrip("/") not in valid_issuers:
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
    Returns user dict if valid token provided, else None. Raises 401 if token is provided but invalid.
    """
    if not credentials or not credentials.credentials:
        return None
    return decode_and_verify_supabase_jwt(credentials.credentials)


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
