"""
ShadowCoder SaaS — Authentication
JWT-based auth with refresh tokens. API key auth for CI/CD.
"""

import hashlib
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

try:
    from jose import jwt, JWTError
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

try:
    import bcrypt as _bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

from saas.database import get_user, get_user_by_email, get_api_key, update_user, get_subscription, get_plan

SECRET_KEY = os.getenv("SHADOWCODER_SECRET_KEY", "dev-secret-change-in-production-please")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours
REFRESH_TOKEN_EXPIRE_DAYS = 30

security = HTTPBearer(auto_error=False)


# ── Password hashing ──────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    if BCRYPT_AVAILABLE:
        return _bcrypt.hashpw(password.encode()[:72], _bcrypt.gensalt()).decode()
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
    if BCRYPT_AVAILABLE and hashed.startswith("$2"):
        try:
            return _bcrypt.checkpw(plain.encode()[:72], hashed.encode())
        except Exception:
            pass
    return hashlib.sha256(plain.encode()).hexdigest() == hashed


# ── JWT tokens ────────────────────────────────────────────────────────────────

def create_access_token(user_id: str, extra: dict = None) -> str:
    payload = {
        "sub": user_id,
        "type": "access",
        "iat": int(time.time()),
        "exp": int(time.time()) + ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        **(extra or {}),
    }
    if JWT_AVAILABLE:
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    # Simple fallback: base64-encoded JSON (NOT secure — use jose in prod)
    import base64, json
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()


def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "type": "refresh",
        "iat": int(time.time()),
        "exp": int(time.time()) + REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    }
    if JWT_AVAILABLE:
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    import base64, json
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()


def decode_token(token: str) -> Optional[dict]:
    if JWT_AVAILABLE:
        try:
            return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError:
            return None
    try:
        import base64, json
        payload = json.loads(base64.urlsafe_b64decode(token + "==").decode())
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


# ── FastAPI dependencies ──────────────────────────────────────────────────────

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Optional[str] = Header(None),
) -> dict:
    """
    Auth dependency. Accepts:
    1. Bearer JWT token (dashboard users)
    2. X-Api-Key header (API / CI/CD clients)
    """
    # Try API key first
    if x_api_key:
        key_record = get_api_key(x_api_key)
        if not key_record or not key_record.get("active"):
            raise HTTPException(status_code=401, detail="Invalid API key")
        user = get_user(key_record["user_id"])
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        key_record["last_used_at"] = datetime.now(timezone.utc).isoformat()
        key_record["total_requests"] = key_record.get("total_requests", 0) + 1
        return user

    # Try JWT Bearer
    if credentials:
        payload = decode_token(credentials.credentials)
        if not payload or payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        user = get_user(payload["sub"])
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user

    raise HTTPException(
        status_code=401,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Optional[str] = Header(None),
) -> Optional[dict]:
    """Optional auth — returns None if not authenticated."""
    try:
        return await get_current_user(credentials, x_api_key)
    except HTTPException:
        return None


def require_plan(*plans: str):
    """Dependency factory: require user to be on one of the given plans."""
    async def _check(user: dict = Depends(get_current_user)):
        if user["plan"] not in plans:
            plan_names = " or ".join(p.title() for p in plans)
            raise HTTPException(
                status_code=403,
                detail=f"This feature requires {plan_names} plan. Upgrade at /billing.",
            )
        return user
    return _check


def require_feature(feature: str):
    """Dependency factory: require plan to have a specific feature enabled."""
    async def _check(user: dict = Depends(get_current_user)):
        from saas.database import get_plan
        plan = get_plan(user["plan"])
        if not plan.get(feature, False):
            raise HTTPException(
                status_code=403,
                detail=f"Feature '{feature}' not available on your current plan.",
            )
        return user
    return _check
