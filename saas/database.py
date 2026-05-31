"""
ShadowCoder SaaS — Database Layer
SQLite (dev) / PostgreSQL (prod) via SQLAlchemy async.

Tables: users, api_keys, subscriptions, scan_history, usage_events, ci_tokens
"""

import asyncio
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# ── In-memory database for zero-dependency dev mode ──────────────────────────
# PERSISTENCE: Save/Load from local JSON for dev survivability

DB_FILE = Path("data/db.json")
DB_FILE.parent.mkdir(exist_ok=True)

_USERS: dict[str, dict] = {}          # user_id → user record
_API_KEYS: dict[str, dict] = {}       # api_key → {user_id, name, ...}
_SUBSCRIPTIONS: dict[str, dict] = {}  # user_id → subscription record
_SCAN_HISTORY: list[dict] = []        # ordered scan records
_USAGE: dict[str, list] = {}          # user_id → [usage events]
_CI_TOKENS: dict[str, dict] = {}      # token → {user_id, repo, ...}

def _save_db():
    try:
        data = {
            "users": _USERS, "api_keys": _API_KEYS, "subs": _SUBSCRIPTIONS,
            "scans": _SCAN_HISTORY, "usage": _USAGE, "ci": _CI_TOKENS
        }
        DB_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception: pass

def _load_db():
    global _USERS, _API_KEYS, _SUBSCRIPTIONS, _SCAN_HISTORY, _USAGE, _CI_TOKENS
    if DB_FILE.exists():
        try:
            data = json.loads(DB_FILE.read_text(encoding="utf-8"))
            _USERS = data.get("users", {})
            _API_KEYS = data.get("api_keys", {})
            _SUBSCRIPTIONS = data.get("subs", {})
            _SCAN_HISTORY = data.get("scans", [])
            _USAGE = data.get("usage", {})
            _CI_TOKENS = data.get("ci", {})
        except Exception: pass

_load_db()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _uid() -> str:
    return uuid.uuid4().hex


# ── Plans ─────────────────────────────────────────────────────────────────────

PLANS = {
    "free": {
        "name": "Free",
        "price_monthly": 0,
        "price_yearly": 0,
        "scans_per_month": 50,
        "ai_enrichment": False,
        "project_analysis": False,
        "api_access": False,
        "ci_cd": False,
        "team_seats": 1,
        "stripe_price_id_monthly": None,
        "stripe_price_id_yearly": None,
        "features": ["50 scans/month", "30+ vulnerability detectors", "Basic reports"],
    },
    "pro": {
        "name": "Pro",
        "price_monthly": 29,
        "price_yearly": 290,
        "scans_per_month": 1000,
        "ai_enrichment": True,
        "project_analysis": True,
        "api_access": True,
        "ci_cd": True,
        "team_seats": 1,
        "stripe_price_id_monthly": os.getenv("STRIPE_PRO_MONTHLY_PRICE_ID", "price_pro_monthly"),
        "stripe_price_id_yearly": os.getenv("STRIPE_PRO_YEARLY_PRICE_ID", "price_pro_yearly"),
        "features": ["1,000 scans/month", "AI explain & fix", "Project analysis", "API access", "CI/CD integration"],
    },
    "team": {
        "name": "Team",
        "price_monthly": 99,
        "price_yearly": 990,
        "scans_per_month": 10000,
        "ai_enrichment": True,
        "project_analysis": True,
        "api_access": True,
        "ci_cd": True,
        "team_seats": 10,
        "stripe_price_id_monthly": os.getenv("STRIPE_TEAM_MONTHLY_PRICE_ID", "price_team_monthly"),
        "stripe_price_id_yearly": os.getenv("STRIPE_TEAM_YEARLY_PRICE_ID", "price_team_yearly"),
        "features": ["10,000 scans/month", "10 team seats", "Priority AI", "Advanced project analysis", "Slack/GitHub integration", "SLA support"],
    },
    "enterprise": {
        "name": "Enterprise",
        "price_monthly": None,  # custom
        "price_yearly": None,
        "scans_per_month": -1,  # unlimited
        "ai_enrichment": True,
        "project_analysis": True,
        "api_access": True,
        "ci_cd": True,
        "team_seats": -1,  # unlimited
        "features": ["Unlimited scans", "Unlimited seats", "On-prem deployment", "SSO/SAML", "Custom integrations", "Dedicated support"],
    },
}


# ── User operations ───────────────────────────────────────────────────────────

def create_user(email: str, name: str, password_hash: str, plan: str = "free") -> dict:
    user_id = _uid()
    user = {
        "user_id": user_id,
        "email": email.lower().strip(),
        "name": name,
        "password_hash": password_hash,
        "plan": plan,
        "created_at": _now(),
        "last_login": None,
        "email_verified": False,
        "avatar_url": f"https://api.dicebear.com/7.x/shapes/svg?seed={user_id}",
        "stripe_customer_id": None,
        "scans_this_month": 0,
        "month_reset_at": _now(),
    }
    _USERS[user_id] = user
    # index by email
    _USERS[f"email:{email.lower()}"] = user_id

    # Create free subscription
    _SUBSCRIPTIONS[user_id] = {
        "user_id": user_id,
        "plan": plan,
        "status": "active",
        "stripe_subscription_id": None,
        "current_period_start": _now(),
        "current_period_end": None,
        "cancel_at_period_end": False,
        "created_at": _now(),
    }
    _save_db()
    return user


def get_user_by_email(email: str) -> Optional[dict]:
    uid = _USERS.get(f"email:{email.lower()}")
    if not uid:
        return None
    return _USERS.get(uid)


def get_user(user_id: str) -> Optional[dict]:
    return _USERS.get(user_id)


def update_user(user_id: str, **kwargs) -> Optional[dict]:
    user = _USERS.get(user_id)
    if not user:
        return None
    user.update(kwargs)
    _save_db()
    return user


# ── API key operations ────────────────────────────────────────────────────────

def create_api_key(user_id: str, name: str = "Default") -> dict:
    raw_key = f"sc_{uuid.uuid4().hex}{uuid.uuid4().hex}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    record = {
        "key_id": _uid(),
        "user_id": user_id,
        "name": name,
        "key_prefix": raw_key[:12] + "...",
        "key_hash": key_hash,
        "created_at": _now(),
        "last_used_at": None,
        "total_requests": 0,
        "active": True,
    }
    _API_KEYS[raw_key] = record
    _API_KEYS[f"hash:{key_hash}"] = raw_key  # reverse lookup
    _save_db()
    return {**record, "raw_key": raw_key}  # raw_key shown ONCE


def get_api_key(raw_key: str) -> Optional[dict]:
    return _API_KEYS.get(raw_key)


def list_api_keys(user_id: str) -> list[dict]:
    return [
        {k: v for k, v in rec.items() if k != "key_hash"}
        for rec in _API_KEYS.values()
        if isinstance(rec, dict) and rec.get("user_id") == user_id
    ]


def revoke_api_key(key_id: str, user_id: str) -> bool:
    for key, rec in _API_KEYS.items():
        if isinstance(rec, dict) and rec.get("key_id") == key_id and rec.get("user_id") == user_id:
            rec["active"] = False
            _save_db()
            return True
    return False


# ── Subscription operations ───────────────────────────────────────────────────

def get_subscription(user_id: str) -> Optional[dict]:
    return _SUBSCRIPTIONS.get(user_id)


def update_subscription(user_id: str, **kwargs) -> Optional[dict]:
    sub = _SUBSCRIPTIONS.get(user_id)
    if not sub:
        return None
    sub.update(kwargs)
    # Sync user plan
    if "plan" in kwargs:
        user = _USERS.get(user_id)
        if user:
            user["plan"] = kwargs["plan"]
    _save_db()
    return sub


def get_plan(plan_name: str) -> dict:
    return PLANS.get(plan_name, PLANS["free"])


# ── Usage & quota ─────────────────────────────────────────────────────────────

def check_quota(user_id: str) -> dict:
    user = get_user(user_id)
    if not user:
        return {"allowed": False, "reason": "User not found"}

    plan = get_plan(user["plan"])
    limit = plan["scans_per_month"]

    if limit == -1:  # unlimited
        return {"allowed": True, "used": user.get("scans_this_month", 0), "limit": -1, "remaining": -1}

    used = user.get("scans_this_month", 0)
    if used >= limit:
        return {"allowed": False, "reason": "Monthly scan limit reached", "used": used, "limit": limit, "remaining": 0}

    return {"allowed": True, "used": used, "limit": limit, "remaining": limit - used}


def record_scan(user_id: str, scan_data: dict) -> dict:
    user = _USERS.get(user_id)
    if user:
        user["scans_this_month"] = user.get("scans_this_month", 0) + 1

    record = {
        "scan_id": _uid(),
        "user_id": user_id,
        "filename": scan_data.get("target_file", "unknown"),
        "source_code": scan_data.get("source_code", ""),
        "vulnerabilities_found": scan_data.get("vulnerabilities_found", 0),
        "exploitable_count": scan_data.get("exploitable_count", 0),
        "chains_found": len(scan_data.get("attack_chains", [])),
        "scan_time_ms": scan_data.get("scan_time_ms", 0),
        "severity_breakdown": {
            sev: sum(1 for f in scan_data.get("findings", []) if f.get("severity") == sev)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        },
        "scanned_at": _now(),
    }
    _SCAN_HISTORY.append(record)

    if user_id not in _USAGE:
        _USAGE[user_id] = []
    _USAGE[user_id].append({"type": "scan", "ts": _now(), **record})

    _save_db()
    return record


def get_scan_history(user_id: str, limit: int = 20) -> list[dict]:
    user_scans = [s for s in _SCAN_HISTORY if s["user_id"] == user_id]
    return sorted(user_scans, key=lambda s: s["scanned_at"], reverse=True)[:limit]


def get_usage_stats(user_id: str) -> dict:
    user = get_user(user_id)
    plan = get_plan(user["plan"]) if user else PLANS["free"]
    history = get_scan_history(user_id, limit=100)

    total_vulns = sum(s["vulnerabilities_found"] for s in history)
    total_critical = sum(s["severity_breakdown"].get("CRITICAL", 0) for s in history)

    return {
        "plan": user["plan"] if user else "free",
        "scans_this_month": user.get("scans_this_month", 0) if user else 0,
        "scan_limit": plan["scans_per_month"],
        "total_scans": len(history),
        "total_vulnerabilities": total_vulns,
        "total_critical": total_critical,
        "avg_vulns_per_scan": round(total_vulns / len(history), 1) if history else 0,
        "recent_scans": history[:5],
    }


# ── CI/CD token operations ────────────────────────────────────────────────────

def create_ci_token(user_id: str, repo: str, name: str) -> dict:
    token = f"ci_{uuid.uuid4().hex}"
    record = {
        "token_id": _uid(),
        "user_id": user_id,
        "token": token,
        "repo": repo,
        "name": name,
        "created_at": _now(),
        "last_used_at": None,
        "total_runs": 0,
        "active": True,
    }
    _CI_TOKENS[token] = record
    _save_db()
    return record


def get_ci_token(token: str) -> Optional[dict]:
    return _CI_TOKENS.get(token)


def list_ci_tokens(user_id: str) -> list[dict]:
    return [r for r in _CI_TOKENS.values() if r.get("user_id") == user_id]
