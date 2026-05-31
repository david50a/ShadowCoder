"""
ShadowCoder SaaS — API Router
Mounts all SaaS endpoints onto the FastAPI app.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Header
from fastapi.responses import JSONResponse, Response as FastResponse, HTMLResponse
from pydantic import BaseModel, EmailStr, Field

from saas.auth import (
    get_current_user, get_current_user_optional,
    hash_password, verify_password,
    create_access_token, create_refresh_token, decode_token,
    require_feature,
)
from saas.database import (
    create_user, get_user_by_email, get_user, update_user,
    create_api_key, list_api_keys, revoke_api_key,
    get_subscription, update_subscription, get_plan, PLANS,
    check_quota, record_scan, get_scan_history, get_usage_stats,
    create_ci_token, get_ci_token, list_ci_tokens,
)
from saas.billing import billing_service
from saas.cicd import (
    generate_badge_svg, generate_github_actions_yaml, generate_gitlab_ci_yaml,
    verify_github_signature, verify_gitlab_token,
    format_ci_result, to_sarif,
)

log = logging.getLogger("shadowcoder.saas")
router = APIRouter()


# ── Request/Response models ───────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    name: str
    password: str = Field(min_length=8)

class LoginRequest(BaseModel):
    email: str
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    settings: Optional[dict] = None

class CreateApiKeyRequest(BaseModel):
    name: str = "Default"

class CheckoutRequest(BaseModel):
    plan: str
    billing_period: str = "monthly"

class CITokenRequest(BaseModel):
    repo: str
    name: str = "CI Pipeline"

class CIScanRequest(BaseModel):
    source_code: str
    filename: str = "ci_scan.py"
    repo: str = ""
    branch: str = ""
    commit_sha: str = ""
    pr_number: Optional[int] = None


# ── Auth endpoints ────────────────────────────────────────────────────────────

@router.post("/auth/register", tags=["Auth"])
async def register(req: RegisterRequest):
    if get_user_by_email(req.email):
        raise HTTPException(status_code=409, detail="Email already registered")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user = create_user(req.email, req.name, hash_password(req.password))
    access  = create_access_token(user["user_id"])
    refresh = create_refresh_token(user["user_id"])

    return {
        "user": _safe_user(user),
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
    }


@router.post("/auth/login", tags=["Auth"])
async def login(req: LoginRequest):
    user = get_user_by_email(req.email)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    update_user(user["user_id"], last_login=datetime.now(timezone.utc).isoformat())
    access  = create_access_token(user["user_id"])
    refresh = create_refresh_token(user["user_id"])

    return {
        "user": _safe_user(user),
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
    }


@router.post("/auth/refresh", tags=["Auth"])
async def refresh_token(req: RefreshRequest):
    payload = decode_token(req.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user = get_user(payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {
        "access_token": create_access_token(user["user_id"]),
        "token_type": "bearer",
    }


@router.post("/auth/logout", tags=["Auth"])
async def logout(user: dict = Depends(get_current_user)):
    # Stateless JWT — client discards token. Blocklist optional for prod.
    return {"message": "Logged out successfully"}


# ── User / profile endpoints ──────────────────────────────────────────────────

@router.get("/user/me", tags=["User"])
async def get_me(user: dict = Depends(get_current_user)):
    sub  = get_subscription(user["user_id"])
    plan = get_plan(user["plan"])
    return {
        "user": _safe_user(user),
        "subscription": sub,
        "plan": plan,
        "quota": check_quota(user["user_id"]),
    }


@router.patch("/user/me", tags=["User"])
async def update_profile(req: UpdateProfileRequest, user: dict = Depends(get_current_user)):
    updates = {k: v for k, v in req.dict().items() if v is not None}
    updated = update_user(user["user_id"], **updates)
    return {"user": _safe_user(updated)}


@router.get("/user/stats", tags=["User"])
async def get_stats(user: dict = Depends(get_current_user)):
    return get_usage_stats(user["user_id"])


@router.get("/user/scans", tags=["User"])
async def get_scans(limit: int = 20, user: dict = Depends(get_current_user)):
    return {"scans": get_scan_history(user["user_id"], limit=min(limit, 100))}


# ── API key endpoints ─────────────────────────────────────────────────────────

@router.post("/user/api-keys", tags=["API Keys"])
async def create_key(req: CreateApiKeyRequest, user: dict = Depends(require_feature("api_access"))):
    existing = list_api_keys(user["user_id"])
    if len(existing) >= 5:
        raise HTTPException(status_code=400, detail="Maximum 5 API keys allowed")
    key = create_api_key(user["user_id"], req.name)
    return key  # raw_key shown only once


@router.get("/user/api-keys", tags=["API Keys"])
async def list_keys(user: dict = Depends(get_current_user)):
    return {"api_keys": list_api_keys(user["user_id"])}


@router.delete("/user/api-keys/{key_id}", tags=["API Keys"])
async def delete_key(key_id: str, user: dict = Depends(get_current_user)):
    ok = revoke_api_key(key_id, user["user_id"])
    if not ok:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"message": "API key revoked"}


# ── Billing endpoints ─────────────────────────────────────────────────────────

@router.get("/billing/plans", tags=["Billing"])
async def list_plans():
    return {"plans": PLANS}


@router.post("/billing/checkout", tags=["Billing"])
async def create_checkout(req: CheckoutRequest, user: dict = Depends(get_current_user)):
    if req.plan not in PLANS:
        raise HTTPException(status_code=400, detail=f"Unknown plan: {req.plan}")
    if req.plan == "enterprise":
        raise HTTPException(status_code=400, detail="Contact sales for Enterprise pricing")

    url = billing_service.create_checkout_session(
        user, req.plan, req.billing_period,
        success_url="http://localhost:8000/billing/success",
        cancel_url="http://localhost:8000/billing",
    )
    if not url:
        raise HTTPException(status_code=500, detail="Could not create checkout session")
    return {"checkout_url": url}


@router.post("/billing/portal", tags=["Billing"])
async def billing_portal(user: dict = Depends(get_current_user)):
    url = billing_service.create_portal_session(user)
    if not url:
        raise HTTPException(status_code=500, detail="Could not create portal session")
    return {"portal_url": url}


@router.post("/billing/cancel", tags=["Billing"])
async def cancel_subscription(user: dict = Depends(get_current_user)):
    ok = billing_service.cancel_subscription(user)
    if not ok:
        raise HTTPException(status_code=400, detail="No active subscription to cancel")
    return {"message": "Subscription will cancel at end of billing period"}


@router.get("/billing/subscription", tags=["Billing"])
async def get_sub(user: dict = Depends(get_current_user)):
    sub  = get_subscription(user["user_id"])
    plan = get_plan(user["plan"])
    quota = check_quota(user["user_id"])
    return {"subscription": sub, "plan": plan, "quota": quota}


# ── Mock Billing Pages (Demo Mode) ───────────────────────────────────────────

@router.get("/billing/mock-checkout", tags=["Billing"], include_in_schema=False)
async def mock_checkout_page(plan: str, period: str, user: str):
    plan_data = get_plan(plan)
    price = plan_data.get(f"price_{period}", 0)
    
    html = f"""
    <html>
    <head>
        <title>ShadowCoder — Secure Checkout</title>
        <style>
            body {{ background: #0a0a0b; color: #fff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
            .card {{ background: #161618; padding: 40px; border-radius: 12px; border: 1px solid #28282c; width: 400px; box-shadow: 0 20px 40px rgba(0,0,0,0.4); }}
            h1 {{ font-size: 24px; margin-bottom: 8px; }}
            .price {{ font-size: 32px; font-weight: 800; margin-bottom: 24px; color: #00ff88; }}
            .plan {{ color: #a1a1a6; margin-bottom: 24px; text-transform: uppercase; letter-spacing: 1px; font-size: 12px; }}
            .input {{ background: #0a0a0b; border: 1px solid #28282c; color: #fff; padding: 12px; width: 100%; border-radius: 6px; margin-bottom: 16px; box-sizing: border-box; }}
            .btn {{ background: #00ff88; color: #000; border: none; padding: 14px; width: 100%; border-radius: 6px; font-weight: 700; cursor: pointer; font-size: 16px; transition: opacity 0.2s; }}
            .btn:hover {{ opacity: 0.9; }}
            .footer {{ margin-top: 24px; color: #48484a; font-size: 11px; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Complete Purchase</h1>
            <div class="plan">{plan} plan ({period})</div>
            <div class="price">${price}</div>
            
            <form action="/api/billing/mock-confirm" method="POST">
                <input type="hidden" name="plan" value="{plan}">
                <input type="hidden" name="user_id" value="{user}">
                
                <label style="font-size: 12px; color: #a1a1a6; display: block; margin-bottom: 4px;">Card Number</label>
                <input class="input" type="text" value="4242 4242 4242 4242" readonly>
                
                <div style="display: flex; gap: 12px;">
                    <div style="flex: 1;">
                        <label style="font-size: 12px; color: #a1a1a6; display: block; margin-bottom: 4px;">Expiry</label>
                        <input class="input" type="text" value="12/28" readonly>
                    </div>
                    <div style="flex: 1;">
                        <label style="font-size: 12px; color: #a1a1a6; display: block; margin-bottom: 4px;">CVC</label>
                        <input class="input" type="text" value="123" readonly>
                    </div>
                </div>
                
                <button type="submit" class="btn">PAY NOW</button>
            </form>
            
            <div class="footer">Demo Mode — No real payment will be processed.</div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@router.post("/billing/mock-confirm", tags=["Billing"], include_in_schema=False)
async def mock_confirm(request: Request):
    form = await request.form()
    user_id = form.get("user_id")
    plan = form.get("plan")
    
    if user_id and plan:
        update_user(user_id, plan=plan)
        update_subscription(user_id, plan=plan, status="active")
        log.info(f"DEMO: User {user_id} upgraded to {plan}")
        
    return HTMLResponse(content=f"""
    <html>
    <head>
        <meta http-equiv="refresh" content="3;url=/">
        <style>
            body {{ background: #0a0a0b; color: #fff; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
            .card {{ text-align: center; }}
            .icon {{ font-size: 64px; color: #00ff88; margin-bottom: 16px; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="icon">✓</div>
            <h1>Payment Successful!</h1>
            <p>Upgrading your account to <strong>{plan.upper()}</strong>...</p>
            <p style="color: #a1a1a6;">Redirecting to dashboard in 3 seconds...</p>
        </div>
    </body>
    </html>
    """)


@router.get("/billing/mock-portal", tags=["Billing"], include_in_schema=False)
async def mock_portal_page():
    return HTMLResponse(content="""
    <html>
    <body>
        <h1>Billing Portal (Demo)</h1>
        <p>In demo mode, subscriptions are managed automatically.</p>
        <a href="/">Back to Dashboard</a>
    </body>
    </html>
    """)


# ── Stripe webhook (no auth) ──────────────────────────────────────────────────

@router.post("/webhooks/stripe", tags=["Webhooks"], include_in_schema=False)
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    try:
        result = billing_service.handle_webhook(payload, sig)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── CI/CD endpoints ───────────────────────────────────────────────────────────

@router.post("/user/ci-tokens", tags=["CI/CD"])
async def create_token(req: CITokenRequest, user: dict = Depends(require_feature("ci_cd"))):
    existing = list_ci_tokens(user["user_id"])
    if len(existing) >= 10:
        raise HTTPException(status_code=400, detail="Maximum 10 CI tokens allowed")
    token = create_ci_token(user["user_id"], req.repo, req.name)
    return token


@router.get("/user/ci-tokens", tags=["CI/CD"])
async def list_tokens(user: dict = Depends(get_current_user)):
    return {"ci_tokens": list_ci_tokens(user["user_id"])}


@router.get("/ci/yaml/github", tags=["CI/CD"])
async def github_yaml(user: dict = Depends(require_feature("ci_cd"))):
    tokens = list_ci_tokens(user["user_id"])
    token = tokens[0]["token"] if tokens else "YOUR_CI_TOKEN"
    return FastResponse(
        content=generate_github_actions_yaml(token),
        media_type="text/yaml",
        headers={"Content-Disposition": "attachment; filename=shadowcoder.yml"},
    )


@router.get("/ci/yaml/gitlab", tags=["CI/CD"])
async def gitlab_yaml(user: dict = Depends(require_feature("ci_cd"))):
    tokens = list_ci_tokens(user["user_id"])
    token = tokens[0]["token"] if tokens else "YOUR_CI_TOKEN"
    return FastResponse(
        content=generate_gitlab_ci_yaml(token),
        media_type="text/yaml",
        headers={"Content-Disposition": "attachment; filename=.shadowcoder-gitlab-ci.yml"},
    )


@router.post("/ci/scan", tags=["CI/CD"])
async def ci_scan(req: CIScanRequest, x_ci_token: str = Header(...)):
    """Authenticated scan endpoint for CI/CD pipelines."""
    token_record = get_ci_token(x_ci_token)
    if not token_record or not token_record.get("active"):
        raise HTTPException(status_code=401, detail="Invalid CI token")

    user = get_user(token_record["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Check quota
    quota = check_quota(user["user_id"])
    if not quota["allowed"]:
        raise HTTPException(status_code=429, detail=f"Scan limit reached: {quota.get('reason')}")

    # Run scan (import here to avoid circular)
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from engine.attack_engine import AttackEngine
    from engine.scan_manager import _report_to_dict

    engine = AttackEngine()
    report = engine.scan(req.source_code, filename=req.filename)
    result = _report_to_dict(report)

    # Record usage
    record_scan(user["user_id"], result)
    token_record["last_used_at"] = datetime.now(timezone.utc).isoformat()
    token_record["total_runs"] = token_record.get("total_runs", 0) + 1

    ci_context = {
        "repo": req.repo,
        "branch": req.branch,
        "commit_sha": req.commit_sha,
        "pr_number": req.pr_number,
    }
    return format_ci_result(result, ci_context)


@router.get("/ci/badge/{user_id}", tags=["CI/CD"])
async def ci_badge(user_id: str, response: Response):
    """SVG badge showing latest scan status."""
    history = get_scan_history(user_id, limit=1)
    if not history:
        svg = generate_badge_svg("scanning")
    else:
        last = history[0]
        n = last["vulnerabilities_found"]
        crit = last["severity_breakdown"].get("CRITICAL", 0)
        if crit > 0:
            svg = generate_badge_svg("critical", n)
        elif n == 0:
            svg = generate_badge_svg("secure", 0)
        elif n <= 3:
            svg = generate_badge_svg("medium", n)
        else:
            svg = generate_badge_svg("high", n)

    response.headers["Cache-Control"] = "no-cache, max-age=0"
    return FastResponse(content=svg, media_type="image/svg+xml")


@router.get("/ci/sarif/{scan_id}", tags=["CI/CD"])
async def get_sarif(scan_id: str, user: dict = Depends(get_current_user)):
    """Export scan result in SARIF format for GitHub Code Scanning."""
    history = get_scan_history(user["user_id"], limit=50)
    scan = next((s for s in history if s.get("scan_id") == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    # Note: full finding detail not stored in history — would be in DB in prod
    sarif = to_sarif(scan)
    return FastResponse(
        content=__import__("json").dumps(sarif, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=shadowcoder-{scan_id}.sarif"},
    )


# ── GitHub webhook ────────────────────────────────────────────────────────────

@router.post("/webhooks/github", tags=["Webhooks"], include_in_schema=False)
async def github_webhook(request: Request, x_hub_signature_256: str = Header(None)):
    payload = await request.body()
    if not verify_github_signature(payload, x_hub_signature_256 or ""):
        raise HTTPException(status_code=403, detail="Invalid GitHub signature")

    event = request.headers.get("X-GitHub-Event", "")
    data  = __import__("json").loads(payload)
    log.info(f"GitHub webhook: {event} from {data.get('repository', {}).get('full_name', '?')}")

    if event in ("push", "pull_request"):
        return {"received": True, "event": event, "note": "Scan triggered via CI token in workflow"}

    return {"received": True, "event": event}


# ── GitLab webhook ────────────────────────────────────────────────────────────

@router.post("/webhooks/gitlab", tags=["Webhooks"], include_in_schema=False)
async def gitlab_webhook(request: Request, x_gitlab_token: str = Header(None)):
    if not verify_gitlab_token(x_gitlab_token or ""):
        raise HTTPException(status_code=403, detail="Invalid GitLab token")

    payload = await request.body()
    data  = __import__("json").loads(payload)
    event = data.get("object_kind", "unknown")
    log.info(f"GitLab webhook: {event}")
    return {"received": True, "event": event}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_user(user: dict) -> dict:
    """Strip sensitive fields before returning to client."""
    return {k: v for k, v in user.items() if k not in ("password_hash",)}
