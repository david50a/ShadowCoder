# ShadowCoder SaaS Setup Guide

## Quick Start

```bash
cp .env.example .env
# Edit .env with your keys
pip install -r requirements.txt
uvicorn api.server:app --reload --port 8000
```

## Endpoints

| URL | Description |
|-----|-------------|
| `http://localhost:8000/` | Main scanner UI |
| `http://localhost:8000/dashboard/` | SaaS dashboard (auth, billing, CI/CD) |
| `http://localhost:8000/docs` | Full API docs (Swagger) |

## SaaS API Routes (46 total)

### Auth
- `POST /api/auth/register` — Create account
- `POST /api/auth/login` — Get JWT token
- `POST /api/auth/refresh` — Refresh token

### Scanning
- `POST /api/scan` → async + WebSocket progress
- `POST /api/scan/sync` → synchronous (good for CI)
- `WS /ws/{job_id}` → real-time progress stream

### User & Billing
- `GET /api/user/me` — Profile + quota
- `GET /api/billing/plans` — All plans + pricing
- `POST /api/billing/checkout` — Stripe checkout
- `POST /api/billing/portal` — Stripe customer portal
- `POST /webhooks/stripe` — Stripe webhook handler

### API Keys
- `POST /api/user/api-keys` — Create key (Pro+)
- `GET /api/user/api-keys` — List keys
- Authenticate with: `X-Api-Key: sc_...` header

### CI/CD
- `POST /api/user/ci-tokens` — Create CI token (Pro+)
- `POST /api/ci/scan` — CI scan endpoint (X-CI-Token header)
- `GET /api/ci/badge/{user_id}` — SVG status badge
- `GET /api/ci/yaml/github` — Download GitHub Actions YAML
- `GET /api/ci/yaml/gitlab` — Download GitLab CI YAML

### AI (Phase 5, requires ANTHROPIC_API_KEY)
- `POST /api/ai/explain` — Explain a vulnerability
- `POST /api/ai/fix` — Generate fix
- `POST /api/ai/triage` — Priority ranking

### Project Analysis (Phase 6)
- `POST /api/project/analyze` — Full codebase analysis

## Stripe Setup

1. Create products in Stripe Dashboard:
   - ShadowCoder Pro ($29/mo, $290/yr)
   - ShadowCoder Team ($99/mo, $990/yr)

2. Copy Price IDs to `.env`

3. Set up webhook endpoint: `https://yourdomain.com/api/webhooks/stripe`
   Events to listen for:
   - `checkout.session.completed`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`

## GitHub Actions Integration

1. Create a CI token from the dashboard → CI/CD tab
2. Add to GitHub repo secrets: `SHADOWCODER_TOKEN`
3. Download the YAML template from dashboard or:

```yaml
# .github/workflows/shadowcoder.yml
- name: ShadowCoder Scan
  run: |
    curl -X POST https://yourapp.com/api/ci/scan \
      -H "X-CI-Token: ${{ secrets.SHADOWCODER_TOKEN }}" \
      -H "Content-Type: application/json" \
      -d '{"source_code": "...","repo": "${{ github.repository }}"}'
```

## Production Deployment

```bash
# With PostgreSQL + Redis
DATABASE_URL=postgresql+asyncpg://... uvicorn api.server:app --workers 4

# Docker
docker build -t shadowcoder .
docker-compose up -d
```

## Plans & Pricing

| Plan | Price | Scans/mo | AI | API | CI/CD |
|------|-------|----------|----|-----|-------|
| Free | $0 | 50 | ✗ | ✗ | ✗ |
| Pro | $29/mo | 1,000 | ✓ | ✓ | ✓ |
| Team | $99/mo | 10,000 | ✓ | ✓ | ✓ |
| Enterprise | Custom | ∞ | ✓ | ✓ | ✓ |
