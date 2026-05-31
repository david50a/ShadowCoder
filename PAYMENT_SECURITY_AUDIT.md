# Payment System Security Audit — ShadowCoder

## Findings

### 1. [CRITICAL] Plan Spoofing via Checkout Metadata
**File:** `saas/billing.py`
**Method:** `_on_checkout_complete`

**Description:** 
The system trusts the `plan` value stored in the Stripe Checkout Session metadata to upgrade the user's account.
```python
def _on_checkout_complete(self, session: dict):
    user_id = session.get("metadata", {}).get("user_id")
    plan    = session.get("metadata", {}).get("plan", "pro") # <--- Trusted from metadata
    if user_id:
        update_user(user_id, stripe_customer_id=session.get("customer"), plan=plan)
```
The metadata is set during session creation in `create_checkout_session` based on the user-provided `plan` argument. An attacker could potentially manipulate the initial request to specify `plan="team"` but somehow trigger a checkout for a lower-priced item, or if the system is misconfigured, gain higher privileges than they paid for.

**Better Practice:** 
The plan should be derived **strictly** from the `price_id` associated with the completed checkout item, which is verified by Stripe.

### 2. [HIGH] Insecure Webhook Handling in Dev/Mock Mode
**File:** `saas/billing.py`
**Method:** `handle_webhook`

**Description:**
When `STRIPE_AVAILABLE` is false (e.g., during development or if the API key is missing), the system accepts **any** JSON payload as a valid Stripe event without any verification.
```python
if not STRIPE_AVAILABLE:
    try:
        event = json.loads(payload)
    except Exception:
        raise ValueError("Invalid payload")
```
An attacker could spoof success webhooks to grant themselves free 'pro' or 'team' access on a local or misconfigured instance.

### 3. [MEDIUM] Missing Dunning Flow
**File:** `saas/billing.py`
**Method:** `_on_payment_failed`

**Description:**
The system logs a warning but does not take action (like suspending the account) when a payment fails.
```python
def _on_payment_failed(self, invoice: dict):
    customer_id = invoice.get("customer")
    log.warning(f"Payment failed for customer {customer_id} — consider dunning flow")
```

## Recommendations

1. **Verify Plan via Price ID:** Update `_on_checkout_complete` to use `_plan_from_price(price_id)` instead of trusting metadata.
2. **Strict Webhook Validation:** Ensure webhooks are always validated, or explicitly disable the endpoint in development mode.
3. **Automated Suspension:** Implement logic to downgrade or suspend users upon `invoice.payment_failed` or `customer.subscription.deleted`.
