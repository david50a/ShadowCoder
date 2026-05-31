"""
ShadowCoder SaaS — Stripe Billing
Subscription management, webhook handling, usage metering.
"""

import json
import logging
import os
import time
from typing import Optional

log = logging.getLogger("shadowcoder.billing")

STRIPE_SECRET_KEY     = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

try:
    import stripe
    stripe.api_key = STRIPE_SECRET_KEY
    STRIPE_AVAILABLE = bool(STRIPE_SECRET_KEY)
except ImportError:
    stripe = None
    STRIPE_AVAILABLE = False


class BillingService:
    """
    Wraps Stripe. Degrades gracefully when STRIPE_SECRET_KEY is unset.
    """

    # ── Customer ──────────────────────────────────────────────────────────────

    def create_customer(self, user: dict) -> Optional[str]:
        """Create Stripe customer, return customer_id."""
        if not STRIPE_AVAILABLE:
            return f"cus_mock_{user['user_id'][:8]}"
        try:
            customer = stripe.Customer.create(
                email=user["email"],
                name=user["name"],
                metadata={"user_id": user["user_id"], "source": "shadowcoder"},
            )
            return customer.id
        except Exception as e:
            log.error(f"Stripe create_customer failed: {e}")
            return None

    # ── Checkout session ──────────────────────────────────────────────────────

    def create_checkout_session(
        self,
        user: dict,
        plan: str,
        billing_period: str = "monthly",
        success_url: str = "http://localhost:8000/billing/success",
        cancel_url:  str = "http://localhost:8000/billing",
    ) -> Optional[str]:
        """Create Stripe Checkout session, return URL."""
        from saas.database import get_plan, update_subscription
        plan_data = get_plan(plan)
        price_id_key = f"stripe_price_id_{billing_period}"
        price_id = plan_data.get(price_id_key)

        if not STRIPE_AVAILABLE or not price_id or not price_id.startswith("price_"):
            # Return a mock URL for demo mode
            return f"/api/billing/mock-checkout?plan={plan}&period={billing_period}&user={user['user_id']}"

        try:
            customer_id = user.get("stripe_customer_id")
            if not customer_id:
                customer_id = self.create_customer(user)

            session = stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=["card"],
                line_items=[{"price": price_id, "quantity": 1}],
                mode="subscription",
                success_url=success_url + "?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=cancel_url,
                metadata={"user_id": user["user_id"], "plan": plan},
                subscription_data={
                    "metadata": {"user_id": user["user_id"], "plan": plan},
                    "trial_period_days": 14 if plan in ("pro", "team") else None,
                },
            )
            return session.url
        except Exception as e:
            log.error(f"Stripe checkout session failed: {e}")
            return None

    # ── Customer portal ───────────────────────────────────────────────────────

    def create_portal_session(self, user: dict, return_url: str = "http://localhost:8000/billing") -> Optional[str]:
        """Stripe customer portal for managing subscription."""
        if not STRIPE_AVAILABLE:
            return "/api/billing/mock-portal"
        try:
            session = stripe.billing_portal.Session.create(
                customer=user.get("stripe_customer_id"),
                return_url=return_url,
            )
            return session.url
        except Exception as e:
            log.error(f"Stripe portal session failed: {e}")
            return None

    # ── Cancel subscription ───────────────────────────────────────────────────

    def cancel_subscription(self, user: dict) -> bool:
        """Schedule subscription to cancel at period end."""
        from saas.database import get_subscription, update_subscription
        sub = get_subscription(user["user_id"])
        if not sub or not sub.get("stripe_subscription_id"):
            return False
        if not STRIPE_AVAILABLE:
            update_subscription(user["user_id"], cancel_at_period_end=True)
            return True
        try:
            stripe.Subscription.modify(
                sub["stripe_subscription_id"],
                cancel_at_period_end=True,
            )
            update_subscription(user["user_id"], cancel_at_period_end=True)
            return True
        except Exception as e:
            log.error(f"Cancel subscription failed: {e}")
            return False

    # ── Webhook handling ──────────────────────────────────────────────────────

    def handle_webhook(self, payload: bytes, sig_header: str) -> dict:
        """
        Process Stripe webhook events.
        Returns {"handled": True, "event_type": ...} or raises ValueError.
        """
        if not STRIPE_AVAILABLE:
            try:
                event = json.loads(payload)
            except Exception:
                raise ValueError("Invalid payload")
        else:
            try:
                event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
            except stripe.error.SignatureVerificationError:
                raise ValueError("Invalid webhook signature")

        event_type = event.get("type", "")
        data = event.get("data", {}).get("object", {})
        log.info(f"Stripe webhook: {event_type}")

        handlers = {
            "checkout.session.completed":         self._on_checkout_complete,
            "customer.subscription.updated":      self._on_subscription_updated,
            "customer.subscription.deleted":      self._on_subscription_deleted,
            "invoice.payment_succeeded":          self._on_payment_succeeded,
            "invoice.payment_failed":             self._on_payment_failed,
        }

        handler = handlers.get(event_type)
        if handler:
            handler(data)

        return {"handled": True, "event_type": event_type}

    def _on_checkout_complete(self, session: dict):
        from saas.database import update_user, update_subscription
        user_id = session.get("metadata", {}).get("user_id")
        
        # SECURITY FIX: Don't trust 'plan' from metadata. 
        # Derive it strictly from the Price ID to prevent spoofing.
        items = session.get("line_items", {}).get("data", [])
        if not items and session.get("id"):
            try:
                # Need to expand line_items as they aren't always in the session object
                full_session = stripe.checkout.Session.retrieve(session["id"], expand=["line_items"])
                items = full_session.get("line_items", {}).get("data", [])
            except Exception:
                log.error("Could not retrieve line items for session")

        price_id = items[0]["price"]["id"] if items else None
        plan = self._plan_from_price(price_id)

        if user_id:
            update_user(user_id, stripe_customer_id=session.get("customer"), plan=plan)
            update_subscription(user_id,
                plan=plan,
                status="active",
                stripe_subscription_id=session.get("subscription"),
            )
            log.info(f"User {user_id} verified upgrade to {plan} via price {price_id}")

    def _on_subscription_updated(self, sub: dict):
        from saas.database import update_subscription
        user_id = sub.get("metadata", {}).get("user_id")
        if user_id:
            # Determine plan strictly from price
            items = sub.get("items", {}).get("data", [])
            price_id = items[0]["price"]["id"] if items else None
            plan = self._plan_from_price(price_id)
            
            status = sub.get("status", "active")
            update_subscription(user_id,
                plan=plan,
                status=status,
                cancel_at_period_end=sub.get("cancel_at_period_end", False),
            )
            log.info(f"Subscription updated for user {user_id}: plan={plan}, status={status}")

    def _on_subscription_deleted(self, sub: dict):
        from saas.database import update_subscription, update_user
        user_id = sub.get("metadata", {}).get("user_id")
        if user_id:
            update_subscription(user_id, plan="free", status="canceled")
            update_user(user_id, plan="free")
            log.info(f"User {user_id} downgraded to free (subscription canceled)")

    def _on_payment_succeeded(self, invoice: dict):
        from saas.database import update_user
        customer_id = invoice.get("customer")
        log.info(f"Payment succeeded for customer {customer_id}")
        # Reset monthly scan count on renewal
        for user in _find_users_by_stripe_customer(customer_id):
            update_user(user["user_id"], scans_this_month=0)

    def _on_payment_failed(self, invoice: dict):
        customer_id = invoice.get("customer")
        log.warning(f"Payment failed for customer {customer_id} — consider dunning flow")

    def _plan_from_price(self, price_id: Optional[str]) -> str:
        from saas.database import PLANS
        if not price_id:
            return "free"
        for plan_name, plan_data in PLANS.items():
            if price_id in (plan_data.get("stripe_price_id_monthly"), plan_data.get("stripe_price_id_yearly")):
                return plan_name
        return "pro"


def _find_users_by_stripe_customer(customer_id: str) -> list:
    from saas.database import _USERS
    return [u for u in _USERS.values() if isinstance(u, dict) and u.get("stripe_customer_id") == customer_id]


billing_service = BillingService()
