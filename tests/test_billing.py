import sys
import os
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from saas.billing import billing_service, BillingService
import saas.billing as billing_module
from saas.database import create_user, get_user, get_subscription, update_user

class TestBillingSecurity(unittest.TestCase):
    def setUp(self):
        # Create a mock user for testing dunning/webhook flows
        self.user = create_user(
            email="billing-test@example.com",
            name="Billing Test User",
            password_hash="mock_hash",
            plan="pro"
        )
        self.user_id = self.user["user_id"]
        # Update user's stripe customer id
        update_user(self.user_id, stripe_customer_id="cus_test_12345")

    def test_webhook_disabled_in_dev_mode(self):
        # Verify that when STRIPE_AVAILABLE is False, handle_webhook raises ValueError
        with patch.object(billing_module, "STRIPE_AVAILABLE", False):
            with self.assertRaises(ValueError) as ctx:
                billing_service.handle_webhook(b'{"id": "evt_test"}', "sig_header")
            self.assertIn("disabled in development/mock mode", str(ctx.exception))

    def test_payment_failed_downgrades_plan(self):
        # Verify that _on_payment_failed downgrades user plan to free and status to past_due
        invoice = {
            "customer": "cus_test_12345",
            "id": "in_test_failed"
        }
        
        # Verify original user plan is pro
        user_before = get_user(self.user_id)
        self.assertEqual(user_before["plan"], "pro")

        # Invoke payment failed handler
        billing_service._on_payment_failed(invoice)

        # Verify plan is now free
        user_after = get_user(self.user_id)
        self.assertEqual(user_after["plan"], "free")

        # Verify subscription is now free with status past_due
        sub = get_subscription(self.user_id)
        self.assertEqual(sub["plan"], "free")
        self.assertEqual(sub["status"], "past_due")

if __name__ == "__main__":
    unittest.main()
