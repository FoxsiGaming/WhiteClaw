# ⚠️ DESTRUCTIVE TEST — Do not run against production.
# Set ENABLE_DESTRUCTIVE_TESTS=True in tests/active/config.py to enable.
"""Destructive: race conditions — double-spend, duplicate actions, concurrency bugs."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import threading
import time
import pytest

from tests.active.config import ENABLE_DESTRUCTIVE_TESTS, TARGET_URL
from tests.active.helpers import safe_post, url_join

if not ENABLE_DESTRUCTIVE_TESTS:
    pytestmark = pytest.mark.skip(
        reason="ENABLE_DESTRUCTIVE_TESTS=False in config.py — "
               "these tests submit concurrent real transactions."
    )


def _fire_n_concurrent(fn, n=10):
    """Fire fn() n times simultaneously and collect results."""
    results = []
    errors = []
    barrier = threading.Barrier(n)

    def _worker():
        try:
            barrier.wait(timeout=5)
            results.append(fn())
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=_worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return results, errors


class TestDoubleSpend:
    def test_coupon_can_only_be_applied_once(self):
        """Apply the same coupon code concurrently — only one request should succeed."""
        coupon = "DISCOUNT10"
        successes = []

        def apply_coupon():
            r = safe_post(url_join("/cart/coupon"),
                          json={"code": coupon, "cart_id": "test_cart_wc"})
            return r

        results, _ = _fire_n_concurrent(apply_coupon, n=10)
        for r in results:
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if data.get("success") or data.get("discount"):
                        successes.append(r.text[:50])
                except Exception:
                    pass

        if len(successes) > 1:
            pytest.fail(
                f"Race condition: coupon applied {len(successes)} times simultaneously — "
                "double-spend vulnerability confirmed"
            )

    def test_order_submitted_only_once_on_double_click(self):
        """Submitting the same order concurrently should create at most one order."""
        order_ids = []

        def submit_order():
            r = safe_post(url_join("/checkout/submit"),
                          json={"product_id": "1", "quantity": 1, "nonce": "wc_test_nonce"})
            return r

        results, _ = _fire_n_concurrent(submit_order, n=5)
        for r in results:
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    oid = data.get("order_id") or data.get("id")
                    if oid:
                        order_ids.append(oid)
                except Exception:
                    pass

        unique_orders = set(order_ids)
        if len(order_ids) > 1 and len(unique_orders) < len(order_ids):
            pytest.fail(
                f"Duplicate orders created: {len(order_ids)} submissions → "
                f"{len(unique_orders)} unique order IDs — possible race condition"
            )


class TestConcurrentWithdrawal:
    def test_balance_not_overdrawn_by_race(self):
        """Withdraw the same credit amount concurrently — balance should not go negative."""
        withdrawals = []

        def withdraw():
            r = safe_post(url_join("/account/withdraw"),
                          json={"amount": 50, "account": "test_wc"})
            return r

        results, _ = _fire_n_concurrent(withdraw, n=10)
        successful = []
        for r in results:
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if data.get("success") or data.get("balance") is not None:
                        successful.append(data.get("balance"))
                except Exception:
                    pass

        negative = [b for b in successful if isinstance(b, (int, float)) and b < 0]
        if negative:
            pytest.fail(
                f"Race condition caused negative balances: {negative} — "
                "concurrent withdrawals exceeded available balance"
            )


class TestParallelAccountActions:
    def test_vote_counted_once_per_user(self):
        """A user should only be able to vote once even with concurrent requests."""
        vote_counts = []

        def submit_vote():
            r = safe_post(url_join("/vote"),
                          json={"item_id": "wc_test_item", "vote": "up"})
            return r

        results, _ = _fire_n_concurrent(submit_vote, n=10)
        accepted = sum(1 for r in results if r and r.status_code == 200)

        if accepted > 1:
            pytest.fail(
                f"Race condition in voting: {accepted}/10 concurrent votes accepted — "
                "should only accept 1 per user"
            )

    def test_gift_card_redeemed_only_once(self):
        """A gift card code should be redeemable only once."""
        redemptions = []

        def redeem():
            r = safe_post(url_join("/redeem"),
                          json={"code": "GIFTCARD-TEST-WC-001"})
            return r

        results, _ = _fire_n_concurrent(redeem, n=8)
        success = [r for r in results if r and r.status_code == 200]
        try:
            actual_successes = [
                r for r in success
                if "success" in r.text.lower() or "redeemed" in r.text.lower()
            ]
        except Exception:
            actual_successes = success

        if len(actual_successes) > 1:
            pytest.fail(
                f"Gift card redeemed {len(actual_successes)} times concurrently — "
                "race condition allows multiple redemptions"
            )
