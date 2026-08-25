#!/usr/bin/env python3
"""Unit tests for the pure logic in authz_diff. No network access."""

import unittest

from authz_diff import Budget, BudgetExhausted, Probe, classify, extract


def probe(status, body_hash, length=100, identity="x"):
    return Probe(
        label="Invoice:1",
        method="GET",
        url="https://example.invalid/api/v1/Invoice/1",
        identity=identity,
        status=status,
        length=length,
        body_hash=body_hash,
    )


class TestExtract(unittest.TestCase):
    def test_wildcard_list(self):
        doc = {"objects": [{"id": "1"}, {"id": "2"}]}
        self.assertEqual(extract(doc, "objects[*].id"), ["1", "2"])

    def test_nested_path(self):
        doc = {"data": {"items": [{"uuid": "abc"}]}}
        self.assertEqual(extract(doc, "data.items[*].uuid"), ["abc"])

    def test_indexed_access(self):
        doc = {"objects": [{"id": "1"}, {"id": "2"}]}
        self.assertEqual(extract(doc, "objects[1].id"), ["2"])

    def test_missing_key_is_empty_not_error(self):
        self.assertEqual(extract({"objects": []}, "objects[*].id"), [])
        self.assertEqual(extract({}, "nope[*].id"), [])

    def test_index_out_of_range(self):
        self.assertEqual(extract({"objects": [{"id": "1"}]}, "objects[5].id"), [])


class TestClassify(unittest.TestCase):
    def test_cross_tenant_idor_is_confirmed(self):
        f = classify(probe(200, "same"), probe(200, "same"), probe(403, "x"))
        self.assertEqual(f.verdict, "CONFIRMED")

    def test_unauthenticated_read_outranks_cross_tenant(self):
        # anon reading owner content is worse than tenant B reading it
        f = classify(probe(200, "same"), probe(200, "same"), probe(200, "same"))
        self.assertEqual(f.verdict, "CRITICAL")

    def test_denied_when_second_tenant_refused(self):
        for status in (401, 403, 404):
            f = classify(probe(200, "a"), probe(status, "b"), probe(403, "c"))
            self.assertEqual(f.verdict, "DENIED", f"status {status}")

    def test_different_content_needs_manual_review(self):
        f = classify(probe(200, "a", 500), probe(200, "b", 120), probe(403, "c"))
        self.assertEqual(f.verdict, "INVESTIGATE")

    def test_owner_cannot_read_means_no_baseline(self):
        f = classify(probe(404, None), probe(404, None), probe(404, None))
        self.assertEqual(f.verdict, "SKIP")

    def test_unexpected_status_flagged(self):
        f = classify(probe(200, "a"), probe(500, "b"), probe(403, "c"))
        self.assertEqual(f.verdict, "INVESTIGATE")

    def test_evidence_captures_all_three_identities(self):
        f = classify(probe(200, "a"), probe(403, "b"), probe(401, "c"))
        self.assertEqual(set(f.evidence), {"owner", "other", "anon"})


class TestBudget(unittest.TestCase):
    def test_budget_is_enforced(self):
        budget = Budget(max_requests=3, rps=0)
        for _ in range(3):
            budget.take()
        with self.assertRaises(BudgetExhausted):
            budget.take()

    def test_spent_is_tracked(self):
        budget = Budget(max_requests=10, rps=0)
        budget.take()
        budget.take()
        self.assertEqual(budget.spent, 2)

    def test_rate_limit_actually_delays(self):
        import time

        budget = Budget(max_requests=5, rps=20.0)  # 50ms apart
        start = time.monotonic()
        budget.take()
        budget.take()
        budget.take()
        self.assertGreater(time.monotonic() - start, 0.09)


if __name__ == "__main__":
    unittest.main(verbosity=2)
