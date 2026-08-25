#!/usr/bin/env python3
"""Unit tests for har_to_config. No network access."""

import json
import os
import tempfile
import unittest

from har_to_config import (
    build_groups,
    find_id_paths,
    is_identifier,
    load_entries,
    normalize,
    resource_name,
    significant_query,
)

HOST = "app.example.invalid"
J = "application/json"


def entry(method, url, mime=J, body='{"objects":[{"id":"1"}]}'):
    return {
        "request": {"method": method, "url": url},
        "response": {"content": {"mimeType": mime, "text": body}},
    }


def write_har(entries):
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".har", delete=False, encoding="utf-8"
    )
    json.dump({"log": {"entries": entries}}, handle)
    handle.close()
    return handle.name


class TestIdentifiers(unittest.TestCase):
    def test_numeric_and_uuid_and_hex(self):
        self.assertTrue(is_identifier("1001"))
        self.assertTrue(is_identifier("550e8400-e29b-41d4-a716-446655440000"))
        self.assertTrue(is_identifier("a3f9c1d2e4b5a6f7"))

    def test_route_names_are_not_identifiers(self):
        for name in ("Invoice", "api", "v1", "getPdf"):
            self.assertFalse(is_identifier(name), name)

    def test_normalize_templates_ids(self):
        self.assertEqual(
            normalize("/api/v1/Invoice/1001"), ("/api/v1/Invoice/{id}", True)
        )
        self.assertEqual(normalize("/api/v1/Invoice"), ("/api/v1/Invoice", False))


class TestResourceName(unittest.TestCase):
    def test_collection(self):
        self.assertEqual(resource_name("/api/v1/Invoice"), "Invoice")

    def test_detail(self):
        self.assertEqual(resource_name("/api/v1/Invoice/{id}"), "Invoice")

    def test_subresource_groups_under_parent_not_action(self):
        # regression: taking the last segment filed this under 'getPdf',
        # which has no collection to harvest ids from
        self.assertEqual(resource_name("/api/v1/Invoice/{id}/getPdf"), "Invoice")
        self.assertEqual(resource_name("/api/v1/Order/{id}/download"), "Order")


class TestQuery(unittest.TestCase):
    def test_paging_params_dropped(self):
        self.assertEqual(significant_query("limit=25&offset=50"), "")

    def test_meaningful_params_kept(self):
        self.assertEqual(significant_query("embed=contact&limit=25"), "embed=contact")


class TestIdPaths(unittest.TestCase):
    def test_top_level_objects(self):
        self.assertIn("objects[*].id", find_id_paths({"objects": [{"id": "1"}]}))

    def test_nested_uuid(self):
        self.assertIn(
            "data.items[*].uuid", find_id_paths({"data": {"items": [{"uuid": "a"}]}})
        )

    def test_no_ids_returns_empty(self):
        self.assertEqual(find_id_paths({"total": 5, "ok": True}), [])


class TestLoadEntries(unittest.TestCase):
    def _load(self, entries):
        path = write_har(entries)
        try:
            return load_entries(path, HOST)
        finally:
            os.unlink(path)

    def test_filters_non_get_and_other_hosts(self):
        kept = self._load(
            [
                entry("GET", f"https://{HOST}/api/v1/Invoice"),
                entry("POST", f"https://{HOST}/api/v1/Invoice"),
                entry("GET", "https://cdn.other.invalid/app.js", "text/javascript", "x"),
            ]
        )
        self.assertEqual(len(kept), 1)

    def test_keeps_non_json_detail_endpoints(self):
        # regression: a case-sensitive 'endswith(pdf)' check dropped getPdf,
        # the exact variant most likely to skip an authorization check
        kept = self._load(
            [entry("GET", f"https://{HOST}/api/v1/Invoice/1/getPdf", "application/pdf", None)]
        )
        self.assertEqual(len(kept), 1)

    def test_drops_static_assets_with_hashed_names(self):
        kept = self._load(
            [entry("GET", f"https://{HOST}/static/a3f9c1d2e4b5a6f7.js", "text/javascript", None)]
        )
        self.assertEqual(kept, [])


class TestBuildGroups(unittest.TestCase):
    def test_variants_group_under_one_object_type(self):
        entries = [
            entry("GET", f"https://{HOST}/api/v1/Invoice?limit=25"),
            entry("GET", f"https://{HOST}/api/v1/Invoice/1001"),
            entry("GET", f"https://{HOST}/api/v1/Invoice/1001/getPdf", "application/pdf", None),
            entry("GET", f"https://{HOST}/api/v1/Invoice/1001?embed=contact"),
        ]
        groups = build_groups(entries, "{base_url}")
        self.assertEqual(list(groups), ["Invoice"])
        self.assertEqual(len(groups["Invoice"]["detail"]), 3)

    def test_paged_repeats_collapse_to_one_group(self):
        entries = [
            entry("GET", f"https://{HOST}/api/v1/Invoice?limit=25"),
            entry("GET", f"https://{HOST}/api/v1/Invoice?limit=25&offset=25"),
        ]
        self.assertEqual(len(build_groups(entries, "{base_url}")), 1)

    def test_detail_without_collection_is_flagged(self):
        entries = [entry("GET", f"https://{HOST}/api/v1/Voucher/9001")]
        groups = build_groups(entries, "{base_url}")
        group = groups["Voucher_orphan"]
        self.assertIn("CHANGE-ME", group["list"])
        self.assertIn("_comment", group)


if __name__ == "__main__":
    unittest.main(verbosity=2)
