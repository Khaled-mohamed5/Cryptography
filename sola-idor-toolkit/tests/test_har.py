"""Verify the captured-traffic path: a HAR replaces introspection entirely."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import solakit.auth as auth_mod
import solakit.http as http_mod
from solakit.config import Account, Safety
from solakit.gql import GraphQLClient
from solakit.harfile import (
    harvest_from_capture,
    load_operations,
    operations_to_candidates,
    parse_document,
)
from solakit.http import ScopedSession, looks_like_edge_block
from solakit.idor import IdorEngine, Verdict
from tests.mock_server import start

A_POLICY = "11111111-1111-1111-1111-111111111111"
A_KEY = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
B_POLICY = "22222222-2222-2222-2222-222222222222"


def _har(entries):
    return {"log": {"version": "1.2", "entries": entries}}


def _entry(doc, variables, response=None, name=""):
    return {
        "request": {
            "method": "POST",
            "url": "https://api.sola.security/graphql",
            "postData": {"text": json.dumps(
                {"operationName": name, "query": doc, "variables": variables})},
        },
        "response": {"status": 200, "content": {
            "text": json.dumps(response) if response else ""}},
    }


def run() -> int:
    failures = []

    def check(cond, msg):
        print(f"  {'PASS' if cond else 'FAIL'}  {msg}")
        if not cond:
            failures.append(msg)

    print("\n[document parsing]")
    t, n, v, root = parse_document(
        "query GetPolicy($id: ID!, $full: Boolean) { policy(id: $id) { id name } }")
    check((t, n, root) == ("query", "GetPolicy", "policy"),
          f"query header parsed ({t}/{n}/{root})")
    check(v == [("id", "ID!"), ("full", "Boolean")], f"variable defs parsed ({v})")

    t2, _, _, root2 = parse_document(
        "mutation Del($policyId: ID!) { deletePolicy(id: $policyId) { id } }")
    check((t2, root2) == ("mutation", "deletePolicy"),
          f"mutation parsed ({t2}/{root2})")

    _, _, _, aliased = parse_document("query Q($id: ID!) { p: policy(id:$id) { id } }")
    check(aliased == "policy", f"alias skipped, real field found ({aliased})")

    print("\n[edge-block detection]")
    waf = {"message": "access denied. Your request was blocked by WAF security rules."}
    check(looks_like_edge_block(403, waf), "WAF 403 recognised as an edge block")
    check(not looks_like_edge_block(403, {"errors": [{"message": "not authorized"}]}),
          "application 403 with GraphQL errors NOT treated as an edge block")
    check(not looks_like_edge_block(200, {"data": {}}), "200 is not an edge block")

    print("\n[HAR ingestion]")
    har = _har([
        _entry("query GetPolicy($id: ID!) { policy(id: $id) { __typename id name tenantId } }",
               {"id": A_POLICY},
               {"data": {"policy": {"__typename": "Policy", "id": A_POLICY,
                                    "name": "A's policy", "tenantId": "tenant-1"}}},
               "GetPolicy"),
        _entry("query GetApiKey($id: ID!) { apiKey(id: $id) { __typename id secret } }",
               {"id": A_KEY},
               {"data": {"apiKey": {"__typename": "ApiKey", "id": A_KEY,
                                    "secret": "SECRET-A"}}},
               "GetApiKey"),
        _entry("query ListPolicies { policies { id name } }", {}, None, "ListPolicies"),
        # noise that must be filtered out
        {"request": {"method": "GET", "url": "https://cdn.example.com/x.png"},
         "response": {"status": 200, "content": {"text": ""}}},
    ])

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "a.har"
        path.write_text(json.dumps(har))
        ops = load_operations(path, only_host="sola.security")
        check(len(ops) == 3, f"3 GraphQL ops extracted, non-GraphQL ignored (got {len(ops)})")

        cands = operations_to_candidates(ops)
        keys = {c.key for c in cands}
        check("query.policy" in keys, "policy candidate derived from capture")
        check("query.apiKey" in keys, "apiKey candidate derived from capture")
        check("query.policies" not in keys,
              "list operation with no id argument correctly excluded")
        pol = next(c for c in cands if c.key == "query.policy")
        check(pol.default_variables == {"id": A_POLICY},
              f"captured variables retained ({pol.default_variables})")
        check(pol.source == "captured", "candidate tagged as captured")

        owned = harvest_from_capture(ops, "A")
        vals = {o.value for o in owned}
        check(A_POLICY in vals and A_KEY in vals,
              f"ids harvested from capture ({len(owned)} found)")
        check(B_POLICY not in vals, "B's id absent from A's capture")

        print("\n[engine driven by capture, no schema]")
        srv, base = start()
        http_mod.IN_SCOPE_HOSTS = frozenset({"127.0.0.1"})
        auth_mod.LOGIN_PATHS = [f"{base}/auth/login"]
        safety = Safety(rate_limit_rps=0, redact_tokens=False)
        session = ScopedSession(safety)
        client = GraphQLClient(session, endpoint=f"{base}/graphql")
        a = Account("A", "a@example.test", "pw-a")
        b = Account("B", "b@example.test", "pw-b")
        auth_mod.login(session, a)
        auth_mod.login(session, b)

        owned_a = harvest_from_capture(ops, "A")
        eng = IdorEngine(client, attacker=b, victim=a, safety=safety)
        findings = eng.run(cands, owned_a, [], max_probes=50,
                           test_tenant_override=False)
        by_op = {}
        for f in findings:
            by_op.setdefault(f.candidate_key, set()).add(f.verdict)
        for k, vv in sorted(by_op.items()):
            print(f"       {k:22} -> {', '.join(sorted(x.value for x in vv))}")

        check(Verdict.CONFIRMED in by_op.get("query.policy", set()),
              "vulnerable resolver CONFIRMED via captured document")
        check(Verdict.CONFIRMED not in by_op.get("query.apiKey", set()),
              "secure resolver still not a finding via captured document")
        srv.shutdown()

    print(f"\n{'=' * 60}")
    if failures:
        print(f"{len(failures)} FAILURE(S):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(run())
