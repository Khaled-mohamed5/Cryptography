"""End-to-end test of the authorization engine against the mock API.

Asserts the three outcomes that matter:
  policy   -> CONFIRMED   (genuinely vulnerable: no tenant check)
  apiKey   -> DENIED      (correctly secured - must NOT be reported)
  profile  -> IGNORES_ID  (resolver ignores the id - must NOT be reported)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import solakit.auth as auth_mod
import solakit.http as http_mod
from solakit.config import Account, Safety
from solakit.gql import GraphQLClient
from solakit.harvest import harvest
from solakit.http import ScopedSession
from solakit.idor import IdorEngine, Verdict
from solakit.recon import SchemaIndex, find_candidates
from tests.mock_server import start


def run() -> int:
    srv, base = start()
    # Test-only: widen the scope allowlist to the loopback mock. Production
    # code keeps its allowlist untouched.
    http_mod.IN_SCOPE_HOSTS = frozenset({"127.0.0.1"})
    auth_mod.LOGIN_PATHS = [f"{base}/auth/login"]

    safety = Safety(rate_limit_rps=0, redact_tokens=False)
    session = ScopedSession(safety)
    client = GraphQLClient(session, endpoint=f"{base}/graphql")

    a = Account(label="A", email="a@example.test", password="pw-a")
    b = Account(label="B", email="b@example.test", password="pw-b")
    auth_mod.login(session, a)
    auth_mod.login(session, b)

    failures: list[str] = []

    def check(cond: bool, msg: str) -> None:
        print(f"  {'PASS' if cond else 'FAIL'}  {msg}")
        if not cond:
            failures.append(msg)

    print("\n[identity]")
    check(a.tenant_id == "tenant-1", f"A resolved to tenant-1 (got {a.tenant_id})")
    check(b.tenant_id == "tenant-2", f"B resolved to tenant-2 (got {b.tenant_id})")
    check(a.user_id == "uid-a", f"A user id extracted (got {a.user_id})")

    print("\n[schema]")
    schema, note = client.introspect(a)
    check(schema is not None, f"introspection returned a schema ({note})")
    index = SchemaIndex(schema)
    candidates = find_candidates(index)
    keys = {c.key for c in candidates}
    check("query.policy" in keys, "policy(id:) identified as a candidate")
    check("query.apiKey" in keys, "apiKey(id:) identified as a candidate")
    check("mutation.deletePolicy" in keys, "deletePolicy(id:) identified as a candidate")
    sev = {c.key: c.severity for c in candidates}
    check(sev.get("query.apiKey") == "critical",
          f"apiKey ranked critical (got {sev.get('query.apiKey')})")

    print("\n[harvest]")
    owned_a, _ = harvest(client, index, a)
    owned_b, _ = harvest(client, index, b)
    a_vals = {o.value for o in owned_a}
    check("11111111-1111-1111-1111-111111111111" in a_vals,
          "A's policy id harvested")
    check("22222222-2222-2222-2222-222222222222" not in a_vals,
          "B's policy id NOT visible to A (listing is correctly scoped)")
    check(any(o.typename == "ApiKey" for o in owned_a),
          "harvested ids carry their __typename")

    print("\n[engine: B attacks A]")
    eng = IdorEngine(client, attacker=b, victim=a, safety=safety)
    findings = eng.run(candidates, owned_a, owned_b, max_probes=200,
                       test_tenant_override=False)

    by_op: dict[str, set[Verdict]] = {}
    for f in findings:
        by_op.setdefault(f.candidate_key, set()).add(f.verdict)

    for k, v in sorted(by_op.items()):
        print(f"       {k:26} -> {', '.join(sorted(x.value for x in v))}")

    check(Verdict.CONFIRMED in by_op.get("query.policy", set()),
          "VULNERABLE policy(id:) reported CONFIRMED")
    check(Verdict.CONFIRMED not in by_op.get("query.apiKey", set())
          and Verdict.LIKELY not in by_op.get("query.apiKey", set()),
          "SECURE apiKey(id:) NOT reported as a finding")
    check(Verdict.IGNORES_ID in by_op.get("query.profile", set())
          or not by_op.get("query.profile"),
          "profile(id:) correctly classified as ignoring the id (no false positive)")

    positives = [f for f in findings if f.is_positive]
    check(all(f.candidate_key == "query.policy" for f in positives),
          f"only the vulnerable resolver produced positives "
          f"({sorted({f.candidate_key for f in positives})})")

    print("\n[safety]")
    mut = [f for f in findings if f.vector == "cross-account-mutation"]
    check(all("NOT EXECUTED" in f.detail for f in mut),
          "mutations recorded but not executed under default safety")

    try:
        http_mod.assert_in_scope("https://docs.sola.security/x")
        check(False, "out-of-scope host rejected")
    except http_mod.OutOfScopeError:
        check(True, "out-of-scope host rejected")

    confirmed = next(f for f in positives if f.verdict is Verdict.CONFIRMED)
    check(bool(confirmed.evidence_seqs), "finding carries evidence exchange ids")
    leaf_names = {f.rsplit(".", 1)[-1] for f in confirmed.leaked_fields}
    check({"name", "tenantId"} <= leaf_names,
          f"leaked fields captured with paths ({confirmed.leaked_fields})")

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
