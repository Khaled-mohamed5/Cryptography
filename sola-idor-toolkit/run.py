#!/usr/bin/env python3
"""Sola Security - cross-account authorization test runner.

Usage:
    export SOLA_A_EMAIL=... SOLA_A_PASSWORD=...
    export SOLA_B_EMAIL=... SOLA_B_PASSWORD=...
    python3 run.py                      # read-only, safe against production
    python3 run.py --allow-mutations    # also fire write operations (review first)

Scope is enforced in code: traffic can only go to the hosts the program lists
as in scope. See solakit/config.py.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from solakit.auth import describe, login, try_tenant_switch
from solakit.config import DEFAULT_SAFETY, GRAPHQL_ENDPOINT, Safety, load_accounts
from solakit.gql import GraphQLClient
from solakit.harvest import harvest
from solakit.http import ScopedSession
from solakit.idor import Finding, IdorEngine, Verdict
from solakit.recon import SchemaIndex, find_candidates, summarise
from solakit.report import console_summary, write_reports


def banner(text: str) -> None:
    print(f"\n{'=' * 68}\n  {text}\n{'=' * 68}")


def main() -> int:
    p = argparse.ArgumentParser(description="Sola Security authorization testing")
    p.add_argument("--out", default="findings", help="output directory")
    p.add_argument("--rate", type=float, default=DEFAULT_SAFETY.rate_limit_rps,
                   help="max requests/second (default: %(default)s)")
    p.add_argument("--allow-mutations", action="store_true",
                   help="actually execute cross-account mutations (destructive)")
    p.add_argument("--max-probes", type=int, default=400,
                   help="cap on attack probes per direction")
    p.add_argument("--schema", type=Path,
                   help="load introspection JSON from file (when the live "
                        "endpoint has introspection disabled)")
    p.add_argument("--endpoint", default=GRAPHQL_ENDPOINT)
    p.add_argument("--no-redact", action="store_true",
                   help="keep tokens in the saved evidence transcript")
    p.add_argument("--one-way", action="store_true",
                   help="only test A->B (default tests both directions)")
    args = p.parse_args()

    safety = Safety(
        rate_limit_rps=args.rate,
        allow_mutations=args.allow_mutations,
        redact_tokens=not args.no_redact,
    )
    session = ScopedSession(safety)
    client = GraphQLClient(session, endpoint=args.endpoint)
    recon_notes: dict[str, str] = {}

    # -- 1. authenticate ----------------------------------------------------
    banner("1. Authenticating both test identities")
    account_a, account_b = load_accounts()
    for acct in (account_a, account_b):
        login(session, acct)
        print(describe(acct))

    same_tenant = bool(account_a.tenant_id) and account_a.tenant_id == account_b.tenant_id
    if same_tenant:
        print("\n  !! Both accounts are in the SAME tenant "
              f"({account_a.tenant_id}).")
        print("     Cross-TENANT isolation cannot be tested in this setup;")
        print("     what follows tests cross-USER access inside one tenant.")
        recon_notes["tenancy"] = (
            f"both accounts share tenant {account_a.tenant_id} - "
            "results reflect intra-tenant user isolation"
        )
    else:
        recon_notes["tenancy"] = (
            f"A={account_a.tenant_id} B={account_b.tenant_id} (distinct tenants)"
        )

    # -- 2. schema ----------------------------------------------------------
    banner("2. Schema discovery")
    schema = None
    if args.schema:
        raw = json.loads(args.schema.read_text())
        schema = raw.get("data", {}).get("__schema") or raw.get("__schema") or raw
        note = f"schema loaded from {args.schema}"
        print(f"  {note}")
        recon_notes["introspection"] = note
    else:
        schema, note = client.introspect(account_a)
        print(f"  {note}")
        recon_notes["introspection"] = note
        if schema:
            recon_notes["introspection_finding"] = (
                "Introspection is enabled on production. On its own this is "
                "usually informational/low, but it hands an attacker the full "
                "attack surface map."
            )

    if not schema:
        suggestions = client.probe_field_suggestions(account_a)
        if suggestions:
            msg = ("introspection disabled but field suggestions leak names: "
                   + ", ".join(suggestions[:15]))
            print(f"  {msg}")
            recon_notes["field_suggestions"] = msg
        print("\n  Cannot build a test plan without a schema.")
        print("  Capture one from the app's JS bundle or a proxied request and")
        print("  re-run with --schema schema.json")
        session.save_evidence(Path(args.out) / "evidence.json")
        return 2

    index = SchemaIndex(schema)
    candidates = find_candidates(index)
    print(f"  {summarise(candidates)}")
    recon_notes["attack_surface"] = summarise(candidates)

    top = [c for c in candidates if c.severity in ("critical", "high")][:12]
    if top:
        print("\n  Highest-value targets:")
        for c in top:
            print(f"    [{c.severity:8}] {c.operation:8} {c.field_name}"
                  f"({c.id_args[0]['name']}) -> {c.return_type}")

    # -- 3. batching --------------------------------------------------------
    banner("3. Request-amplification check")
    listing = next(
        (f["name"] for f in index.fields_of(index.query_type)
         if not any(a.get("type", {}).get("kind") == "NON_NULL" for a in (f.get("args") or []))
         and not f["name"].startswith("__")),
        None,
    )
    if listing:
        ok, note = client.probe_alias_batching(account_a, listing)
        print(f"  {'UNBOUNDED' if ok else 'limited'}: {note}")
        recon_notes["alias_batching"] = note
        if ok:
            recon_notes["batching_finding"] = (
                "Alias batching is unbounded: a single HTTP request can carry "
                "many resolver invocations, defeating per-request rate limits."
            )

    # -- 4. harvest ---------------------------------------------------------
    banner("4. Harvesting owned objects")
    owned_a, notes_a = harvest(client, index, account_a)
    owned_b, notes_b = harvest(client, index, account_b)
    print(f"  Account A owns {len(owned_a)} identifier(s)")
    print(f"  Account B owns {len(owned_b)} identifier(s)")
    recon_notes["harvest_A"] = f"{len(owned_a)} identifiers"
    recon_notes["harvest_B"] = f"{len(owned_b)} identifiers"

    if not owned_a and not owned_b:
        print("\n  Neither account exposed any object identifiers.")
        print("  Seed both accounts with data in the UI first, then re-run.")
        session.save_evidence(Path(args.out) / "evidence.json")
        return 2

    for label, sample in (("A", owned_a), ("B", owned_b)):
        if sample:
            print(f"\n  Sample ({label}):")
            for o in sample[:6]:
                print(f"    {o.display}  <- {o.source_field}{o.json_path[1:]}")

    # -- 5. tenant switch ---------------------------------------------------
    if not same_tenant and account_a.tenant_id:
        banner("5. IdP tenant-switch attempt")
        ok, note = try_tenant_switch(session, account_b, account_a.tenant_id)
        print(f"  {'ACCEPTED - serious' if ok else 'rejected'}: {note}")
        recon_notes["tenant_switch"] = f"{'ACCEPTED' if ok else 'rejected'}: {note}"

    # -- 6. cross-account engine -------------------------------------------
    banner("6. Cross-account authorization probes")
    findings: list[Finding] = []

    print(f"\n  Direction 1: B attacks A's objects ({len(owned_a)} targets)")
    eng1 = IdorEngine(client, attacker=account_b, victim=account_a, safety=safety)
    findings += eng1.run(candidates, owned_a, owned_b,
                         max_probes=args.max_probes,
                         test_tenant_override=not same_tenant)
    print(console_summary(eng1.findings))

    if not args.one_way:
        print(f"\n  Direction 2: A attacks B's objects ({len(owned_b)} targets)")
        eng2 = IdorEngine(client, attacker=account_a, victim=account_b, safety=safety)
        findings += eng2.run(candidates, owned_b, owned_a,
                             max_probes=args.max_probes,
                             test_tenant_override=not same_tenant)
        print(console_summary(eng2.findings))

    # -- 7. report ----------------------------------------------------------
    banner("7. Writing report")
    outdir = Path(args.out)
    session.save_evidence(outdir / "evidence.json")
    md, js = write_reports(outdir, session, (account_a, account_b), findings, recon_notes)
    print(f"  {md}")
    print(f"  {js}")
    print(f"  {outdir / 'evidence.json'}  ({len(session.exchanges)} exchanges)")

    positives = [f for f in findings if f.is_positive]
    banner(f"DONE - {len(positives)} positive finding(s)")
    if positives:
        print(console_summary(findings))
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted")
        sys.exit(130)
