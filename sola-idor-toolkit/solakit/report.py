"""Render findings as JSON plus a submission-ready Markdown report."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .config import Account
from .http import Exchange, ScopedSession
from .idor import Finding, Verdict

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

VERDICT_ICON = {
    Verdict.CONFIRMED: "[CONFIRMED]",
    Verdict.LIKELY: "[LIKELY]",
    Verdict.DENIED: "[ok-denied]",
    Verdict.NOT_FOUND: "[ok-scoped]",
    Verdict.IGNORES_ID: "[noise]",
    Verdict.NO_BASELINE: "[skipped]",
    Verdict.ERROR: "[not-run]",
}


def _exchange_map(session: ScopedSession) -> dict[int, Exchange]:
    return {e.seq: e for e in session.exchanges}


def write_reports(
    outdir: Path,
    session: ScopedSession,
    accounts: tuple[Account, Account],
    findings: list[Finding],
    recon_notes: dict[str, str],
) -> tuple[Path, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    a, b = accounts

    positives = [f for f in findings if f.is_positive]
    positives.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    mutation_candidates = [
        f for f in findings
        if f.vector == "cross-account-mutation" and f.verdict is Verdict.ERROR
    ]

    # -- JSON ---------------------------------------------------------------
    json_path = outdir / "findings.json"
    json_path.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "target": "Sola Security (HackerOne)",
        "accounts": [a.redacted(), b.redacted()],
        "recon": recon_notes,
        "summary": _counts(findings),
        "findings": [f.to_dict() for f in findings],
    }, indent=2, default=str))

    # -- Markdown -----------------------------------------------------------
    ex_map = _exchange_map(session)
    lines: list[str] = []
    add = lines.append

    add("# Sola Security - Authorization Testing Report")
    add("")
    add(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    add(f"Endpoint: `https://api.sola.security/graphql`")
    add("")
    add("## Test identities")
    add("")
    add("| Account | User ID | Tenant | Roles |")
    add("|---|---|---|---|")
    for acct in (a, b):
        add(f"| {acct.label} (`{acct.email}`) | `{acct.user_id}` | "
            f"`{acct.tenant_id}` | {', '.join(acct.roles) or '-'} |")
    add("")

    if a.tenant_id and a.tenant_id == b.tenant_id:
        add("> **Note:** both accounts resolved to the *same* tenant. "
            "Cross-tenant findings are not meaningful in this configuration - "
            "results below reflect cross-*user* access within one tenant. "
            "To test the tenant boundary, place the second account in a "
            "separate organisation.")
        add("")

    add("## Recon")
    add("")
    for k, v in recon_notes.items():
        add(f"- **{k}**: {v}")
    add("")

    counts = _counts(findings)
    add("## Result summary")
    add("")
    add("| Verdict | Count |")
    add("|---|---|")
    for k, v in counts.items():
        add(f"| {k} | {v} |")
    add("")

    if not positives:
        add("### No cross-account access confirmed")
        add("")
        add("Every identifier-taking operation that produced a working baseline "
            "correctly refused the other account. That is the expected result "
            "for a sound authorization model.")
        add("")
    else:
        add(f"### {len(positives)} authorization finding(s)")
        add("")

    for i, f in enumerate(positives, 1):
        add(f"---")
        add("")
        add(f"## Finding {i}: {f.severity.upper()} - `{f.candidate_key}` "
            f"({f.vector})")
        add("")
        add(f"**Verdict:** {f.verdict.value}  ")
        add(f"**Impact:** account **{f.attacker}** accessed an object owned by "
            f"account **{f.victim}**.  ")
        add(f"**Object:** `{f.victim_typename}:{f.victim_id}` via argument "
            f"`{f.id_arg}`  ")
        add("")
        add(f"{f.detail}")
        add("")
        if f.leaked_fields:
            add("**Fields exposed to the unauthorised caller:**")
            add("")
            add("```")
            for name in f.leaked_fields:
                add(name)
            add("```")
            add("")
        add("### Reproduction")
        add("")
        for seq in f.evidence_seqs:
            ex = ex_map.get(seq)
            if not ex:
                continue
            add(f"**Step {seq} - {ex.note}** (HTTP {ex.status})")
            add("")
            add("```bash")
            add(ex.as_curl())
            add("```")
            add("")
            add("<details><summary>Response</summary>")
            add("")
            add("```json")
            add(json.dumps(ex.response_body, indent=2, default=str)[:4000])
            add("```")
            add("")
            add("</details>")
            add("")

    if mutation_candidates:
        add("---")
        add("")
        add("## Mutation candidates (not executed)")
        add("")
        add("These mutations accept a caller-supplied object identifier and were "
            "**not** fired, because a cross-tenant write against production can "
            "destroy real data. Review them and re-run with `--allow-mutations` "
            "only against objects you own.")
        add("")
        for f in mutation_candidates:
            add(f"- `{f.candidate_key}` (arg `{f.id_arg}`, severity {f.severity})")
        add("")

    add("---")
    add("")
    add(f"Total HTTP exchanges recorded: {len(session.exchanges)} "
        f"(full transcript in `evidence.json`).")

    md_path = outdir / "REPORT.md"
    md_path.write_text("\n".join(lines))
    return md_path, json_path


def _counts(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.verdict.value] = out.get(f.verdict.value, 0) + 1
    return out


def console_summary(findings: list[Finding]) -> str:
    positives = [f for f in findings if f.is_positive]
    lines = []
    counts = _counts(findings)
    lines.append("  " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if positives:
        lines.append("")
        lines.append(f"  {len(positives)} POSITIVE finding(s):")
        for f in sorted(positives, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
            lines.append(
                f"    {VERDICT_ICON[f.verdict]} [{f.severity}] {f.candidate_key} "
                f"- {f.attacker} read {f.victim}'s {f.victim_typename or 'object'}"
            )
    return "\n".join(lines)
