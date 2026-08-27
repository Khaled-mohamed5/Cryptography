"""Cross-account authorization testing engine.

A naive IDOR scanner sends account B's token with account A's object id, sees
HTTP 200, and calls it a finding. That produces false positives constantly,
because a 200 can also mean:

  * the resolver ignored the id argument and returned B's *own* object,
  * the field returns null-with-200 (the GraphQL norm for a denial),
  * the object is genuinely public.

So every probe here is run against controls:

  baseline  A asks for A's object   -> proves the query works and shows the
                                       response an authorised caller receives
  attack    B asks for A's object   -> the actual test
  control   B asks for B's object   -> proves the resolver honours the id arg

A finding is only reported when the attack returns data, the baseline
succeeded, and the attack response differs from the control - i.e. B really
did receive A's data rather than its own.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .config import Account, Safety
from .gql import GqlResult, GraphQLClient
from .harvest import OwnedObject
from .recon import Candidate


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"        # attacker received the victim's object
    LIKELY = "LIKELY"              # attacker received data it should not have
    DENIED = "DENIED"              # correctly refused
    NOT_FOUND = "NOT_FOUND"        # correctly scoped out of existence
    IGNORES_ID = "IGNORES_ID"      # resolver ignored the identifier - not IDOR
    NO_BASELINE = "NO_BASELINE"    # query/id pair never worked for the owner
    ERROR = "ERROR"


@dataclass
class Finding:
    verdict: Verdict
    candidate_key: str
    id_arg: str
    victim_id: str
    victim_typename: str
    attacker: str
    victim: str
    severity: str
    detail: str
    evidence_seqs: list[int] = field(default_factory=list)
    leaked_fields: list[str] = field(default_factory=list)
    vector: str = "cross-account-object-reference"

    @property
    def is_positive(self) -> bool:
        return self.verdict in (Verdict.CONFIRMED, Verdict.LIKELY)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "vector": self.vector,
            "operation": self.candidate_key,
            "id_argument": self.id_arg,
            "victim_object": f"{self.victim_typename}:{self.victim_id}",
            "attacker_account": self.attacker,
            "victim_account": self.victim,
            "severity": self.severity,
            "detail": self.detail,
            "leaked_fields": self.leaked_fields,
            "evidence_exchange_seqs": self.evidence_seqs,
        }


def _normalise(data: Any) -> str:
    return json.dumps(data, sort_keys=True, default=str)


def _leaked_field_names(data: Any, limit: int = 40) -> list[str]:
    """Flatten the keys that actually carried a non-null value."""
    out: list[str] = []

    def walk(node: Any, prefix: str = "") -> None:
        if len(out) >= limit:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "__typename":
                    continue
                p = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    walk(v, p)
                elif v is not None:
                    out.append(p)
        elif isinstance(node, list):
            for item in node[:3]:
                walk(item, prefix)

    walk(data)
    return out[:limit]


def select_ids_for(
    candidate: Candidate, owned: list[OwnedObject], *, max_ids: int = 4
) -> list[OwnedObject]:
    """Pick the identifiers most likely to be semantically valid for a field.

    Feeding a user id into `policy(id:)` just produces noise, so we prefer
    identifiers whose __typename relates to the field's return type or name.
    """
    target = (candidate.return_type + " " + candidate.field_name).lower()
    exact = [o for o in owned if o.typename and o.typename.lower() in target]
    if exact:
        return exact[:max_ids]
    # Fall back to identifiers whose source field name overlaps the candidate.
    stem = candidate.field_name.lower().lstrip("get").rstrip("s")
    loose = [o for o in owned if stem and stem in o.source_field.lower()]
    if loose:
        return loose[:max_ids]
    return owned[:max_ids]


class IdorEngine:
    def __init__(
        self,
        client: GraphQLClient,
        attacker: Account,
        victim: Account,
        safety: Safety,
    ) -> None:
        self.client = client
        self.attacker = attacker
        self.victim = victim
        self.safety = safety
        self.findings: list[Finding] = []

    # -- low level ---------------------------------------------------------

    def _probe(
        self,
        candidate: Candidate,
        id_arg: str,
        id_value: str,
        account: Account,
        *,
        tenant_override: str | None = None,
        note: str = "",
    ) -> GqlResult:
        # Start from the argument values the application itself sent, where we
        # captured them - that keeps every other variable realistic and only
        # the object reference under test changes.
        variables: dict[str, Any] = dict(candidate.default_variables)
        variables[id_arg] = id_value
        # Anything still unset gets a placeholder so the document validates.
        # Where that is wrong the baseline simply fails and the candidate is
        # skipped - it never produces a false finding.
        for vname in candidate.var_names:
            variables.setdefault(vname, None)
        return self.client.execute(
            candidate.document,
            account=account,
            variables=variables,
            tenant_override=tenant_override,
            note=note,
        )

    # -- read-side BOLA ----------------------------------------------------

    def test_object_read(
        self, candidate: Candidate, victim_obj: OwnedObject, attacker_obj: OwnedObject | None
    ) -> Finding:
        id_arg = candidate.id_args[0]["name"]

        baseline = self._probe(
            candidate, id_arg, victim_obj.value, self.victim,
            note=f"baseline {candidate.key} as {self.victim.label} (owner)",
        )
        if not baseline.has_data:
            return Finding(
                verdict=Verdict.NO_BASELINE,
                candidate_key=candidate.key, id_arg=id_arg,
                victim_id=victim_obj.value, victim_typename=victim_obj.typename,
                attacker=self.attacker.label, victim=self.victim.label,
                severity=candidate.severity,
                detail=f"owner could not read own object; skipped. "
                       f"HTTP {baseline.status} {baseline.error_text[:120]}",
                evidence_seqs=[baseline.exchange.seq],
            )

        attack = self._probe(
            candidate, id_arg, victim_obj.value, self.attacker,
            note=f"ATTACK {candidate.key}: {self.attacker.label} -> {self.victim.label}'s object",
        )

        seqs = [baseline.exchange.seq, attack.exchange.seq]

        if attack.is_authz_denial():
            return Finding(
                verdict=Verdict.DENIED, candidate_key=candidate.key, id_arg=id_arg,
                victim_id=victim_obj.value, victim_typename=victim_obj.typename,
                attacker=self.attacker.label, victim=self.victim.label,
                severity=candidate.severity,
                detail=f"correctly denied: {attack.error_text[:160] or f'HTTP {attack.status}'}",
                evidence_seqs=seqs,
            )
        if not attack.has_data:
            verdict = Verdict.NOT_FOUND if attack.is_not_found() else Verdict.DENIED
            return Finding(
                verdict=verdict, candidate_key=candidate.key, id_arg=id_arg,
                victim_id=victim_obj.value, victim_typename=victim_obj.typename,
                attacker=self.attacker.label, victim=self.victim.label,
                severity=candidate.severity,
                detail=f"no data returned to attacker ({attack.error_text[:140] or 'null'})",
                evidence_seqs=seqs,
            )

        # Attacker got data. Rule out a resolver that ignores the id argument.
        if attacker_obj is not None:
            control = self._probe(
                candidate, id_arg, attacker_obj.value, self.attacker,
                note=f"control {candidate.key}: {self.attacker.label} -> own object",
            )
            seqs.append(control.exchange.seq)
            if control.has_data and _normalise(control.data) == _normalise(attack.data):
                return Finding(
                    verdict=Verdict.IGNORES_ID, candidate_key=candidate.key,
                    id_arg=id_arg, victim_id=victim_obj.value,
                    victim_typename=victim_obj.typename,
                    attacker=self.attacker.label, victim=self.victim.label,
                    severity=candidate.severity,
                    detail="resolver returned the attacker's own object for both "
                           "ids - the id argument is ignored, not an IDOR",
                    evidence_seqs=seqs,
                )

        identical = _normalise(attack.data) == _normalise(baseline.data)
        leaked = _leaked_field_names(attack.data)
        return Finding(
            verdict=Verdict.CONFIRMED if identical else Verdict.LIKELY,
            candidate_key=candidate.key, id_arg=id_arg,
            victim_id=victim_obj.value, victim_typename=victim_obj.typename,
            attacker=self.attacker.label, victim=self.victim.label,
            severity=candidate.severity,
            detail=(
                "attacker received a byte-identical copy of the owner's object"
                if identical else
                "attacker received data for an object owned by another account "
                "(differs from owner's view - partial or field-level exposure)"
            ),
            leaked_fields=leaked,
            evidence_seqs=seqs,
        )

    # -- tenant boundary ---------------------------------------------------

    def test_tenant_override(self, candidate: Candidate, victim_obj: OwnedObject) -> Finding:
        """Re-issue the attack with the victim's tenant id in request headers.

        Authority must come from the signed token claim. Where a backend reads
        the tenant from a client-controlled header instead, this alone grants
        full cross-tenant access.
        """
        id_arg = candidate.id_args[0]["name"]
        res = self._probe(
            candidate, id_arg, victim_obj.value, self.attacker,
            tenant_override=self.victim.tenant_id,
            note=f"tenant-header override {candidate.key} -> tenant {self.victim.tenant_id}",
        )
        if res.has_data and not res.is_authz_denial():
            return Finding(
                verdict=Verdict.CONFIRMED, candidate_key=candidate.key, id_arg=id_arg,
                victim_id=victim_obj.value, victim_typename=victim_obj.typename,
                attacker=self.attacker.label, victim=self.victim.label,
                severity="critical",
                detail="backend honoured a client-supplied tenant header instead "
                       "of the signed tenantId claim",
                leaked_fields=_leaked_field_names(res.data),
                evidence_seqs=[res.exchange.seq],
                vector="tenant-header-override",
            )
        return Finding(
            verdict=Verdict.DENIED, candidate_key=candidate.key, id_arg=id_arg,
            victim_id=victim_obj.value, victim_typename=victim_obj.typename,
            attacker=self.attacker.label, victim=self.victim.label,
            severity=candidate.severity,
            detail="tenant header override rejected",
            evidence_seqs=[res.exchange.seq],
            vector="tenant-header-override",
        )

    # -- write-side BFLA ---------------------------------------------------

    def test_mutation(self, candidate: Candidate, victim_obj: OwnedObject) -> Finding:
        """Cross-tenant mutation testing. Disabled unless explicitly enabled.

        Read-side findings are usually sufficient to demonstrate a broken
        authorization model. Firing an update or delete at an object across a
        tenant boundary on a live production system risks destroying data, so
        this stays behind an explicit flag.
        """
        id_arg = candidate.id_args[0]["name"]
        if not self.safety.allow_mutations:
            return Finding(
                verdict=Verdict.ERROR, candidate_key=candidate.key, id_arg=id_arg,
                victim_id=victim_obj.value, victim_typename=victim_obj.typename,
                attacker=self.attacker.label, victim=self.victim.label,
                severity=candidate.severity,
                detail="NOT EXECUTED - mutation candidate recorded only "
                       "(enable with --allow-mutations after reviewing impact)",
                vector="cross-account-mutation",
            )
        res = self._probe(
            candidate, id_arg, victim_obj.value, self.attacker,
            note=f"ATTACK mutation {candidate.key} cross-account",
        )
        if res.has_data and not res.is_authz_denial():
            return Finding(
                verdict=Verdict.CONFIRMED, candidate_key=candidate.key, id_arg=id_arg,
                victim_id=victim_obj.value, victim_typename=victim_obj.typename,
                attacker=self.attacker.label, victim=self.victim.label,
                severity="critical",
                detail="mutation accepted against an object owned by another account",
                leaked_fields=_leaked_field_names(res.data),
                evidence_seqs=[res.exchange.seq],
                vector="cross-account-mutation",
            )
        return Finding(
            verdict=Verdict.DENIED, candidate_key=candidate.key, id_arg=id_arg,
            victim_id=victim_obj.value, victim_typename=victim_obj.typename,
            attacker=self.attacker.label, victim=self.victim.label,
            severity=candidate.severity,
            detail=f"mutation refused: {res.error_text[:160] or f'HTTP {res.status}'}",
            evidence_seqs=[res.exchange.seq],
            vector="cross-account-mutation",
        )

    # -- driver ------------------------------------------------------------

    def run(
        self,
        candidates: list[Candidate],
        victim_owned: list[OwnedObject],
        attacker_owned: list[OwnedObject],
        *,
        max_probes: int = 400,
        test_tenant_override: bool = True,
    ) -> list[Finding]:
        probes = 0
        for cand in candidates:
            if probes >= max_probes:
                break
            targets = select_ids_for(cand, victim_owned)
            if not targets:
                continue
            attacker_candidates = select_ids_for(cand, attacker_owned)
            attacker_obj = attacker_candidates[0] if attacker_candidates else None

            for victim_obj in targets:
                if probes >= max_probes:
                    break
                probes += 1
                if cand.operation == "mutation":
                    finding = self.test_mutation(cand, victim_obj)
                else:
                    finding = self.test_object_read(cand, victim_obj, attacker_obj)
                self.findings.append(finding)

                # Only escalate to the header-override variant where the
                # straightforward attempt was correctly denied - that is where
                # it can still tell us something new.
                if (
                    test_tenant_override
                    and cand.operation == "query"
                    and finding.verdict in (Verdict.DENIED, Verdict.NOT_FOUND)
                    and self.victim.tenant_id
                    and self.victim.tenant_id != self.attacker.tenant_id
                ):
                    probes += 1
                    self.findings.append(self.test_tenant_override(cand, victim_obj))

        return self.findings
