"""GraphQL client, introspection, and response classification."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import GRAPHQL_ENDPOINT, Account
from .auth import auth_headers
from .http import Exchange, ScopedSession

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name description
        args { ...InputValue }
        type { ...TypeRef }
      }
      inputFields { ...InputValue }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) { name }
      possibleTypes { ...TypeRef }
    }
  }
}
fragment InputValue on __InputValue {
  name description type { ...TypeRef } defaultValue
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name
    ofType { kind name ofType { kind name ofType { kind name } } } } } }
}
"""


@dataclass
class GqlResult:
    exchange: Exchange
    data: Any
    errors: list[dict]

    @property
    def status(self) -> int | None:
        return self.exchange.status

    @property
    def has_data(self) -> bool:
        """True when the server actually returned a non-null payload."""
        if self.data is None:
            return False
        if isinstance(self.data, dict):
            return any(v is not None for v in self.data.values())
        return True

    @property
    def error_text(self) -> str:
        return " | ".join(str(e.get("message", "")) for e in self.errors)

    def is_authz_denial(self) -> bool:
        """Does the response look like a deliberate authorization refusal?"""
        if self.status in (401, 403):
            return True
        needles = (
            "not authorized", "unauthorized", "forbidden", "access denied",
            "permission", "not allowed", "no access", "unauthenticated",
            "not a member", "does not belong",
        )
        low = self.error_text.lower()
        return any(n in low for n in needles)

    def is_not_found(self) -> bool:
        low = self.error_text.lower()
        return any(n in low for n in ("not found", "does not exist", "no such", "unknown id"))


class GraphQLClient:
    def __init__(self, session: ScopedSession, endpoint: str = GRAPHQL_ENDPOINT) -> None:
        self.session = session
        self.endpoint = endpoint

    def execute(
        self,
        query: str,
        *,
        account: Account,
        variables: dict | None = None,
        operation_name: str | None = None,
        tenant_override: str | None = None,
        note: str = "",
    ) -> GqlResult:
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name

        ex = self.session.post(
            self.endpoint,
            headers=auth_headers(account, tenant_override=tenant_override),
            json_body=payload,
            note=note or f"gql as {account.label}",
        )
        body = ex.response_body if isinstance(ex.response_body, dict) else {}
        return GqlResult(
            exchange=ex,
            data=body.get("data"),
            errors=body.get("errors") or [],
        )

    def introspect(self, account: Account) -> tuple[dict | None, str]:
        """Full introspection. Returns (schema, note)."""
        res = self.execute(
            INTROSPECTION_QUERY, account=account, note="introspection"
        )
        if res.has_data and isinstance(res.data, dict) and res.data.get("__schema"):
            schema = res.data["__schema"]
            n_types = len(schema.get("types") or [])
            return schema, f"introspection ENABLED ({n_types} types exposed)"
        from .http import looks_like_edge_block
        body = res.exchange.response_body
        if looks_like_edge_block(res.status, body):
            return None, (
                f"BLOCKED AT THE EDGE (HTTP {res.status}) - the request never "
                f"reached the GraphQL server, so this says nothing about "
                f"whether introspection is enabled. Body: {str(body)[:200]}"
            )
        if res.status == 200 and res.errors:
            return None, (
                f"introspection DISABLED by the server: {res.error_text[:200]}"
            )
        return None, (
            f"introspection unavailable (HTTP {res.status}): "
            f"{res.error_text[:200] or str(body)[:200]}"
        )

    def probe_field_suggestions(self, account: Account, guess: str = "zzzq") -> list[str]:
        """When introspection is off, GraphQL 'Did you mean' errors still leak
        field names. Useful for confirming the schema is only half-hidden."""
        res = self.execute(
            "query { %s }" % guess, account=account, note="field-suggestion probe"
        )
        suggestions: list[str] = []
        for err in res.errors:
            msg = str(err.get("message", ""))
            if "did you mean" in msg.lower():
                tail = msg.lower().split("did you mean", 1)[1]
                for tok in tail.replace("or", ",").split(","):
                    tok = tok.strip(" ?.\"'\n")
                    if tok and tok.isidentifier():
                        suggestions.append(tok)
        return suggestions

    def probe_alias_batching(self, account: Account, field: str, width: int = 25) -> tuple[bool, str]:
        """Alias batching lets one HTTP request carry N resolver calls.

        Where it is unbounded it amplifies any other flaw: it defeats
        per-request rate limiting and turns a slow ID probe into a fast one.
        We test with a deliberately small width - the point is to establish
        whether a limit exists, not to generate load.
        """
        aliases = " ".join(f"a{i}: {field}" for i in range(width))
        res = self.execute(
            "query { %s }" % aliases, account=account, note="alias-batching probe"
        )
        low = res.error_text.lower()
        if any(n in low for n in ("too many", "limit", "complexity", "depth", "exceed")):
            return False, f"batching appears limited: {res.error_text[:200]}"
        if res.has_data:
            return True, f"{width} aliased resolvers accepted in a single request"
        return False, f"inconclusive (HTTP {res.status}): {res.error_text[:160]}"
