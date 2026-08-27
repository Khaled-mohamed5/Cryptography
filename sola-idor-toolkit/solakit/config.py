"""Scope, credentials, and safety configuration.

Everything the toolkit is *allowed* to touch is declared here. The HTTP layer
enforces the allowlist, so a typo in a target URL fails closed instead of
sending authenticated traffic somewhere out of scope.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Program scope (HackerOne: Sola Security, as published 2026-04-29)
# ---------------------------------------------------------------------------

# Hosts we are permitted to send test traffic to.
IN_SCOPE_HOSTS: frozenset[str] = frozenset({
    "www.sola.security",   # marketing site
    "app.sola.security",   # primary web application
    "api.sola.security",   # GraphQL API
})

# Hosts we may authenticate against but must NOT attack. auth.sola.security is
# Frontegg (third-party IdP) and is explicitly out of scope: we use it only to
# obtain our own tokens, exactly as a normal user's browser would.
AUTH_ONLY_HOSTS: frozenset[str] = frozenset({
    "auth.sola.security",
})

# Explicitly out of scope - never send traffic here.
OUT_OF_SCOPE_HOSTS: frozenset[str] = frozenset({
    "docs.sola.security",   # GitBook, third-party
    "freshchat.com",        # third-party chat widget
})

GRAPHQL_ENDPOINT = "https://api.sola.security/graphql"
APP_ORIGIN = "https://app.sola.security"
FRONTEGG_BASE = "https://auth.sola.security"


@dataclass
class Account:
    """One test identity. `label` is what shows up in findings."""
    label: str
    email: str
    password: str

    # Populated after login.
    access_token: str | None = None
    refresh_token: str | None = None
    user_id: str | None = None
    tenant_id: str | None = None
    tenant_ids: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)

    def redacted(self) -> dict:
        return {
            "label": self.label,
            "email": self.email,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "tenant_ids": self.tenant_ids,
            "roles": self.roles,
            "permissions_count": len(self.permissions),
        }


def load_accounts() -> tuple[Account, Account]:
    """Credentials come from env vars so they never land in git."""
    a = Account(
        label="A",
        email=os.environ.get("SOLA_A_EMAIL", ""),
        password=os.environ.get("SOLA_A_PASSWORD", ""),
    )
    b = Account(
        label="B",
        email=os.environ.get("SOLA_B_EMAIL", ""),
        password=os.environ.get("SOLA_B_PASSWORD", ""),
    )
    missing = [x.label for x in (a, b) if not x.email or not x.password]
    if missing:
        raise SystemExit(
            f"Missing credentials for account(s): {', '.join(missing)}.\n"
            "Set SOLA_A_EMAIL / SOLA_A_PASSWORD / SOLA_B_EMAIL / SOLA_B_PASSWORD."
        )
    return a, b


@dataclass
class Safety:
    """Guard rails. The defaults are the ones safe to run against production."""

    # Requests per second, across all workers. Bug bounty testing should never
    # look like a load test.
    rate_limit_rps: float = 3.0

    # Mutations are enumerated and reported but never executed unless this is
    # explicitly turned on. A cross-tenant delete/update against a live SaaS
    # can destroy another customer's real data - that is not a risk worth
    # taking to prove a finding that a read-only probe already demonstrates.
    allow_mutations: bool = False

    # Blind ID guessing against production is noisy and can touch real tenants.
    # Off by default; the cross-account replay does not need it, because every
    # ID we replay is one we legitimately own on the other account.
    allow_id_bruteforce: bool = False

    # Strip Authorization headers / tokens from saved evidence.
    redact_tokens: bool = True

    # Stop the whole run after this many consecutive transport errors.
    max_consecutive_errors: int = 8

    request_timeout: float = 30.0


DEFAULT_SAFETY = Safety()
