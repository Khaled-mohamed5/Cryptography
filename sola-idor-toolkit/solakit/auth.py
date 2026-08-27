"""Frontegg authentication and JWT claim extraction.

auth.sola.security is Frontegg, a third-party IdP that the program lists as
OUT OF SCOPE. We therefore use it for one thing only: logging in as ourselves,
exactly as the real app does, to obtain tokens for the in-scope API. No
attack traffic is directed at it.

The JWT claims we pull out here are what make cross-tenant testing meaningful:
they tell us, authoritatively, which user id and which tenant id each account
is supposed to be confined to.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from .config import APP_ORIGIN, FRONTEGG_BASE, Account
from .http import ScopedSession

# Frontegg exposes the same identity API directly on the IdP host and,
# in most embedded setups, proxied under the application origin. We try the
# app-proxied path first because it is in scope and is what the SPA itself uses.
LOGIN_PATHS = [
    f"{APP_ORIGIN}/frontegg/identity/resources/auth/v1/user",
    f"{FRONTEGG_BASE}/identity/resources/auth/v1/user",
]
TENANT_SWITCH_PATHS = [
    f"{APP_ORIGIN}/frontegg/identity/resources/users/v1/me/tenant",
    f"{FRONTEGG_BASE}/identity/resources/users/v1/me/tenant",
]
ME_PATHS = [
    f"{APP_ORIGIN}/frontegg/identity/resources/users/v1/me",
    f"{FRONTEGG_BASE}/identity/resources/users/v1/me",
]


def decode_jwt(token: str) -> dict[str, Any]:
    """Read JWT claims without verifying. We are inspecting our own token."""
    try:
        _, payload_b64, _ = token.split(".")[:3]
    except ValueError:
        return {}
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, json.JSONDecodeError):
        return {}


def jwt_header(token: str) -> dict[str, Any]:
    try:
        header_b64 = token.split(".")[0]
    except (ValueError, IndexError):
        return {}
    padded = header_b64 + "=" * (-len(header_b64) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, json.JSONDecodeError):
        return {}


def login(session: ScopedSession, account: Account) -> Account:
    """Authenticate one account and populate its identity fields."""
    last_detail = ""
    for path in LOGIN_PATHS:
        ex = session.post(
            path,
            headers={"Content-Type": "application/json", "Origin": APP_ORIGIN},
            json_body={"email": account.email, "password": account.password},
            allow_auth_host=True,
            note=f"login {account.label}",
        )
        if ex.error:
            last_detail = ex.error
            continue
        body = ex.response_body if isinstance(ex.response_body, dict) else {}

        if ex.status == 200 and body.get("mfaRequired"):
            raise SystemExit(
                f"[{account.label}] Login requires MFA. Complete enrollment in the "
                "browser, or disable MFA on the test account, then re-run."
            )

        token = body.get("accessToken")
        if ex.status in (200, 201) and token:
            account.access_token = token
            account.refresh_token = body.get("refreshToken")
            claims = decode_jwt(token)
            account.user_id = (
                claims.get("sub") or claims.get("userId") or (body.get("user") or {}).get("id")
            )
            account.tenant_id = claims.get("tenantId")
            account.tenant_ids = claims.get("tenantIds") or []
            account.roles = claims.get("roles") or []
            account.permissions = claims.get("permissions") or []
            return account

        last_detail = f"HTTP {ex.status} from {path}: {str(ex.response_body)[:300]}"

    raise SystemExit(f"[{account.label}] Login failed. {last_detail}")


def auth_headers(account: Account, *, tenant_override: str | None = None) -> dict[str, str]:
    """Headers a normal authenticated request carries.

    `tenant_override` injects the Frontegg tenant-selection headers. In a
    correctly built multi-tenant backend these are advisory at most: authority
    must come from the signed `tenantId` claim. Where the backend trusts the
    header instead, this single change turns into full cross-tenant access,
    which is why it is tested explicitly.
    """
    headers = {
        "Authorization": f"Bearer {account.access_token}",
        "Content-Type": "application/json",
        "Origin": APP_ORIGIN,
        "Referer": f"{APP_ORIGIN}/",
    }
    if tenant_override:
        headers["frontegg-tenant-id"] = tenant_override
        headers["x-tenant-id"] = tenant_override
        headers["x-frontegg-tenant-id"] = tenant_override
    return headers


def try_tenant_switch(
    session: ScopedSession, account: Account, target_tenant: str
) -> tuple[bool, str]:
    """Ask the IdP to re-scope our token to a tenant we should not belong to.

    A success here is a serious finding on its own: it means an authenticated
    user can mint a validly-signed token for a foreign tenant.
    """
    for path in TENANT_SWITCH_PATHS:
        ex = session.put(
            path,
            headers=auth_headers(account),
            json_body={"tenantId": target_tenant},
            allow_auth_host=True,
            note=f"tenant switch {account.label} -> {target_tenant}",
        )
        if ex.error:
            continue
        if ex.status in (200, 201):
            body = ex.response_body if isinstance(ex.response_body, dict) else {}
            new_token = body.get("accessToken")
            if new_token:
                claims = decode_jwt(new_token)
                if claims.get("tenantId") == target_tenant:
                    return True, (
                        f"Token re-issued with tenantId={target_tenant} "
                        f"(HTTP {ex.status})"
                    )
            return True, f"HTTP {ex.status} accepted the switch request"
        return False, f"HTTP {ex.status}: {str(ex.response_body)[:200]}"
    return False, "no tenant-switch endpoint reachable"


def describe(account: Account) -> str:
    claims_note = ""
    if account.access_token:
        hdr = jwt_header(account.access_token)
        claims_note = f" alg={hdr.get('alg')}"
    return (
        f"[{account.label}] {account.email}\n"
        f"     user_id : {account.user_id}\n"
        f"     tenant  : {account.tenant_id}\n"
        f"     tenants : {account.tenant_ids}\n"
        f"     roles   : {account.roles}\n"
        f"     perms   : {len(account.permissions)} permission(s){claims_note}"
    )
