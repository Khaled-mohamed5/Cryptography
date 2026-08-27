"""A deliberately mixed-behaviour multi-tenant GraphQL API, for testing the
engine offline. It contains one genuinely vulnerable resolver, one correctly
secured resolver, and one resolver that ignores its id argument (the classic
false-positive trap).
"""
from __future__ import annotations

import base64
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

TENANTS = {"tenant-1": "uid-a", "tenant-2": "uid-b"}
USERS = {
    "a@example.test": {"pw": "pw-a", "uid": "uid-a", "tenant": "tenant-1"},
    "b@example.test": {"pw": "pw-b", "uid": "uid-b", "tenant": "tenant-2"},
}
POLICIES = {
    "11111111-1111-1111-1111-111111111111": {"tenant": "tenant-1", "name": "A's policy"},
    "22222222-2222-2222-2222-222222222222": {"tenant": "tenant-2", "name": "B's policy"},
}
APIKEYS = {
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa": {"tenant": "tenant-1", "secret": "SECRET-A"},
    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb": {"tenant": "tenant-2", "secret": "SECRET-B"},
}


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def make_token(uid: str, tenant: str) -> str:
    return f"{_b64({'alg':'RS256','typ':'JWT'})}.{_b64({'sub':uid,'tenantId':tenant,'tenantIds':[tenant],'roles':['member'],'permissions':[]})}.sig"


def parse_token(auth: str | None) -> dict | None:
    if not auth or not auth.startswith("Bearer "):
        return None
    try:
        payload = auth.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:
        return None


def _t(name, kind="OBJECT"):
    return {"kind": kind, "name": name, "ofType": None}


def _nn(inner):
    return {"kind": "NON_NULL", "name": None, "ofType": inner}


def _list(inner):
    return {"kind": "LIST", "name": None, "ofType": inner}


def _obj(name, fields):
    return {"kind": "OBJECT", "name": name, "description": None, "fields": fields,
            "inputFields": None, "interfaces": [], "enumValues": None, "possibleTypes": None}


def _f(name, type_ref, args=None):
    return {"name": name, "description": None, "args": args or [], "type": type_ref}


def _arg(name, type_ref):
    return {"name": name, "description": None, "type": type_ref, "defaultValue": None}


SCALAR_ID = _t("ID", "SCALAR")
SCALAR_STR = _t("String", "SCALAR")

SCHEMA = {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        _obj("Query", [
            _f("policy", _t("Policy"), [_arg("id", _nn(SCALAR_ID))]),
            _f("apiKey", _t("ApiKey"), [_arg("id", _nn(SCALAR_ID))]),
            _f("profile", _t("User"), [_arg("id", _nn(SCALAR_ID))]),
            _f("policies", _list(_t("Policy"))),
            _f("apiKeys", _list(_t("ApiKey"))),
            _f("me", _t("User")),
        ]),
        _obj("Mutation", [
            _f("deletePolicy", _t("Policy"), [_arg("id", _nn(SCALAR_ID))]),
        ]),
        _obj("Policy", [_f("id", SCALAR_ID), _f("name", SCALAR_STR), _f("tenantId", SCALAR_STR)]),
        _obj("ApiKey", [_f("id", SCALAR_ID), _f("secret", SCALAR_STR), _f("tenantId", SCALAR_STR)]),
        _obj("User", [_f("id", SCALAR_ID), _f("email", SCALAR_STR), _f("tenantId", SCALAR_STR)]),
        {"kind": "SCALAR", "name": "ID", "fields": None, "inputFields": None,
         "interfaces": None, "enumValues": None, "possibleTypes": None, "description": None},
        {"kind": "SCALAR", "name": "String", "fields": None, "inputFields": None,
         "interfaces": None, "enumValues": None, "possibleTypes": None, "description": None},
    ],
}

ROOT_FIELD_RE = re.compile(r"\{\s*(\w+)")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, code: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")

        if self.path.endswith("/auth/login"):
            u = USERS.get(body.get("email", ""))
            if not u or u["pw"] != body.get("password"):
                return self._send(401, {"errors": [{"message": "bad credentials"}]})
            return self._send(200, {
                "accessToken": make_token(u["uid"], u["tenant"]),
                "refreshToken": "rt",
                "user": {"id": u["uid"]},
            })

        if self.path.endswith("/graphql"):
            return self._graphql(body)

        self._send(404, {"errors": [{"message": "no route"}]})

    def _graphql(self, body: dict):
        claims = parse_token(self.headers.get("Authorization"))
        if not claims:
            return self._send(401, {"errors": [{"message": "unauthenticated"}]})
        caller_tenant = claims["tenantId"]
        caller_uid = claims["sub"]

        query = body.get("query", "")
        variables = body.get("variables") or {}

        if "__schema" in query:
            return self._send(200, {"data": {"__schema": SCHEMA}})

        m = ROOT_FIELD_RE.search(query)
        field = m.group(1) if m else ""
        oid = variables.get("id")

        # -- listings (used for harvesting) --------------------------------
        if field == "policies":
            return self._send(200, {"data": {"policies": [
                {"__typename": "Policy", "id": pid, "name": p["name"], "tenantId": p["tenant"]}
                for pid, p in POLICIES.items() if p["tenant"] == caller_tenant
            ]}})
        if field == "apiKeys":
            return self._send(200, {"data": {"apiKeys": [
                {"__typename": "ApiKey", "id": kid, "secret": k["secret"], "tenantId": k["tenant"]}
                for kid, k in APIKEYS.items() if k["tenant"] == caller_tenant
            ]}})
        if field == "me":
            return self._send(200, {"data": {"me": {
                "__typename": "User", "id": caller_uid,
                "email": f"{caller_uid}@example.test", "tenantId": caller_tenant}}})

        # -- VULNERABLE: no tenant check -----------------------------------
        if field == "policy":
            p = POLICIES.get(oid)
            if not p:
                return self._send(200, {"data": {"policy": None},
                                        "errors": [{"message": "not found"}]})
            return self._send(200, {"data": {"policy": {
                "__typename": "Policy", "id": oid, "name": p["name"],
                "tenantId": p["tenant"]}}})

        # -- SECURE: enforces tenant ---------------------------------------
        if field == "apiKey":
            k = APIKEYS.get(oid)
            if not k or k["tenant"] != caller_tenant:
                return self._send(200, {"data": {"apiKey": None},
                                        "errors": [{"message": "not authorized"}]})
            return self._send(200, {"data": {"apiKey": {
                "__typename": "ApiKey", "id": oid, "secret": k["secret"],
                "tenantId": k["tenant"]}}})

        # -- IGNORES the id argument (false-positive trap) ------------------
        if field == "profile":
            return self._send(200, {"data": {"profile": {
                "__typename": "User", "id": caller_uid,
                "email": f"{caller_uid}@example.test", "tenantId": caller_tenant}}})

        if field == "deletePolicy":
            return self._send(200, {"data": {"deletePolicy": None},
                                    "errors": [{"message": "not authorized"}]})

        return self._send(200, {"data": None,
                                "errors": [{"message": f"unknown field {field}"}]})


def start(port: int = 0) -> tuple[HTTPServer, str]:
    srv = HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"
