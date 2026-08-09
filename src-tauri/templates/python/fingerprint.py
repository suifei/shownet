"""The TLS and HTTP/2 shape this client is supposed to present.

ShowNet's own TLS stack cannot be linked into a Python package, so this
states the target and curl_cffi is what meets it. The two are not the same
thing, which is why verify_fingerprint exists: it measures what the client
really sent rather than trusting that impersonate= did what it claims.
"""

from __future__ import annotations

from typing import Any

CONTRACT: dict[str, Any] = __SHOWNET_CONTRACT__


def verify_fingerprint(session: Any, probe_url: str = "https://tls.peet.ws/api/all") -> dict[str, Any]:
    """Compare the fingerprint this session actually sends against CONTRACT.

    Returns the measured JA3 alongside the target and whether they match.
    A mismatch is not an exception: the caller decides whether an
    approximate profile is good enough for the site being called.
    """
    target = CONTRACT.get("targetJa3")
    try:
        measured = session.get(probe_url, timeout=30).json()
    except Exception as error:  # noqa: BLE001 - reported, not raised
        return {"ok": False, "error": str(error), "target": target}
    observed = (measured.get("tls") or {}).get("ja3")
    return {
        "ok": bool(target) and observed == target,
        "target": target,
        "observed": observed,
        "note": "no target was recorded for this capture" if not target else "",
    }
