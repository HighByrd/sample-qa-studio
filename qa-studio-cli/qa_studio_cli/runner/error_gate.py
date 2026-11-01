"""Opt-in error gate for the QA Studio runner.

A browser run can pass (HTTP 200, the page renders) while the target app
silently logged a server error during it — e.g. a swallowed DB write that drops
a lead. This gate queries the app's staging ``/api/test/errors-since`` support
endpoint for errors logged *during the run* and fails the run if any appeared.
See the PURL QA automation plan §3 (and the QA_TEST_PLAN §59 dropped-lead lesson).

It runs inside the runner, so it applies to both local (`--local-only`) and
cloud/console-triggered executions and its outcome shows in the run result.

Opt-in via environment, so it only runs where it's configured (staging):

    ERROR_GATE_ENABLED=true          # must be a truthy value
    TEST_SUPPORT_TOKEN=<secret>      # required; sent as the x-test-support-token header
    TEST_SUPPORT_BASE_URL=<url>      # optional; defaults below

Fail-closed: if the endpoint can't be reached or rejects the token, the gate
FAILS the run rather than silently passing — a broken gate is not a green gate.
"""
from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Mapping, Optional

# Verify TLS against certifi's CA bundle when available, so the gate doesn't
# false-fail on hosts whose ambient trust store is incomplete (e.g. the
# python.org macOS build). Falls back to the system default on Linux workers.
try:  # pragma: no cover - trivial env branch
    import certifi

    _SSL_CONTEXT: Optional[ssl.SSLContext] = ssl.create_default_context(cafile=certifi.where())
except Exception:  # pragma: no cover
    _SSL_CONTEXT = ssl.create_default_context()

DEFAULT_BASE_URL = "https://staging.my.highbyrd.com/api/test"
_TRUTHY = {"1", "true", "yes", "on"}
_MAX_ROWS_IN_DETAIL = 10


def now_ms() -> int:
    """Current time as epoch milliseconds (UTC), matching the server's
    ``occurredAt`` comparison. Uses ``time.time()`` to avoid the naive-datetime
    timezone trap in ``datetime.utcnow().timestamp()``."""
    return int(time.time() * 1000)


def is_enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    """True only when explicitly opted in AND a token is configured."""
    env = os.environ if env is None else env
    return (
        (env.get("ERROR_GATE_ENABLED", "") or "").strip().lower() in _TRUTHY
        and bool(env.get("TEST_SUPPORT_TOKEN"))
    )


@dataclass
class GateResult:
    passed: bool
    detail: str


def check(
    before_ms: int,
    env: Optional[Mapping[str, str]] = None,
    timeout: float = 15.0,
) -> GateResult:
    """Query ``errors-since?ts=<before_ms>`` and decide pass/fail."""
    env = os.environ if env is None else env
    token = env.get("TEST_SUPPORT_TOKEN", "")
    base = (env.get("TEST_SUPPORT_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
    url = f"{base}/errors-since?ts={before_ms}"
    req = urllib.request.Request(url, headers={"x-test-support-token": token})

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CONTEXT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return GateResult(
            False,
            f"error-gate endpoint returned HTTP {exc.code} (token/config problem)",
        )
    except Exception as exc:  # transport / parse failure — fail closed
        return GateResult(False, f"error-gate endpoint unreachable: {exc}")

    count = body.get("count", 0) if isinstance(body, dict) else 0
    if count:
        rows = (body.get("rows") or [])[:_MAX_ROWS_IN_DETAIL]
        detail = "; ".join(
            f"[{r.get('occurredAt')}] {r.get('errorCode')} "
            f"{r.get('trpcPath') or '-'}: {r.get('message')}"
            for r in rows
        )
        return GateResult(False, f"{count} new application error(s) during the run: {detail}")

    return GateResult(True, "no new application errors")
