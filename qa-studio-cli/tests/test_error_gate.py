import json
import urllib.error
import urllib.request

from qa_studio_cli.runner import error_gate

ENV_ON = {
    "ERROR_GATE_ENABLED": "true",
    "TEST_SUPPORT_TOKEN": "tok",
    "TEST_SUPPORT_BASE_URL": "http://host/api/test",
}


def test_is_enabled_truth_table():
    assert error_gate.is_enabled({}) is False
    # flag on but no token -> not enabled
    assert error_gate.is_enabled({"ERROR_GATE_ENABLED": "true"}) is False
    # token but flag off -> not enabled
    assert error_gate.is_enabled({"ERROR_GATE_ENABLED": "false", "TEST_SUPPORT_TOKEN": "t"}) is False
    assert error_gate.is_enabled({"ERROR_GATE_ENABLED": "true", "TEST_SUPPORT_TOKEN": "t"}) is True
    assert error_gate.is_enabled({"ERROR_GATE_ENABLED": "1", "TEST_SUPPORT_TOKEN": "t"}) is True


def test_is_enabled_host_scoping():
    env = {
        "ERROR_GATE_ENABLED": "true",
        "TEST_SUPPORT_TOKEN": "t",
        "ERROR_GATE_HOSTS": "staging.my.highbyrd.com,staging.myvisithub.com",
    }
    # a PURL host runs the gate...
    assert error_gate.is_enabled(env, "https://staging.myvisithub.com/p/abc") is True
    assert error_gate.is_enabled(env, "https://staging.my.highbyrd.com/dashboard") is True
    # ...a different app's host does not (can't false-fail it)
    assert error_gate.is_enabled(env, "https://staging.highbyrd.com/") is False
    # default allowlist = the support endpoint host when ERROR_GATE_HOSTS unset
    env2 = {"ERROR_GATE_ENABLED": "true", "TEST_SUPPORT_TOKEN": "t",
            "TEST_SUPPORT_BASE_URL": "https://staging.my.highbyrd.com/api/test"}
    assert error_gate.is_enabled(env2, "https://staging.my.highbyrd.com/x") is True
    assert error_gate.is_enabled(env2, "https://other.example.com/x") is False


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def _patch(monkeypatch, fn):
    monkeypatch.setattr(urllib.request, "urlopen", fn)


def test_check_passes_when_no_new_errors(monkeypatch):
    _patch(monkeypatch, lambda req, timeout=15.0, context=None: _FakeResp({"count": 0, "rows": []}))
    assert error_gate.check(0, env=ENV_ON).passed is True


def test_check_fails_on_new_errors(monkeypatch):
    payload = {
        "count": 2,
        "rows": [
            {"occurredAt": "t1", "errorCode": "INTERNAL", "trpcPath": "campaigns.order", "message": "boom"},
            {"occurredAt": "t2", "errorCode": "INTERNAL", "trpcPath": None, "message": "bang"},
        ],
    }
    _patch(monkeypatch, lambda req, timeout=15.0, context=None: _FakeResp(payload))
    res = error_gate.check(0, env=ENV_ON)
    assert res.passed is False
    assert "2 new application error" in res.detail
    assert "campaigns.order" in res.detail


def test_check_fails_closed_on_http_error(monkeypatch):
    def _raise(req, timeout=15.0, context=None):
        raise urllib.error.HTTPError("http://x", 404, "nf", {}, None)

    _patch(monkeypatch, _raise)
    res = error_gate.check(0, env=ENV_ON)
    assert res.passed is False
    assert "404" in res.detail


def test_check_fails_closed_on_transport_error(monkeypatch):
    def _raise(req, timeout=15.0, context=None):
        raise OSError("connection refused")

    _patch(monkeypatch, _raise)
    res = error_gate.check(0, env=ENV_ON)
    assert res.passed is False
    assert "unreachable" in res.detail
