#!/usr/bin/env python3
"""Smoke test for the optional local AI RCA layer of scoobyLog.

Runs without pytest and without a real Ollama server: it spins up a tiny mock
HTTP endpoint that mimics Ollama's /api/generate contract. Exercises:

  1. Happy path        → status "ok", full analysis, deterministic payload
  2. Endpoint down     → status "error", pipeline does not crash
  3. strict-local      → non-local endpoint refused before any network call
  4. JSON salvage      → truncated model JSON is recovered
  5. Sanitization      → IPs scrubbed unless raw mode

Usage:  python test_local_ai.py
Exit 0 = all passed.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pandas as pd

import scoobyLog as sl


# --------------------------------------------------------------------------- #
# Mock Ollama endpoint
# --------------------------------------------------------------------------- #
_LAST_REQUEST = {}


def _make_handler(analysis, *, truncate=False):
    class _H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n) or b"{}")
            _LAST_REQUEST.clear()
            _LAST_REQUEST.update(req)
            # Verify the deterministic contract scoobyLog must send
            assert req.get("format") == "json"
            assert req.get("stream") is False
            assert req["options"]["temperature"] == sl.LOCAL_AI_TEMPERATURE
            inner = json.dumps(analysis, ensure_ascii=False)
            if truncate:
                inner = inner[:-3] + " garbage"  # corrupt the tail
            body = json.dumps({"model": req.get("model"), "response": inner,
                               "done": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    return _H


def _serve(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/api/generate"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
def _sample_df():
    df = pd.DataFrame({
        "_time": ["2024-03-15T09:00:00Z", "2024-03-15T09:00:10Z"],
        "host": ["web01", "db01"],
        "message": ["ok login 10.0.0.5", "connection timeout to 10.0.0.9:5432"],
    })
    df["_timestamp_parsed"] = pd.to_datetime(df["_time"], utc=True)
    df["_log_level"] = ["INFO", "ERROR"]
    df["_is_error"] = [False, True]
    df["_is_warning"] = [False, False]
    df["_is_anomaly"] = [False, True]
    df["_is_recovery"] = [False, False]
    df["_anomaly_tags"] = [[], ["timeout"]]
    return df


def _root_cause(df):
    return {
        "first_error_ts": df["_timestamp_parsed"].iloc[1],
        "root_event": {"_log_level": "ERROR", "host": "db01"},
        "anomaly_tags": ["timeout"],
        "cascade_count": 1,
        "mttr": None,
        "precursors": df.head(1),
    }


_ANALYSIS = {
    "root_cause_probabile": "Timeout DB",
    "confidenza": "MEDIA",
    "motivazione": "Sequenza timeout",
    "cause_alternative": ["query lenta"],
    "evidenze_chiave": ["ERROR connection timeout"],
    "evidenze_deboli": [],
    "evidenze_mancanti": ["metriche RAM"],
    "prossimi_controlli": ["dmesg"],
    "rischio_falso_positivo": "MEDIO",
    "raccomandazione_operativa": "Aumentare pool",
}


def _deterministic():
    return {
        "version": "test", "incident_id": "IR-TEST",
        "total_events": 2, "error_events": 1,
        "severity": "P3", "network_evidence": {"timeout": ["10.0.0.9"]},
        "root_cause_host": "db01", "root_cause_tags": ["timeout"],
    }


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def test_happy_path():
    df = _sample_df()
    ctx = sl.build_local_ai_context(df, _deterministic())
    srv, ep = _serve(_make_handler(_ANALYSIS))
    try:
        res = sl.local_ai_rca(ctx, endpoint=ep, model="mistral:7b")
    finally:
        srv.shutdown()
    assert res["status"] == "ok", res
    assert res["provider"] == "ollama-compatible"
    assert res["model"] == "mistral:7b"
    assert res["analysis"]["confidenza"] == "MEDIA"
    print("✓ happy_path")


def test_endpoint_down():
    df = _sample_df()
    ctx = sl.build_local_ai_context(df, _deterministic())
    # Port 1 is unused/refused
    res = sl.local_ai_rca(ctx, endpoint="http://127.0.0.1:1/api/generate", timeout=2)
    assert res["status"] == "error" and res["error"], res
    print("✓ endpoint_down")


def test_strict_local_refuses_remote():
    df = _sample_df()
    ctx = sl.build_local_ai_context(df, _deterministic())
    res = sl.local_ai_rca(ctx, endpoint="http://example.com/api/generate",
                          strict_local=True)
    assert res["status"] == "error" and "non locale" in res["error"], res
    # And the inverse: explicitly allowed hosts pass the guard
    assert sl._local_ai_endpoint_is_local("http://127.0.0.1:11434/x")
    assert sl._local_ai_endpoint_is_local("http://192.168.1.10:11434/x")
    assert not sl._local_ai_endpoint_is_local("http://8.8.8.8/x")
    print("✓ strict_local")


def test_json_salvage():
    df = _sample_df()
    ctx = sl.build_local_ai_context(df, _deterministic())
    srv, ep = _serve(_make_handler(_ANALYSIS, truncate=True))
    try:
        res = sl.local_ai_rca(ctx, endpoint=ep)
    finally:
        srv.shutdown()
    # Salvage may recover a partial object or report a clean error — never crash
    assert res["status"] in ("ok", "error"), res
    assert "_local_ai_salvage_json" in dir(sl)
    assert sl._local_ai_salvage_json('noise {"a": 1} tail}') == {"a": 1}
    assert sl._local_ai_salvage_json("no json") is None
    print("✓ json_salvage")


def test_sanitization():
    df = _sample_df()
    ctx_clean = sl.build_local_ai_context(df, _deterministic(), sanitize=True)
    ctx_raw = sl.build_local_ai_context(df, _deterministic(), sanitize=False)
    blob_clean = json.dumps(ctx_clean)
    blob_raw = json.dumps(ctx_raw)
    assert "10.0.0.9" not in blob_clean, "IP leaked despite sanitization"
    assert "10.0.0.9" in blob_raw, "raw mode should preserve IPs"
    print("✓ sanitization")


def test_schema_validation():
    df = _sample_df()
    ctx = sl.build_local_ai_context(df, _deterministic())
    bad = {k: v for k, v in _ANALYSIS.items() if k != "confidenza"}  # drop required key
    srv, ep = _serve(_make_handler(bad))
    try:
        res = sl.local_ai_rca(ctx, endpoint=ep)
    finally:
        srv.shutdown()
    assert res["status"] == "error" and "Schema non valido" in res["error"], res
    ok, missing = sl.validate_local_ai_result(_ANALYSIS)
    assert ok and not missing
    ok2, missing2 = sl.validate_local_ai_result({"foo": 1})
    assert not ok2 and "confidenza" in missing2
    print("✓ schema_validation")


if __name__ == "__main__":
    test_happy_path()
    test_endpoint_down()
    test_strict_local_refuses_remote()
    test_json_salvage()
    test_sanitization()
    test_schema_validation()
    print("\nALL TESTS PASSED")
