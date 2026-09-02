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
    "problema": "Timeout di connessione verso il database db01",
    "evidenze": [
        {"timestamp": "2024-03-15T09:00:10Z", "host": "db01",
         "estratto": "connection timeout", "rilevanza": "errore di rete verso il DB"},
    ],
    "fix": ["Verificare la raggiungibilità del DB (mtr db01)", "Aumentare il pool di connessioni"],
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


def test_diagnose_happy():
    """AI diagnosis: valid evidence is kept, source is the local model."""
    df = _sample_df()
    ctx = sl.build_local_ai_context(df, _deterministic())
    srv, ep = _serve(_make_handler(_ANALYSIS))
    try:
        res = sl.local_ai_rca(ctx, endpoint=ep, model="mistral:7b")
    finally:
        srv.shutdown()
    assert res["status"] == "ok", res
    diag = sl.build_diagnosis(res, df, _root_cause(df))
    assert diag["fonte"].startswith("AI locale"), diag
    assert diag["problema"].startswith("Timeout"), diag
    assert len(diag["evidenze"]) == 1 and diag["evidenze_scartate"] == 0, diag
    assert diag["confidenza"] == "MEDIA", diag
    assert diag["fix"], diag
    block = sl.render_diagnosis_block(diag)
    assert "PROBLEMA" in block and "FIX SUGGERITO" in block
    section = sl.render_diagnosis_section(diag)
    assert "13.6 Diagnosi Intelligente" in section
    print("✓ diagnose_happy")


def test_diagnose_invented_evidence():
    """Invented evidence is discarded; >50% discarded degrades confidence."""
    df = _sample_df()
    analysis = dict(_ANALYSIS)
    analysis["evidenze"] = [
        # valid: real ts + real excerpt
        {"timestamp": "2024-03-15T09:00:10Z", "host": "db01",
         "estratto": "connection timeout", "rilevanza": "reale"},
        # invented timestamp
        {"timestamp": "2024-03-15T23:59:59Z", "host": "db01",
         "estratto": "connection timeout", "rilevanza": "ts inventato"},
        # invented excerpt
        {"timestamp": "2024-03-15T09:00:10Z", "host": "db01",
         "estratto": "kernel panic on cpu0", "rilevanza": "estratto inventato"},
    ]
    valid, discarded = sl.validate_evidence(analysis, df)
    assert len(valid) == 1 and len(discarded) == 2, (valid, discarded)
    ai_result = {"status": "ok", "model": "mistral:7b", "analysis": analysis}
    diag = sl.build_diagnosis(ai_result, df, _root_cause(df))
    assert diag["evidenze_scartate"] == 2, diag
    assert diag["confidenza"] == "BASSA", diag  # MEDIA degraded
    assert diag["nota"] and "scartate" in diag["nota"], diag
    print("✓ diagnose_invented_evidence")


def test_diagnose_fallback():
    """AI unavailable → deterministic fallback still produces a full diagnosis."""
    df = _sample_df()
    ctx = sl.build_local_ai_context(df, _deterministic())
    res = sl.local_ai_rca(ctx, endpoint="http://127.0.0.1:1/api/generate", timeout=2)
    assert res["status"] == "error"
    diag = sl.build_diagnosis(res, df, _root_cause(df))
    assert "deterministica" in diag["fonte"], diag
    assert diag["problema"] and diag["fix"], diag
    assert diag["evidenze"], diag  # built from real error rows
    block = sl.render_diagnosis_block(diag)
    assert "Fonte: analisi deterministica" in block
    print("✓ diagnose_fallback")


def test_diagnose_schema_missing_keys():
    """Model response without the new diagnosis keys → clean schema error."""
    df = _sample_df()
    ctx = sl.build_local_ai_context(df, _deterministic())
    bad = {k: v for k, v in _ANALYSIS.items() if k != "evidenze"}
    srv, ep = _serve(_make_handler(bad))
    try:
        res = sl.local_ai_rca(ctx, endpoint=ep)
    finally:
        srv.shutdown()
    assert res["status"] == "error" and "Schema non valido" in res["error"], res
    # And the pipeline still degrades to the deterministic fallback
    diag = sl.build_diagnosis(res, df, _root_cause(df))
    assert "deterministica" in diag["fonte"], diag
    print("✓ diagnose_schema_missing_keys")


if __name__ == "__main__":
    test_happy_path()
    test_endpoint_down()
    test_strict_local_refuses_remote()
    test_json_salvage()
    test_sanitization()
    test_schema_validation()
    test_diagnose_happy()
    test_diagnose_invented_evidence()
    test_diagnose_fallback()
    test_diagnose_schema_missing_keys()
    print("\nALL TESTS PASSED")
