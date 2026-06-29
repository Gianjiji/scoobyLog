#!/usr/bin/env python3
"""
scoobyLog — SIEM Incident Analyzer  v4.3
=============================================
Senior Network Systems Administrator & Python Engineer utility.

Processes SIEM-exported CSV logs to:
  - Parse and normalize timestamps (multi-format, epoch, UTC)
  - Sort events chronologically
  - Isolate unique-key flows (session/IP/host/transaction)
  - Detect anomalies via regex on log levels and network patterns
  - Identify precursor events and root cause (first error in chain)
  - Calculate MTTR (Mean Time To Recover)
  - Generate a comprehensive Markdown Incident Response Report

Usage:
    python scoobylog.py logs.csv                          # drag & drop / positional
    python scoobylog.py --input logs.csv [options]
    python scoobylog.py --input logs.csv --json-summary --output-dir /tmp/reports/
    python scoobylog.py --input logs.csv --no-report --export-csv enriched.csv
    python scoobylog.py --input logs.csv --summary        # TLDR only, stdout

Options:
    CSV_FILE / --input/-i  Path to SIEM CSV export (positional or flag)
    --output/-o            Output Markdown file (default: <input>_incident_report.md)
    --output-dir           Directory for all output files
    --timestamp-col        Timestamp column name (default: auto-detect)
    --level-col            Log level column name (default: auto-detect)
    --flow-key             Unique flow key column (default: auto-detect)
    --flow-value           Specific flow value to isolate (default: most anomalous)
    --no-flow              Disable flow isolation (analyze all events)
    --encoding             CSV encoding (default: utf-8)
    --max-rows             Max rows in timeline table (default: 30)
    --chain-depth          Max events in ASCII event chain (default: 12)
    --since                Discard events before this ISO 8601 timestamp
    --until                Discard events after this ISO 8601 timestamp
    --min-level            Minimum log level for timeline (DEBUG/INFO/WARNING/ERROR/CRITICAL)
    --json-summary         Write machine-readable IR-<hash>.json alongside the report
    --export-csv PATH      Export enriched DataFrame (with _log_level, _anomaly_tags, etc.)
    --patterns-file PATH   JSON file with custom patterns to extend built-in detection
    --max-events N         Process only first N events (fast triage of large CSV exports)
    --alert-webhook URL    POST JSON summary to webhook (Slack, PagerDuty, Opsgenie, custom)
    --anonymize            Pseudonymize IPs, session IDs, UUIDs and emails in the report
    --format {md,html}     Output format: html (default, self-contained, no deps) or md (Markdown)
    --open                 Open the report in the default browser after generation
    --no-report            Skip report generation (useful with --json-summary or --export-csv)
    --summary              Print TLDR executive summary to stdout and exit
    --quiet/-q             Suppress progress output (errors still go to stderr)
    --local-ai             Optional local AI RCA via Ollama-compatible endpoint (offline, off by default)
    --local-ai-endpoint URL   Local LLM endpoint (default: http://localhost:11434/api/generate)
    --local-ai-model NAME     Local model, e.g. llama3.1:8b or mistral:7b (default: llama3.1:8b)
    --local-ai-timeout SEC    AI request timeout in seconds (default: 300)
    --local-ai-max-events N   Max timeline events sent as context (default: 30)
    --local-ai-strict-local   Refuse non-local endpoints (default: on; disable with --local-ai-no-strict-local)
    --local-ai-raw            Send raw un-sanitized log text to the model (default: off)
    --version              Print version and exit
"""

import argparse
import re
import sys
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

import pandas as pd
import numpy as np

VERSION = "4.3"

# ---------------------------------------------------------------------------
# CONFIGURATION – tune these regexes for your environment
# ---------------------------------------------------------------------------

TIMESTAMP_CANDIDATES = [
    "_time", "timestamp", "time", "datetime", "event_time",
    "log_time", "occurred", "date_time"
]

FLOW_KEY_CANDIDATES = [
    "session_id", "sessionid", "transaction_id", "txn_id",
    "request_id", "correlation_id", "flow_id", "conn_id",
    "src_ip", "source_ip", "clientip", "client_ip",
    "host", "hostname", "src"
]

LOG_LEVEL_REGEX = re.compile(
    r'\b(CRITICAL|FATAL|EMERG|ALERT|ERROR|ERR|WARN(?:ING)?|NOTICE|INFO|DEBUG|TRACE)\b',
    re.IGNORECASE
)

ERROR_LEVELS   = {"CRITICAL", "FATAL", "EMERG", "ALERT", "ERROR", "ERR"}
WARNING_LEVELS = {"WARN", "WARNING", "NOTICE"}
RECOVERY_PATTERNS = re.compile(
    r'\b(?:restored?|recovered?|resolved?|stabilized?|back\s+online|circuit.breaker\s+reset|'
    r'reconnected?|healthy|all\s+checks\s+pass(?:ing)?)\b',
    re.IGNORECASE
)

NETWORK_PATTERNS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "ipv6": re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b'
    ),
    "port": re.compile(r'\b(?:port|dport|sport|dst_port|src_port)[=:\s]+(?:\d{1,5})\b', re.IGNORECASE),
    "url": re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE),
    "mac": re.compile(r'\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b'),
    "timeout": re.compile(
        r'\b(?:timeout|timed?\s*out|connection\s+refused|reset\s+by\s+peer|ETIMEDOUT|ECONNRESET)\b',
        re.IGNORECASE
    ),
    "auth_fail": re.compile(
        r'\b(?:auth(?:entication)?\s+fail(?:ed)?|invalid\s+(?:password|credential|token)|'
        r'unauthorized|403|401)\b',
        re.IGNORECASE
    ),
    "dns_error": re.compile(
        r'\b(?:NXDOMAIN|SERVFAIL|dns\s+error|name\s+resolution\s+fail)\b',
        re.IGNORECASE
    ),
    "packet_loss": re.compile(
        r'\b(?:packet\s+loss|dropped?\s+packet|retransmit|duplicate\s+ack)\b',
        re.IGNORECASE
    ),
}

ANOMALY_PATTERNS = {
    "oom_killer":       re.compile(r'\bOOM\b|out\s+of\s+memory|kill\s+process|oom.killer', re.IGNORECASE),
    "segfault":         re.compile(r'\bsegfault|segmentation\s+fault|SIGSEGV\b', re.IGNORECASE),
    "disk_full":        re.compile(r'\bno\s+space\s+left|disk\s+full|ENOSPC\b', re.IGNORECASE),
    "cpu_spike":        re.compile(r'\bload\s+average[:\s]+(?:[5-9]\d|\d{3,})', re.IGNORECASE),
    "service_restart":  re.compile(r'\brestart(?:ed|ing)?|start(?:ed)?\s+(?:service|daemon)|systemd.*start', re.IGNORECASE),
    "certificate":      re.compile(r'\bcert(?:ificate)?\s+(?:expired?|invalid|error)|SSL\s+error|TLS\s+handshake\s+fail', re.IGNORECASE),
    "kernel_panic":     re.compile(r'\bkernel\s+panic|BUG:|Oops:|Call\s+Trace:', re.IGNORECASE),
    "stack_trace":      re.compile(r'\b(?:Traceback|Exception|at\s+\w+\.\w+\(|\tat\s+)', re.IGNORECASE),
    "slow_query":       re.compile(r'\bslow\s+query|long\s+query|query\s+time[:\s]+\d', re.IGNORECASE),
    "pool_exhausted":   re.compile(r'\bpool\s+exhaust|connection\s+pool|max\s+connections?\s+reach', re.IGNORECASE),
}

TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%b %d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%d-%m-%Y %H:%M:%S",
]

CAUSE_LABELS = {
    "timeout":         "**Errore di rete/connettività** — timeout, reset, rifiuto connessione",
    "auth_fail":       "**Fallimento autenticazione/autorizzazione** — credenziali o token invalidi",
    "dns_error":       "**Risoluzione DNS fallita** — NXDOMAIN o SERVFAIL",
    "oom_killer":      "**Esaurimento memoria (OOM)** — processo terminato dal kernel",
    "disk_full":       "**Disco pieno** — ENOSPC, write failure",
    "cpu_spike":       "**CPU spike** — load average critico",
    "segfault":        "**Crash applicativo** — segmentation fault / SIGSEGV",
    "stack_trace":     "**Eccezione non gestita** — stack trace rilevato",
    "certificate":     "**Errore TLS/SSL** — certificato scaduto o invalido",
    "kernel_panic":    "**Kernel panic** — sistema instabile",
    "service_restart": "**Riavvio servizio** — crash rilevato da supervisor",
    "slow_query":      "**Slow query database** — possibile precursore di degrado",
    "pool_exhausted":  "**Pool connessioni esaurito** — saturazione risorse",
    "packet_loss":     "**Perdita pacchetti / retransmit** — degrado rete",
}

REMEDIATION_STEPS = {
    "oom_killer": [
        "Verificare disponibilità memoria: `free -h` e `cat /proc/meminfo`",
        "Top processi per consumo RAM: `ps aux --sort=-%mem | head -20`",
        "Revisionare heap JVM/applicativo: parametri `-Xmx`, `-Xms`",
        "Controllare memory leak con `jmap -histo <pid>` o profiler",
        "Valutare scaling verticale (RAM) o orizzontale (più nodi)",
        "Impostare alerting su soglia memoria (85%+ → WARNING, 95%+ → CRITICAL)",
        "Considerare cgroups `memory.limit_in_bytes` per isolamento processo",
    ],
    "slow_query": [
        "Analizzare query con `EXPLAIN` / `EXPLAIN ANALYZE`",
        "Verificare indici mancanti: `pt-index-usage` (MySQL) / `pg_stat_user_indexes` (PG)",
        "Controllare lock contention: `SHOW PROCESSLIST` / `pg_stat_activity`",
        "Ottimizzare parametri: `innodb_buffer_pool_size`, `shared_buffers`",
        "Abilitare slow query log con threshold: `long_query_time = 1`",
        "Valutare read replica per query di sola lettura",
    ],
    "pool_exhausted": [
        "Aumentare `max_connections` e dimensione pool",
        "Identificare connection leak: connessioni mai chiuse / idle > timeout",
        "Implementare retry con backoff esponenziale e jitter",
        "Monitorare `Threads_connected` (MySQL) / `numbackends` (PG)",
        "Valutare connection pooler: PgBouncer, ProxySQL, HikariCP",
    ],
    "timeout": [
        "Misurare latenza di rete: `ping`, `traceroute`, `mtr <host>`",
        "Verificare timeout settings applicativo vs. upstream (devono concordare)",
        "Controllare health checks e timeout del load balancer",
        "Analizzare firewall stateful connection tables (nf_conntrack overflow)",
        "Controllare TCP retransmit: `netstat -s | grep retransmit`",
        "Verificare MTU mismatch: `ping -s 1472 -M do <host>`",
    ],
    "stack_trace": [
        "Analizzare stack trace completo per identificare frame di eccezione",
        "Verificare input validation (NullPointerException, IndexOutOfBounds)",
        "Controllare versione dipendenze e compatibility matrix",
        "Aggiungere circuit breaker per chiamate remote (Resilience4j, Hystrix)",
        "Implementare dead letter queue per messaggi che causano crash",
    ],
    "cpu_spike": [
        "Identificare processi CPU-intensive: `top -bn1`, `pidstat -u 1 5`",
        "Thread dump JVM: `jstack <pid>` o `kill -3 <pid>`",
        "Verificare cron/backup schedulati in coincidenza con l'incidente",
        "Analizzare query full-scan non indicizzate come causa CPU database",
        "Controllare resource limits: `ulimit -a`, `cgroup cpu.shares`",
    ],
    "disk_full": [
        "Trovare directory pesanti: `du -sh /* | sort -rh | head -20`",
        "Ruotare log files: `logrotate -f /etc/logrotate.conf`",
        "Pulire core dump: `find / -name 'core.*' -delete`",
        "Espandere volume LVM: `lvextend -L+10G /dev/vg0/lv0 && resize2fs`",
        "Impostare alerting su soglia disco (80%+ → WARNING, 90%+ → CRITICAL)",
    ],
    "certificate": [
        "Verificare scadenza: `openssl s_client -connect host:443 | openssl x509 -noout -dates`",
        "Rinnovare certificato (Let's Encrypt: `certbot renew`)",
        "Aggiornare certificato su load balancer, CDN e backend",
        "Implementare monitoring scadenza (30gg → WARNING, 7gg → CRITICAL)",
        "Verificare catena CA completa e intermediate certificates",
    ],
    "auth_fail": [
        "Verificare credenziali e rotazione secrets/API key",
        "Controllare policy IAM/RBAC: permessi effettivi del service account",
        "Analizzare pattern accessi per possibile brute force o credential stuffing",
        "Ruotare API keys/service account passwords",
        "Implementare rate limiting su endpoint di autenticazione",
    ],
    "kernel_panic": [
        "Analizzare kernel log: `dmesg | tail -100`",
        "Controllare hardware error: `mcelog`, `smartctl -a /dev/sda`",
        "Verificare integrità RAM con `memtest86`",
        "Aggiornare kernel e driver a versione stabile",
        "Controllare OOM killer correlato: `dmesg | grep -i oom`",
    ],
    "segfault": [
        "Analizzare core dump: `gdb <binary> <core>`, `bt full`",
        "Verificare versione binari e librerie shared (`ldd <binary>`)",
        "Controllare memory corruption: Valgrind, AddressSanitizer",
        "Verificare ASLR e stack canary: `sysctl kernel.randomize_va_space`",
        "Aggiornare l'applicativo a versione stabile con patch",
    ],
    "dns_error": [
        "Testare risoluzione: `dig +trace <hostname>`, `nslookup <hostname>`",
        "Verificare `/etc/resolv.conf` e `/etc/nsswitch.conf`",
        "Controllare DNS server responsiveness: `dig @<dns-server> <hostname>`",
        "Aggiungere DNS caching locale (dnsmasq, systemd-resolved)",
        "Verificare propagazione DNS per modifiche recenti (TTL scaduto?)",
    ],
    "packet_loss": [
        "Misurare packet loss: `mtr --report <host>`, `ping -c 100 <host>`",
        "Verificare errori interfaccia: `ip -s link show <iface>`",
        "Controllare buffer overflow NIC: `ethtool -S <iface> | grep -i drop`",
        "Analizzare switch/router per errori e CRC",
        "Verificare duplex mismatch: `ethtool <iface> | grep -i duplex`",
    ],
}


def build_response_playbook(detected_tags: list) -> str:
    """
    Build a per-pattern technical remediation playbook based on detected anomaly tags.
    Only includes steps for patterns actually detected in the incident.
    """
    if not detected_tags:
        return "_Nessun pattern specifico rilevato — applicare procedure generali di incident response._"

    sections = []
    for tag in detected_tags:
        steps = REMEDIATION_STEPS.get(tag)
        if not steps:
            continue
        label  = CAUSE_LABELS.get(tag, tag.replace("_", " ").title())
        header = label.replace("**", "").split("—")[0].strip()
        lines  = [f"#### Pattern: `{tag}` — {header}"]
        for i, step in enumerate(steps, 1):
            lines.append(f"  {i}. {step}")
        sections.append("\n".join(lines))

    if not sections:
        return "_Pattern rilevati non mappati nel playbook — escalare a L3._"

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# FORMATTING HELPERS
# ---------------------------------------------------------------------------

def fmt_ts(ts) -> str:
    """Format a pandas Timestamp to ISO 8601; includes milliseconds when sub-second precision is present."""
    if ts is None or (isinstance(ts, float) and np.isnan(ts)):
        return "N/A"
    try:
        if hasattr(ts, "strftime"):
            if getattr(ts, "microsecond", 0):
                # Trim to milliseconds (3 digits) for readability
                return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
            return ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        return str(ts)
    except Exception:
        return str(ts)


def fmt_duration(td) -> str:
    """Format a timedelta to human-readable string."""
    try:
        total_seconds = int(abs(td.total_seconds()))
        hours, rem = divmod(total_seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        if hours:
            return f"{hours}h {minutes}m {seconds}s"
        if minutes:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"
    except Exception:
        return str(td)


def fmt_relative_ts(ts, base_ts) -> str:
    """Format as HH:MM:SS (T+Xm Ys) relative to base_ts. Falls back to absolute fmt_ts."""
    if ts is None or base_ts is None:
        return fmt_ts(ts)
    try:
        abs_str = ts.strftime("%H:%M:%S")
        delta   = ts - base_ts
        if delta.total_seconds() < 0:
            return f"{abs_str} (T-{fmt_duration(-delta)})"
        return f"{abs_str} (T+{fmt_duration(delta)})" if delta.total_seconds() > 0 else abs_str
    except Exception:
        return fmt_ts(ts)


# ---------------------------------------------------------------------------
# TIMESTAMP PARSING
# ---------------------------------------------------------------------------

def parse_timestamp_series(series: pd.Series) -> pd.Series:
    """Attempt numeric epoch, explicit timestamp formats, then pandas inference."""
    if series.empty:
        return pd.Series(dtype="datetime64[ns, UTC]")

    # 1) Prima gestisci epoch numerici: secondi o millisecondi.
    numeric = pd.to_numeric(series, errors="coerce")
    if len(series) > 0 and numeric.notna().sum() / len(series) > 0.8:
        median_val = numeric.median()
        if 1e9 < median_val < 2e9:
            return pd.to_datetime(numeric, unit="s", utc=True, errors="coerce")
        elif 1e12 < median_val < 2e12:
            return pd.to_datetime(numeric, unit="ms", utc=True, errors="coerce")

    # 2) Poi prova i formati espliciti, incluso quello con virgola nei millisecondi.
    best_parsed = None
    best_count = 0

    for fmt in TIMESTAMP_FORMATS:
        try:
            candidate = pd.to_datetime(series, format=fmt, errors="coerce", utc=True)
            count = candidate.notna().sum()
            if count > best_count:
                best_count = count
                best_parsed = candidate
        except Exception:
            continue

    if best_parsed is not None and best_count > 0:
        return best_parsed

    # 3) Solo alla fine usa l'inferenza generica di pandas.
    return pd.to_datetime(series, errors="coerce", utc=True)

# ---------------------------------------------------------------------------
# LOG LEVEL EXTRACTION
# ---------------------------------------------------------------------------

def extract_log_level(row: pd.Series, level_col: Optional[str]) -> str:
    if level_col and level_col in row.index and pd.notna(row[level_col]):
        val = str(row[level_col]).strip().upper()
        if val == "ERR":    val = "ERROR"
        if val == "WARN":   val = "WARNING"
        return val

    for field in row.index:
        val = str(row[field]) if pd.notna(row[field]) else ""
        m = LOG_LEVEL_REGEX.search(val)
        if m:
            level = m.group(1).upper()
            if level == "ERR":  level = "ERROR"
            if level == "WARN": level = "WARNING"
            return level
    return "UNKNOWN"


def severity_rank(level: str) -> int:
    ranks = {
        "CRITICAL": 7, "FATAL": 7, "EMERG": 7, "ALERT": 6,
        "ERROR": 5, "ERR": 5, "WARNING": 4, "WARN": 4,
        "NOTICE": 3, "INFO": 2, "DEBUG": 1, "TRACE": 0, "UNKNOWN": -1
    }
    return ranks.get(level.upper(), -1)


# ---------------------------------------------------------------------------
# NETWORK EVIDENCE EXTRACTION
# ---------------------------------------------------------------------------

def extract_network_evidence(df: pd.DataFrame) -> dict:
    evidence = {k: set() for k in NETWORK_PATTERNS}
    text_cols = df.select_dtypes(include="object").columns

    for col in text_cols:
        combined = df[col].dropna().astype(str)
        for pattern_name, pattern in NETWORK_PATTERNS.items():
            try:
                matches = combined.str.extractall(f"({pattern.pattern})")
                if not matches.empty:
                    evidence[pattern_name].update(matches[0].dropna().tolist())
            except Exception:
                pass

    return {k: sorted(v) for k, v in evidence.items() if v}


# ---------------------------------------------------------------------------
# ANOMALY DETECTION
# ---------------------------------------------------------------------------

def detect_anomalies(df: pd.DataFrame, level_col_name: str = "_log_level") -> pd.DataFrame:
    if df.empty:
        for col in ("_raw_combined", "_is_error", "_is_warning", "_is_recovery",
                    "_is_anomaly", "_anomaly_tags"):
            df[col] = pd.Series(dtype="object" if col in ("_raw_combined", "_anomaly_tags") else "bool")
        for pattern_name in ANOMALY_PATTERNS:
            df[f"_anomaly_{pattern_name}"] = pd.Series(dtype="bool")
        for net_name in ("timeout", "auth_fail", "dns_error", "packet_loss"):
            df[f"_anomaly_{net_name}"] = pd.Series(dtype="bool")
        return df

    text_cols = df.select_dtypes(include="object").columns

    df["_raw_combined"] = df[text_cols].fillna("").apply(
        lambda row: " ".join(row.astype(str)), axis=1
    )
    df["_is_error"]   = df[level_col_name].apply(lambda l: l.upper() in ERROR_LEVELS)
    df["_is_warning"] = df[level_col_name].apply(lambda l: l.upper() in WARNING_LEVELS)
    df["_is_recovery"] = df["_raw_combined"].str.contains(
        RECOVERY_PATTERNS.pattern, flags=re.IGNORECASE, regex=True, na=False
    )

    for pattern_name, pattern in ANOMALY_PATTERNS.items():
        df[f"_anomaly_{pattern_name}"] = df["_raw_combined"].str.contains(
            pattern.pattern, flags=re.IGNORECASE, regex=True, na=False
        )
    for net_name, net_pat in NETWORK_PATTERNS.items():
        if net_name in ("timeout", "auth_fail", "dns_error", "packet_loss"):
            df[f"_anomaly_{net_name}"] = df["_raw_combined"].str.contains(
                net_pat.pattern, flags=re.IGNORECASE, regex=True, na=False
            )

    anomaly_flag_cols = [c for c in df.columns if c.startswith("_anomaly_")]
    df["_is_anomaly"] = df["_is_error"] | df[anomaly_flag_cols].any(axis=1)
    # Vectorized tag assembly via numpy boolean matrix — avoids slow .apply()
    tag_names   = [c.replace("_anomaly_", "") for c in anomaly_flag_cols]
    bool_matrix = df[anomaly_flag_cols].values          # shape: (N, M)
    df["_anomaly_tags"] = [
        [tag_names[j] for j in range(len(tag_names)) if row[j]]
        for row in bool_matrix
    ]
    return df


# ---------------------------------------------------------------------------
# PRECURSOR ANALYSIS
# ---------------------------------------------------------------------------

def find_precursors(df: pd.DataFrame, first_error_ts, window_minutes: int = 10) -> pd.DataFrame:
    """Find warning/anomalous events before the first error that may have caused it."""
    if "_timestamp_parsed" not in df.columns or first_error_ts is None:
        return pd.DataFrame()
    window_start = first_error_ts - pd.Timedelta(minutes=window_minutes)
    return df[
        (df["_timestamp_parsed"] >= window_start) &
        (df["_timestamp_parsed"] < first_error_ts) &
        (df["_is_anomaly"] | df["_is_warning"])
    ].copy()


# ---------------------------------------------------------------------------
# ROOT CAUSE IDENTIFICATION
# ---------------------------------------------------------------------------

def find_root_cause(df: pd.DataFrame, flow_key: Optional[str] = None) -> dict:
    """Identify root cause: first error event + cascade analysis + MTTR."""
    _empty = {
        "root_event": pd.Series(dtype=object), "cascade_count": 0,
        "flow_key": "N/A", "anomaly_tags": [], "mttr": None,
        "first_error_ts": None, "precursors": pd.DataFrame(),
    }
    if df.empty:
        return _empty

    errors = df[df["_is_error"]].copy()
    if errors.empty:
        warnings = df[df["_is_warning"]].copy()
        candidate = warnings.iloc[0] if not warnings.empty else df.iloc[0]
    else:
        candidate = errors.iloc[0]

    cascade_count = 0
    mttr = None
    first_error_ts = None

    if "_timestamp_parsed" in df.columns:
        first_error_ts = candidate["_timestamp_parsed"]
        subsequent = df[
            (df["_timestamp_parsed"] > first_error_ts) &
            (df["_timestamp_parsed"] <= first_error_ts + pd.Timedelta(minutes=5)) &
            (df["_is_error"])
        ]
        cascade_count = len(subsequent)

        # MTTR: time from first error to first recovery event after all errors
        recovery_events = df[
            (df["_timestamp_parsed"] > first_error_ts) &
            df["_is_recovery"]
        ]
        if not recovery_events.empty:
            recovery_ts = recovery_events["_timestamp_parsed"].min()
            mttr = recovery_ts - first_error_ts

    precursors = find_precursors(df, first_error_ts)

    return {
        "root_event":      candidate,
        "cascade_count":   cascade_count,
        "flow_key":        str(candidate.get(flow_key, "N/A")) if flow_key else "N/A",
        "anomaly_tags":    candidate.get("_anomaly_tags", []),
        "mttr":            mttr,
        "first_error_ts":  first_error_ts,
        "precursors":      precursors,
    }


# ---------------------------------------------------------------------------
# FLOW ISOLATION
# ---------------------------------------------------------------------------

def detect_flow_key(df: pd.DataFrame, hint: Optional[str] = None) -> Optional[str]:
    if hint and hint in df.columns:
        return hint

    for candidate in FLOW_KEY_CANDIDATES:
        if candidate in df.columns:
            nuniq = df[candidate].nunique()
            if 1 < nuniq < len(df) * 0.9:
                return candidate
        for col in df.columns:
            if col.lower() == candidate.lower():
                nuniq = df[col].nunique()
                if 1 < nuniq < len(df) * 0.9:
                    return col

    obj_cols = df.select_dtypes(include="object").columns
    for col in obj_cols:
        if col.startswith("_"):
            continue
        nuniq = df[col].nunique()
        if 1 < nuniq <= 500:
            return col

    return None


def isolate_flow(df: pd.DataFrame, flow_key: str, target_value: Optional[str] = None) -> pd.DataFrame:
    if target_value:
        return df[df[flow_key].astype(str) == str(target_value)]
    if "_is_error" in df.columns:
        flow_errors = df.groupby(flow_key)["_is_error"].sum()
        if flow_errors.max() > 0:
            return df[df[flow_key] == flow_errors.idxmax()]
    if "_is_anomaly" in df.columns:
        flow_anomaly = df.groupby(flow_key)["_is_anomaly"].sum()
        if flow_anomaly.max() > 0:
            return df[df[flow_key] == flow_anomaly.idxmax()]
    return df


# ---------------------------------------------------------------------------
# ANALYTICAL FUNCTIONS — burst detection, severity, host impact, log gaps
# ---------------------------------------------------------------------------

def compute_severity_score(df: pd.DataFrame, root_cause: dict) -> dict:
    """
    Compute a 0–100 incident severity score.
    Components (each 0–25):
      - Error ratio   : % of events that are ERRORs
      - Cascade depth : cascade count relative to total events
      - MTTR factor   : longer MTTR = higher score (capped at 1h)
      - Pattern weight: presence of CRITICAL/OOM/kernel_panic/segfault
    """
    total = len(df)
    if total == 0:
        return {"score": 0, "grade": "N/A", "components": {}}

    error_ratio  = min(df["_is_error"].sum() / total, 1.0)
    score_errors = error_ratio * 25

    cascade = root_cause.get("cascade_count", 0)
    score_cascade = min(cascade / max(total * 0.5, 1), 1.0) * 25

    mttr = root_cause.get("mttr")
    if mttr is not None:
        mttr_secs = mttr.total_seconds()
        score_mttr = min(mttr_secs / 3600, 1.0) * 25
    else:
        score_mttr = 15  # unknown MTTR = assume moderate

    # Pattern weights for high-severity signatures
    high_sev_patterns = {"oom_killer", "kernel_panic", "segfault", "disk_full", "certificate"}
    has_critical = (df["_log_level"] == "CRITICAL").any()
    has_high_sev = any(
        df.get(f"_anomaly_{p}", pd.Series(False)).any()
        for p in high_sev_patterns
    )
    score_pattern = (15 if has_critical else 0) + (10 if has_high_sev else 0)
    score_pattern = min(score_pattern, 25)

    total_score = int(score_errors + score_cascade + score_mttr + score_pattern)
    total_score = max(0, min(100, total_score))

    if total_score >= 80:
        grade = "P1 — CRITICO"
    elif total_score >= 60:
        grade = "P2 — ALTO"
    elif total_score >= 40:
        grade = "P3 — MEDIO"
    elif total_score >= 20:
        grade = "P4 — BASSO"
    else:
        grade = "P5 — INFORMATIVO"

    return {
        "score": total_score,
        "grade": grade,
        "components": {
            "error_ratio":    round(score_errors, 1),
            "cascade_depth":  round(score_cascade, 1),
            "mttr_factor":    round(score_mttr, 1),
            "pattern_weight": round(score_pattern, 1),
        }
    }


def compute_burst_windows(df: pd.DataFrame, resample_seconds: int = 30) -> list:
    """
    Find time windows with statistically anomalous event density.
    Uses Pandas resample + mean+2σ threshold (z-score approach).
    Returns burst windows sorted by event count descending.
    """
    if "_timestamp_parsed" not in df.columns or df.empty:
        return []

    ts_valid = df["_timestamp_parsed"].dropna()
    if len(ts_valid) < 5:
        return []

    rule = f"{resample_seconds}s"
    indexed = df.set_index("_timestamp_parsed").sort_index()
    counts  = indexed.resample(rule).size()
    err_counts = indexed.resample(rule)["_is_error"].sum() if "_is_error" in indexed.columns else counts * 0

    mean_c = counts.mean()
    std_c  = counts.std()
    if std_c == 0 or pd.isna(std_c):
        return []

    threshold = mean_c + 2 * std_c
    burst_windows = counts[counts > threshold]

    bursts = []
    for w_start, count in burst_windows.items():
        w_end = w_start + pd.Timedelta(seconds=resample_seconds)
        z_score = (count - mean_c) / std_c
        bursts.append({
            "start":       fmt_ts(w_start),
            "end":         fmt_ts(w_end),
            "events":      int(count),
            "errors":      int(err_counts.get(w_start, 0)),
            "z_score":     round(z_score, 1),
            "rate_factor": round(count / mean_c, 1),
        })

    return sorted(bursts, key=lambda b: b["events"], reverse=True)


def build_host_impact(df: pd.DataFrame) -> Optional[pd.DataFrame]:
    """Build per-host impact matrix with DOWN/DEGRADED/OK severity classification."""
    host_col = None
    for cand in ("host", "hostname", "src", "source"):
        if cand in df.columns:
            host_col = cand
            break
    if not host_col:
        return None

    agg = df.groupby(host_col).agg(
        total=("_is_anomaly", "count"),
        errors=("_is_error", "sum"),
        warnings=("_is_warning", "sum"),
        anomalies=("_is_anomaly", "sum"),
        recovery=("_is_recovery", "sum"),
    ).sort_values("errors", ascending=False)
    agg["err_%"] = (agg["errors"] / agg["total"] * 100).round(1)
    agg["warn_%"] = (agg["warnings"] / agg["total"] * 100).round(1)

    def _host_status(row) -> str:
        if row["err_%"] >= 50:
            return "**DOWN**"
        if row["err_%"] >= 15 or row["warn_%"] >= 25:
            return "**DEGRADED**"
        return "OK"

    agg["Stato"] = agg.apply(_host_status, axis=1)
    agg["err_%"] = agg["err_%"].astype(str) + "%"
    agg["warn_%"] = agg["warn_%"].astype(str) + "%"
    return agg.reset_index()


def detect_log_gaps(df: pd.DataFrame, multiplier: float = 5.0,
                    min_gap_seconds: float = 60.0) -> list:
    """
    Detect suspicious gaps using 75th-percentile × multiplier with a minimum floor.
    Using median would produce false positives when burst events compress it to near-zero.
    The floor prevents flagging normal log cadence in low-volume streams.
    """
    if "_timestamp_parsed" not in df.columns or len(df) < 3:
        return []

    ts = df["_timestamp_parsed"].dropna().sort_values().reset_index(drop=True)
    deltas = ts.diff().dropna().dt.total_seconds()
    if deltas.empty:
        return []

    p75 = float(deltas.quantile(0.75))
    if p75 <= 0:
        p75 = float(deltas.mean())
    if p75 <= 0:
        return []

    threshold_secs = max(p75 * multiplier, min_gap_seconds)

    gaps = []
    for i in range(1, len(ts)):
        delta_secs = (ts[i] - ts[i - 1]).total_seconds()
        if delta_secs >= threshold_secs:
            gaps.append({
                "from":         fmt_ts(ts[i - 1]),
                "to":           fmt_ts(ts[i]),
                "gap_minutes":  round(delta_secs / 60, 1),
                "gap_factor":   round(delta_secs / p75, 1),
            })
    return sorted(gaps, key=lambda g: g["gap_minutes"], reverse=True)[:10]


def detect_duplicates(df: pd.DataFrame) -> int:
    """Count exact duplicate rows (excluding internal _ columns)."""
    display_cols = [c for c in df.columns if not c.startswith("_")]
    if not display_cols:
        return 0
    return int(df[display_cols].duplicated().sum())


def _plural_it(n: int, singular: str, plural: str) -> str:
    """Italian pluralization helper."""
    return f"{n} {singular}" if n == 1 else f"{n} {plural}"


def compute_trend(df: pd.DataFrame) -> str:
    """
    Compare error rate in the first vs. second half of the time window to determine
    whether the incident is escalating, stable, or recovering.
    """
    if "_timestamp_parsed" not in df.columns or "_is_error" not in df.columns:
        return "N/D"
    ts = df["_timestamp_parsed"].dropna()
    if len(ts) < 4:
        return "N/D"
    midpoint = ts.min() + (ts.max() - ts.min()) / 2
    first    = df[df["_timestamp_parsed"] <  midpoint]
    second   = df[df["_timestamp_parsed"] >= midpoint]
    if len(first) == 0 or len(second) == 0:
        return "N/D"
    r1 = first["_is_error"].sum()  / len(first)
    r2 = second["_is_error"].sum() / len(second)
    if r2 > r1 * 1.25:
        return f"↑ ESCALATING ({r1*100:.0f}% → {r2*100:.0f}% error rate)"
    elif r2 < r1 * 0.75:
        return f"↓ RECOVERING ({r1*100:.0f}% → {r2*100:.0f}% error rate)"
    else:
        return f"→ STABLE ({r1*100:.0f}% → {r2*100:.0f}% error rate)"


def build_service_impact(df: pd.DataFrame) -> str:
    """
    Classify each sourcetype/source as DOWN / DEGRADED / OK based on error %.
    DOWN ≥ 50% errors, DEGRADED ≥ 15% errors or ≥ 25% warnings, otherwise OK.
    """
    col = next((c for c in ("sourcetype", "source") if c in df.columns), None)
    if col is None:
        return "_Colonna sourcetype/source assente._"

    lines = [f"| {col} | Stato | err_% | Errori | Warning |", "|---|---|---|---|---|"]
    for src, group in df.groupby(col):
        total    = len(group)
        errors   = int(group["_is_error"].sum())
        warnings = int(group["_is_warning"].sum())
        err_pct  = errors / total * 100 if total > 0 else 0
        warn_pct = warnings / total * 100 if total > 0 else 0

        if err_pct >= 50:
            status = "**DOWN**"
        elif err_pct >= 15 or warn_pct >= 25:
            status = "**DEGRADED**"
        else:
            status = "OK"
        lines.append(f"| `{src}` | {status} | {err_pct:.1f}% | {errors} | {warnings} |")

    return "\n".join(lines)


def worst_service_status(df: pd.DataFrame) -> str:
    """Return worst service status across all sourcetypes: DOWN > DEGRADED > OK."""
    col = next((c for c in ("sourcetype", "source") if c in df.columns), None)
    if col is None:
        return "UNKNOWN"
    worst = "OK"
    for _, group in df.groupby(col):
        total    = len(group)
        err_pct  = group["_is_error"].sum() / total * 100 if total > 0 else 0
        warn_pct = group["_is_warning"].sum() / total * 100 if total > 0 else 0
        if err_pct >= 50:
            return "DOWN"
        if err_pct >= 15 or warn_pct >= 25:
            worst = "DEGRADED"
    return worst


# SLA thresholds in seconds per priority level
SLA_THRESHOLDS = {"P1": 300, "P2": 1800, "P3": 7200, "P4": 86400}

def compute_rc_confidence(root_cause: dict) -> dict:
    """
    Estimate confidence in the automated root cause identification.
    ALTA: CRITICAL/FATAL/EMERG with ≥1 tag, OR ERROR with cascade ≥5, OR ERROR with ≥2 tags + cascade ≥3.
    MEDIA: ERROR with ≥1 tag or any CRITICAL without tags.
    BASSA: fallback to WARNING/UNKNOWN, no cascades, no tags.
    """
    level   = root_cause["root_event"].get("_log_level", "UNKNOWN")
    tags    = root_cause.get("anomaly_tags", [])
    cascade = root_cause.get("cascade_count", 0)

    if level in {"CRITICAL", "FATAL", "EMERG", "ALERT"} and len(tags) >= 1:
        label, reason = "ALTA", f"evento {level} con {len(tags)} pattern confermati"
    elif level == "ERROR" and cascade >= 5:
        label, reason = "ALTA", f"ERROR + cascata critica di {cascade} errori downstream"
    elif level == "ERROR" and len(tags) >= 2 and cascade >= 3:
        label, reason = "ALTA", f"ERROR + {len(tags)} pattern + cascata {cascade} errori"
    elif level in {"CRITICAL", "FATAL"} and not tags:
        label, reason = "MEDIA", "evento CRITICAL senza pattern specifici"
    elif level == "ERROR" and len(tags) >= 1:
        label, reason = "MEDIA", f"ERROR con {len(tags)} pattern confermato(i)"
    elif level == "ERROR":
        label, reason = "MEDIA", "ERROR senza pattern specifici — identificazione per livello"
    else:
        label, reason = "BASSA", f"primo evento anomalo al livello {level} — possibile falso positivo"

    return {"label": label, "reason": reason}


def detect_sla_breach(mttr, severity_grade: str) -> Optional[str]:
    """
    Return an SLA breach warning string if MTTR exceeds the threshold for the incident grade.
    Matches P1/P2/P3/P4 from the grade string.
    """
    if mttr is None:
        return None
    mttr_secs = mttr.total_seconds()
    for priority in ("P1", "P2", "P3", "P4"):
        if priority in severity_grade:
            threshold = SLA_THRESHOLDS.get(priority)
            if threshold and mttr_secs > threshold:
                sla_str = fmt_duration(pd.Timedelta(seconds=threshold))
                return (
                    f"⚠️ **SLA BREACH** — MTTR `{fmt_duration(mttr)}` supera la soglia {priority} "
                    f"di `{sla_str}` (SoP standard)"
                )
            return None
    return None


def detect_cross_host_cascade(df: pd.DataFrame, window_seconds: float = 2.0) -> str:
    """
    Find ERROR events on different hosts that occurred within window_seconds of each other,
    indicating synchronous cross-host failure propagation.
    Returns a Markdown table or a descriptive string.
    """
    if "_timestamp_parsed" not in df.columns or "_is_error" not in df.columns:
        return "_Dati timestamp/errore assenti._"

    host_col = next((c for c in ("host", "hostname") if c in df.columns), None)
    if not host_col:
        return "_Colonna host assente — analisi cross-host non disponibile._"

    errors = (
        df[df["_is_error"]]
        .sort_values("_timestamp_parsed")
        .reset_index(drop=True)
    )
    if len(errors) < 2:
        return "_Errori insufficienti per analisi cross-host._"

    msg_col = next((c for c in ("message", "msg") if c in df.columns), None)

    groups, seen_starts = [], set()
    for i in range(len(errors) - 1):
        t0 = errors.loc[i, "_timestamp_parsed"]
        h0 = str(errors.loc[i, host_col])
        start_str = fmt_ts(t0)
        if start_str in seen_starts:
            continue

        members = [{"host": h0, "ts": start_str, "level": errors.loc[i, "_log_level"]}]
        for j in range(i + 1, len(errors)):
            tj = errors.loc[j, "_timestamp_parsed"]
            if pd.isna(tj) or (tj - t0).total_seconds() > window_seconds:
                break
            hj = str(errors.loc[j, host_col])
            if hj != h0:
                members.append({"host": hj, "ts": fmt_ts(tj), "level": errors.loc[j, "_log_level"]})

        if len(members) >= 2:
            seen_starts.add(start_str)
            # Deduplicate consecutive same-host members; preserve insertion order
            unique_hosts = list(dict.fromkeys(m["host"] for m in members))
            hosts_str  = " → ".join(unique_hosts)
            levels_str = ", ".join(dict.fromkeys(m["level"] for m in members))
            msg_str    = ""
            if msg_col:
                msg_str = str(errors.loc[i, msg_col])[:80] if pd.notna(errors.loc[i, msg_col]) else ""
            groups.append({
                "Inizio": start_str,
                "Host (ordine)": hosts_str,
                "Livelli": levels_str,
                "Finestra (s)": window_seconds,
                "Trigger": msg_str,
            })

    if not groups:
        return f"_Nessun errore cross-host simultaneo rilevato (finestra: {window_seconds}s)._"

    lines = ["| Inizio | Host (ordine) | Livelli | Trigger |", "|---|---|---|---|"]
    for g in groups[:10]:
        lines.append(
            f"| `{g['Inizio']}` | `{g['Host (ordine)']}` | {g['Livelli']} | {g['Trigger'][:60]} |"
        )
    return "\n".join(lines)


def build_recovery_timeline(df: pd.DataFrame) -> Optional[pd.DataFrame]:
    """
    Build a per-host recovery timeline: first error time, first recovery time,
    and per-host downtime duration.
    """
    if "_timestamp_parsed" not in df.columns or "_is_error" not in df.columns:
        return None

    host_col = next((c for c in ("host", "hostname", "src", "source") if c in df.columns), None)
    if not host_col:
        return None

    rows = []
    for host, group in df.groupby(host_col):
        errors    = group[group["_is_error"]]
        recoveries = group[group["_is_recovery"]]
        if errors.empty:
            continue
        first_err = errors["_timestamp_parsed"].min()
        first_rec = recoveries["_timestamp_parsed"].min() if not recoveries.empty else None
        downtime  = fmt_duration(first_rec - first_err) if first_rec is not None else "N/D"
        rows.append({
            "Host":            str(host),
            "Primo Errore":    fmt_ts(first_err),
            "Primo Recovery":  fmt_ts(first_rec) if first_rec is not None else "—",
            "Downtime":        downtime,
            "# Errori":        int(len(errors)),
        })

    if not rows:
        return None
    return pd.DataFrame(rows).sort_values("Primo Errore").reset_index(drop=True)


def build_network_flow_matrix(df: pd.DataFrame) -> str:
    """
    Build a src_ip → dst_ip flow matrix showing total events and error count per pair.
    Requires src_ip and dst_ip columns (common in SIEM CIM-compliant exports).
    """
    src_col = next((c for c in ("src_ip", "source_ip", "clientip", "src") if c in df.columns), None)
    dst_col = next((c for c in ("dst_ip", "dest_ip", "dest", "dst") if c in df.columns), None)

    if not src_col or not dst_col:
        return "_Colonne src_ip/dst_ip assenti — matrice flussi non disponibile._"

    matrix = (
        df.groupby([src_col, dst_col])
        .agg(total=("_is_anomaly", "count"), errors=("_is_error", "sum"))
        .reset_index()
        .sort_values("errors", ascending=False)
        .head(20)
    )
    if matrix.empty:
        return "_Nessun flusso src→dst rilevato._"

    matrix.columns = ["src_ip", "dst_ip", "Total", "Errori"]
    matrix["err_%"] = (matrix["Errori"] / matrix["Total"] * 100).round(1).astype(str) + "%"

    lines = ["| src_ip | dst_ip | Totale | Errori | err_% |", "|---|---|---|---|---|"]
    for _, r in matrix.iterrows():
        lines.append(f"| `{r['src_ip']}` | `{r['dst_ip']}` | {r['Total']} | {r['Errori']} | {r['err_%']} |")
    return "\n".join(lines)


_BARS = " ▁▂▃▄▅▆▇█"  # 9 levels (index 0 = empty bucket)

def build_error_rate_chart(df: pd.DataFrame) -> str:
    """
    Render a per-minute ASCII bar chart showing event density and error count.
    Uses Unicode block characters scaled to the peak event bucket.
    """
    if "_timestamp_parsed" not in df.columns or df.empty:
        return "_Dati insufficienti per il grafico._"

    indexed  = df.set_index("_timestamp_parsed").sort_index()
    total_c  = indexed.resample("1min").size()
    error_c  = (
        indexed.resample("1min")["_is_error"].sum()
        if "_is_error" in indexed.columns else total_c * 0
    )
    if total_c.empty or total_c.max() == 0:
        return "_Nessun dato temporale per il grafico._"

    peak = total_c.max()
    lines = ["```"]
    for ts, count in total_c.items():
        bar_len  = max(1, int(count / peak * 24)) if count > 0 else 0
        bar_char = "█" if int(error_c.get(ts, 0)) > 0 else "▒"
        bar      = (bar_char * bar_len).ljust(24)
        err      = int(error_c.get(ts, 0))
        err_note = f"  ◉ {err} err" if err > 0 else ""
        lines.append(f"  {ts.strftime('%H:%M')}  {bar}  {count:>3}{err_note}")
    lines.append("```")
    return "\n".join(lines)


def build_sourcetype_breakdown(df: pd.DataFrame) -> str:
    """Per-sourcetype (or source) error/warning/total breakdown."""
    col = next((c for c in ("sourcetype", "source") if c in df.columns), None)
    if col is None:
        return "_Colonna sourcetype/source assente._"

    agg = (
        df.groupby(col)
        .agg(total=("_is_anomaly", "count"),
             errors=("_is_error", "sum"),
             warnings=("_is_warning", "sum"))
        .sort_values("errors", ascending=False)
        .reset_index()
    )
    agg["err_%"] = (agg["errors"] / agg["total"] * 100).round(1).astype(str) + "%"

    lines = [f"| {col} | Totale | Errori | Warning | err_% |", "|---|---|---|---|---|"]
    for _, r in agg.iterrows():
        lines.append(f"| `{r[col]}` | {r['total']} | {r['errors']} | {r['warnings']} | {r['err_%']} |")
    return "\n".join(lines)


def build_top_errors(df: pd.DataFrame, top_n: int = 5) -> str:
    """
    Find the most frequently recurring error messages.
    Normalizes messages by stripping numbers, IPs, and UUIDs before grouping.
    """
    if "_is_error" not in df.columns or df["_is_error"].sum() == 0:
        return "_Nessun evento errore trovato._"

    msg_col = next((c for c in ("message", "msg", "_raw") if c in df.columns), None)
    if msg_col is None:
        return "_Colonna message assente._"

    _normalize_re = re.compile(
        r'(?:'
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'  # UUID v4
        r'|\b\d{1,3}(?:\.\d{1,3}){3}\b'                                    # IPv4
        r'|0x[0-9a-f]+'                                                     # hex literal
        r'|\b\d+\b'                                                         # bare integers
        r')',
        re.IGNORECASE
    )
    errors = df[df["_is_error"]][msg_col].dropna().astype(str)
    normalized = errors.apply(lambda m: _normalize_re.sub("<N>", m).strip())
    counts = normalized.value_counts().head(top_n)

    if counts.empty:
        return "_Nessun messaggio errore da analizzare._"

    lines = ["| # | Messaggio (normalizzato) | Occorrenze |", "|---|---|---|"]
    for i, (msg, cnt) in enumerate(counts.items(), 1):
        lines.append(f"| {i} | `{str(msg)[:120]}` | {cnt} |")
    if counts.max() == 1:
        lines.append("\n> _Tutti gli errori sono eventi unici — nessun pattern ricorrente rilevato._")
    return "\n".join(lines)


def build_incident_narrative(
    df: pd.DataFrame,
    root_cause: dict,
    bursts: list,
    recovery_timeline: Optional[pd.DataFrame],
    rc_confidence: dict,
) -> str:
    """
    Generate a natural-language Italian prose summary of the incident timeline.
    Suitable as a standalone ticket description or executive briefing.
    """
    if df.empty:
        return "_Dati insufficienti per la narrazione._"

    paragraphs = []

    # Use first error timestamp as T+0 reference for relative times
    t_zero = root_cause.get("first_error_ts")
    if t_zero is None and "_timestamp_parsed" in df.columns:
        t_zero = df["_timestamp_parsed"].min()

    # Opening: first sign of trouble (relative to first error)
    first_warn = df[df["_is_warning"]].iloc[0] if df["_is_warning"].any() else None

    if first_warn is not None and "_timestamp_parsed" in first_warn.index:
        warn_ts   = fmt_relative_ts(first_warn["_timestamp_parsed"], t_zero)
        warn_host = first_warn.get("host", "N/A")
        warn_msg  = str(first_warn.get("message", ""))[:100]
        paragraphs.append(
            f"Alle **{warn_ts}** il sistema ha mostrato i primi segnali di degrado su `{warn_host}`: "
            f"_{warn_msg}_."
        )

    # Root cause event
    rc = root_cause["root_event"]
    rc_ts   = fmt_relative_ts(root_cause["first_error_ts"], t_zero)
    rc_host = rc.get("host", "N/A")
    rc_lvl  = rc.get("_log_level", "?")
    rc_tags = root_cause.get("anomaly_tags", [])
    tag_str = f" con pattern _{', '.join(rc_tags[:3])}_" if rc_tags else ""
    paragraphs.append(
        f"Il **primo errore** (T+0) è stato rilevato alle **{rc_ts}** su `{rc_host}` "
        f"(livello: `{rc_lvl}`){tag_str}."
    )

    # Cascade
    cascade = root_cause.get("cascade_count", 0)
    if cascade > 0:
        paragraphs.append(
            f"L'evento ha innescato una **cascata di {cascade} errori** nei 5 minuti successivi, "
            f"coinvolgendo host multipli in una propagazione a catena del fallimento."
        )

    # Precursor events (warnings/info before first error)
    prec_df = root_cause.get("precursors")
    if prec_df is not None and not prec_df.empty and "_timestamp_parsed" in prec_df.columns:
        first_prec = prec_df.iloc[0]
        prec_ts    = fmt_relative_ts(first_prec["_timestamp_parsed"], t_zero)
        prec_host  = first_prec.get("host", "N/A")
        prec_msg   = str(first_prec.get("message", first_prec.get("_raw", "")))[:100]
        paragraphs.append(
            f"**Evento precursore rilevato** alle {prec_ts} su `{prec_host}`: "
            f"_{prec_msg}_ — il degrado era in corso prima del primo errore formale."
        )

    # Burst peak
    if bursts:
        b = bursts[0]
        paragraphs.append(
            f"Il **picco dell'incidente** si è verificato nella finestra "
            f"`{b['start']}` — `{b['end']}` con **{b['events']} eventi** "
            f"(z-score: {b['z_score']}, {b['rate_factor']}× la densità normale)."
        )

    # Recovery
    mttr = root_cause.get("mttr")
    if mttr is not None:
        recovery_ts = fmt_relative_ts(
            (root_cause["first_error_ts"] + mttr) if root_cause["first_error_ts"] else None,
            t_zero
        )
        paragraphs.append(
            f"Il sistema si è **ripristinato in {fmt_duration(mttr)}** dal primo errore "
            f"(recovery a {recovery_ts})."
        )
        if recovery_timeline is not None and not recovery_timeline.empty:
            slowest = recovery_timeline.sort_values("# Errori", ascending=False).iloc[0]
            paragraphs.append(
                f"L'host più colpito è stato `{slowest['Host']}` "
                f"con **{slowest['# Errori']} errori** e un downtime di **{slowest['Downtime']}**."
            )
    else:
        paragraphs.append(
            "Nel periodo analizzato **non è stato rilevato un evento di recovery** — "
            "verificare se il sistema si è ripristinato al di fuori della finestra temporale."
        )

    # Confidence closing
    paragraphs.append(
        f"Confidenza nell'identificazione automatica: **{rc_confidence['label']}** "
        f"({rc_confidence['reason']})."
    )

    return "\n\n".join(paragraphs)


# ---------------------------------------------------------------------------
# MARKDOWN REPORT HELPERS
# ---------------------------------------------------------------------------

def _md_table(df: pd.DataFrame, max_rows: int = 20,
              inject_ts: bool = True) -> str:
    """Render DataFrame as Markdown table, injecting a Timestamp column when available."""
    display_cols = [c for c in df.columns if not c.startswith("_")]
    sub = df.head(max_rows).copy()

    # Inject human-readable timestamp as first column
    if inject_ts and "_timestamp_parsed" in sub.columns:
        sub.insert(0, "Timestamp", sub["_timestamp_parsed"].apply(fmt_ts))
        display_cols = ["Timestamp"] + display_cols

    sub = sub[display_cols].fillna("")
    for col in sub.select_dtypes(include="object").columns:
        sub[col] = sub[col].astype(str).str[:100]

    header    = "| " + " | ".join(str(c) for c in sub.columns) + " |"
    separator = "| " + " | ".join("---" for _ in sub.columns) + " |"
    rows = []
    for _, row in sub.iterrows():
        cells = " | ".join(str(v).replace("|", "¦").replace("\n", " ") for v in row)
        rows.append(f"| {cells} |")
    return "\n".join([header, separator] + rows)


def _build_ascii_chain(df: pd.DataFrame, max_events: int = 12,
                       gap_threshold_seconds: float = 30.0,
                       rc_ts=None) -> str:
    """
    Build an ASCII event-chain diagram centered on the root cause event.
    Selects up to max_events/2 events before and after rc_ts (if provided),
    otherwise takes the first max_events anomaly events chronologically.
    Gap markers (╎) are inserted when consecutive event intervals exceed gap_threshold_seconds.
    The root cause event is marked with ★; errors with ◉; warnings/others with △.
    """
    if "_timestamp_parsed" not in df.columns:
        return ""
    anom = df[df["_is_anomaly"]].copy()
    if anom.empty:
        return ""

    if rc_ts is not None and "_timestamp_parsed" in anom.columns:
        half = max_events // 2
        before = anom[anom["_timestamp_parsed"] <  rc_ts].tail(half)
        after  = anom[anom["_timestamp_parsed"] >= rc_ts].head(max_events - len(before))
        chain_df = pd.concat([before, after]).reset_index(drop=True)
    else:
        chain_df = anom.head(max_events).reset_index(drop=True)

    lines = ["```"]
    for i, (_, row) in enumerate(chain_df.iterrows()):
        if i > 0:
            prev_ts = chain_df.loc[i - 1, "_timestamp_parsed"]
            curr_ts = row["_timestamp_parsed"]
            if pd.notna(prev_ts) and pd.notna(curr_ts):
                gap_secs = (curr_ts - prev_ts).total_seconds()
                if gap_secs >= gap_threshold_seconds:
                    lines.append(f"{'':22}╎  [GAP: {fmt_duration(curr_ts - prev_ts)}]")

        ts      = fmt_ts(row.get("_timestamp_parsed"))
        level   = row.get("_log_level", "?")
        host    = str(row.get("host", row.get("source", "?")))
        msg     = str(row.get("message", ""))[:65] if "message" in row.index else ""
        tags    = ",".join(row.get("_anomaly_tags", []))[:30]
        is_last = (i == len(chain_df) - 1)
        connector = " " if is_last else "│"

        is_rc = (rc_ts is not None and pd.notna(row.get("_timestamp_parsed"))
                 and row["_timestamp_parsed"] == rc_ts)
        if is_rc:
            marker = "★"
        elif level in ERROR_LEVELS:
            marker = "◉"
        else:
            marker = "△"

        rc_flag = " ← ROOT CAUSE" if is_rc else ""
        lines.append(f"{ts} {marker} [{level:<8}] {host:<10} {msg}{rc_flag}")
        if tags:
            lines.append(f"{'':22}{connector}  ↳ tags: {tags}")
        elif not is_last:
            lines.append(f"{'':22}│")
    lines.append("```")
    return "\n".join(lines)


def _build_cause_list(tags: list, error_only_tags: list, rc_level: str) -> str:
    """
    Build a clean numbered list of probable causes from anomaly tags.
    error_only_tags: tags seen in ERROR/CRITICAL events only (not recovery events),
    preventing service_restart / recovery patterns from polluting the cause list.
    """
    causes = []
    for tag in tags:
        if tag in CAUSE_LABELS:
            causes.append(f"1. {CAUSE_LABELS[tag]}")
    # Add correlated tags from other error events (not from root cause event)
    correlated = sorted(set(error_only_tags) - set(tags))
    for tag in correlated:
        if tag in CAUSE_LABELS:
            causes.append(f"1. *(correlato)* {CAUSE_LABELS[tag]}")
    if not causes:
        causes.append(
            f"1. **Evento di errore al livello {rc_level}** — nessun pattern specifico corrisponde"
        )
    return "\n".join(causes)


def build_cooccurrence_summary(df: pd.DataFrame) -> str:
    """Build a text summary of which anomaly types co-occur most frequently."""
    anomaly_flag_cols = [
        c for c in df.columns
        if c.startswith("_anomaly_") and c != "_anomaly_tags"
    ]
    if len(anomaly_flag_cols) < 2:
        return "_Dati insufficienti per analisi co-occorrenza._"

    anom_df = df[anomaly_flag_cols].astype(int)
    pairs = []
    cols = anomaly_flag_cols
    for i in range(len(cols)):
        for j in range(i + 1, len(cols)):
            both = int((anom_df[cols[i]] & anom_df[cols[j]]).sum())
            if both > 0:
                t1 = cols[i].replace("_anomaly_", "")
                t2 = cols[j].replace("_anomaly_", "")
                pairs.append((t1, t2, both))
    if not pairs:
        return "_Nessuna co-occorrenza rilevata tra pattern di anomalia._"

    pairs.sort(key=lambda x: x[2], reverse=True)
    lines = ["| Pattern A | Pattern B | Co-occorrenze |\n|---|---|---|"]
    for t1, t2, count in pairs[:10]:
        lines.append(f"| `{t1}` | `{t2}` | {count} |")
    return "\n".join(lines)


def generate_SIEM_queries(
    df: pd.DataFrame,
    ts_col: Optional[str],
    flow_key: Optional[str],
    root_cause: dict,
    source_file: str,
) -> str:
    """
    Generate multiple focused SIEM SPL queries for incident reproduction.
    Returns a Markdown-formatted string with three labelled code blocks:
      1. Full incident window (±10 min)
      2. Root-cause host focused
      3. Per-pattern regex (top detected pattern)
    """
    rc_ts   = root_cause.get("first_error_ts")
    rc_host = root_cause.get("root_event", pd.Series()).get("host", "")
    rc_tags = root_cause.get("anomaly_tags", [])

    if rc_ts is not None:
        t_earliest = fmt_ts(rc_ts - pd.Timedelta(minutes=10))
        t_latest   = fmt_ts(rc_ts + pd.Timedelta(minutes=10))
        time_filter = f'earliest="{t_earliest}" latest="{t_latest}"'
        t_rc_str    = fmt_ts(rc_ts)
    else:
        time_filter = 'earliest=-1h latest=now'
        t_rc_str    = "N/A"

    source_line = ""
    if "source" in df.columns:
        sources = df["source"].dropna().unique()[:3]
        if len(sources):
            source_line = "(" + " OR ".join(f'source="{s}"' for s in sources) + ")"

    flow_filter = ""
    if flow_key and root_cause.get("flow_key", "N/A") != "N/A":
        flow_filter = f'{flow_key}="{root_cause["flow_key"]}"'

    base_parts  = [p for p in [source_line, flow_filter] if p]
    base_filter = " ".join(base_parts) if base_parts else "*"
    table_fields = " ".join(f for f in ["_time", "host", "source", "log_level", "message", flow_key or ""] if f.strip())
    sev_eval = (
        '| eval severity=case(\n'
        '    log_level="CRITICAL" OR log_level="FATAL", 5,\n'
        '    log_level="ERROR",   4,\n'
        '    log_level="WARNING", 3,\n'
        '    log_level="INFO",    2,\n'
        '    true(), 1)'
    )

    # Query 1: Full incident window
    q1 = (
        f"search {time_filter} {base_filter}\n"
        f"{sev_eval}\n"
        f"| where severity >= 3\n"
        f"| sort 0 _time\n"
        f"| table {table_fields}"
    )

    # Query 2: Root cause host drill-down (±5 min tighter window)
    if rc_host and rc_ts is not None:
        t_host_early = fmt_ts(rc_ts - pd.Timedelta(minutes=5))
        t_host_late  = fmt_ts(rc_ts + pd.Timedelta(minutes=5))
        q2 = (
            f'search earliest="{t_host_early}" latest="{t_host_late}" host="{rc_host}"\n'
            f"{sev_eval}\n"
            f"| sort 0 _time\n"
            f"| table {table_fields}"
        )
    else:
        q2 = f"search {time_filter} {base_filter}\n| sort 0 _time\n| table {table_fields}"

    # Query 3: Pattern-specific regex search
    pattern_query_map = {
        "oom_killer":     r'(?i)(out of memory|OOM|kill process)',
        "timeout":        r'(?i)(timeout|timed out|ETIMEDOUT|ECONNRESET)',
        "stack_trace":    r'(?i)(Traceback|Exception|at \w+\.\w+\()',
        "pool_exhausted": r'(?i)(pool exhaust|max connections)',
        "slow_query":     r'(?i)(slow query|long query)',
        "auth_fail":      r'(?i)(auth.*fail|invalid.*token|unauthorized)',
        "disk_full":      r'(?i)(no space left|ENOSPC|disk full)',
        "cpu_spike":      r'(?i)(load average [5-9]\d)',
        "kernel_panic":   r'(?i)(kernel panic|BUG:|Call Trace)',
        "certificate":    r'(?i)(cert.*expired|SSL error|TLS.*fail)',
    }
    q3_label = rc_tags[0] if rc_tags else "error"
    q3_regex = pattern_query_map.get(q3_label, r'(?i)(error|critical|fatal)')
    q3 = (
        f"search {time_filter} {source_line or '*'}\n"
        f'| where match(message, "{q3_regex}")\n'
        f"| sort 0 _time\n"
        f"| table {table_fields}"
    )

    blocks = [
        f"**Query 1 — Finestra Incidente Completa** (RC @ `{t_rc_str}`, ±10 min)\n```spl\n{q1}\n```",
        f"**Query 2 — Host Root Cause** (`{rc_host or 'N/A'}`, ±5 min)\n```spl\n{q2}\n```",
        f"**Query 3 — Pattern Specifico** (`{q3_label}`)\n```spl\n{q3}\n```",
    ]
    return "\n\n".join(blocks)


# ---------------------------------------------------------------------------
# ANONYMIZATION
# ---------------------------------------------------------------------------

def anonymize_report(text: str) -> str:
    """
    Replace identifying artefacts in a report string with consistent pseudonyms.
    Substitutions applied (all consistent within the document):
      - IPv4 addresses → ANON-IP-N  (same IP always gets same N)
      - Session/trace IDs matching sess-*/trace-*/req-*/txn-* → ANON-SID-N
      - RFC 4122 UUIDs → ANON-UUID-N
      - Email addresses → ANON-MAIL-N
    """
    import itertools

    _ipv4_re   = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
    _uuid_re   = re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.IGNORECASE)
    _sid_re    = re.compile(r'\b(?:sess|trace|req|txn|trx|span)-[A-Za-z0-9_\-]{3,64}\b', re.IGNORECASE)
    _email_re  = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')

    _counters: dict = {}

    def _replace(pattern: re.Pattern, prefix: str, s: str) -> str:
        mapping: dict = {}
        counter = itertools.count(1)
        def _sub(m: re.Match) -> str:
            val = m.group(0)
            if val not in mapping:
                mapping[val] = f"{prefix}-{next(counter)}"
            return mapping[val]
        return pattern.sub(_sub, s)

    text = _replace(_ipv4_re,  "ANON-IP",   text)
    text = _replace(_uuid_re,  "ANON-UUID", text)
    text = _replace(_sid_re,   "ANON-SID",  text)
    text = _replace(_email_re, "ANON-MAIL", text)
    return text


# ---------------------------------------------------------------------------
# HTML OUTPUT
# ---------------------------------------------------------------------------

def wrap_html(markdown_content: str, incident_id: str, severity_grade: str) -> str:
    """
    Wrap a Markdown report string in a self-contained HTML page.
    Uses marked.js (CDN) to render Markdown client-side and highlight.js for code blocks.
    No Python dependencies required beyond the stdlib html module.
    """
    import html as _html
    escaped = _html.escape(markdown_content)
    severity_color = {
        "P1": "#e74c3c", "P2": "#e67e22", "P3": "#f1c40f", "P4": "#2ecc71"
    }.get(severity_grade[:2] if severity_grade else "", "#3498db")

    return f"""<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>scoobyLog — {incident_id}</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css">
<style>
  :root {{
    --accent: {severity_color};
    --bg: #f8f9fa; --fg: #212529; --card: #ffffff;
    --border: #dee2e6; --code-bg: #f1f3f5;
  }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
         background: var(--bg); color: var(--fg); margin: 0; padding: 0; }}
  #banner {{ background: var(--accent); color: #fff; padding: .6rem 2rem;
             font-size: .85rem; display: flex; justify-content: space-between; }}
  #content {{ max-width: 1100px; margin: 2rem auto; padding: 0 1.5rem 4rem; }}
  h1 {{ border-bottom: 3px solid var(--accent); padding-bottom: .4rem; }}
  h2 {{ border-bottom: 1px solid var(--border); padding-bottom: .2rem; margin-top: 2.5rem; }}
  h3 {{ margin-top: 1.8rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: .9rem; }}
  th {{ background: var(--accent); color: #fff; padding: .5rem .8rem; text-align: left; }}
  td {{ padding: .45rem .8rem; border-bottom: 1px solid var(--border); }}
  tr:nth-child(even) td {{ background: var(--code-bg); }}
  code {{ background: var(--code-bg); border-radius: 3px; padding: .1em .35em;
          font-family: 'SFMono-Regular',Consolas,monospace; font-size: .88em; }}
  pre {{ background: var(--code-bg); border: 1px solid var(--border); border-radius: 6px;
        padding: 1rem; overflow-x: auto; }}
  pre code {{ background: none; padding: 0; }}
  blockquote {{ border-left: 4px solid var(--accent); margin: 1rem 0;
                padding: .5rem 1rem; background: var(--card); }}
  a {{ color: var(--accent); }}
  @media print {{ #banner {{ display:none; }} }}
</style>
</head>
<body>
<div id="banner">
  <span>scoobyLog v{VERSION} — Incident Response Report</span>
  <span>{incident_id}</span>
</div>
<div id="content">
<div id="md-source" style="display:none">{escaped}</div>
<div id="rendered"></div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/marked/9.1.6/marked.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<script>
  marked.setOptions({{
    highlight: function(code, lang) {{
      const l = hljs.getLanguage(lang) ? lang : 'plaintext';
      return hljs.highlight(code, {{language: l}}).value;
    }},
    breaks: true, gfm: true
  }});
  const src = document.getElementById('md-source').textContent;
  document.getElementById('rendered').innerHTML = marked.parse(src);
  document.querySelectorAll('pre code').forEach(el => hljs.highlightElement(el));
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# REPORT GENERATION
# ---------------------------------------------------------------------------

def generate_report(
    df: pd.DataFrame,
    root_cause: dict,
    network_evidence: dict,
    flow_key: Optional[str],
    flow_df: pd.DataFrame,
    source_file: str,
    args: argparse.Namespace,
    severity: Optional[dict] = None,
    bursts: Optional[list] = None,
    host_impact: Optional[pd.DataFrame] = None,
    log_gaps: Optional[list] = None,
    duplicate_count: int = 0,
    recovery_timeline: Optional[pd.DataFrame] = None,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _src_path = Path(source_file)
    if _src_path.exists():
        raw_bytes  = _src_path.read_bytes()
        file_hash  = hashlib.md5(raw_bytes).hexdigest()[:8].upper()
        sha256     = hashlib.sha256(raw_bytes).hexdigest()
    else:
        # stdin mode: derive hash from DataFrame content for reproducibility
        _df_bytes  = df.to_csv(index=False).encode()
        file_hash  = hashlib.md5(_df_bytes).hexdigest()[:8].upper()
        sha256     = hashlib.sha256(_df_bytes).hexdigest()
    incident_id = file_hash

    total_events   = len(df)
    error_events   = int(df["_is_error"].sum())
    warning_events = int(df["_is_warning"].sum())
    anomaly_events = int(df["_is_anomaly"].sum())
    unique_flows   = df[flow_key].nunique() if flow_key else "N/A"

    if "_timestamp_parsed" in df.columns:
        t_start  = df["_timestamp_parsed"].min()
        t_end    = df["_timestamp_parsed"].max()
        duration = t_end - t_start
        time_range = (
            f"`{fmt_ts(t_start)}` → `{fmt_ts(t_end)}`  "
            f"*(durata: `{fmt_duration(duration)}`)*"
        )
    else:
        t_start = t_end = duration = None
        time_range = "N/A"

    severity_label = (
        "🔴 CRITICA"   if error_events > 0 else
        "🟡 WARNING"   if warning_events > 0 else
        "🟢 INFORMATIVA"
    )

    # Severity score block
    if severity:
        sev_score = severity["score"]
        sev_grade = severity["grade"]
        sc = severity["components"]
        severity_block = (
            f"| **Severity Score** | `{sev_score}/100` — _{sev_grade}_ |\n"
            f"| ↳ Error ratio | `{sc['error_ratio']}/25` |\n"
            f"| ↳ Cascade depth | `{sc['cascade_depth']}/25` |\n"
            f"| ↳ MTTR factor | `{sc['mttr_factor']}/25` |\n"
            f"| ↳ Pattern weight | `{sc['pattern_weight']}/25` |"
        )
    else:
        severity_block = "| **Severity Score** | `N/D` |"

    rc_event        = root_cause["root_event"]
    rc_time         = root_cause["first_error_ts"]
    rc_time_str     = fmt_ts(rc_time)
    rc_level        = rc_event.get("_log_level", "UNKNOWN")
    rc_tags         = root_cause["anomaly_tags"]
    rc_tags_str     = ", ".join(rc_tags) if rc_tags else "—"
    cascade         = root_cause["cascade_count"]
    mttr            = root_cause["mttr"]
    precursors      = root_cause["precursors"]

    rc_raw_fields = {
        k: v for k, v in rc_event.items()
        if not k.startswith("_") and pd.notna(v) and str(v).strip()
    }
    rc_raw = "\n".join(f"  {k}: {str(v)[:200]}" for k, v in rc_raw_fields.items())

    # Collect anomaly tags — split into error-only (for cause list) and all (for actions)
    error_only_tags = list({
        tag
        for _, row in df[df["_is_error"] & ~df["_is_recovery"]].iterrows()
        for tag in row.get("_anomaly_tags", [])
    })
    # Tags for recommended alert patterns — exclude recovery markers
    _recovery_marker_tags = {"service_restart"}
    all_df_tags = list({
        tag
        for tags_list in df["_anomaly_tags"]
        for tag in tags_list
        if tag not in _recovery_marker_tags
    })

    # Timeline table — optionally filtered by --min-level
    min_level = getattr(args, "min_level", None)
    if min_level:
        min_rank = severity_rank(min_level)
        timeline_df = df[df["_log_level"].apply(severity_rank) >= min_rank].copy()
    else:
        timeline_df = df[df["_is_anomaly"]].copy()
    if "_timestamp_parsed" in timeline_df.columns:
        timeline_df = timeline_df.sort_values("_timestamp_parsed")
    timeline_table = _md_table(timeline_df, max_rows=args.max_rows)

    # ASCII event chain — centered on root cause timestamp
    chain_depth = getattr(args, "chain_depth", 12)
    ascii_chain = _build_ascii_chain(df, max_events=chain_depth,
                                     rc_ts=root_cause.get("first_error_ts"))

    # Cause list — use error-only tags to avoid recovery-event pollution
    cause_list = _build_cause_list(rc_tags, error_only_tags, rc_level)

    # Co-occurrence matrix
    cooccurrence_block = build_cooccurrence_summary(df)

    # Error rate chart (per-minute)
    error_rate_chart = build_error_rate_chart(df)

    # Per-sourcetype breakdown and service impact
    sourcetype_block     = build_sourcetype_breakdown(df)
    service_impact_block = build_service_impact(df)
    _worst_svc           = worst_service_status(df)   # clean status for §0 table
    _worst_svc_md        = f"**{_worst_svc}**" if _worst_svc != "OK" else "OK"

    # Top recurring errors
    top_errors_block = build_top_errors(df)

    # Incident trend (escalating / stable / recovering)
    trend_str = compute_trend(df)

    # Pre-compute SPL query (outside f-string for exception safety)
    try:
        spl_query = generate_SIEM_queries(df, args.timestamp_col, flow_key, root_cause, source_file)
    except Exception as e:
        spl_query = f"# Errore generazione query SPL: {e}"

    # Root cause confidence
    rc_confidence = compute_rc_confidence(root_cause)

    # SLA breach check
    sla_grade = severity["grade"] if severity else ""
    sla_breach = detect_sla_breach(mttr, sla_grade)

    # Cross-host cascade correlation
    cross_host_block = detect_cross_host_cascade(df)

    # Response playbook — per-pattern technical remediation steps
    response_playbook = build_response_playbook(error_only_tags)

    # TLDR causa label — pre-computed to avoid fragile f-string expression
    _first_tag = rc_tags[0] if rc_tags else None
    _causa_raw = CAUSE_LABELS.get(_first_tag, "") if _first_tag else ""
    _causa_label = _causa_raw.split("**")[1] if "**" in _causa_raw else "vedere sezione RCA"

    # TLDR alert block for executive readers
    host_count = (
        host_impact[host_impact.columns[0]].nunique()
        if host_impact is not None and not host_impact.empty else "N/A"
    )
    tldr_severity = severity["grade"] if severity else "N/D"
    tldr_lines = [
        f"- **Incidente**: `{error_events}` errori in `{fmt_duration(duration) if duration is not None else 'N/D'}`",
        f"- **Severity**: `{tldr_severity}` ({(severity or {}).get('score', 'N/D')}/100)",
        f"- **Root cause**: `{rc_level}` @ `{rc_time_str}` su `{rc_event.get('host', 'N/A')}`",
        f"- **Causa**: {_causa_label}",
        f"- **Confidenza RCA**: `{rc_confidence['label']}` — {rc_confidence['reason']}",
        f"- **MTTR**: `{fmt_duration(mttr) if mttr else 'non recuperato'}`",
        f"- **Flusso critico**: `{root_cause['flow_key']}`",
        f"- **Host coinvolti**: `{host_count}`",
    ]
    if sla_breach:
        tldr_lines.append(f"- {sla_breach}")
    tldr_block = "\n".join(tldr_lines)

    # MTTR block
    if mttr is not None:
        mttr_line = f"| MTTR (Time to Recover) | `{fmt_duration(mttr)}` |"
    else:
        mttr_line = "| MTTR (Time to Recover) | `N/D — nessun evento di recovery rilevato` |"

    # Cascade summary
    cascade_text = (
        f"Il primo errore ha generato una cascata di **{cascade} eventi di errore** "
        f"nei 5 minuti successivi — indicatore di failure propagation."
        if cascade > 0 else
        "Il primo errore non ha generato cascate significative entro 5 minuti."
    )

    # Precursor section (Italian-correct pluralization)
    if not precursors.empty:
        prec_n = len(precursors)
        prec_label = _plural_it(prec_n, "evento precursore", "eventi precursori")
        prec_table = _md_table(precursors, max_rows=10)
        precursor_block = (
            f"Nei 10 minuti precedenti il primo errore sono stati rilevati "
            f"**{prec_label}** (warning/anomalie):\n\n"
            f"{prec_table}"
        )
    else:
        precursor_block = "_Nessun evento precursore rilevato nei 10 minuti antecedenti._"

    # Burst analysis section (with z-score)
    if bursts:
        burst_rows = "\n".join(
            f"| `{b['start']}` | `{b['end']}` | {b['events']} | {b['errors']} | {b['rate_factor']}x | z={b['z_score']} |"
            for b in bursts
        )
        burst_block = (
            "| Inizio Burst | Fine Burst | # Eventi | # Errori | Moltiplicatore | z-score |\n"
            "|---|---|---|---|---|---|\n"
            f"{burst_rows}"
        )
    else:
        burst_block = "_Nessun burst statisticamente significativo rilevato (soglia: media + 2σ)._"

    # Host impact matrix
    if host_impact is not None and not host_impact.empty:
        host_block = _md_table(host_impact, max_rows=20, inject_ts=False)
    else:
        host_block = "_Host non rilevati (colonna host/hostname assente)._"

    # Log gap section (with gap_factor)
    if log_gaps:
        gap_rows = "\n".join(
            f"| `{g['from']}` | `{g['to']}` | **{g['gap_minutes']} min** | {g.get('gap_factor', 'N/A')}× p75 |"
            for g in log_gaps
        )
        gap_block = (
            "> ⚠️ Gap rilevati nella sequenza dei log — possibile perdita di eventi "
            "(soglia: 75° percentile × 5, minimo 60s).\n\n"
            "| Da | A | Durata Gap | Fattore |\n|---|---|---|---|\n"
            f"{gap_rows}"
        )
    else:
        gap_block = "_Nessun gap significativo rilevato nella sequenza dei log (soglia: 75° percentile × 5, minimo 60s)._"

    # Flow summary table
    if flow_key and flow_key in df.columns:
        flow_summary = df.groupby(flow_key).agg(
            total_events=("_is_anomaly", "count"),
            anomalies=("_is_anomaly", "sum"),
            errors=("_is_error", "sum"),
            warnings=("_is_warning", "sum"),
        ).sort_values("errors", ascending=False).head(15)
        flow_table = _md_table(flow_summary.reset_index(), max_rows=15, inject_ts=False)
    else:
        flow_table = "_Nessuna chiave di flusso rilevata._"

    # Critical flow detail
    flow_detail = _md_table(flow_df.head(25), max_rows=25) if not flow_df.empty else ""

    # Anomaly breakdown
    anomaly_flag_cols = [
        c for c in df.columns
        if c.startswith("_anomaly_") and c != "_anomaly_tags"
    ]
    anomaly_rows = []
    for col in anomaly_flag_cols:
        count = int(df[col].sum())
        if count > 0:
            tag   = col.replace("_anomaly_", "")
            label = tag.replace("_", " ").title()
            desc  = CAUSE_LABELS.get(tag, "").split("**")[1] if tag in CAUSE_LABELS and "**" in CAUSE_LABELS[tag] else ""
            anomaly_rows.append(f"| {label} | {count} | {desc} |")

    anomaly_table = (
        "| Tipo Anomalia | # | Descrizione |\n|---|---|---|\n" +
        "\n".join(anomaly_rows)
    ) if anomaly_rows else "_Nessuna anomalia specifica rilevata._"

    # Recovery timeline block
    if recovery_timeline is not None and not recovery_timeline.empty:
        recovery_block = _md_table(recovery_timeline, max_rows=20, inject_ts=False)
    else:
        recovery_block = "_Nessun evento di recovery rilevato per host specifici._"

    # Network flow matrix
    flow_matrix_block = build_network_flow_matrix(df)

    # Network evidence
    net_label_map = {
        "ipv4":        "IPv4 Addresses",
        "ipv6":        "IPv6 Addresses",
        "port":        "Port References",
        "url":         "URLs Observed",
        "mac":         "MAC Addresses",
        "timeout":     "Timeout / Connection Refused",
        "auth_fail":   "Authentication Failures",
        "dns_error":   "DNS Errors",
        "packet_loss": "Packet Loss / Retransmit",
    }
    net_sections = []
    for key, values in network_evidence.items():
        if values:
            label = net_label_map.get(key, key.replace("_", " ").title())
            items = "\n".join(f"  - `{v}`" for v in values[:30])
            net_sections.append(f"### {label}\n{items}")
    net_block = "\n\n".join(net_sections) if net_sections else "_Nessuna evidenza di rete estratta._"

    # Raw log extracts — sort by severity desc (CRITICAL first), then chronologically
    has_raw_col = "_raw" in df.columns
    raw_errors = (
        df[df["_is_error"]]
        .assign(_sev_rank=df["_log_level"].apply(severity_rank))
        .sort_values(["_sev_rank", "_timestamp_parsed"], ascending=[False, True])
        .head(5)
    )
    raw_log_blocks = []
    for i, (_, row) in enumerate(raw_errors.iterrows(), 1):
        ts_str = fmt_ts(row.get("_timestamp_parsed"))
        lvl    = row.get("_log_level", "?")
        if has_raw_col and pd.notna(row.get("_raw")):
            raw_text = str(row["_raw"])[:500]
            block = f"  [RAW] {raw_text}"
        else:
            fields = {k: v for k, v in row.items()
                      if not k.startswith("_") and pd.notna(v)}
            block  = "\n".join(f"  {k}: {str(v)[:200]}" for k, v in fields.items())
        raw_log_blocks.append(
            f"**Evento Errore #{i}** — `{ts_str}` — `{lvl}`\n```\n{block}\n```"
        )
    raw_logs_section = "\n\n".join(raw_log_blocks) if raw_log_blocks else "_Nessun evento errore trovato._"

    # Executive summary text
    exec_summary_lines = [
        f"L'analisi del log SIEM ha rilevato **{anomaly_events} eventi anomali** "
        f"su **{total_events} totali** nell'intervallo {time_range}."
    ]
    if error_events > 0:
        exec_summary_lines.append(
            f"Identificati **{error_events} eventi ERROR/CRITICAL/FATAL** con "
            f"{'cascata di fallimenti' if cascade > 0 else 'impatto isolato'}."
        )
    if mttr is not None:
        exec_summary_lines.append(f"Il sistema si è ripristinato in **{fmt_duration(mttr)}** dal primo errore.")
    exec_summary_lines.append(
        f"La **root cause** è l'evento `{rc_level}` registrato a `{rc_time_str}` "
        f"su `{rc_event.get('host', 'host sconosciuto')}`, con tags: _{rc_tags_str}_."
    )
    exec_summary = "\n\n".join(exec_summary_lines)

    # Incident narrative prose
    incident_narrative = build_incident_narrative(
        df, root_cause, bursts or [], recovery_timeline, rc_confidence
    )

    dup_note = f" ({duplicate_count} eventi duplicati rilevati)" if duplicate_count > 0 else ""

    # -----------------------------------------------------------------------
    report = f"""# Incident Response Report

---

## Metadati Incident

| Campo | Valore |
|---|---|
| **Incident ID** | `IR-{incident_id}` |
| **Data Analisi** | `{now}` |
| **Sorgente Dati** | `{source_file}` |
| **MD5 Sorgente** | `{file_hash}` |
| **SHA-256 Sorgente** | `{sha256}` |
| **Analista** | Script Automatico — scoobyLog v{VERSION} |
| **Classificazione** | {severity_label} |
{severity_block}

---

> ### ⚡ TLDR — Sintesi Operativa
>
{chr(10).join("> " + line for line in tldr_block.splitlines())}

---

## 0. Quick Reference — Dati per il Ticket

> Copiare questa tabella direttamente nel ticket o nell'alert.

| Campo | Valore |
|---|---|
| **Incident ID** | `IR-{incident_id}` |
| **Severity** | `{tldr_severity}` ({(severity or {}).get('score', 'N/D')}/100) |
| **Classificazione** | {severity_label} |
| **Root Cause** | `{rc_level}` @ `{rc_time_str}` su `{rc_event.get('host', 'N/A')}` |
| **Causa** | {_causa_label} |
| **MTTR** | `{fmt_duration(mttr) if mttr else 'non recuperato'}` |
| **Trend** | {trend_str} |
| **Service Impact** | {_worst_svc_md} |
| **Host impattati** | `{host_count}` |
| **Errori totali** | `{error_events}` |
| **Cascata** | `{cascade}` errori downstream |
| **Confidenza RCA** | `{rc_confidence['label']}` — {rc_confidence['reason']} |
| **Flusso critico** | `{root_cause['flow_key']}` |
| **Analizzato da** | scoobyLog v{VERSION} |
{f"| **SLA** | {sla_breach} |" if sla_breach else ""}

---

## 1. Executive Summary

{exec_summary}

### 1.1 Narrazione dell'Incidente

{incident_narrative}

---

## 2. Statistiche Generali

| Metrica | Valore |
|---|---|
| Totale eventi analizzati | `{total_events}`{dup_note} |
| Intervallo temporale | {time_range} |
| Flussi/sessioni unici (`{flow_key or "N/A"}`) | `{unique_flows}` |
| Host coinvolti | `{host_count}` |
| Eventi ERROR/CRITICAL/FATAL | `{error_events}` |
| Eventi WARNING | `{warning_events}` |
| Totale anomalie rilevate | `{anomaly_events}` |
| Percentuale eventi anomali | `{100 * anomaly_events / total_events:.1f}%` |
{mttr_line}
| Trend incidente | {trend_str} |

### 2.1 Impatto per Servizio / Sourcetype

{service_impact_block}

---

## 3. Timeline degli Eventi

> La tabella mostra gli eventi anomali in ordine cronologico con timestamp espliciti.

{timeline_table if not timeline_df.empty else "_Nessun evento anomalo rilevato._"}

### 3.1 Catena di Evento (ASCII)

{ascii_chain}

### 3.2 Grafico Densità Eventi (per minuto)

> `█` = minuto con errori &nbsp; `▒` = minuto senza errori &nbsp; ◉ = errori presenti

{error_rate_chart}

### 3.3 Analisi Burst (picchi statistici)

{burst_block}

---

## 4. Analisi Precursori

{precursor_block}

---

## 5. Analisi per Flusso / Chiave Univoca

**Chiave di flusso rilevata**: `{flow_key or "N/A"}`

Flussi ordinati per numero di errori:

{flow_table}

### 5.1 Flusso più critico — `{root_cause['flow_key']}`

{flow_detail}

---

## 6. Impatto per Host

{host_block}

---

## 7. Recovery Timeline per Host

> Mostra quando ogni host ha rilevato il primo errore e il primo evento di recovery,
> con il tempo di downtime calcolato automaticamente.

{recovery_block}

---

## 8. Breakdown Anomalie e Co-occorrenze

{anomaly_table}

### 8.1 Co-occorrenza Pattern

{cooccurrence_block}

### 8.2 Breakdown per Sourcetype

{sourcetype_block}

### 8.3 Errori Ricorrenti (top 5)

{top_errors_block}

---

## 9. Integrità Log — Gap Analysis

{gap_block}

---

## 10. Matrice Flussi di Rete (src → dst)

{flow_matrix_block}

---

## 11. Evidenze di Rete

{net_block}

---

## 12. Estratti Log Raw

Gli estratti seguenti sono i log originali non modificati degli eventi di errore:

{raw_logs_section}

---

## 13. Root Cause Analysis (RCA)

### 13.1 Evento Root Cause

```
Timestamp   : {rc_time_str}
Livello     : {rc_level}
Flusso      : {root_cause['flow_key']}
Tags        : {rc_tags_str}
Cascade     : {cascade} errori successivi entro 5 minuti
MTTR        : {fmt_duration(mttr) if mttr else "N/D"}
Confidenza  : {rc_confidence['label']} — {rc_confidence['reason']}

--- Campi evento ---
{rc_raw}
```

{f"> {sla_breach}" if sla_breach else ""}

### 13.2 Catena Causale

{cascade_text}

### 13.3 Correlazione Cross-Host

> Errori su host diversi rilevati entro 2 secondi l'uno dall'altro — indica propagazione sincrona.

{cross_host_block}

### 13.4 Causa Radice Determinata

Basandosi sull'analisi automatica dei pattern, le cause radice identificate sono:

{cause_list}

> **Conclusione tecnica**: L'evento iniziale a `{rc_time_str}` su `{rc_event.get('host', 'N/A')}` ha
> innescato la sequenza di fallimenti documentata. Confidenza RCA: **{rc_confidence['label']}**.
> Il documento costituisce evidenza tecnica per il ticket.
>
> Riferimento univoco: **IR-{incident_id}** — generato `{now}`

---

## 14. Azioni Raccomandate

1. **Immediato** — Verificare lo stato del servizio/host nel flusso `{root_cause['flow_key']}`.
2. **Breve termine** — Analizzare i log di sistema intorno a `{rc_time_str}` ±10 minuti.
3. **Investigazione** — Correlare con metriche infrastrutturali (CPU, RAM, rete, IOPS) per lo stesso periodo.
4. **Prevenzione** — Aggiornare le soglie di alerting SIEM per i pattern: _{", ".join(all_df_tags[:5]) or "N/A"}_.
5. **Post-mortem** — Documentare la catena causale e validare il runbook di risposta.
{"6. **Integrità log** — Verificare la perdita di eventi nei gap rilevati." if log_gaps else ""}

### 14.1 Playbook Tecnico di Risposta

{response_playbook}

---

## 15. Appendice Tecnica

### 15.1 Colonne CSV Analizzate

```
{chr(10).join("  - " + c for c in df.columns if not c.startswith("_"))}
```

### 15.2 Parametri di Analisi

| Parametro | Valore |
|---|---|
| File sorgente | `{source_file}` |
| Hash file | `{file_hash}` |
| Colonna timestamp | `{args.timestamp_col or "auto-rilevata"}` |
| Colonna log level | `{args.level_col or "auto-rilevata"}` |
| Chiave flusso | `{flow_key or "auto-rilevata"}` |
| Valore flusso target | `{args.flow_value or "auto-selezionato (più critico)"}` |
| Campo _raw SIEM | `{"presente" if has_raw_col else "assente — campi strutturati usati"}` |
| Versione script | `{VERSION}` |
| SHA-256 file sorgente | `{sha256}` |

### 15.3 SIEM SPL — Query di Riproduzione

Tre query mirate per la verifica rapida dell'incidente in SIEM:

{spl_query}

> **Chain of custody**: Il file analizzato (`{source_file}`) ha hash SHA-256 `{sha256}`.
> Il report è stato generato in modo deterministico e riproducibile. Incident ID: **IR-{incident_id}**.

---

*Report generato automaticamente da `scoobylog.py` v{VERSION}*
*Incident Reference: **IR-{incident_id}** — {now}*
"""
    return report


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

RAW_LOG_REGEX = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,.]\d{3,6})\s+'
    r'(?P<level>CRITICAL|FATAL|ERROR|ERR|WARN(?:ING)?|NOTICE|INFO|DEBUG|TRACE)\s+'
    r'(?P<logger>\[[^\]]+\])?\s*'
    r'(?P<thread>\([^)]+\))?\s*'
    r'(?P<message>.*)$',
    re.IGNORECASE
)


def looks_like_raw_log(text: str) -> bool:
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        return RAW_LOG_REGEX.match(line) is not None
    return False


def parse_raw_log_text(text: str, source_file: str = "raw-log") -> pd.DataFrame:
    rows = []

    for line in text.splitlines():
        if not line.strip():
            continue

        match = RAW_LOG_REGEX.match(line)

        if match:
            data = match.groupdict()

            level = data["level"].upper()
            if level == "ERR":
                level = "ERROR"
            if level == "WARN":
                level = "WARNING"

            rows.append({
                "timestamp": data["timestamp"],
                "log_level": level,
                "logger": (data.get("logger") or "").strip("[]"),
                "thread": (data.get("thread") or "").strip("()"),
                "message": data.get("message") or "",
                "source": source_file,
                "_raw": line,
            })

        else:
            # Gestisce righe multilinea tipo stack trace:
            # se una riga non inizia con timestamp, la accoda al messaggio precedente.
            if rows:
                rows[-1]["message"] += "\n" + line
                rows[-1]["_raw"] += "\n" + line
            else:
                rows.append({
                    "timestamp": None,
                    "log_level": "UNKNOWN",
                    "logger": "",
                    "thread": "",
                    "message": line,
                    "source": source_file,
                    "_raw": line,
                })

    return pd.DataFrame(rows)

def load_csv(path: str, encoding: str = "utf-8", quiet: bool = False) -> pd.DataFrame:
    def _log(msg: str) -> None:
        if not quiet:
            print(msg)

    encodings = (encoding, "utf-8-sig", "latin-1", "cp1252")

    def _decode_bytes(raw: bytes):
        for enc in encodings:
            try:
                return raw.decode(enc), enc
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="replace"), "utf-8-replace"

    # stdin: può essere CSV oppure raw log
    if path == "-":
        try:
            import io
            raw = sys.stdin.buffer.read()
            text, used_enc = _decode_bytes(raw)

            if looks_like_raw_log(text):
                df = parse_raw_log_text(text, source_file="stdin")
                _log(f"[+] Log raw caricato da stdin: {len(df)} righe (encoding: {used_enc})")
                return df

            for enc in encodings:
                try:
                    df = pd.read_csv(io.BytesIO(raw), encoding=enc, low_memory=False)
                    _log(f"[+] CSV caricato da stdin: {len(df)} righe, {len(df.columns)} colonne (encoding: {enc})")
                    return df
                except UnicodeDecodeError:
                    continue

            print("[!] Impossibile decodificare stdin.", file=sys.stderr)
            sys.exit(1)

        except Exception as e:
            print(f"[!] Errore lettura stdin: {e}", file=sys.stderr)
            sys.exit(1)

    # file normale: può essere CSV, .log, oppure senza estensione
    try:
        raw = Path(path).read_bytes()
        text, used_enc = _decode_bytes(raw)

        if looks_like_raw_log(text):
            df = parse_raw_log_text(text, source_file=str(path))
            _log(f"[+] Log raw caricato: {len(df)} righe (encoding: {used_enc})")
            return df

    except Exception as e:
        print(f"[!] Errore lettura file: {e}", file=sys.stderr)
        sys.exit(1)

    # fallback: comportamento CSV attuale
    for enc in encodings:
        try:
            df = pd.read_csv(path, encoding=enc, low_memory=False)
            _log(f"[+] CSV caricato: {len(df)} righe, {len(df.columns)} colonne (encoding: {enc})")
            return df
        except UnicodeDecodeError:
            continue
        except Exception as e:
            print(f"[!] Errore caricamento CSV/log: {e}", file=sys.stderr)
            sys.exit(1)

    print("[!] Impossibile determinare l'encoding del file.", file=sys.stderr)
    sys.exit(1)

def detect_timestamp_col(df: pd.DataFrame) -> Optional[str]:
    for c in TIMESTAMP_CANDIDATES:
        if c in df.columns:
            return c
    cols_lower = {c.lower(): c for c in df.columns}
    for c in TIMESTAMP_CANDIDATES:
        if c.lower() in cols_lower:
            return cols_lower[c.lower()]
    return None


def detect_level_col(df: pd.DataFrame) -> Optional[str]:
    for candidate in ("log_level", "level", "severity", "loglevel", "log level", "priority"):
        if candidate in df.columns:
            return candidate
        for col in df.columns:
            if col.lower() == candidate:
                return col
    return None


# ---------------------------------------------------------------------------
# OPTIONAL LOCAL AI RCA LAYER  (Ollama-compatible, offline, deterministic)
# ---------------------------------------------------------------------------
# This layer is OFF by default. With --local-ai it sends the deterministic
# evidence already computed by scoobyLog (root cause, MTTR, severity, network
# evidence, cascade, hosts, recovery) plus a short, sanitized timeline/raw
# excerpt to a *local* LLM served by an Ollama-compatible endpoint
# (default http://localhost:11434/api/generate) and asks it to write a senior
# SRE review. Everything stays offline: no cloud calls, no paid API.
#
# The model only reorganizes facts scoobyLog already proved; it is explicitly
# instructed not to invent timestamps, IPs, hostnames or error codes, which
# keeps hallucinations out. Every failure mode (endpoint down, timeout,
# malformed/incomplete JSON, invalid schema, non-local endpoint, --local-ai
# absent) degrades gracefully (status="error") and never affects the
# deterministic report.

import json as _json
import ipaddress as _ipaddress
import urllib.request as _urlreq
import urllib.error as _urlerr
from collections import Counter as _Counter
from urllib.parse import urlparse as _urlparse

LOCAL_AI_DEFAULT_ENDPOINT    = "http://localhost:11434/api/generate"
LOCAL_AI_DEFAULT_MODEL       = "llama3.1:8b"   # alt: mistral:7b
LOCAL_AI_DEFAULT_TIMEOUT     = 300             # seconds (local models can be slow)
LOCAL_AI_DEFAULT_MAX_EVENTS  = 30              # timeline rows sent as context
LOCAL_AI_RAW_EXTRACTS        = 5               # raw error rows sent as context
LOCAL_AI_TEMPERATURE         = 0.1             # low → deterministic
LOCAL_AI_MSG_MAXLEN          = 500             # truncate each log message
LOCAL_AI_PROVIDER            = "ollama-compatible"

# Keys the model MUST return. Used both in the prompt and for schema validation.
LOCAL_AI_REQUIRED_KEYS = (
    "root_cause_probabile",
    "confidenza",
    "motivazione",
    "cause_alternative",
    "evidenze_chiave",
    "evidenze_deboli",
    "evidenze_mancanti",
    "prossimi_controlli",
    "rischio_falso_positivo",
    "raccomandazione_operativa",
)

# Strict senior-analyst contract. Italian, to match the report language.
LOCAL_AI_SYSTEM_PROMPT = (
    "Sei un Senior Network Systems Administrator e SRE incaricato della Root "
    "Cause Analysis di un incidente di produzione. Ricevi evidenze "
    "deterministiche già estratte da uno strumento di analisi log e un breve "
    "estratto di timeline; non hai altro contesto.\n"
    "REGOLE TASSATIVE:\n"
    "1. Usa esclusivamente le evidenze fornite. Non inventare nulla.\n"
    "2. Non inventare servizi, timestamp, indirizzi IP, hostname, codici di "
    "errore o valori numerici. Se un dato non è presente, dichiaralo mancante.\n"
    "3. Evita allucinazioni: se le evidenze non bastano per concludere, "
    "indicalo in 'evidenze_mancanti' e abbassa la 'confidenza'.\n"
    "4. Tono tecnico, sintetico, da analista senior. Rispondi in italiano.\n"
    "5. Restituisci ESCLUSIVAMENTE un oggetto JSON valido, senza testo extra e "
    "senza markdown, con ESATTAMENTE queste chiavi:\n"
    "   - \"root_cause_probabile\": string\n"
    "   - \"confidenza\": string (\"ALTA\" | \"MEDIA\" | \"BASSA\")\n"
    "   - \"motivazione\": string\n"
    "   - \"cause_alternative\": array di string\n"
    "   - \"evidenze_chiave\": array di string\n"
    "   - \"evidenze_deboli\": array di string\n"
    "   - \"evidenze_mancanti\": array di string\n"
    "   - \"prossimi_controlli\": array di string\n"
    "   - \"rischio_falso_positivo\": string (\"BASSO\" | \"MEDIO\" | \"ALTO\")\n"
    "   - \"raccomandazione_operativa\": string\n"
)


def _local_ai_endpoint_is_local(endpoint: str) -> bool:
    """True if the endpoint host is loopback, link-local, *.local or RFC1918
    private — the only destinations allowed when --local-ai-strict-local is on
    (the default). Keeps evidence from ever leaving the machine/LAN."""
    try:
        host = (_urlparse(endpoint).hostname or "").strip().lower()
    except Exception:
        return False
    if not host:
        return False
    if host == "localhost" or host.endswith(".local"):
        return True
    try:
        ip = _ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


# Public alias matching the name suggested in the spec.
is_local_endpoint = _local_ai_endpoint_is_local


def _local_ai_truncate(text, limit=LOCAL_AI_MSG_MAXLEN):
    text = "" if text is None else str(text)
    return text if len(text) <= limit else text[:limit] + "…[troncato]"


def _local_ai_row_text(row, df_columns):
    parts = []
    for col in df_columns:
        if col.startswith("_"):
            continue
        val = row.get(col)
        if val is None:
            continue
        sval = str(val)
        if sval and sval.lower() != "nan":
            parts.append(f"{col}={sval}")
    return _local_ai_truncate(" | ".join(parts))


def build_local_ai_context(df, deterministic, *,
                           max_events=LOCAL_AI_DEFAULT_MAX_EVENTS,
                           sanitize=True):
    """Merge the deterministic evidence dict with a short timeline excerpt and
    raw error extracts into the model's complete context. Only proven facts go
    in; the raw CSV is never sent wholesale. When sanitize=True, free-text log
    messages are scrubbed of IPs/UUIDs/session IDs/emails (anonymize_report)."""
    context = dict(deterministic)

    # Timeline excerpt: prioritize errors/criticals, capped at max_events.
    timeline = []
    raw_extracts = []
    try:
        _err_df = df[df["_is_error"]] if "_is_error" in df.columns else df
        if _err_df.empty:
            _err_df = df
        for _, row in _err_df.head(max_events).iterrows():
            timeline.append({
                "ts":    fmt_ts(row.get("_timestamp_parsed")),
                "level": row.get("_log_level", "N/D"),
                "tags":  list(row.get("_anomaly_tags", []) or []),
                "raw":   _local_ai_row_text(row, df.columns),
            })
        for _, row in _err_df.head(LOCAL_AI_RAW_EXTRACTS).iterrows():
            raw_extracts.append(_local_ai_row_text(row, df.columns))
    except Exception:
        timeline, raw_extracts = [], []

    context["timeline_excerpt"]  = timeline
    context["raw_error_extracts"] = raw_extracts

    if sanitize:
        try:
            for ev in context["timeline_excerpt"]:
                ev["raw"] = anonymize_report(ev["raw"])
            context["raw_error_extracts"] = [
                anonymize_report(x) for x in context["raw_error_extracts"]
            ]
            if isinstance(context.get("network_evidence"), dict):
                context["network_evidence"] = {
                    k: [anonymize_report(str(x)) for x in v]
                    for k, v in context["network_evidence"].items()
                }
        except Exception:
            pass

    return context


def top_recurring_errors(df, top=5):
    """Most frequent anomaly tags on error rows (deterministic)."""
    try:
        c = _Counter(
            tag
            for _, row in df[df["_is_error"]].iterrows()
            for tag in (row.get("_anomaly_tags", []) or [])
        )
        return [{"tag": t, "count": n} for t, n in c.most_common(top)]
    except Exception:
        return []


def validate_local_ai_result(analysis):
    """Return (ok, missing_keys). The model output must be a dict containing
    every required key. Used to reject malformed schemas deterministically."""
    if not isinstance(analysis, dict):
        return False, list(LOCAL_AI_REQUIRED_KEYS)
    missing = [k for k in LOCAL_AI_REQUIRED_KEYS if k not in analysis]
    return (len(missing) == 0), missing


def local_ai_rca(context, *, endpoint=LOCAL_AI_DEFAULT_ENDPOINT,
                 model=LOCAL_AI_DEFAULT_MODEL,
                 timeout=LOCAL_AI_DEFAULT_TIMEOUT,
                 temperature=LOCAL_AI_TEMPERATURE,
                 strict_local=True):
    """Call a local Ollama-compatible endpoint for an AI-assisted RCA review.

    ALWAYS returns a dict with a "status" key ("ok" | "error"); never raises.
    Any failure (non-local endpoint under strict mode, endpoint down, timeout,
    malformed/incomplete JSON, invalid schema) is reported as status="error"
    with "error" set, leaving the deterministic pipeline untouched.
    """
    base = {
        "enabled":      True,
        "provider":     LOCAL_AI_PROVIDER,
        "model":        model,
        "endpoint":     endpoint,
        "status":       "error",
        "error":        None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    if strict_local and not _local_ai_endpoint_is_local(endpoint):
        base["error"] = (
            "Endpoint non locale rifiutato da --local-ai-strict-local. "
            "Usa un endpoint loopback/RFC1918 oppure --local-ai-no-strict-local."
        )
        return base

    user_prompt = (
        "Evidenze deterministiche ed estratto di timeline dell'incidente (JSON):\n"
        + _json.dumps(context, indent=2, ensure_ascii=False, default=str)
        + "\n\nProduci la RCA come JSON secondo il contratto."
    )
    payload = {
        "model":   model,
        "prompt":  user_prompt,
        "system":  LOCAL_AI_SYSTEM_PROMPT,
        "stream":  False,
        "format":  "json",
        "options": {"temperature": temperature},
    }

    try:
        req = _urlreq.Request(
            endpoint,
            data=_json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "User-Agent": f"scoobyLog/{VERSION}"},
            method="POST",
        )
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except _urlerr.HTTPError as e:
        # e.g. Ollama 404 when the model isn't installed
        _detail = ""
        try:
            _detail = e.read().decode("utf-8", errors="replace")[:LOCAL_AI_MSG_MAXLEN]
        except Exception:
            pass
        base["error"] = (f"HTTP {e.code} dall'endpoint. "
                         f"Il modello '{model}' potrebbe non essere installato "
                         f"(`ollama pull {model}`). {_detail}".strip())
        return base
    except _urlerr.URLError as e:
        reason = getattr(e, "reason", e)
        base["error"] = (f"Endpoint non raggiungibile ({reason}). "
                         f"Avvia Ollama e scarica il modello: `ollama run {model}`.")
        return base
    except Exception as e:  # pragma: no cover - defensive catch-all
        base["error"] = f"Chiamata fallita: {e}"
        return base

    try:
        outer = _json.loads(raw)
    except Exception:
        base["error"] = "Risposta non-JSON dall'endpoint."
        base["raw"] = raw[:LOCAL_AI_MSG_MAXLEN]
        return base

    inner_text = outer.get("response", "") if isinstance(outer, dict) else ""
    if not inner_text:
        base["error"] = "Risposta vuota dal modello."
        return base

    try:
        analysis = _json.loads(inner_text)
    except Exception:
        analysis = _local_ai_salvage_json(inner_text)
        if analysis is None:
            base["error"] = "JSON del modello incompleto o non valido."
            base["raw"] = inner_text[:LOCAL_AI_MSG_MAXLEN]
            return base

    ok, missing = validate_local_ai_result(analysis)
    if not ok:
        base["error"] = f"Schema non valido: chiavi mancanti {missing}."
        base["raw"] = inner_text[:LOCAL_AI_MSG_MAXLEN]
        return base

    base["status"]   = "ok"
    base["analysis"] = analysis
    return base


def _local_ai_salvage_json(text):
    """Best-effort recovery of a JSON object from a truncated/noisy model
    response. Deterministic; no model involved. Returns dict or None."""
    start = text.find("{")
    if start == -1:
        return None
    end = text.rfind("}")
    while end > start:
        try:
            return _json.loads(text[start:end + 1])
        except Exception:
            end = text.rfind("}", start, end)
    return None


def local_ai_summary_block(ai_result):
    """Compact block for the --json-summary (full detail lives in the separate
    IR-<hash>_local_ai.json file referenced by result_path)."""
    if ai_result is None:
        return {"enabled": False, "status": "disabled"}
    return {
        "enabled":     ai_result.get("enabled", True),
        "provider":    ai_result.get("provider"),
        "model":       ai_result.get("model"),
        "endpoint":    ai_result.get("endpoint"),
        "status":      ai_result.get("status"),
        "error":       ai_result.get("error"),
        "result_path": ai_result.get("result_path"),
    }


def render_local_ai_section(ai_result):
    """Render the AI review as a Markdown report section (§13.5). Works for both
    ok and error results so the report always documents what happened."""
    lines = ["## 13.5 AI Local RCA Review (sperimentale)", ""]
    lines.append(
        f"> Provider: `{ai_result.get('provider', 'N/D')}` · "
        f"Modello: `{ai_result.get('model', 'N/D')}` · "
        f"Endpoint: `{ai_result.get('endpoint', 'N/D')}` · "
        f"Stato: **{ai_result.get('status', 'N/D')}**"
    )
    lines.append("")
    if ai_result.get("status") != "ok":
        lines.append(f"⚠️ **Local AI RCA non disponibile**: {ai_result.get('error', 'errore sconosciuto')}")
        lines.append("")
        lines.append("> L'analisi deterministica soprastante non è influenzata.")
        lines.append("")
        return "\n".join(lines)

    an = ai_result.get("analysis", {}) or {}

    def _bullets(key, title):
        vals = an.get(key) or []
        if not isinstance(vals, list):
            vals = [vals]
        vals = [str(v) for v in vals if str(v).strip()]
        if not vals:
            return []
        out = [f"**{title}:**", ""]
        out += [f"- {v}" for v in vals]
        out.append("")
        return out

    lines.append(f"**Root cause probabile:** {an.get('root_cause_probabile', 'N/D')}")
    lines.append("")
    lines.append(f"**Confidenza:** {an.get('confidenza', 'N/D')}  ·  "
                 f"**Rischio falso positivo:** {an.get('rischio_falso_positivo', 'N/D')}")
    lines.append("")
    if an.get("motivazione"):
        lines.append(f"**Motivazione:** {an['motivazione']}")
        lines.append("")
    lines += _bullets("cause_alternative", "Cause alternative")
    lines += _bullets("evidenze_chiave", "Evidenze chiave")
    lines += _bullets("evidenze_deboli", "Evidenze deboli")
    lines += _bullets("evidenze_mancanti", "Evidenze mancanti")
    lines += _bullets("prossimi_controlli", "Prossimi controlli")
    if an.get("raccomandazione_operativa"):
        lines.append(f"**Raccomandazione operativa:** {an['raccomandazione_operativa']}")
        lines.append("")
    lines.append("> ⚠️ Analisi generata da modello locale; usare come supporto, "
                 "non come fonte unica. Verificare sempre contro le evidenze "
                 "deterministiche.")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description=f"scoobyLog — SIEM Incident Analyzer v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scoobylog.py logs.csv                          # drag & drop / positional
  python scoobylog.py --input -                         # read CSV from stdin (pipe)
  python scoobylog.py --input logs.csv
  python scoobylog.py --input logs.csv --format html --open
  python scoobylog.py --input logs.csv --patterns-file custom.json
  python scoobylog.py --input logs.csv --json-summary --output-dir /tmp/reports/
  python scoobylog.py --input logs.csv --since 2024-03-15T08:00:00Z --until 2024-03-15T09:00:00Z
  python scoobylog.py --input logs.csv --min-level ERROR --chain-depth 20
  python scoobylog.py --input logs.csv --flow-key session_id --flow-value sess-abc123
  python scoobylog.py --input logs.csv --no-flow --quiet --json-summary
  python scoobylog.py --input logs.csv --summary        # TLDR to stdout, no file written
  python scoobylog.py --input logs.csv --no-report --export-csv enriched.csv --json-summary
""",
    )
    # Positional argument — enables drag & drop: `python scoobylog.py /dragged/path.csv`
    # On macOS/Linux terminals, dragging a file inserts its path; this catches that pattern.
    parser.add_argument("input_file", nargs="?", default=None,
                        metavar="CSV_FILE",
                        help="Input CSV file (positional shortcut for --input, supports drag & drop)")
    parser.add_argument("--input",         "-i", required=False, default=None,
                        help="Path to SIEM CSV export (use --input or the positional argument)")
    parser.add_argument("--output",        "-o", default=None)
    parser.add_argument("--output-dir",          default=None,
                        help="Directory for all output files (overrides --output location)")
    parser.add_argument("--timestamp-col",       default=None)
    parser.add_argument("--level-col",           default=None)
    parser.add_argument("--flow-key",            default=None)
    parser.add_argument("--flow-value",          default=None)
    parser.add_argument("--no-flow",             action="store_true",
                        help="Disable flow isolation (treat all events as a single flow)")
    parser.add_argument("--encoding",            default="utf-8")
    parser.add_argument("--max-rows",      type=int, default=30)
    parser.add_argument("--chain-depth",   type=int, default=12,
                        help="Max events in the ASCII chain diagram (default: 12)")
    parser.add_argument("--since",         default=None,
                        help="Discard events before this ISO 8601 timestamp (e.g. 2024-03-15T08:00:00Z)")
    parser.add_argument("--until",         default=None,
                        help="Discard events after this ISO 8601 timestamp")
    parser.add_argument("--min-level",     default=None,
                        choices=["DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL"],
                        help="Minimum log level to include in the timeline table (default: all anomalies)")
    parser.add_argument("--json-summary",  action="store_true",
                        help="Write IR-<hash>.json summary alongside the Markdown report")
    parser.add_argument("--export-csv",    default=None,
                        metavar="PATH",
                        help="Export enriched DataFrame (with _log_level, _anomaly_tags, etc.) to CSV")
    parser.add_argument("--max-events",     type=int, default=None,
                        metavar="N",
                        help="Process only the first N events after sorting (fast triage of large CSVs)")
    parser.add_argument("--alert-webhook",   default=None,
                        metavar="URL",
                        help="POST JSON summary to this webhook URL (Slack, PagerDuty, Opsgenie, Teams, custom)")
    parser.add_argument("--patterns-file",   default=None,
                        metavar="PATH",
                        help="JSON file with custom detection patterns to extend built-in rules")
    parser.add_argument("--anonymize",       action="store_true",
                        help="Pseudonymize IPs, session IDs, UUIDs and emails in the report for safe sharing")
    parser.add_argument("--format",         default="html", choices=["md", "html"],
                        help="Output format: html (self-contained HTML, default) or md (Markdown)")
    parser.add_argument("--open",           action="store_true",
                        help="Open the report in the default browser after generation (useful with --format html)")
    parser.add_argument("--no-report",     action="store_true",
                        help="Skip Markdown report generation (useful with --json-summary or --export-csv alone)")
    parser.add_argument("--summary",       action="store_true",
                        help="Print TLDR executive summary to stdout and exit (no report written)")
    parser.add_argument("--quiet", "-q",   action="store_true",
                        help="Suppress progress output (errors still printed to stderr)")
    # Optional local AI RCA layer (Ollama-compatible, offline, off by default)
    parser.add_argument("--local-ai",            action="store_true",
                        dest="local_ai",
                        help="Enable optional local AI RCA via an Ollama-compatible endpoint (offline, off by default)")
    parser.add_argument("--local-ai-endpoint",   default=LOCAL_AI_DEFAULT_ENDPOINT,
                        dest="local_ai_endpoint", metavar="URL",
                        help=f"Local LLM endpoint (default: {LOCAL_AI_DEFAULT_ENDPOINT})")
    parser.add_argument("--local-ai-model",      default=LOCAL_AI_DEFAULT_MODEL,
                        dest="local_ai_model", metavar="NAME",
                        help=f"Local model name, e.g. llama3.1:8b or mistral:7b (default: {LOCAL_AI_DEFAULT_MODEL})")
    parser.add_argument("--local-ai-timeout",    type=int, default=LOCAL_AI_DEFAULT_TIMEOUT,
                        dest="local_ai_timeout", metavar="SEC",
                        help=f"AI request timeout in seconds (default: {LOCAL_AI_DEFAULT_TIMEOUT})")
    parser.add_argument("--local-ai-max-events", type=int, default=LOCAL_AI_DEFAULT_MAX_EVENTS,
                        dest="local_ai_max_events", metavar="N",
                        help=f"Max timeline events sent to the model as context (default: {LOCAL_AI_DEFAULT_MAX_EVENTS})")
    # strict-local on by default; --local-ai-no-strict-local disables it (3.8-safe)
    parser.add_argument("--local-ai-strict-local",    action="store_true",
                        dest="local_ai_strict_local", default=True,
                        help="Refuse non-local endpoints (loopback/RFC1918 only). Default: on")
    parser.add_argument("--local-ai-no-strict-local", action="store_false",
                        dest="local_ai_strict_local",
                        help="Allow a non-local AI endpoint (disables the strict-local guard)")
    parser.add_argument("--local-ai-raw",        action="store_true",
                        dest="local_ai_raw", default=False,
                        help="Send raw (un-sanitized) log text to the model. Default: off (IP/UUID/session/email scrubbed)")
    parser.add_argument("--version",       action="version", version=f"scoobylog {VERSION}")
    args = parser.parse_args()

    # Resolve input: positional drag-and-drop path takes precedence if --input is not set.
    # Strip surrounding quotes that some terminals/shells inject on drag.
    _raw_input = args.input or args.input_file
    if _raw_input is None:
        if getattr(sys, "frozen", False) or sys.stdin.isatty():
            # No file was dragged onto the .exe / no arg passed — ask interactively
            # instead of parser.error(), which would print usage and exit before
            # the user (double-clicking the packaged .exe) can read anything.
            print()
            print("[!] Nessun file di log trovato.")
            print("    Trascina un file CSV sull'eseguibile, oppure inserisci qui sotto il percorso completo.")
            print()
            try:
                _raw_input = input("Percorso file CSV: ").strip()
            except (EOFError, KeyboardInterrupt):
                _raw_input = ""
            if not _raw_input:
                print("\n[!] Nessun percorso inserito. Uscita.", file=sys.stderr)
                sys.exit(1)
        else:
            parser.error("Specificare il file CSV come argomento posizionale o con --input")
    args.input = _raw_input.strip().strip("'\"")

    def log(msg: str) -> None:
        if not args.quiet and not getattr(args, "summary", False):
            print(msg)

    # Load custom patterns from --patterns-file (JSON) before any analysis
    if getattr(args, "patterns_file", None):
        import json as _json
        try:
            _pf = _json.loads(Path(args.patterns_file).read_text(encoding="utf-8"))
            _custom_patterns = _pf.get("patterns", {})
            for _name, _regex in _custom_patterns.items():
                ANOMALY_PATTERNS[_name] = re.compile(_regex, re.IGNORECASE)
            CAUSE_LABELS.update(_pf.get("labels", {}))
            REMEDIATION_STEPS.update(_pf.get("remediation", {}))
            _n = len(_custom_patterns)
            print(f"[+] Pattern personalizzati caricati: {_n} da {args.patterns_file}")
        except Exception as _e:
            print(f"[!] Errore caricamento --patterns-file: {_e}", file=sys.stderr)
            sys.exit(1)

    _stdin_mode = (args.input == "-")
    if _stdin_mode:
        input_path = Path("stdin")
    else:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"[!] File non trovato: {args.input}", file=sys.stderr)
            sys.exit(1)

    if args.output_dir:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = None

    _fmt = getattr(args, "format", "md")
    _ext = ".html" if _fmt == "html" else ".md"
    if args.output:
        output_path = Path(args.output)
        # Honour explicit extension; otherwise force to match --format
        if output_path.suffix.lower() not in (".md", ".html"):
            output_path = output_path.with_suffix(_ext)
        if out_dir:
            output_path = out_dir / output_path.name
    elif _stdin_mode:
        # stdin has no natural stem — use timestamp so concurrent runs don't collide
        _ts_now = datetime.now().strftime("%Y%m%dT%H%M%S")
        stem = f"stdin_incident_report_{_ts_now}{_ext}"
        output_path = out_dir / stem if out_dir else Path(stem)
    else:
        stem = f"{input_path.stem}_incident_report{_ext}"
        output_path = out_dir / stem if out_dir else input_path.parent / stem

    log(f"[*] scoobyLog v{VERSION}")
    log(f"[*] Input : {input_path}")
    log(f"[*] Output: {output_path}")
    log("")

    df = load_csv(args.input, encoding=args.encoding,
                  quiet=args.quiet or getattr(args, "summary", False))

    if df.empty:
        print("[!] CSV vuoto — nessun dato da analizzare.", file=sys.stderr)
        sys.exit(1)

    ts_col = args.timestamp_col or detect_timestamp_col(df)
    if ts_col and ts_col in df.columns:
        log(f"[+] Colonna timestamp : '{ts_col}'")
        df["_timestamp_parsed"] = parse_timestamp_series(df[ts_col])
        ok = df["_timestamp_parsed"].notna().sum()
        log(f"[+] Timestamp parsati : {ok}/{len(df)}")
        df = df.sort_values("_timestamp_parsed").reset_index(drop=True)
        log("[+] Ordinato cronologicamente")
        # Apply --since / --until time range filter
        if args.since:
            try:
                since_ts = pd.to_datetime(args.since, utc=True)
                before   = len(df)
                df = df[df["_timestamp_parsed"] >= since_ts].reset_index(drop=True)
                log(f"[+] --since {args.since}: rimossi {before - len(df)} eventi precedenti")
            except Exception as e:
                print(f"[!] --since non valido: {e}", file=sys.stderr)
        if args.until:
            try:
                until_ts = pd.to_datetime(args.until, utc=True)
                before   = len(df)
                df = df[df["_timestamp_parsed"] <= until_ts].reset_index(drop=True)
                log(f"[+] --until {args.until}: rimossi {before - len(df)} eventi successivi")
            except Exception as e:
                print(f"[!] --until non valido: {e}", file=sys.stderr)
    else:
        print("[!] Nessuna colonna timestamp rilevata", file=sys.stderr)

    # --max-events: keep only first N rows after sorting (fast triage mode)
    max_ev = getattr(args, "max_events", None)
    if max_ev and len(df) > max_ev:
        log(f"[+] --max-events {max_ev}: troncato da {len(df)} a {max_ev} eventi")
        df = df.head(max_ev).reset_index(drop=True)

    level_col = args.level_col or detect_level_col(df)
    if level_col:
        log(f"[+] Colonna log level : '{level_col}'")
    df["_log_level"] = df.apply(lambda row: extract_log_level(row, level_col), axis=1)

    log("[*] Rilevamento anomalie...")
    df = detect_anomalies(df, level_col_name="_log_level")
    log(f"[+] Anomalie: {df['_is_anomaly'].sum()} | Errori: {df['_is_error'].sum()} | Warning: {df['_is_warning'].sum()} | Recovery: {df['_is_recovery'].sum()}")

    if getattr(args, "no_flow", False):
        flow_key = None
        flow_df  = df.copy()
        log("[+] Flow isolation disabilitata (--no-flow)")
    else:
        flow_key = detect_flow_key(df, hint=args.flow_key)
        if flow_key:
            log(f"[+] Chiave di flusso  : '{flow_key}'")
            flow_df = isolate_flow(df, flow_key, target_value=args.flow_value)
            log(f"[+] Flusso critico    : {len(flow_df)} eventi")
        else:
            log("[!] Nessuna chiave di flusso rilevata")
            flow_df = df.copy()

    log("[*] Root cause analysis...")
    root_cause = find_root_cause(df, flow_key=flow_key)
    log(f"[+] Root cause: {root_cause['root_event'].get('_log_level', '?')} @ {fmt_ts(root_cause['first_error_ts'])}")
    log(f"[+] Cascade   : {root_cause['cascade_count']} errori | MTTR: {fmt_duration(root_cause['mttr']) if root_cause['mttr'] else 'N/D'}")
    log(f"[+] Precursori: {len(root_cause['precursors'])} eventi")

    log("[*] Estrazione evidenze di rete...")
    network_evidence = extract_network_evidence(df)
    log(f"[+] Evidenze  : { {k: len(v) for k, v in network_evidence.items()} }")

    log("[*] Analisi avanzata (burst, severity, host, gap, recovery)...")
    severity         = compute_severity_score(df, root_cause)
    bursts           = compute_burst_windows(df)
    host_impact      = build_host_impact(df)
    log_gaps         = detect_log_gaps(df)
    dup_count        = detect_duplicates(df)
    recovery_timeline = build_recovery_timeline(df)
    log(f"[+] Severity  : {severity['score']}/100 — {severity['grade']}")
    log(f"[+] Burst     : {len(bursts)} finestre | Gaps: {len(log_gaps)} | Duplicati: {dup_count}")
    if host_impact is not None:
        log(f"[+] Host      : {len(host_impact)} host coinvolti")
    if recovery_timeline is not None:
        log(f"[+] Recovery  : {len(recovery_timeline)} host con timeline recovery")

    # ----- Optional local AI RCA (offline, Ollama-compatible). Off by default -----
    # Computed BEFORE the report so its section can be embedded in MD/HTML and in
    # the --json-summary. Degrades gracefully: any failure leaves status="error"
    # and never affects the deterministic output above.
    ai_result = None
    if getattr(args, "local_ai", False):
        import json as _json_main
        log("[*] Analisi AI locale (Ollama-compatible)...")
        _hash_src_ai = (input_path.read_bytes() if input_path.exists()
                        else df.to_csv(index=False).encode())
        _ir_id_ai    = hashlib.md5(_hash_src_ai).hexdigest()[:8].upper()
        try:
            _ai_err_tags = list({
                tag
                for _, row in df[df["_is_error"] & ~df["_is_recovery"]].iterrows()
                for tag in row.get("_anomaly_tags", [])
            })
            _ai_playbook = [t for t in _ai_err_tags if t in REMEDIATION_STEPS]
        except Exception:
            _ai_playbook = []
        _ai_host_count = (
            int(host_impact[host_impact.columns[0]].nunique())
            if host_impact is not None and not host_impact.empty else 0
        )
        # Deterministic evidence dict — mirrors the --json-summary schema so the
        # model sees exactly the facts scoobyLog already proved (no raw CSV).
        _ai_deterministic = {
            "version":          VERSION,
            "incident_id":      f"IR-{_ir_id_ai}",
            "total_events":     int(len(df)),
            "error_events":     int(df["_is_error"].sum()),
            "warning_events":   int(df["_is_warning"].sum()),
            "anomaly_events":   int(df["_is_anomaly"].sum()),
            "host_count":       _ai_host_count,
            "severity":         (severity or {}).get("grade", "N/D"),
            "severity_score":   (severity or {}).get("score", 0),
            "trend":            compute_trend(df),
            "service_impact":   worst_service_status(df),
            "mttr_seconds":     (root_cause["mttr"].total_seconds()
                                 if root_cause.get("mttr") else None),
            "cascade_count":    int(root_cause.get("cascade_count", 0) or 0),
            "root_cause_ts":    fmt_ts(root_cause.get("first_error_ts")),
            "root_cause_level": root_cause.get("root_event", {}).get("_log_level", "N/D"),
            "root_cause_host":  root_cause.get("root_event", {}).get("host", "N/D"),
            "root_cause_tags":  list(root_cause.get("anomaly_tags", []) or []),
            "playbook_patterns": _ai_playbook,
            "network_evidence": {k: list(v) for k, v in (network_evidence or {}).items()},
            "burst_count":      len(bursts) if bursts is not None else 0,
            "log_gaps":         len(log_gaps) if log_gaps is not None else 0,
            "duplicate_count":  int(dup_count or 0),
            "top_recurring_errors": top_recurring_errors(df),
            "recovery_timeline": (recovery_timeline.to_dict(orient="records")
                                  if recovery_timeline is not None else []),
        }
        # Honour --anonymize: when set, data must be sanitized regardless of --local-ai-raw
        _ai_sanitize = getattr(args, "anonymize", False) or not getattr(args, "local_ai_raw", False)
        ai_context = build_local_ai_context(
            df, _ai_deterministic,
            max_events=getattr(args, "local_ai_max_events", LOCAL_AI_DEFAULT_MAX_EVENTS),
            sanitize=_ai_sanitize,
        )
        ai_result = local_ai_rca(
            ai_context,
            endpoint=getattr(args, "local_ai_endpoint", LOCAL_AI_DEFAULT_ENDPOINT),
            model=getattr(args, "local_ai_model", LOCAL_AI_DEFAULT_MODEL),
            timeout=getattr(args, "local_ai_timeout", LOCAL_AI_DEFAULT_TIMEOUT),
            strict_local=getattr(args, "local_ai_strict_local", True),
        )
        _ai_dir      = out_dir if out_dir else output_path.parent
        ai_path      = _ai_dir / f"IR-{_ir_id_ai}_local_ai.json"
        ai_result["incident_id"] = f"IR-{_ir_id_ai}"
        ai_result["result_path"] = str(ai_path)
        try:
            ai_path.write_text(
                _json_main.dumps(ai_result, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        except Exception as _ae:
            print(f"[!] Scrittura risultato AI fallita: {_ae}", file=sys.stderr)
        if ai_result.get("status") == "ok":
            _an = ai_result.get("analysis", {}) or {}
            log(f"[✓] AI RCA: {ai_path} (modello {ai_result.get('model')})")
            _rc = _an.get("root_cause_probabile")
            if _rc:
                log(f"    → {_rc} (confidenza: {_an.get('confidenza', 'N/D')})")
        else:
            log(f"[!] AI RCA non disponibile: {ai_result.get('error', 'errore sconosciuto')}")

    # Build full Markdown report only when needed (writing MD file or --summary TLDR extraction)
    _needs_report = not getattr(args, "no_report", False) or getattr(args, "summary", False)
    if _needs_report:
        log("[*] Generazione report Markdown...")
        report = generate_report(
            df=df,
            root_cause=root_cause,
            network_evidence=network_evidence,
            flow_key=flow_key,
            flow_df=flow_df,
            source_file=str(input_path),
            args=args,
            severity=severity,
            bursts=bursts,
            host_impact=host_impact,
            log_gaps=log_gaps,
            duplicate_count=dup_count,
            recovery_timeline=recovery_timeline,
        )
    else:
        report = ""
        log("[*] Generazione report saltata (--no-report attivo)")

    # Embed the AI Local RCA Review section into the report (if AI ran),
    # placed between §13 (Root Cause Analysis) and §14 (Azioni Raccomandate).
    if ai_result is not None and report:
        _ai_md = render_local_ai_section(ai_result)
        _marker = "## 14. Azioni Raccomandate"
        if _marker in report:
            report = report.replace(_marker, _ai_md + "\n" + _marker, 1)
        else:
            report = report + "\n" + _ai_md

    # --summary: print TLDR to stdout and exit without writing any file
    if getattr(args, "summary", False):
        try:
            tldr_raw = report.split("> ### ⚡ TLDR")[1].split("\n---\n")[0]
            # First line is "— Sintesi Operativa" (rest of the header); skip it
            all_lines = tldr_raw.splitlines()[1:]
            lines = [l.lstrip(">").strip() for l in all_lines if l.lstrip(">").strip()]
            print("\n".join(lines))
        except (IndexError, ValueError):
            print("[!] TLDR non disponibile nel report generato.", file=sys.stderr)
            return 1
        return 0

    if not getattr(args, "no_report", False):
        # Apply anonymization before formatting (covers both MD and HTML)
        if getattr(args, "anonymize", False):
            report = anonymize_report(report)
            log("[*] Anonimizzazione applicata (IP, session ID, UUID, email)")

        if _fmt == "html":
            _sev_grade = severity["grade"] if severity else ""
            _ir_id = f"IR-{hashlib.md5((input_path.read_bytes() if input_path.exists() else df.to_csv(index=False).encode())).hexdigest()[:8].upper()}"
            output_content = wrap_html(report, _ir_id, _sev_grade)
        else:
            output_content = report
        output_path.write_text(output_content, encoding="utf-8")
        size_kb = output_path.stat().st_size / 1024
        _fmt_label = "HTML" if _fmt == "html" else "MD"
        log(f"\n[✓] Report {_fmt_label}: {output_path} ({size_kb:.1f} KB)")
        if getattr(args, "open", False):
            import webbrowser
            webbrowser.open(output_path.resolve().as_uri())
            log(f"[*] Aperto nel browser: {output_path.resolve()}")
    else:
        log("\n[*] --no-report attivo: file non scritto")

    # Optional enriched CSV export
    if getattr(args, "export_csv", None):
        export_path = Path(args.export_csv)
        export_df = df.copy()
        # Serialize list columns to pipe-separated strings for CSV compatibility
        if "_anomaly_tags" in export_df.columns:
            export_df["_anomaly_tags"] = export_df["_anomaly_tags"].apply(
                lambda v: "|".join(v) if isinstance(v, list) else (v or "")
            )
        export_df.to_csv(export_path, index=False, encoding="utf-8")
        log(f"[✓] Export CSV: {export_path} ({len(export_df)} righe, {len(export_df.columns)} colonne)")

    # Optional JSON summary
    if args.json_summary:
        import json
        _hash_src = input_path.read_bytes() if input_path.exists() else df.to_csv(index=False).encode()
        file_hash = hashlib.md5(_hash_src).hexdigest()[:8].upper()
        json_dir  = out_dir if out_dir else output_path.parent
        json_path = json_dir / f"IR-{file_hash}.json"

        # Compute fields not yet available in main scope
        _trend = compute_trend(df)
        _svc_status = worst_service_status(df)
        _error_only_tags = list({
            tag
            for _, row in df[df["_is_error"] & ~df["_is_recovery"]].iterrows()
            for tag in row.get("_anomaly_tags", [])
        })
        _playbook_patterns = [t for t in _error_only_tags if t in REMEDIATION_STEPS]
        _host_count = (
            int(host_impact[host_impact.columns[0]].nunique())
            if host_impact is not None and not host_impact.empty else 0
        )
        _precursor_count = len(root_cause["precursors"]) if root_cause.get("precursors") is not None else 0

        summary = {
            "version":         VERSION,
            "incident_id":     f"IR-{file_hash}",
            "analyzed_at":     datetime.now(timezone.utc).isoformat(),
            "source_file":     str(input_path),
            "total_events":    len(df),
            "error_events":    int(df["_is_error"].sum()),
            "warning_events":  int(df["_is_warning"].sum()),
            "anomaly_events":  int(df["_is_anomaly"].sum()),
            "host_count":      _host_count,
            "precursor_count": _precursor_count,
            "severity":        severity,
            "trend":           _trend,
            "service_impact":  _svc_status,
            "mttr_seconds":    root_cause["mttr"].total_seconds() if root_cause["mttr"] else None,
            "cascade_count":   root_cause["cascade_count"],
            "root_cause_ts":   fmt_ts(root_cause["first_error_ts"]),
            "root_cause_level": root_cause["root_event"].get("_log_level", "UNKNOWN"),
            "root_cause_host":  root_cause["root_event"].get("host", "N/A"),
            "root_cause_tags":  root_cause["anomaly_tags"],
            "playbook_patterns": _playbook_patterns,
            "network_evidence": {k: list(v) for k, v in network_evidence.items()},
            "burst_count":     len(bursts),
            "log_gaps":        log_gaps,
            "duplicate_count": dup_count,
            "recovery_timeline": (
                recovery_timeline.to_dict(orient="records") if recovery_timeline is not None else []
            ),
            "report_path":     str(output_path) if not getattr(args, "no_report", False) else None,
            "local_ai":        local_ai_summary_block(ai_result),
        }
        json_path.write_text(json.dumps(summary, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
        log(f"[✓] Report JSON: {json_path}")

    # --alert-webhook: POST JSON summary to an HTTP endpoint (Slack/PagerDuty/Opsgenie/custom)
    webhook_url = getattr(args, "alert_webhook", None)
    if webhook_url:
        import urllib.request as _urlreq
        import json as _json
        # Build a compact payload compatible with most webhook formats
        _hash_src2 = input_path.read_bytes() if input_path.exists() else df.to_csv(index=False).encode()
        _ir_id2    = f"IR-{hashlib.md5(_hash_src2).hexdigest()[:8].upper()}"
        _sev2      = severity or {}
        payload = {
            "incident_id":    _ir_id2,
            "analyzed_at":    datetime.now(timezone.utc).isoformat(),
            "source_file":    str(input_path),
            "severity_grade": _sev2.get("grade", "N/A"),
            "severity_score": _sev2.get("score", 0),
            "total_events":   len(df),
            "error_events":   int(df["_is_error"].sum()),
            "mttr_seconds":   root_cause["mttr"].total_seconds() if root_cause["mttr"] else None,
            "cascade_count":  root_cause["cascade_count"],
            "root_cause_ts":  fmt_ts(root_cause["first_error_ts"]),
            "root_cause_host": root_cause["root_event"].get("host", "N/A"),
            "root_cause_tags": root_cause["anomaly_tags"],
            "report_path":    str(output_path) if not getattr(args, "no_report", False) else None,
            "scoobylog_version": VERSION,
        }
        try:
            _body = _json.dumps(payload, default=str).encode()
            _req  = _urlreq.Request(
                webhook_url,
                data=_body,
                headers={"Content-Type": "application/json", "User-Agent": f"scoobyLog/{VERSION}"},
                method="POST",
            )
            with _urlreq.urlopen(_req, timeout=10) as _resp:
                log(f"[✓] Webhook POST: {webhook_url} → HTTP {_resp.status}")
        except Exception as _we:
            print(f"[!] Webhook POST fallito: {_we}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    # When packaged with PyInstaller and launched by double-click (no CLI args,
    # no file dragged onto the .exe), keep the console window open after exit —
    # otherwise it flashes and disappears before the user can read anything.
    _frozen_no_args = getattr(sys, "frozen", False) and len(sys.argv) <= 1
    try:
        _exit_code = main()
    except SystemExit as _se:
        _exit_code = _se.code if isinstance(_se.code, int) else (0 if _se.code is None else 1)
    if _frozen_no_args:
        input("\nPremi INVIO per chiudere...")
    sys.exit(_exit_code)
