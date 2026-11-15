"""Fixtures condivise: CSV di esempio generati al volo e avvio della CLI.

I CSV non sono file nel repository ma vengono costruiti qui, in modo deterministico:
così si vede a colpo d'occhio cosa contengono e perché.
"""
import csv
import random
import subprocess
import sys
import warnings
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
warnings.filterwarnings("ignore", category=Warning, module="scoobyLog")

COLUMNS = ["_time", "host", "sourcetype", "level", "message", "src_ip", "dst_ip", "session_id"]


def marker(tag: str) -> str:
    """JavaScript che, se eseguito, lascia una traccia verificabile in window.__pwned."""
    return "window.__pwned=(window.__pwned||[]).concat('%s')" % tag


# Un payload per ogni via d'ingresso nota. Niente cifre nei payload: lo strumento
# normalizza i numeri nei messaggi e un payload con cifre verrebbe alterato per caso,
# facendo sembrare sicuro ciò che non lo è.
HOSTILE_MESSAGES = {
    "tick-img": 'db connection failed `<img src=x onerror="%s">` upstream' % marker("tick-img"),
    "img": 'cache miss <img src=x onerror="%s"> on node' % marker("img"),
    "svg": 'auth error <svg onload="%s"></svg> token' % marker("svg"),
    "link": "see [details](javascript:%s) now"
            % marker("link").replace("(", "%28").replace(")", "%29"),
    "script": "queue stalled <script>%s</script> retry" % marker("script"),
    "iframe": 'disk full <iframe srcdoc="<script>parent.%s</script>"></iframe> abort'
              % marker("iframe"),
    "fence": 'trace end\n```\n<img src=x onerror="%s">\n```' % marker("fence"),
    "pipe": 'a | b | <img src=x onerror="%s"> | c' % marker("pipe"),
    "pixel": "loaded ![pixel](https://tracker.invalid/p.png) asset",
}
HOSTILE_HOST = 'web`<img src=x onerror="%s">`' % marker("host")
HOSTILE_IP = '`<img src=x onerror="%s">`' % marker("ip")


def _write(path: Path, rows) -> Path:
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(COLUMNS)
        writer.writerows(rows)
    return path


def build_benign_rows():
    rng = random.Random(7)
    moment = datetime(2026, 11, 1, 10, 0, 0)
    hosts = ["web-01", "web-02", "db-01", "cache_01"]
    errors = [
        "db connection timeout after 30s to 10.0.0.5:5432",
        "OutOfMemoryError: Java heap space",
        "upstream timed out (110: Connection timed out) while reading response header",
        "disk usage 97% on /var",
        "connection refused session=sess-ab12cd user=mario@example.com",
    ]
    normal = ["GET /api/v1/items 200 12ms", "health check ok", "cache hit key=user_42",
              "POST /login 302"]
    rows = []
    for index in range(300):
        host = rng.choice(hosts)
        moment += timedelta(seconds=rng.randint(1, 9))
        if 120 <= index < 170 and rng.random() < 0.6:
            level = rng.choice(["ERROR", "ERROR", "CRITICAL", "WARN"])
            message = rng.choice(errors)
        else:
            level, message = "INFO", rng.choice(normal)
        rows.append([moment.isoformat(), host, "app_log", level, message,
                     "10.0.0.%d" % rng.randint(1, 9), "10.0.1.%d" % rng.randint(1, 5),
                     "sess-%04d" % rng.randint(1, 30)])
    return rows


def build_hostile_rows():
    moment = datetime(2026, 11, 1, 10, 0, 0)
    rows = []

    def add(host, level, message, src="10.0.0.1", dst="10.0.1.1", session="sess-aa"):
        nonlocal moment
        rows.append([moment.isoformat(), host, "app", level, message, src, dst, session])
        moment += timedelta(seconds=3)

    for _ in range(40):
        add("web-a", "INFO", "request ok")
    for repeat in range(6):
        for message in HOSTILE_MESSAGES.values():
            add(HOSTILE_HOST if repeat % 2 == 0 else "db-a", "ERROR", message,
                src=HOSTILE_IP, session='sess-`<img src=x onerror="%s">`' % marker("session"))
    for _ in range(20):
        add("web-a", "INFO", "request ok")
    return rows


@pytest.fixture(scope="session")
def benign_csv(tmp_path_factory) -> Path:
    return _write(tmp_path_factory.mktemp("benign") / "benign.csv", build_benign_rows())


@pytest.fixture(scope="session")
def hostile_csv(tmp_path_factory) -> Path:
    return _write(tmp_path_factory.mktemp("hostile") / "hostile.csv", build_hostile_rows())


def run_cli(csv_path: Path, out_dir: Path, *extra: str) -> subprocess.CompletedProcess:
    """Esegue scoobyLog come farebbe un utente, in un processo separato."""
    return subprocess.run(
        [sys.executable, str(ROOT / "scoobyLog.py"), str(csv_path),
         "--output-dir", str(out_dir), "--quiet", *extra],
        capture_output=True, text=True, timeout=180,
    )


def _report(csv_path: Path, out_dir: Path, fmt: str) -> str:
    result = run_cli(csv_path, out_dir, "--format", fmt)
    assert result.returncode == 0, result.stderr[-2000:]
    produced = list(out_dir.glob("*_incident_report.%s" % fmt))
    assert len(produced) == 1, [p.name for p in out_dir.iterdir()]
    return produced[0].read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def benign_md(benign_csv, tmp_path_factory) -> str:
    return _report(benign_csv, tmp_path_factory.mktemp("benign_md"), "md")


@pytest.fixture(scope="session")
def hostile_md(hostile_csv, tmp_path_factory) -> str:
    return _report(hostile_csv, tmp_path_factory.mktemp("hostile_md"), "md")


@pytest.fixture(scope="session")
def hostile_html_path(hostile_csv, tmp_path_factory) -> Path:
    out_dir = tmp_path_factory.mktemp("hostile_html")
    _report(hostile_csv, out_dir, "html")
    return next(out_dir.glob("*.html"))
