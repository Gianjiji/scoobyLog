"""Test di caratterizzazione: cosa produce oggi lo strumento su log normali.

Non giudicano l'analisi, la fotografano: struttura del report, conteggi che si
possono ricontare a mano dal CSV, formati di uscita. Servono come rete di sicurezza
prima di qualunque refactoring di generate_report e main.
"""
import re
from collections import Counter

import pytest

from conftest import build_benign_rows, run_cli

SECTIONS = [
    "## Metadati Incident",
    "## 0. Quick Reference",
    "## 1. Executive Summary",
    "## 2. Statistiche Generali",
    "## 3. Timeline degli Eventi",
    "## 4. Analisi Precursori",
    "## 5. Analisi per Flusso",
    "## 6. Impatto per Host",
    "## 7. Recovery Timeline per Host",
    "## 8. Breakdown Anomalie",
    "## 9. Integrità Log",
    "## 10. Matrice Flussi di Rete",
    "## 11. Evidenze di Rete",
    "## 12. Estratti Log Raw",
    "## 13. Root Cause Analysis",
    "## 14. Azioni Raccomandate",
    "## 15. Appendice Tecnica",
]


def table_value(report: str, label: str) -> str:
    """Il valore fra backtick nella riga di tabella che inizia con `label`."""
    match = re.search(r"^\| %s \| `([^`]*)`" % re.escape(label), report, re.M)
    assert match, "riga %r non trovata" % label
    return match.group(1)


class TestStruttura:
    def test_titolo(self, benign_md):
        assert benign_md.startswith("# Incident Response Report")

    def test_tutte_le_sezioni_nell_ordine_previsto(self, benign_md):
        positions = [benign_md.find(section) for section in SECTIONS]
        missing = [s for s, p in zip(SECTIONS, positions) if p < 0]
        assert missing == []
        assert positions == sorted(positions)

    def test_le_tabelle_sono_ben_formate(self, benign_md):
        """Ogni riga di una tabella ha lo stesso numero di celle dell'intestazione."""
        lines = benign_md.split("\n")
        checked = 0
        for index, line in enumerate(lines[:-1]):
            if not re.fullmatch(r"\|(\s*:?-+:?\s*\|)+", lines[index + 1].strip()):
                continue
            columns = lines[index + 1].count("|") - 1
            cursor = index + 2
            while cursor < len(lines) and lines[cursor].startswith("|"):
                cells = len(re.findall(r"(?<!\\)\|", lines[cursor])) - 1
                assert cells == columns, "riga %d: %s" % (cursor + 1, lines[cursor][:120])
                cursor += 1
                checked += 1
        assert checked > 50

    def test_i_blocchi_di_codice_sono_chiusi(self, benign_md):
        fences = [l for l in benign_md.split("\n") if l.startswith("```")]
        assert len(fences) % 2 == 0


class TestConteggi:
    """Numeri che si ricontano dal CSV senza passare dal codice sotto test."""

    def setup_method(self):
        self.rows = build_benign_rows()
        self.levels = Counter(row[3] for row in self.rows)

    def test_totale_eventi(self, benign_md):
        assert table_value(benign_md, "Totale eventi analizzati") == str(len(self.rows))

    def test_errori(self, benign_md):
        expected = self.levels["ERROR"] + self.levels["CRITICAL"]
        assert table_value(benign_md, "Eventi ERROR/CRITICAL/FATAL") == str(expected)

    def test_warning(self, benign_md):
        assert table_value(benign_md, "Eventi WARNING") == str(self.levels["WARN"])

    def test_host(self, benign_md):
        assert table_value(benign_md, "Host coinvolti") == str(len({row[1] for row in self.rows}))

    def test_la_root_cause_e_il_primo_errore(self, benign_md):
        first_error = next(row for row in self.rows if row[3] in ("ERROR", "CRITICAL"))
        line = next(l for l in benign_md.split("\n") if l.startswith("| **Root Cause** |"))
        assert "`%s`" % first_error[1] in line
        assert "`%s`" % first_error[3] in line

    def test_hash_del_file_sorgente(self, benign_md, benign_csv):
        import hashlib
        digest = hashlib.sha256(benign_csv.read_bytes()).hexdigest()
        assert "`%s`" % digest in benign_md


class TestRiga:
    def test_esecuzioni_ripetute_danno_lo_stesso_report(self, benign_csv, benign_md, tmp_path):
        """A parte data di analisi e identificativo, l'analisi è deterministica."""
        result = run_cli(benign_csv, tmp_path, "--format", "md")
        assert result.returncode == 0
        again = next(tmp_path.glob("*.md")).read_text(encoding="utf-8")

        def stable(text):
            text = re.sub(r"\d{4}-\d{2}-\d{2}[ T][\d:.]+( UTC)?", "TS", text)
            return re.sub(r"IR-[A-Z0-9-]+", "IR-ID", text)

        assert stable(again) == stable(benign_md)

    def test_formato_html_predefinito(self, benign_csv, tmp_path):
        result = run_cli(benign_csv, tmp_path)
        assert result.returncode == 0, result.stderr[-1000:]
        produced = [p.name for p in tmp_path.iterdir()]
        assert produced == ["benign_incident_report.html"]

    def test_anonimizzazione(self, benign_csv, tmp_path):
        result = run_cli(benign_csv, tmp_path, "--format", "md", "--anonymize")
        assert result.returncode == 0, result.stderr[-1000:]
        report = next(tmp_path.glob("*.md")).read_text(encoding="utf-8")
        assert "ANON-IP-" in report
        assert not re.search(r"\b10\.0\.[01]\.\d\b", report)
        assert "mario@example.com" not in report

    def test_file_inesistente(self, tmp_path):
        result = run_cli(tmp_path / "manca.csv", tmp_path)
        assert result.returncode != 0
        assert list(tmp_path.iterdir()) == []

    def test_versione(self):
        import subprocess
        import sys
        from conftest import ROOT
        result = subprocess.run([sys.executable, str(ROOT / "scoobyLog.py"), "--version"],
                                capture_output=True, text=True, timeout=120)
        assert result.returncode == 0
        assert re.search(r"scoobylog \d+\.\d+", result.stdout)
