# scoobyLog

**Analizzatore di Incidenti Splunk** — strumento Python di livello senior per elaborare export CSV da Splunk e generare report di Incident Response completi in formato Markdown o HTML.

```
scoobylog v4.3
```

## Cosa fa

A partire da un CSV esportato da Splunk, scoobyLog esegue automaticamente:

- Parsing dei timestamp in qualsiasi formato (ISO 8601, Apache/nginx, syslog, epoch in secondi/ms)
- Ordinamento cronologico e normalizzazione in UTC
- Isolamento del flusso più anomalo tramite chiave univoca (sessione, request ID, IP sorgente, ...)
- Rilevamento anomalie via regex: OOM, segfault, disco pieno, timeout, fallimenti di autenticazione, stack trace, slow query, pool esaurito e altro
- Identificazione della **root cause** — il primo errore della catena — con misurazione della profondità della cascata
- Calcolo del **MTTR** (Mean Time To Recover) e rilevamento **violazione SLA** (P1–P4)
- Generazione di un **Report di Incident Response** completo con timeline, catena di eventi ASCII, evidenze di rete, matrice di impatto per host, analisi RCA, query SPL per riproduzione dell'incidente e playbook tecnico

## Requisiti

```
Python 3.8+
pandas >= 1.3.0
numpy  >= 1.21.0
```

Installazione dipendenze:

```bash
pip install -r requirements.txt
```

## Utilizzo

```bash
# Argomento posizionale / drag & drop
python scoobylog.py logs.csv

# Forma con flag
python scoobylog.py --input logs.csv

# Report HTML, aperto nel browser
python scoobylog.py --input logs.csv --format html --open

# Riepilogo TLDR rapido su stdout (nessun file scritto)
python scoobylog.py --input logs.csv --summary

# Lettura da stdin (pipe da Splunk CLI, curl, ecc.)
cat export.csv | python scoobylog.py --input -

# JSON leggibile da macchina + CSV arricchito, senza report Markdown
python scoobylog.py --input logs.csv --no-report --json-summary --export-csv arricchito.csv

# Filtro intervallo temporale + livello minimo
python scoobylog.py --input logs.csv --since 2024-03-15T08:00:00Z --until 2024-03-15T09:00:00Z --min-level ERROR

# Anonimizzazione IP, ID di sessione, UUID ed email prima della condivisione
python scoobylog.py --input logs.csv --anonymize

# Invio del riepilogo JSON a webhook Slack/PagerDuty/Opsgenie
python scoobylog.py --input logs.csv --alert-webhook https://hooks.example.com/incident

# Estensione del rilevamento con pattern personalizzati
python scoobylog.py --input logs.csv --patterns-file pattern_custom.json
```

## Riferimento opzioni CLI

| Flag | Predefinito | Descrizione |
|---|---|---|
| `CSV_FILE` | — | File di input posizionale (drag & drop) |
| `--input / -i` | — | Percorso al CSV di Splunk (`-` per stdin) |
| `--output / -o` | `<input>_incident_report.html` | Percorso file di output |
| `--output-dir` | — | Cartella per tutti i file di output |
| `--timestamp-col` | automatico | Nome colonna timestamp |
| `--level-col` | automatico | Nome colonna log level |
| `--flow-key` | automatico | Colonna chiave di flusso univoca |
| `--flow-value` | automatico (più anomalo) | Valore di flusso specifico da isolare |
| `--no-flow` | disattivo | Disabilita l'isolamento del flusso |
| `--encoding` | utf-8 | Encoding del file CSV |
| `--max-rows` | 30 | Numero massimo di righe nella tabella timeline |
| `--chain-depth` | 12 | Numero massimo di eventi nella catena ASCII |
| `--since` | — | Scarta eventi precedenti a questo timestamp ISO 8601 |
| `--until` | — | Scarta eventi successivi a questo timestamp ISO 8601 |
| `--min-level` | — | Livello minimo di log per la timeline |
| `--max-events N` | — | Elabora solo i primi N eventi (triage rapido) |
| `--json-summary` | disattivo | Scrive `IR-<hash>.json` insieme al report |
| `--export-csv PERCORSO` | — | Esporta il DataFrame arricchito in CSV |
| `--patterns-file PERCORSO` | — | File JSON con pattern di rilevamento personalizzati |
| `--alert-webhook URL` | — | Invia il riepilogo JSON a un webhook |
| `--anonymize` | disattivo | Pseudonimizza IP, ID sessione, UUID ed email |
| `--format {md,html}` | html | Formato di output |
| `--open` | disattivo | Apre il report nel browser dopo la generazione |
| `--no-report` | disattivo | Salta la generazione del report |
| `--summary` | disattivo | Stampa il TLDR su stdout ed esce |
| `--quiet / -q` | disattivo | Sopprime l'output di avanzamento |
| `--local-ai` | disattivo | Abilita la RCA assistita da LLM locale (Ollama, offline) |
| `--local-ai-endpoint URL` | `http://localhost:11434/api/generate` | Endpoint del modello locale |
| `--local-ai-model NAME` | `llama3.1:8b` | Modello locale (es. `llama3.1:8b`, `mistral:7b`) |
| `--local-ai-timeout SEC` | `300` | Timeout della richiesta AI in secondi |
| `--local-ai-max-events N` | `30` | Eventi di timeline inviati al modello come contesto |
| `--local-ai-strict-local` | attivo | Rifiuta endpoint non locali (loopback/RFC1918); disabilita con `--local-ai-no-strict-local` |
| `--local-ai-raw` | disattivo | Invia i log grezzi (non sanificati) al modello |
| `--version` | — | Stampa la versione ed esce |

## RCA assistita da AI locale (opzionale, offline)

Con `--local-ai` scoobyLog può arricchire l'analisi deterministica con una
review da SRE senior generata da un **LLM locale** servito da un endpoint
**compatibile con Ollama** (default `http://localhost:11434/api/generate`).
Tutto resta **offline**: nessuna chiamata cloud, nessuna API a pagamento.

- È **disattivato di default**: senza `--local-ai` il comportamento non cambia.
- Il modello riceve **le evidenze già provate** da scoobyLog (root cause, MTTR,
  severity, evidenze di rete, cascata, host, recovery) più un **estratto di
  timeline** (`--local-ai-max-events`, default 30, messaggi troncati a 500
  caratteri). Il prompt impone di non inventare servizi, timestamp, IP o codici
  di errore e di dichiarare esplicitamente le evidenze mancanti — riducendo le
  allucinazioni.
- Per impostazione predefinita il testo dei log viene **sanificato**
  (IP, UUID, ID di sessione, email pseudonimizzati) prima dell'invio; usa
  `--local-ai-raw` per inviarli grezzi.
- Se è attivo `--anonymize`, i dati inviati al modello **vengono sempre
  anonimizzati**, anche con `--local-ai-raw`.
- `--local-ai-strict-local` (attivo di default) **rifiuta endpoint non locali**:
  sono ammessi solo loopback, `localhost`, `*.local` e reti private RFC1918.
  Disattivalo con `--local-ai-no-strict-local`.
- La chiamata è **deterministica** (`temperature 0.1`, `format: json`,
  `stream: false`); la risposta viene letta da `response["response"]`, il JSON
  troncato/incompleto viene recuperato in best-effort e lo **schema viene
  validato** (chiavi obbligatorie). Schema non valido → `status: "error"`.
- **Degradazione robusta**: endpoint non raggiungibile, timeout, modello non
  installato (`ollama pull <model>`), JSON malformato o schema non valido →
  scoobyLog scrive comunque un risultato con `"status": "error"`, annota la
  sezione del report con *"Local AI RCA non disponibile: &lt;motivo&gt;"* e
  prosegue senza errori fatali.

Il risultato viene scritto in `IR-<hash>_local_ai.json`, incluso anche nel blocco
`local_ai` del `--json-summary` e in una sezione **§13.5 — AI Local RCA Review**
del report MD/HTML. Struttura:

```json
{
  "enabled": true,
  "provider": "ollama-compatible",
  "model": "llama3.1:8b",
  "endpoint": "http://localhost:11434/api/generate",
  "status": "ok",
  "error": null,
  "generated_at": "2026-...Z",
  "incident_id": "IR-<hash>",
  "result_path": "IR-<hash>_local_ai.json",
  "analysis": {
    "root_cause_probabile": "...",
    "confidenza": "ALTA|MEDIA|BASSA",
    "motivazione": "...",
    "cause_alternative": ["..."],
    "evidenze_chiave": ["..."],
    "evidenze_deboli": ["..."],
    "evidenze_mancanti": ["..."],
    "prossimi_controlli": ["..."],
    "rischio_falso_positivo": "BASSO|MEDIO|ALTO",
    "raccomandazione_operativa": "..."
  }
}
```

Nel `--json-summary` viene aggiunto un blocco **compatto** `local_ai`
(`enabled`, `provider`, `model`, `endpoint`, `status`, `error`, `result_path`);
il dettaglio completo resta nel file `IR-<hash>_local_ai.json`.

Test rapido (senza Ollama, con endpoint mock): `python test_local_ai.py`.

**Nessuna chiamata cloud viene mai effettuata**: il layer AI è completamente
opzionale e di supporto all'analista; l'analisi deterministica resta la fonte
primaria.

Prerequisiti (una tantum): installare [Ollama](https://ollama.com) e scaricare
un modello. Esempi:

```bash
# prerequisito: Ollama in esecuzione + modello scaricato
ollama pull llama3.1:8b

# uso base (endpoint locale di default)
python scoobyLog.py logs.csv --json-summary --local-ai

# endpoint/modello personalizzati
python scoobyLog.py logs.csv --local-ai --local-ai-model mistral:7b --local-ai-endpoint http://localhost:11434/api/generate
```

## Struttura del report

```
§0  Quick Reference — tabella pronta da incollare nel ticket
§1  Executive Summary + §1.1 Narrazione dell'Incidente
§2  Statistiche + §2.1 Impatto per Servizio (DOWN/DEGRADED/OK per sourcetype)
§3  Timeline eventi + §3.1 Catena ASCII + §3.2 Grafico densità errori + §3.3 Analisi Burst
§4  Analisi Precursori
§5  Analisi per Flusso + §5.1 Dettaglio flusso critico
§6  Matrice impatto per Host (Stato: DOWN/DEGRADED/OK)
§7  Recovery Timeline per Host (con durata downtime)
§8  Breakdown anomalie + §8.1 Co-occorrenze + §8.2 Sourcetype + §8.3 Errori ricorrenti
§9  Integrità Log — Gap Analysis
§10 Matrice Flussi di Rete (src → dst)
§11 Evidenze di Rete (IP, porte, URL, timeout, fallimenti auth, errori DNS)
§12 Estratti Log Raw (top 5 errori, ordinati per severità)
§13 RCA + §13.1 Evento root + §13.2 Cascata + §13.3 Cross-Host + §13.4 Lista cause
§14 Azioni Raccomandate + §14.1 Playbook Tecnico (rimedi per pattern)
§15 Appendice — §15.1 Colonne + §15.2 Parametri + §15.3 Query SPL (×3)
```

## Pattern personalizzati

Estendi il rilevamento integrato senza modificare lo script:

```json
{
  "patterns": {
    "mio_pattern": "stringa regex"
  },
  "labels": {
    "mio_pattern": "**Etichetta** — descrizione per la lista cause"
  },
  "remediation": {
    "mio_pattern": [
      "Passo 1: ...",
      "Passo 2: ..."
    ]
  }
}
```

Da passare con `--patterns-file pattern_custom.json`.

## Capacità di rilevamento

**Pattern anomalie**: OOM killer, segfault, disco pieno, picco CPU, riavvio servizio, errori certificato TLS/SSL, kernel panic, stack trace, slow query, pool di connessioni esaurito

**Pattern di rete**: IPv4/IPv6, porte, URL, MAC, timeout/ETIMEDOUT/ECONNRESET, fallimenti autenticazione (401/403), errori DNS (NXDOMAIN/SERVFAIL), perdita pacchetti/retransmit

**Analisi avanzata**: rilevamento burst statistico (media+2σ), rilevamento gap adattivo (75° percentile×5), correlazione cascata cross-host (finestra 2 secondi), rilevamento violazione SLA (P1–P4), trend incidente (ESCALATING/STABLE/RECOVERING), scoring affidabilità RCA (ALTA/MEDIA/BASSA)

## Schema JSON summary

Con `--json-summary`, scoobyLog scrive `IR-<hash>.json` con:

```json
{
  "version": "4.3",
  "incident_id": "IR-XXXXXXXX",
  "analyzed_at": "...",
  "source_file": "...",
  "total_events": 21,
  "error_events": 11,
  "warning_events": 5,
  "anomaly_events": 14,
  "host_count": 5,
  "severity": { "score": 62, "grade": "P2 — ALTO", "components": {} },
  "trend": "...",
  "service_impact": "DEGRADED",
  "mttr_seconds": 75.0,
  "cascade_count": 10,
  "root_cause_ts": "...",
  "root_cause_level": "ERROR",
  "root_cause_host": "lb-01",
  "root_cause_tags": ["timeout"],
  "playbook_patterns": ["timeout", "oom_killer"],
  "network_evidence": {},
  "burst_count": 1,
  "log_gaps": [],
  "duplicate_count": 0,
  "recovery_timeline": []
}
```

## Test rapido

```bash
python scoobylog.py sample_splunk.csv
# → sample_splunk_incident_report.md (simulazione MySQL OOM → failure a cascata)
```

Output atteso:

```
[✓] Root cause: ERROR @ 2024-03-15T08:01:45Z su lb-01 (timeout)
[✓] Cascata: 10 errori downstream | MTTR: 1m 15s
[✓] Severity: 62/100 — P2 ALTO
```

## Licenza

MIT — vedi [LICENSE](LICENSE)
