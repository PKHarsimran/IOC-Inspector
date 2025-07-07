# IOC Inspector 🕵️‍♂️

**Fast, SOC-ready malicious-document scanner** — turn suspicious PDFs, DOC(X), XLS(X) & RTFs into IOC-rich, SIEM-friendly reports.


---

## ⚡ Why IOC Inspector?

| 🔑  | Value to Analysts |
|-----|------------------|
| **One-command triage** | `ioc-inspector invoice.docx` → instant verdict & Markdown report |
| **Actionable scoring** | Custom heuristics blend macro flags, embedded-object metrics, and feed look-ups (VirusTotal + AbuseIPDB) into a **0-100 risk score** |
| **Analyst-first outputs** | Markdown for tickets, JSON / CSV for Splunk & Elastic |
| **Runs anywhere** | Linux • macOS • Windows • headless in GitHub Actions |
| **Extensible** | All logic lives in `ioc_inspector_core/` — swap parsers, add feeds, tweak weights |

---

## 🔍 Feature Matrix

| Category            | What you get                                                                    |
|---------------------|---------------------------------------------------------------------------------|
| **Formats**         | PDF • DOC / DOCX • XLS / XLSX • RTF                                             |
| **Static Analysis** | Macro dump & keyword scan • Obfuscation finder • Embedded-object counter        |
| **IOC Extraction**  | URLs • Domains • IPs • Base64 strings • Hidden links                            |
| **Threat Enrichment** | VirusTotal, AbuseIPDB (URLScan optional)                                      |
| **Scoring Engine**  | Heuristic weights + rule modifiers (configurable)                               |
| **Reporting**       | Markdown & JSON (CSV optional)                                                  |
| **Automation**      | Dir-recursive scan • Quiet / Verbose switches • GitHub Actions workflow         |

---

## 🗺️  How It Works

```text
main.py (CLI)
   │
   ▼
ioc_inspector_core.__init__.analyze()
   ├─► pdf_parser.py      (if .pdf)
   ├─► doc_parser.py      (if Office/RTF)
   │     └─► macro_analyzer.py
   │
   ├─► url_reputation.py  (VirusTotal)
   ├─► abuseipdb_check.py (AbuseIPDB)
   ▼
heuristics.py   →  score + verdict
   ▼
report_generator.py → Markdown / JSON
   ▼
logger.py  →  stdout + ./logs/ioc_inspector.log
```

## 🚀 Quick Start
```bash
# 1 – Clone
$ git clone https://github.com/<your-user>/ioc-inspector.git
$ cd ioc-inspector

# 2 – Install
$ python -m venv venv && source venv/bin/activate
$ pip install -r requirements.txt

# 3 – Configure APIs
$ cp .env.example .env
$ nano .env            # add VT_API_KEY & ABUSEIPDB_API_KEY

# 4 – Scan a file
$ python main.py --file examples/sample_invoice.docx --report
```

<details> <summary>Example output</summary>
examples/sample_invoice.docx: score=45 verdict=suspicious
See reports/sample_invoice_report.md for full IOC tables.
</details>

## ⚙️ Configuration Highlights (settings.py)
```python
RISK_WEIGHTS = {
    "macro":          25,
    "obfuscation":    20,
    "malicious_url":  30,
    "malicious_ip":   25,
}

VT_THRESHOLD            = 5   # vendors to flag URL/IP malicious
ABUSE_CONFIDENCE_CUTOFF = 70  # AbuseIPDB confidence to flag IP
REPORT_FORMATS          = ["markdown", "json"]
```

🗂️ Repository Layout
```text
ioc-inspector/
├── ioc_inspector_core/         ← all analysis logic
│   ├── __init__.py
│   ├── pdf_parser.py
│   ├── doc_parser.py
│   ├── macro_analyzer.py
│   ├── url_reputation.py
│   ├── abuseipdb_check.py
│   ├── heuristics.py
│   └── report_generator.py
│
├── logger.py                   ← stdout + rotating file logger
├── main.py                     ← CLI entry-point
├── settings.py                 ← config + heuristic weights
│
├── examples/                   ← safe sample docs
├── reports/                    ← auto-generated reports (git-ignored)
├── logs/                       ← run-time logs (git-ignored)
│
├── tests/                      ← pytest unit tests
├── requirements.txt
├── .env.example
├── .gitignore
├── LICENSE
└── .github/
    └── workflows/
        └── analyzer.yml        ← CI + manual scan action
```

## ➡️ Pathway

| Stage        | Still to do before the next stage |
|--------------|-----------------------------------|
| **pre-0.1** *(current)* | • Pin library versions in `requirements.txt`<br>• Add unit tests for PDF & macro branches<br>• Tighten error handling & logging<br>• Final-pass README polish |
| **0.1**      | Dependency-pinned CLI with Markdown / JSON output and a passing test-suite |
| **0.2**      | Optional CSV export · Docker image · extra threat-feed look-ups |
| **1.0**      | Performance tuning · full docs · stable config & semantic versioning |
