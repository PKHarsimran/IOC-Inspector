# IOC Inspector 🕵️‍♂️
[![CI](https://github.com/PKHarsimran/IOC-Inspector/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/PKHarsimran/IOC-Inspector/actions/workflows/ci.yml)

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
---

## 📦 Dependencies at a Glance

| Category | Package | Why it’s needed |
|----------|---------|-----------------|
| **Core document parsing** | `oletools 0.60.1` | Extract VBA macros & OLE streams from DOC/XLS/RTF |
| | `olefile 0.46` | Low-level helper used by oletools |
| | `pdfminer.six 20231228` | Scrape plain text & objects out of PDFs |
| | `PyMuPDF 1.24.3` | Fast parser for embedded files & JavaScript inside PDFs |
| **IOC extraction & enrichment** | `requests 2.32.3` | Make REST calls to VirusTotal & AbuseIPDB |
| | `python-dotenv 1.0.1` | Load API keys from `.env` without hard-coding secrets |
| | `tldextract 5.1.2` | Split domain / sub-domain / TLD cleanly in URLs |
| **Reporting** | *(built-in Markdown / JSON generators)* | |
| | *Optional* `Jinja2 3.1.4` | Only needed if you later switch to HTML-template reports |
| **CLI niceties (optional)** | `rich 13.7.1` | Colourful console output & progress bars |
| | `tabulate 0.9.0` | Pretty ASCII tables for verbose mode |

> **Tip:** If you just want the core scanner, install with  
> ```bash
> pip install -r requirements.txt
> ```  
> and skip the optional “niceties.”  
> Uncomment them in `requirements.txt` whenever you want fancy console output.

flowchart TD
    A[CLI (main.py / Click)] -->|flags<br> file / dir| B[Dispatcher<br>(ioc_inspector_core/__init__)]
    
    subgraph Parsers
        B --> C1[PDF parser<br>pdf_parser.py]
        B --> C2[Office parser<br>doc_parser.py]
    end
    
    C1 -- URLs / IPs / embeds --> D[Enrichment]
    C2 -- URLs / IPs / macros --> D
    
    subgraph Enrichment
        D --> D1[VT lookup<br>url_reputation.py]
        D --> D2[AbuseIPDB<br>abuseipdb_check.py]
    end
    
    D --> E[Heuristics<br>heuristics.py]
    E --> F[Reports<br>report_generator.py]
    E --> G[Logger<br>logger.py]
    F --> H[(Markdown / JSON)]
    
    style Parsers fill:#f0f8ff,stroke:#333,stroke-width:1px
    style Enrichment fill:#fff8dc,stroke:#333,stroke-width:1px


## ➡️ Pathway

| Stage        | Still to do before the next stage |
|--------------|-----------------------------------|
| **pre-0.1** *(current)* | • Pin library versions in `requirements.txt`<br>• Add unit tests for PDF & macro branches<br>• Tighten error handling & logging<br>• Final-pass README polish |
| **0.1**      | Dependency-pinned CLI with Markdown / JSON output and a passing test-suite |
| **0.2**      | Optional CSV export · Docker image · extra threat-feed look-ups |
| **1.0**      | Performance tuning · full docs · stable config & semantic versioning |
