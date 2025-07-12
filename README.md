# IOC Inspector 🕵️‍♂️
[![CI](https://github.com/PKHarsimran/IOC-Inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/PKHarsimran/IOC-Inspector/actions/workflows/ci.yml)
[![Lint & Type-check](https://github.com/PKHarsimran/IOC-Inspector/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/PKHarsimran/IOC-Inspector/actions/workflows/lint.yml)  
[![Codecov](https://codecov.io/gh/PKHarsimran/IOC-Inspector/branch/main/graph/badge.svg?token=F7IJ44D5AC)](https://codecov.io/gh/PKHarsimran/IOC-Inspector)
[![License: MIT](https://img.shields.io/github/license/PKHarsimran/IOC-Inspector.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%20|%203.11-blue)




**Fast, SOC-ready malicious-document scanner** — turn suspicious PDFs, DOC(X), XLS(X) & RTFs into IOC-rich, SIEM-friendly reports.

---

## ✅ What's New
- Cross-platform CI with **Linux + Windows** and **Python 3.10/3.11** support
- Improved parser error handling with custom `ParserError`
- Dynamic API key loading for test reliability
- Coverage-gated CI with **>80%** unit test coverage
- Final README polish ✨

---

## ⚡ Why IOC Inspector?

| 🔑 | Value to Analysts |
|----|------------------|
| **One-command triage** | `ioc-inspector invoice.docx` → instant verdict & Markdown report |
| **Actionable scoring** | Custom heuristics blend macro flags, **auto-exec/API hits**, embedded-object metrics and threat-feed look-ups (VirusTotal + AbuseIPDB) into a **0-100 risk score** |
| **Analyst-first outputs** | Markdown for tickets, JSON / CSV for Splunk & Elastic |
| **Runs anywhere** | Linux • Windows • headless in GitHub Actions |
| **Extensible** | All logic lives in `ioc_inspector_core/` — swap parsers, add feeds, tweak weights |

---

## 🔍 Feature Matrix

| Category            | What you get                                                                                      |
|---------------------|----------------------------------------------------------------------------------------------------|
| **Formats**         | PDF • DOC / DOCX • XLS / XLSX • RTF                                                                |
| **Static Analysis** | Macro dump, **deep auto-exec & suspicious-API analysis**, obfuscation finder, embedded-object counter |
| **IOC Extraction**  | URLs • Domains • IPs • Base64 blobs • Hidden links                                                 |
| **Threat Enrichment** | VirusTotal • AbuseIPDB                                                                      |
| **Scoring Engine**  | Heuristic weights + rule modifiers (configurable)                                                  |
| **Reporting**       | Markdown & JSON (CSV optional)                                                                     |
| **Automation**      | Dir-recursive scan • Quiet / Verbose switches • GitHub Actions workflow                            |

---

## 🚀 Quick Start

```bash
# 1 – Clone
$ git clone https://github.com/PKHarsimran/IOC-Inspector.git
$ cd IOC-Inspector

# 2 – Install (Linux/macOS)
$ python -m venv venv && source venv/bin/activate

# 2 – Install (Windows)
> python -m venv venv && venv\Scripts\activate

# 3 – Install requirements
(venv) $ pip install -r requirements.txt

# 4 – Set up API keys
(venv) $ cp .env.example .env
(venv) $ nano .env    # Add your VT_API_KEY & ABUSEIPDB_API_KEY

# 5 – Run
(venv) $ python main.py --file examples/sample_invoice.docx --report
```

<details><summary>Example Output</summary>
examples/sample_invoice.docx: score=45 verdict=suspicious  
See reports/sample_invoice_report.md for full IOC tables.
</details>

---

## ⚙️ Configuration Highlights (settings.py)
```python
RISK_WEIGHTS = {
    "macro":          25,   # any VBA present
    "autoexec":       15,   # AutoOpen / Document_Open …
    "obfuscation":    20,   # long Base-64 blobs, XOR strings
    "susp_call":       5,   # CreateObject, Shell … (×3 capped at 15)
    "malicious_url":  30,   # VirusTotal consensus
    "malicious_ip":   25,   # AbuseIPDB ≥ confidence cutoff
}

VT_THRESHOLD            = 5    # vendors that must flag URL/IP malicious
ABUSE_CONFIDENCE_CUTOFF = 70   # AbuseIPDB confidence to flag IP
REPORT_FORMATS          = ["markdown", "json"]
```

🗂️ Repository Layout
```text
ioc-inspector/
├── ioc_inspector_core/         ← all analysis logic
│   ├── __init__.py
│   ├── pdf_parser.py
│   ├── doc_parser.py
│   ├── macro_analyzer.py       ← deep VBA heuristics
│   ├── url_reputation.py
│   ├── abuseipdb_check.py
│   ├── heuristics.py
│   └── report_generator.py
│
├── logger.py
├── main.py
├── settings.py
│
├── examples/
├── reports/        (git-ignored)
├── logs/           (git-ignored)
│
├── tests/
└── requirements.txt
```
---

## 📦 Dependencies at a Glance

| Category | Package | Why it’s needed |
|----------|---------|-----------------|
| Core     | `oletools`, `pdfminer.six`, `PyMuPDF`, `requests`, `python-dotenv`, `tldextract` | Parsing, enrichment, API config |
| Reporting| *(builtin)* | Markdown/JSON rendering |
| Optional | `tabulate`, `rich`, `jinja2` | Pretty console output, HTML reports |

---

### 🗺️ How the code flows

```mermaid
flowchart TD
    CLI["CLI (main.py)"] --> DISPATCH["Dispatcher (__init__.analyze)"]

    subgraph "Parsers"
        DISPATCH --> PDF["pdf_parser.py"]
        DISPATCH --> OFFICE["doc_parser.py"]
        OFFICE --> MACRO["macro_analyzer.py"]
    end

    PDF --> ENRICH
    MACRO --> ENRICH
    subgraph "Reputation enrichment"
        ENRICH --> VT["url_reputation.py"]
        ENRICH --> ABIP["abuseipdb_check.py"]
    end

    ENRICH --> SCORE["heuristics.py"]
    SCORE --> REPORT["report_generator.py"]
    SCORE --> LOG["logger.py"]
    REPORT --> OUTPUT["Markdown / JSON"]
```

**What happens step-by-step**

| Stage | Module | Job |
|-------|--------|-----|
| **CLI** | `main.py` | Reads flags, builds file list, prints a headline. |
| **Dispatcher** | `ioc_inspector_core/__init__.py` | Routes each file to the right parser. |
| **Parsers** | `pdf_parser.py` & `doc_parser.py` | Extract URLs, IPs, macros, embeds, JavaScript. |
| **Enrichment** | `url_reputation.py`, `abuseipdb_check.py` | Query VirusTotal & AbuseIPDB; attach verdicts. |
| **Scoring** | `heuristics.py` | Apply weights, produce 0-100 risk score & verdict. |
| **Reporting** | `report_generator.py` | Write Markdown + JSON with IOC tables. |
| **Logging** | `logger.py` | Console + rotating file breadcrumbs for every stage. |

---

## 📊 Coverage & Reliability
- ✅ **>80% test coverage** (enforced in CI)
- ✅ Coverage badge + reports via Codecov
- ✅ Works on **Linux and Windows** runners
- ✅ CLI smoke test validates API usage and report generation

---
# 🛣️ Roadmap to v1.0.0

This outlines the path for taking IOC Inspector from a solid prototype (v0.1.0) to a polished, production-ready v1.0.0 release.

---

## ✅ Phase 1: Foundation (v0.1.0 – Done)
- [x] Static IOC extraction: PDF, DOCX, XLSX, RTF
- [x] Threat enrichment: VirusTotal + AbuseIPDB
- [x] Heuristic-based scoring engine
- [x] Markdown + JSON reporting
- [x] Command-line interface with flags (`--report`, `--quiet`, etc.)
- [x] Cross-platform CI (Linux + Windows)
- [x] 80%+ test coverage with CLI smoke tests
- [x] Final README polish and first release tag

---

## 🚧 Phase 2: Stability & Feedback (`v0.2.x`)
Focus: Hardening the product & improving feedback loop

### Technical Improvements
- [ ] JSON schema validation for report output
- [ ] Improve error messaging with file context (e.g., filetype, parser used)
- [ ] Separate reporting logic from CLI to enable more formats

### Developer Experience
- [ ] Add `make test`, `make lint`, `make run` shortcuts
- [ ] Add GitHub Discussions or feedback template
- [ ] Incorporate feedback from test users

---

## ✨ Phase 3: Export & Integrations (`v0.3.x`)
Focus: SIEM-friendliness & analyst use

- [ ] CSV export for Splunk or Excel
- [ ] JSONL support for batch pipelines
- [ ] HTML export with embedded styles
- [ ] Normalize field naming for ingestion (e.g. `ioc.type`, `ioc.source`)
- [ ] (Optional) Tag known MITRE ATT&CK techniques from enriched IOCs

---

## 🚀 Phase 4: Productionization (`v0.9.x`)
Focus: Distribution & packaging polish

- [ ] Publish to PyPI for `pipx` install
- [ ] Provide Docker image with CLI entrypoint
- [ ] Build Windows binary via PyInstaller
- [ ] Automate changelogs & releases via GitHub Actions
- [ ] Use SemVer auto-tagging (`release-please`)

---

## 🏁 v1.0.0 Criteria
IOC Inspector will be tagged v1.0.0 when:

- [ ] All supported formats parse reliably with test coverage
- [ ] JSON / Markdown / CSV output is schema-stable
- [ ] Test coverage is >90%
- [ ] CLI is frictionless and documented
- [ ] Docker + PyPI builds work out-of-box
- [ ] Users validate usefulness via feedback

---

## 🧩 Post-1.0 Ideas
Optional features to consider post-v1.0:

- [ ] Ntfy/webhook notifications for batch runs
- [ ] Web UI using Streamlit or Flask
- [ ] Threat feed exporter (e.g. to MISP or CSV dump)
- [ ] Language support for French / Spanish SOC teams

---

💬 Questions? Feedback? File an [Issue](https://github.com/PKHarsimran/IOC-Inspector/issues) or start a discussion.

---
