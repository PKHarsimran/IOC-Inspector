# IOC Inspector 🕵️‍♂️

**Fast, SOC‑ready malicious document scanner** that turns suspicious PDFs, DOC(X), XLS(X), and RTFs into IOC‑rich, SIEM‑friendly reports.

---

## ⚡ Why IOC Inspector?
- **One‑command triage** – run `ioc-inspector invoice.docx` and get an instant verdict.
- **Actionable scoring** – custom heuristics blend macro analysis, embedded‑object metrics, and feed lookups (VirusTotal + AbuseIPDB) into a 0‑100 risk score.
- **Analyst‑first outputs** – Markdown for tickets, JSON/CSV for Splunk & Elastic.
- **Runs anywhere** – Linux, macOS, Windows, or headless in GitHub Actions.

---

## 🔍 Feature Matrix
| Category           | What you get                                                                 |
|--------------------|------------------------------------------------------------------------------|
| **Formats**        | PDF • DOC/DOCX • XLS/XLSX • RTF                                              |
| **Static Analysis**| Macro dump, obfuscation finder, embedded‑object counter                      |
| **IOC Extraction** | URLs, domains, IPs, base64 strings, hidden links                             |
| **Threat Enrichment** | VirusTotal, AbuseIPDB, URLScan.io (configurable)                          |
| **Scoring Engine** | Adjustable heuristic weights + rule‑based modifiers                         |
| **Reporting**      | Markdown & JSON (optional CSV)                                               |
| **Automation**     | Batch directory scan, quiet/verbose modes, GitHub Actions workflow          |

---

## 🚀 Quick Start
```bash
# 1 – Clone
$ git clone https://github.com/<your-user>/ioc-inspector.git
$ cd ioc-inspector

# 2 – Install
$ python -m venv venv && source venv/bin/activate
$ pip install -r requirements.txt

# 3 – Configure APIs
$ cp .env.example .env && nano .env  # add VT_API_KEY & ABUSEIPDB_API_KEY

# 4 – Scan a file
$ python ioc_inspector.py --file examples/sample_invoice.docx --report
```

---

## ⚙️ GitHub Actions
Trigger scans directly in the GitHub UI:
```
Actions ► **Run Analyzer** ► target_file=examples/sample_invoice.docx
```
Artifacts: Markdown & JSON reports.  
Secrets consumed: `VT_API_KEY`, `ABUSEIPDB_API_KEY` (stored in **Repo → Settings → Secrets → Actions**).

---

## 🛠️ Configuration Highlights (`config.py`)
- `RISK_WEIGHTS` – tweak scoring for macros, obfuscation, malicious URLs
- `VT_THRESHOLD` – min vendor count to consider a URL/IP malicious
- `ABUSE_CONFIDENCE_CUTOFF` – min AbuseIPDB confidence to flag IPs
- `REPORT_FORMATS` – enable/disable Markdown, JSON, CSV

---

**Repo structure**|
```
ioc-inspector/
├── analyzer/
│   ├── __init__.py
│   ├── pdf_parser.py
│   ├── doc_parser.py
│   ├── heuristics.py
│   ├── macro_analyzer.py
│   ├── url_reputation.py
│   ├── abuseipdb_check.py
│   └── report_generator.py
├── examples/
│   └── sample_invoice.docx
├── reports/
│   └── .gitkeep
├── main.py
├── config.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
└── .github/
    └── workflows/
        └── analyzer.yml
```
