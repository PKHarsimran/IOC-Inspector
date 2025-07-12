# Unit Testing Guide

This document provides an overview of the unit-test suite added in the recent merge, explaining its structure, purpose, and how to extend it.

---

## 🎯 Goals of the Test Suite

1. **Validate parser behavior** (PDF & Office):
   - Ensure corrupt inputs raise `ParserError` with proper logging.
   - Confirm valid inputs produce the expected output schema and types.  
2. **Catch regressions** in future changes to parsing, enrichment, scoring, or reporting logic.  
3. **Maintain a stable API contract**: Parsers must keep returning the same field names and data types.  
4. **Enforce code quality** via automated linting (Ruff) and type-checking (Mypy).  
5. **Achieve ≥ 80 % code coverage**, so any drop below that threshold fails the CI build.  

---

## 🗂️ Test Structure

```
tests/
├── conftest.py # shared fixtures and autouse stubs
└── unit/
├── test_pdf_parser_error.py # corrupt PDF → ParserError + ERROR log
├── test_pdf_parser_ok.py # valid PDF → correct fields & types
├── test_doc_parser.py # Office parser happy & failure paths
├── test_analyze_dispatch.py # dispatch logic smoke tests
├── test_heuristics.py # scoring logic scenarios
├── test_url_reputation.py # VirusTotal helper, no-key cases
├── test_abuseipdb_check.py # AbuseIPDB helper, no-key & empty input
└── test_report_generator.py # Markdown & JSON report outputs
```

### Shared Fixtures (`conftest.py`)

- **`sample_pdf`**: Path to `examples/test.pdf` (benign PDF sample).  
- **`sample_docm`**: Path to `examples/macro_test.docm` (Office file with macros).  
- **`stub_requests`** (autouse): Monkey-patches `requests.get` and `requests.post` to return dummy JSON, preventing real HTTP calls during unit tests.  

---

## 🔍 Test Categories

### 1. Parser Tests

#### PDF Parser
- **`test_pdf_parser_error.py`**  
  Creates a 1-byte “garbage.pdf” → expects `ParserError` and an ERROR log record.

- **`test_pdf_parser_ok.py`**  
  Uses `sample_pdf` → asserts presence of keys (`type`, `urls`, `ips`, `embedded_files`, `js_count`) and correct types.

#### Office Parser
- **`test_doc_parser.py`**  
  - **Happy path**: `parse_office(sample_docm)` → `macro` flag true, URL/IP lists.  
  - **Failure path**: Corrupt DOCM → raises `ParserError`.

### 2. Dispatcher Tests

- **`test_analyze_dispatch.py`**  
  Ensures `analyze()` chooses **PDF** or **Office** parser based on file extension.

### 3. Core Logic Tests

- **`test_heuristics.py`**  
  Verifies scoring output for various combinations of IOCs (macro, embedded, JS).

- **`test_url_reputation.py`**  
  Tests the internal `_vt_url_id` function and early exit when `VT_API_KEY` is unset.

- **`test_abuseipdb_check.py`**  
  Tests early-exit when `ABUSEIPDB_API_KEY` is unset or input list is empty.

### 4. Report Generator Tests

- **`test_report_generator.py`**  
  Generates both Markdown and JSON reports to a temporary directory and asserts key content.

---

## ✅ Running Tests Locally

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests with coverage
pytest
```
The pytest.ini file automatically applies --cov=ioc_inspector_core --cov-fail-under=80.

🚀 Extending the Suite

- Add new parser tests: Follow the test_* naming convention and use sample_pdf/sample_docm fixtures.

- Mock external services: Use the stub_requests fixture or create similar stubs for new clients.

- Increase coverage: Write tests for any untested functions in ioc_inspector_core/ (e.g., deeper abuseIPDB branches).

- Integration tests: Create a new folder tests/integration/ for end-to-end scenarios using real API keys.

