# Security Policy

IOC Inspector parses potentially malicious files; security is a first-class concern.
If you find a vulnerability, please **report it privately** so we can fix it quickly.

---

## 🔒 Supported Versions

| Version | Status | Notes                           |
|---------|--------|---------------------------------|
| `main`  | ✅ Supported | Active development branch |
| `0.1.x` *(upcoming)* | ✅ Supported | First stable release – security patches only |
| `<0.1` (pre-release commits & tags) | ❌ Unsupported | Please upgrade |

We follow **semantic versioning** once `v1.0` lands: the last minor of each major line receives security fixes for 12 months.

---

## 📢 Reporting a Vulnerability

1. **Email** `sec@pkharsimran.dev` *(PGP key on Keybase)*  
   – or open a **GitHub Security Advisory** (preferred for GitHub users).  
2. Please include:  
   * Clear reproduction steps or PoC file  
   * Affected version / commit hash  
   * Impact assessment if known  
3. You’ll receive an acknowledgment within **48 hours** (often sooner).  
4. We aim to ship fixes within **14 days**, coordinated with you for public disclosure.  
5. Credit will be given in the changelog unless you request anonymity.

> **Do not file vulnerabilities in public GitHub issues**—this risks exploitation before a patch is ready.

---

## 🔐 Security Best-Practices for Users

* Run IOC Inspector inside a **restricted user account**—never as Administrator/Root.  
* If possible, open suspicious docs in a sandbox (VM / container) before scanning.  
* Keep your **VirusTotal** and **AbuseIPDB** API keys private; never commit them.

Thank you for helping keep IOC Inspector and its users safe!
