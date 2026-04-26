<div align="center">

<!-- BANNER -->
<img src="https://img.shields.io/badge/-%F0%9F%9B%A1%EF%B8%8F%20AutoVuln-0b0f1a?style=for-the-badge&logoColor=white" alt="AutoVuln" height="60"/>

# AutoVuln: Passive Security Scanner

**A Burp Suite extension that silently watches every HTTP response and surfaces security vulnerabilities in real time.**

[![Version](https://img.shields.io/badge/version-1.0.0-3b82f6?style=flat-square)](https://github.com)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Compatible-f97316?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQxIDAtOC0zLjU5LTgtOHMzLjU5LTggOC04IDggMy41OSA4IDgtMy41OSA4LTggOHoiLz48L3N2Zz4=)](https://portswigger.net/burp)
[![Python](https://img.shields.io/badge/Jython-2.7-facc15?style=flat-square&logo=python&logoColor=white)](https://www.jython.org)
[![License](https://img.shields.io/badge/license-MIT-22c55e?style=flat-square)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-8b5cf6?style=flat-square)](https://github.com)

<br/>

> **AutoVuln passively inspects every in-scope HTTP request/response flowing through Burp Suite,  
> automatically classifying vulnerabilities by severity, deduplicating across endpoints,  
> and exporting professional reports, with zero active probing.**

<br/>

</div>

---

## ⚡ Quick Install

### Step 1: Install Jython (if not already configured)

Burp Suite needs Jython to run Python extensions. Skip this step if you already have it set up.

1. Download the **Jython Standalone JAR** from [jython.org/download](https://www.jython.org/download)  
   (get the file named `jython-standalone-2.7.x.jar`)
2. In Burp Suite, go to `Extensions → Options → Python Environment`
3. Under **Python Environment**, click `Select file...`
4. Choose the downloaded `.jar` file
5. Click `OK` — Burp will confirm Jython is loaded

### Step 2: Load AutoVuln

```
1. In Burp Suite, go to  Extensions → Add
2. Set Extension Type    → Python
3. Click Select file     → choose autovuln.py
4. Click Next            → AutoVuln tab appears in the main tab bar
```

### Step 3: Add your target to Burp scope

> **AutoVuln only processes in-scope traffic.** It will not surface any findings until your target is added to Burp's scope.

```
1. Go to Target → Scope
2. Click Add (under Include in scope)
3. Enter your target URL or hostname  e.g. https://example.com
4. Click OK
```

Once your target is in scope, AutoVuln will begin passively analysing every request that flows through Burp and findings will appear in the AutoVuln tab in real time.

---

## 🎯 What It Does

AutoVuln registers as a passive `IHttpListener`. For every response that matches your **Burp scope**, it runs eight independent analysis modules and surfaces findings directly in its dark-themed UI tab. No manual scanning, no active requests, no noise from out-of-scope traffic.

```
Browser / Proxy Tool
      │
      ▼
 Burp Suite (HTTP traffic)
      │  IHttpListener intercept
      ▼
 AutoVuln _process()
      ├── check_headers()      → Security headers, CORS, HSTS, CSP, Cache
      ├── check_cookies()      → Flags, PII in cookies, JWT/JSON in values  
      ├── check_versions()     → Vulnerable JS libraries, MySQL, framework versions
      ├── check_body()         → Internal IP, email, error/stack trace disclosure
      ├── check_html()         → Forms, autocomplete, charset, file upload
      ├── check_request()      → JWT Bearer PII analysis
      ├── check_methods()      → Dangerous HTTP verbs (PUT, DELETE, TRACE...)
      └── check_secrets()      → 30+ secret patterns (AWS, GCP, GitHub, Stripe...)
              │
              ▼
       FindingStore (dedup + merge)
              │
              ▼
         AutoVuln UI Tab
```

---

## 🛡️ Detection Coverage

### Module 1: Security Headers

| Finding | Severity | CWE |
|---------|----------|-----|
| Website is Vulnerable to Clickjacking | Medium | CWE-1021 |
| HTTP Strict Transport Security (HSTS) Disabled | Medium | CWE-319 |
| Content Security Policy Header is Missing | Medium | CWE-116 |
| Misconfigured CSP Security Header (`unsafe-inline`, wildcards) | Medium | CWE-116 |
| X-Content-Type Header is Missing | Low | CWE-693 |
| Server Information Disclosure (version in header) | Medium | CWE-200 |
| Vulnerable Framework Version Disclosure (`X-Powered-By`, `X-AspNet-Version`) | Medium | CWE-200 |
| Misconfigured Access Control Allow Origin (CORS `*`) | High | CWE-942 |
| Access Control Allow Origin Not Defined | Informational | CWE-942 |
| Cacheable HTTP Response (HTML/JSON without `no-store`) | Low | CWE-524 |

### Module 2: Cookie Analyzer

| Finding | Severity | CWE |
|---------|----------|-----|
| Cookie HTTPOnly Flag Missing | Low | CWE-1004 |
| Cookie Secure Flag Missing | Low | CWE-614 |
| Cookie Path Set to Root | Low | CWE-1004 |
| Sensitive PII Data Passed in Cookie (email in value) | High | CWE-312 |
| Data Exposure in Cookie (JWT in value) | Medium | CWE-312 |
| Data Exposure in Cookie (serialized JSON in value) | Medium | CWE-312 |

### Module 3: Vulnerable Library Versions

| Finding | Severity | CWE |
|---------|----------|-----|
| Vulnerable jQuery Version (< 3.6.0) | Medium | CWE-1104 |
| Vulnerable/Outdated Bootstrap Version (< 3.4.1 or 4.0–4.3.0) | Medium | CWE-1104 |
| Vulnerable JavaScript Version Disclosure (AngularJS < 13.0.0) | Medium | CWE-1104 |
| Outdated MySQL Version Disclosure | Medium | CWE-200 |
| JavaScript Version Disclosure (versioned filenames) | Informational | CWE-200 |

### Module 4: Response Body Scanner

| Finding | Severity | CWE |
|---------|----------|-----|
| Email Address Disclosed | Low | CWE-200 |
| Internal IP Disclosure (RFC-1918 ranges) | Medium | CWE-200 |
| Improper Error Handling (stack traces, SQL errors, exceptions) | Medium | CWE-209 |

### Module 5: HTML Analyzer

| Finding | Severity | CWE |
|---------|----------|-----|
| Password Autocomplete Enabled | Low | CWE-522 |
| HTML Does Not Specify Charset | Informational | CWE-116 |
| Character Limit Not Set on Input Field (no `maxlength`) | Low | CWE-400 |
| Path-Relative Stylesheet Import | Low | CWE-693 |
| Uploaded File Size Limit Not Defined | Low | CWE-400 |
| Phone Number Disclosure in View Page Source | Informational | CWE-200 |

### Module 6: Request Analyzer

| Finding | Severity | CWE |
|---------|----------|-----|
| Sensitive Data in Authorization Bearer (PII in JWT payload) | High | CWE-312 |

### Module 7: HTTP Methods

| Finding | Severity | CWE |
|---------|----------|-----|
| OPTIONS Method Enabled | Low | CWE-16 |
| Dangerous HTTP Methods Enabled (PUT / DELETE / TRACE / CONNECT) | Critical | CWE-650 |

### Module 8: Secrets Detector (30+ patterns)

<details>
<summary><strong>Click to expand full secrets coverage</strong></summary>

| Secret Type | Severity | CWE |
|-------------|----------|-----|
| AWS Access Key ID (`AKIA…`) | Critical | CWE-798 |
| AWS Secret Access Key | Critical | CWE-798 |
| AWS S3 Bucket URL | Medium | CWE-200 |
| Google API Key (`AIza…`) | Critical | CWE-798 |
| Google OAuth Client Secret (`GOCSPX-…`) | Critical | CWE-798 |
| Firebase API Key | Medium | CWE-798 |
| GitHub Personal Access Token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) | Critical | CWE-798 |
| GitHub App Token | Critical | CWE-798 |
| GitLab Personal Access Token (`glpat-…`) | Critical | CWE-798 |
| Stripe Secret Key (`sk_live_`, `sk_test_`) | Critical | CWE-798 |
| Stripe Publishable Key (`pk_live_`, `pk_test_`) | Low | CWE-200 |
| Slack Bot Token (`xoxb-…`) | High | CWE-798 |
| Slack User Token (`xoxp-…`) | High | CWE-798 |
| Slack Webhook URL | Medium | CWE-200 |
| Twilio API Key (`SK…`) | High | CWE-798 |
| SendGrid API Key (`SG.…`) | High | CWE-798 |
| Mailgun API Key (`key-…`) | High | CWE-798 |
| Azure Storage Connection String | Critical | CWE-798 |
| GCP Service Account Key (JSON fragment) | Critical | CWE-798 |
| RSA Private Key (`BEGIN RSA PRIVATE KEY`) | Critical | CWE-321 |
| Generic Private Key (EC, DSA, OPENSSH, PGP, ENCRYPTED) | Critical | CWE-321 |
| PGP Private Key Block | Critical | CWE-321 |
| SSH Private Key (`BEGIN OPENSSH PRIVATE KEY`) | Critical | CWE-321 |
| Generic Database Connection String (MySQL, PostgreSQL, MongoDB, MSSQL, Oracle, JDBC) | Critical | CWE-798 |
| MongoDB Connection String (`mongodb://`, `mongodb+srv://`) | Critical | CWE-798 |
| Hardcoded Password in Source (`password =`, `passwd:`, `pwd =`) | Critical | CWE-259 |
| Generic API Secret in Source (`api_secret`, `client_secret`, `secret_key`) | Critical | CWE-798 |
| Bearer Token in Response Body | High | CWE-312 |
| Encryption Key (Hex 256-bit, AES/cipher key patterns) | Critical | CWE-321 |
| Encryption Key (Base64, 256-bit) | Critical | CWE-321 |
| NPM Auth Token (`.npmrc` leak) | Critical | CWE-798 |
| JWT Signing Secret (`jwt_secret =`) | Critical | CWE-798 |

</details>

---

## 🖥️ UI Features

### Main Dashboard

```
┌─────────────────────────────────────────────────────────────────────┐
│  🛡 AutoVuln   passive security scanner        ● scanning  12 findings│
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  12  │  │    2     │  │    3     │  │    5     │  │    2     │  │
│  │TOTAL │  │ CRITICAL │  │  HIGH    │  │  MEDIUM  │  │   LOW    │  │
│  └──────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
├─────────────────────────────────────────────────────────────────────┤
│  [Clear]  [Export CSV]  [Export DOCX]                [⏸ Pause]       │
├──────┬────────────┬──────────────────────┬──────────────┬─────┬─────┤
│  #   │  Severity  │  Finding             │  Endpoint    │ Sta │ CWE │
├──────┼────────────┼──────────────────────┼──────────────┼─────┼─────┤
│  1   │  CRITICAL  │  Dangerous HTTP...   │  3 endpoints │ 200 │ ... │
│  2   │  HIGH      │  CORS Wildcard...    │  /api/v1/... │ 200 │ ... │
└──────┴────────────┴──────────────────────┴──────────────┴─────┴─────┘
```

**Severity Cards:** Clickable cards filter the table instantly. Shows counts for Total, Critical, High, Medium, Low.

**Scan Status:** Live indicator in the header. Shows `● scanning` (green) or `● paused` (red) with a real-time finding counter.

**Pause / Resume:** Instantly halts all passive scanning without unloading the extension. Useful during authenticated flows where you don't want noise.

### Finding Detail Panel

Click any row to expand the full detail panel inline:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  [CRITICAL]  Dangerous HTTP Methods Enabled    [▶ Send to Repeater]     │
├──────────────────────────┬──────────────────────────────────────────────┤
│  TARGET                  │  CLASSIFICATION                              │
│  Host:        target.com │  CWE:       CWE-650                         │
│  HTTP Status: 200        │  Severity:  Critical                        │
│  URL:         /api/v1/.. │                                              │
├──────────────────────────┴──────────────────────────────────────────────┤
│  DESCRIPTION                                                            │
│  The server allows dangerous HTTP methods: PUT, DELETE. These can be   │
│  abused to modify server-side resources.                               │
├─────────────────────────────┬───────────────────────────────────────────┤
│  EVIDENCE                   │  REMEDIATION                             │
│  Allow: GET, POST, PUT,     │  Disable PUT, DELETE, TRACE, CONNECT at  │
│  DELETE, OPTIONS            │  web server or WAF level.                │
├─────────────────────────────┴───────────────────────────────────────────┤
│  AFFECTED ENDPOINTS (3)                              3 endpoints affected│
│  [1]  https://target.com/api/v1/users  (HTTP 200)                      │
│  [2]  https://target.com/api/v1/items  (HTTP 200)                      │
│  [3]  https://target.com/api/admin     (HTTP 302)                      │
└─────────────────────────────────────────────────────────────────────────┘
```

### Right-Click Context Menu

Right-click any table row for quick clipboard actions:

- **Copy Endpoint URL:** clean path without query string
- **Copy Full URL:** complete URL including query parameters
- **Copy Evidence:** raw evidence text for pasting into reports

---

## 🔁 Smart Deduplication & Endpoint Merging

AutoVuln deduplicates at two levels:

**1. Finding-level dedup:** The same finding type on the same host is stored as **one row**, not N rows:

```
✅ AutoVuln behaviour
────────────────────────────────────
#1  HSTS Missing   3 endpoints
```

**2. Endpoint-level dedup:** Query parameters are stripped before comparing:  
`/login?next=/dashboard` and `/login?ref=email` are treated as the same endpoint `/login`.

**3. Merge on hit:** When a new endpoint triggers an existing finding, it is appended to `Affected Endpoints` automatically. The detail panel and both export formats reflect all affected paths.

---

## 📤 Export Formats

### CSV Export

Columns: `#` · `Finding Name` · `Severity` · `CWE` · `Host` · `Endpoints Count` · `Affected Endpoints (endpoint | HTTP status)` · `Description` · `Evidence` · `Remediation`

- Formula injection prevention: cells starting with `=`, `+`, `-`, `@` are prefixed with `'` to prevent execution in Excel/Google Sheets
- Multi-endpoint findings list all affected paths semicolon-separated in a single cell

### DOCX Export

- Title page with generation timestamp and total finding count
- Executive summary table with counts per severity
- Per-finding tables with: Severity · CWE · Host · Affected Endpoints · Description · Evidence · Remediation
- Multi-endpoint findings show a numbered list in the Affected Endpoints row
- No external dependencies. Built with raw OOXML, opens in Word and LibreOffice

---

## 🔀 Send to Repeater

When viewing any finding detail, click **▶ Send to Repeater** to instantly forward the original captured request into Burp's Repeater tab, pre-labelled with the finding name for easy tracking.

```
Finding:  "Website is Vulnerable to Clickjacking"
     │
     └─► Burp Repeater  Tab: "Website is Vulnerable to Clickja"
                         Ready to modify & replay
```

> Only findings captured **during the current session** have a stored raw request.  
> The button is automatically disabled for findings where no request data is available.

---

## 🏗️ Architecture

```
autovuln.py
│
├── Finding                  Data model. Stores name, severity, CWE, host, url,
│                            description, evidence, remediation, affected_endpoints[].
│
├── FindingStore             Thread-safe in-memory store with O(1) dedup via dict index.
│                            Fires UI listener callbacks on every add/merge/clear.
│
├── Check Modules (8×)       Pure functions. Return list of finding dicts.
│   ├── check_headers()
│   ├── check_cookies()
│   ├── check_versions()
│   ├── check_body()
│   ├── check_html()
│   ├── check_request()
│   ├── check_methods()
│   └── check_secrets()
│
├── dispatch()               Calls all 8 modules, wraps results in Finding objects.
│
├── export_csv()             CSV writer with formula injection prevention.
├── export_docx_simple()     Raw OOXML DOCX writer, no external deps.
│
├── UIBuilder (JRunnable)    Builds and owns the entire Swing UI.
│   ├── Header bar           Brand, scan status, finding counter.
│   ├── Stat cards (5×)      Filterable severity counters.
│   ├── Toolbar              Clear, Export CSV, Export DOCX, Pause.
│   ├── JTable               Sortable findings table with custom cell renderers.
│   ├── Detail panel         Inline expanded view with Send to Repeater.
│   └── refresh()            Called on EDT via SwingUtilities.invokeLater().
│
└── BurpExtender             Entry point. Implements IBurpExtender + IHttpListener + ITab.
```

---

## ⚙️ Configuration & Behaviour

| Behaviour | Details |
|-----------|---------|
| **Scope enforcement** | Only processes URLs marked in-scope in Burp's Target scope. Out-of-scope traffic is ignored entirely. |
| **Status code filtering** | Skips `404` and `5xx` responses to avoid flooding findings from error pages. |
| **Body size limit** | Reads up to `512 KB` of response body per request. Larger bodies are truncated for performance. |
| **Passive only** | No active requests are ever made. AutoVuln only reads traffic that already flows through Burp. |
| **Thread safety** | All UI updates are dispatched via `SwingUtilities.invokeLater()`. The store fires callbacks safely from any thread. |

---

## 📋 Severity Reference

| Level | Colour | Meaning |
|-------|--------|---------|
| 🔴 **Critical** | Red | Immediate exploitation risk: credentials, private keys, dangerous methods |
| 🟠 **High** | Orange | Significant attack surface: CORS wildcard, PII in cookies/JWT, known-bad tokens |
| 🟡 **Medium** | Yellow | Security weakening: missing headers, version disclosure, CSP misconfig |
| 🟢 **Low** | Yellow-green | Defence-in-depth gaps: cookie flags, autocomplete, relative CSS imports |
| 🔵 **Informational** | Blue | Awareness items: charset, phone/JS version disclosure |

---

## 🔒 Security Properties of the Extension Itself

- **No active scanning:** reads responses only, sends no requests
- **No network calls:** zero outbound traffic from the extension
- **No file writes:** only when you explicitly trigger an export
- **Secrets redacted in evidence:** matched secret values are partially masked (first 6 chars + `****`) in the UI and exports
- **ReDoS-hardened regexes:** all quantifiers in secret patterns are bounded; non-greedy alternates used where applicable
- **CSV formula injection prevention:** dangerous leading characters prefixed before write
- **JWT payload decoded safely:** `errors="replace"` on UTF-8 decode, wrapped in `try/except`

---

## 🛠️ Requirements

| Component | Requirement |
|-----------|-------------|
| Burp Suite | Community or Professional (any recent version) |
| Jython | 2.7.x, configured in `Extensions → Options → Python Environment` |
| Java | JDK 8+ (bundled with Burp) |
| OS | Windows, macOS, Linux |
| Dependencies | **None** (single file, stdlib only) |

---

## 📁 Files

```
autovuln.py        ← The entire extension. Drop this into Burp.
README.md          ← This file.
```

---

## 🚀 Usage Workflow

```
1.  Add target to Burp scope
        Target → Scope → Add

2.  Load AutoVuln
        Extensions → Add → Python → autovuln.py

3.  Browse the target (manually or via Spider/Crawler)
        Findings appear in real time as traffic flows through Burp

4.  Use severity cards to filter
        Click [HIGH] to see only high-severity findings

5.  Click any row to inspect
        Full detail panel with evidence, remediation, affected endpoints

6.  Send to Repeater for validation
        Click [▶ Send to Repeater] → modify headers → resend → confirm

7.  Export for reporting
        [Export CSV]  spreadsheet-ready
        [Export DOCX] client-ready Word document
```

---

## 🤝 Contributing

Contributions welcome. New check modules, additional secret patterns, and UI improvements are all fair game.

When adding a new check module:

1. Create a `check_yourmodule()` function returning a list of `_found(...)` dicts
2. Add it to `dispatch()` 
3. Each finding needs: `name`, `severity`, `description`, `evidence`, `remediation`, `cwe`
4. Use `_trunc(s, n)` on any user-controlled value before putting it in `evidence`
5. Bound all regex quantifiers: no `{n,}` without an upper limit

---

<div align="center">

**Built for security professionals, by a security professional.**

*AutoVuln is a passive scanner. All testing should be performed only on systems you own or have explicit written permission to test.*

<br/>

[![Made with Python](https://img.shields.io/badge/Made%20with-Python%20%2F%20Jython-3b82f6?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![Burp Extension](https://img.shields.io/badge/Burp%20Suite-Extension-f97316?style=flat-square)](https://portswigger.net/burp/documentation/desktop/extensions)

</div>
