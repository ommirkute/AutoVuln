# -*- coding: utf-8 -*-
# AutoVuln - Passive Vulnerability Scanner for Burp Suite
# Language: Python (Jython 2.7 compatible)
# Load directly in Burp: Extensions > Add > Extension Type: Python
# No external dependencies required.

from burp import IBurpExtender, IHttpListener, ITab
from java.io import PrintWriter, File
from java.awt import BorderLayout, FlowLayout, GridLayout, Font, Color, Dimension, Cursor
from java.awt.event import MouseAdapter
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
from javax.swing import (JPanel, JScrollPane, JTable, JLabel, JButton,
                          JTextArea, JFileChooser, JOptionPane, BorderFactory,
                          SwingUtilities, JSplitPane, JPopupMenu, JMenuItem)
from javax.swing import BoxLayout
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing import SwingConstants
from java.lang import Runnable as JRunnable
import re
import base64
import csv
import datetime

# ===============================================================================
# CONSTANTS
# ===============================================================================

VERSION = "1.0.0"
EXT_NAME = "AutoVuln - Passive Scanner"

SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH   = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW    = "Low"
SEVERITY_INFO   = "Informational"

# ===============================================================================
# FINDING MODEL
# ===============================================================================

class Finding(object):
    def __init__(self, name, severity, description, evidence, remediation, cwe, host, url, status_code=0,
                 raw_request=None, http_service=None):
        self.name        = name
        self.severity    = severity
        self.description = description
        self.evidence    = evidence
        self.remediation = remediation
        self.cwe         = cwe
        self.host        = host
        self.url         = url
        self.status_code = status_code
        # Clean endpoint = scheme + host + path only (no query string, no fragment)
        _parts           = url.split("?")[0].split("#")[0]
        self.endpoint    = _parts
        self.timestamp   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # affected_endpoints: list of dicts, one per unique endpoint this finding was seen on.
        # Each dict: {endpoint, status_code, raw_request, http_service}
        # The first entry mirrors this finding's own initial hit.
        self.affected_endpoints = [{
            "endpoint":     self.endpoint,
            "status_code":  status_code,
            "raw_request":  raw_request,
            "http_service": http_service,
        }]

    @property
    def raw_request(self):
        """Primary request -- first captured endpoint (used by Send to Repeater)."""
        return self.affected_endpoints[0]["raw_request"] if self.affected_endpoints else None

    @property
    def http_service(self):
        """Primary HTTP service -- first captured endpoint."""
        return self.affected_endpoints[0]["http_service"] if self.affected_endpoints else None

    def merge_endpoint(self, url, status_code, raw_request=None, http_service=None):
        """Add a new endpoint occurrence to this finding (dedup by clean endpoint path)."""
        ep = url.split("?")[0].split("#")[0]
        for existing in self.affected_endpoints:
            if existing["endpoint"] == ep:
                return  # already recorded this exact endpoint
        self.affected_endpoints.append({
            "endpoint":     ep,
            "status_code":  status_code,
            "raw_request":  raw_request,
            "http_service": http_service,
        })

    def dedup_key(self):
        # Dedup per (host, finding name) only -- same finding on different endpoints
        # is merged via merge_endpoint() rather than stored as a new row.
        return "{}|{}".format(self.host, self.name)


# ===============================================================================
# FINDING STORE (in-memory, dedup per host + finding name + endpoint URL)
# ===============================================================================

class FindingStore(object):
    def __init__(self):
        self._index    = {}   # key -> Finding (O(1) lookup, replaces linear scan)
        self._findings = []
        self._listeners = []

    def _fire(self):
        for cb in self._listeners:
            try:
                cb()
            except Exception:
                pass  # never let a UI callback crash the listener loop

    def add(self, finding):
        key = finding.dedup_key()
        if key not in self._index:
            self._index[key] = finding
            self._findings.append(finding)
            self._fire()
            return True
        else:
            # Finding already exists -- merge this endpoint (O(1) lookup)
            ep0 = finding.affected_endpoints[0] if finding.affected_endpoints else {}
            self._index[key].merge_endpoint(
                finding.url,
                finding.status_code,
                ep0.get("raw_request"),
                ep0.get("http_service"))
            self._fire()
            return False

    def get_all(self):
        return list(self._findings)

    def clear(self):
        self._index.clear()
        del self._findings[:]
        self._fire()

    def add_listener(self, cb):
        self._listeners.append(cb)

    def size(self):
        return len(self._findings)

    def summary(self):
        counts = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0, SEVERITY_LOW: 0, SEVERITY_INFO: 0}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


# ===============================================================================
# CHECK MODULES
# ===============================================================================

def _found(name, severity, description, evidence, remediation, cwe):
    return dict(name=name, severity=severity, description=description,
                evidence=evidence, remediation=remediation, cwe=cwe)

def _trunc(s, n=150):
    if not s:
        return ""
    s = s if isinstance(s, str) else str(s)
    return s[:n] + "..." if len(s) > n else s


# -- 1. Header Checker ----------------------------------------------------------

def check_headers(resp_headers, req_headers=None):
    results = []
    h = {k.lower(): v for k, v in resp_headers.items()}
    rh = {k.lower(): v for k, v in (req_headers or {}).items()}
    content_type = h.get("content-type", "").lower()

    # X-Frame-Options
    if "x-frame-options" not in h:
        results.append(_found(
            "Website is Vulnerable to Clickjacking", SEVERITY_MEDIUM,
            "The X-Frame-Options header is missing. Attackers can embed the page in an iframe "
            "and perform clickjacking attacks, tricking users into clicking malicious elements.",
            "X-Frame-Options header is absent in the response.",
            "Add: X-Frame-Options: DENY or SAMEORIGIN. Alternatively use CSP frame-ancestors directive.",
            "CWE-1021"))

    # HSTS
    if "strict-transport-security" not in h:
        results.append(_found(
            "HTTP Strict Transport Security (HSTS) Disabled", SEVERITY_MEDIUM,
            "The Strict-Transport-Security header is missing. Without HSTS, browsers may connect "
            "over HTTP, exposing traffic to man-in-the-middle attacks.",
            "Strict-Transport-Security header is absent.",
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "CWE-319"))

    # CSP
    csp = h.get("content-security-policy", None)
    if csp is None:
        results.append(_found(
            "Content Security Policy Header is Missing", SEVERITY_MEDIUM,
            "The Content-Security-Policy header is not set, increasing XSS and data injection risk.",
            "Content-Security-Policy header is absent.",
            "Define a strict CSP: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
            "CWE-116"))
    elif any(x in csp for x in ["unsafe-inline", "unsafe-eval", "*"]):
        results.append(_found(
            "Misconfigured CSP Security Header", SEVERITY_MEDIUM,
            "The CSP header contains dangerous directives (unsafe-inline, unsafe-eval, or wildcard) "
            "that significantly weaken its protection.",
            "CSP: " + _trunc(csp),
            "Remove unsafe-inline, unsafe-eval, and wildcards. Use nonces or hashes for inline scripts.",
            "CWE-116"))

    # X-Content-Type-Options
    if "x-content-type-options" not in h:
        results.append(_found(
            "X-Content-Type Header is Missing", SEVERITY_LOW,
            "Missing X-Content-Type-Options allows browsers to MIME-sniff responses, enabling certain attacks.",
            "X-Content-Type-Options header is absent.",
            "Add: X-Content-Type-Options: nosniff",
            "CWE-693"))

    # Server header version disclosure
    server = h.get("server", "")
    if server and re.search(r'[0-9]', server):
        results.append(_found(
            "Server Information Disclosure", SEVERITY_MEDIUM,
            "The Server header discloses web server software and version, aiding attackers in targeting CVEs.",
            "Server: " + server,
            "Suppress version from Server header. Apache: ServerTokens Prod | Nginx: server_tokens off",
            "CWE-200"))

    # X-Powered-By
    powered_by = h.get("x-powered-by", "")
    if powered_by:
        results.append(_found(
            "Vulnerable Framework Version Disclosure", SEVERITY_MEDIUM,
            "X-Powered-By reveals server-side technology and version. Enables targeted CVE exploitation.",
            "X-Powered-By: " + powered_by,
            "Remove X-Powered-By. PHP: expose_php=Off | Express: app.disable('x-powered-by')",
            "CWE-200"))

    # ASP.NET version
    aspnet = h.get("x-aspnet-version", "")
    if aspnet:
        results.append(_found(
            "Vulnerable Framework Version Disclosure", SEVERITY_MEDIUM,
            "X-AspNet-Version header discloses the .NET framework version in use.",
            "X-AspNet-Version: " + aspnet,
            "Add <httpRuntime enableVersionHeader='false'/> in web.config.",
            "CWE-200"))

    # CORS -- only relevant when request includes an Origin header
    acao = h.get("access-control-allow-origin", None)
    has_origin_request = "origin" in rh
    if acao == "*":
        results.append(_found(
            "Misconfigured Access Control Allow Origin", SEVERITY_HIGH,
            "Access-Control-Allow-Origin is set to wildcard (*), allowing any origin to make "
            "cross-origin requests and potentially access sensitive data.",
            "Access-Control-Allow-Origin: *",
            "Restrict CORS to specific trusted origins. Validate Origin header server-side.",
            "CWE-942"))
    elif acao is None and has_origin_request:
        # Only flag when a cross-origin request was actually made
        results.append(_found(
            "Access Control Allow Origin Not Defined", SEVERITY_INFO,
            "A cross-origin request was made (Origin header present) but Access-Control-Allow-Origin "
            "is not defined in the response.",
            "Request had Origin: {} -- no ACAO header in response.".format(rh.get("origin", "")),
            "Define Access-Control-Allow-Origin explicitly if cross-origin access is required.",
            "CWE-942"))

    # Cache-Control -- only flag on dynamic content (HTML/JSON/XML), not static assets
    _cacheable_types = ("text/html", "application/json", "application/xml", "text/xml")
    if any(t in content_type for t in _cacheable_types):
        cc = h.get("cache-control", "")
        if not cc or ("no-store" not in cc and "no-cache" not in cc):
            results.append(_found(
                "Cacheable HTTP Response", SEVERITY_LOW,
                "A dynamic response (HTML/JSON) lacks adequate Cache-Control directives. "
                "Sensitive data may be cached by browsers or intermediate proxies.",
                "Cache-Control: " + (cc if cc else "absent") + " | Content-Type: " + content_type,
                "Set: Cache-Control: no-store, no-cache, must-revalidate and Pragma: no-cache "
                "on responses containing sensitive or dynamic data.",
                "CWE-524"))

    return results


# -- 2. Cookie Analyzer ---------------------------------------------------------

RE_EMAIL = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
RE_JWT   = re.compile(r'ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
# Stricter JSON: must have quoted key, colon, value -- avoids matching CSS/URLs
RE_JSON  = re.compile(r'\{["\'][^"\']{1,100}["\']\s*:\s*["\'\d\[{]')

def check_cookies(set_cookie_headers):
    import re as _re
    results = []
    if not set_cookie_headers:
        return results

    httponly_reported = secure_reported = path_reported = False

    for cookie in set_cookie_headers:
        lower = cookie.lower()

        _httponly_attr = _re.search(r'(^|;)\s*httponly\s*(;|$)', lower)
        if not httponly_reported and not _httponly_attr:
            results.append(_found(
                "Cookie HTTPOnly Flag Missing", SEVERITY_LOW,
                "A cookie is set without the HttpOnly flag, allowing JavaScript access. "
                "An XSS vulnerability could be used to steal the cookie.",
                "Set-Cookie: " + _trunc(cookie),
                "Add HttpOnly attribute to all session and authentication cookies.",
                "CWE-1004"))
            httponly_reported = True

        # Check for Secure as a standalone attribute (not substring of e.g. "insecure")
        _secure_attr = _re.search(r'(^|;)\s*secure\s*(;|$)', lower)
        if not secure_reported and not _secure_attr:
            results.append(_found(
                "Cookie Secure Flag Missing", SEVERITY_LOW,
                "A cookie lacks the Secure flag, meaning it may be transmitted over unencrypted HTTP.",
                "Set-Cookie: " + _trunc(cookie),
                "Add Secure attribute to all cookies to enforce HTTPS-only transmission.",
                "CWE-614"))
            secure_reported = True

        if not path_reported and "path=/" in lower:
            results.append(_found(
                "Cookie Path Set to Root", SEVERITY_LOW,
                "Cookie path is set to '/', making it accessible to all paths on the domain.",
                "Set-Cookie: " + _trunc(cookie),
                "Restrict cookie path to the specific application context (e.g., path=/app).",
                "CWE-1004"))
            path_reported = True

        # Extract cookie value
        value = ""
        if "=" in cookie:
            val_part = cookie.split("=", 1)[1]
            value = val_part.split(";")[0] if ";" in val_part else val_part

        if RE_EMAIL.search(value):
            results.append(_found(
                "Sensitive PII Data Passed in Cookie", SEVERITY_HIGH,
                "A cookie value contains what appears to be an email address (PII). "
                "PII in cookies risks exposure through logs, proxies, and XSS.",
                "Cookie contains email-like value: " + _trunc(value),
                "Never store PII in cookies. Use server-side session references instead.",
                "CWE-312"))

        if RE_JWT.search(value):
            results.append(_found(
                "Data Exposure in Cookie", SEVERITY_MEDIUM,
                "A cookie contains a JWT token. JWT payloads are base64-encoded and readable "
                "by anyone -- sensitive claims must not be stored in JWT payloads.",
                "Cookie contains JWT: " + _trunc(value),
                "Ensure JWTs contain no sensitive PII. Use opaque session tokens where possible.",
                "CWE-312"))

        elif RE_JSON.search(value):
            results.append(_found(
                "Data Exposure in Cookie", SEVERITY_MEDIUM,
                "A cookie value contains serialized JSON, potentially exposing internal data structures.",
                "Cookie contains JSON: " + _trunc(value),
                "Replace JSON data in cookies with opaque server-side session identifiers.",
                "CWE-312"))

    return results


# -- 3. Version Detector --------------------------------------------------------

LIBS = [
    {
        "name":     "jQuery",
        "pattern":  re.compile(r'jquery[.\-/](\d+\.\d+\.\d+)', re.IGNORECASE),
        # Vuln: all 1.x, 2.x, 3.0-3.5.1 (exclusive upper bound: 3.6.0 is safe)
        "vuln_max": (3, 6, 0),
        "cwe":      "CWE-1104",
        "finding":  "Vulnerable jQuery Version",
    },
    {
        "name":     "Bootstrap",
        "pattern":  re.compile(r'bootstrap[.\-/](\d+\.\d+\.\d+)', re.IGNORECASE),
        # Vuln: all 1.x, 2.x, 3.0-3.4.0, 4.0-4.3.0 (4.3.1+ is safe)
        "vuln_ranges": [(0,0,0, 3,4,1), (4,0,0, 4,3,1)],
        "cwe":      "CWE-1104",
        "finding":  "Vulnerable/Outdated Bootstrap Version Disclosure",
    },
    {
        "name":     "AngularJS",
        "pattern":  re.compile(r'angular[.\-/](\d+\.\d+\.\d+)', re.IGNORECASE),
        # AngularJS (1.x) is fully EOL; Angular 2-12 had various vulns
        "vuln_max": (13, 0, 0),
        "cwe":      "CWE-1104",
        "finding":  "Vulnerable JavaScript Version Disclosure",
    },
]


def _parse_version(ver_str):
    """Parse '3.5.1' -> (3, 5, 1). Returns None on failure."""
    try:
        parts = ver_str.split(".")
        return tuple(int(x) for x in parts[:3])
    except (ValueError, AttributeError):
        return None


def _is_vuln_version(lib, ver_str):
    """Return True if version is in a known-vulnerable range for this lib."""
    v = _parse_version(ver_str)
    if v is None:
        return False
    if "vuln_max" in lib:
        return v < lib["vuln_max"]
    if "vuln_ranges" in lib:
        for r in lib["vuln_ranges"]:
            lo = r[0:3]
            hi = r[3:6]
            if tuple(lo) <= v < tuple(hi):
                return True
    return False

RE_MYSQL  = re.compile(r'mysql\s+(\d+\.\d+\.\d+)', re.IGNORECASE)
RE_JS_VER = re.compile(r'([a-zA-Z][a-zA-Z0-9_-]*)[.\-/](\d+\.\d+\.\d+)\.(?:min\.)?js', re.IGNORECASE)
# Library names already handled by LIBS -- skip them in the generic JS version check
_KNOWN_LIB_NAMES = frozenset(lib["name"].lower() for lib in LIBS)

def check_versions(body):
    results = []
    if not body:
        return results

    for lib in LIBS:
        m = lib["pattern"].search(body)
        if m:
            ver = m.group(1)
            if _is_vuln_version(lib, ver):
                results.append(_found(
                    lib["finding"], SEVERITY_MEDIUM,
                    "The application uses {} version {} which is outdated and may contain known "
                    "security vulnerabilities including XSS and prototype pollution.".format(lib["name"], ver),
                    "{} version detected: {}".format(lib["name"], ver),
                    "Update {} to the latest stable version. Review changelogs for security patches.".format(lib["name"]),
                    lib["cwe"]))

    m = RE_MYSQL.search(body)
    if m:
        results.append(_found(
            "Outdated MySQL Version Disclosure", SEVERITY_MEDIUM,
            "MySQL version {} is disclosed in the response. Enables targeted CVE exploitation.".format(m.group(1)),
            "MySQL version in response: " + m.group(1),
            "Suppress DB error messages. Upgrade MySQL to a supported version.",
            "CWE-200"))

    m = RE_JS_VER.search(body)
    if m and m.group(1).lower() not in _KNOWN_LIB_NAMES:
        results.append(_found(
            "JavaScript Version Disclosure", SEVERITY_INFO,
            "JavaScript library filenames reveal version information, enabling tech stack fingerprinting.",
            "JS file with version: " + m.group(0),
            "Serve JS libraries without version numbers in filenames or use a CDN that abstracts versioning.",
            "CWE-200"))

    return results


# -- 4. Body Scanner ------------------------------------------------------------

RE_INTERNAL_IP = re.compile(
    r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3})')

RE_ERROR = re.compile(
    r'(?:stack\s+trace|exception|traceback|at line \d+'
    r'|\bsyntaxerror\b|\bfatal error\b|\buncaught exception\b'
    r'|\bwarning:\s|\bparse error\b|\bsql syntax\b'
    r'|ORA-\d+|SQLSTATE|mysqli_|pg_query)',
    re.IGNORECASE)

def check_body(body, content_type):
    results = []
    if not body:
        return results

    m = RE_EMAIL.search(body)
    if m:
        results.append(_found(
            "Email Address Disclosed", SEVERITY_LOW,
            "The response body contains email addresses, potentially enabling phishing and spam attacks.",
            "Email found: " + m.group(),
            "Remove email addresses from public pages or obfuscate them. Use contact forms instead.",
            "CWE-200"))

    m = RE_INTERNAL_IP.search(body)
    if m:
        results.append(_found(
            "Internal IP Disclosure", SEVERITY_MEDIUM,
            "A private/internal IP address is exposed in the response, revealing network topology.",
            "Internal IP found: " + m.group(),
            "Sanitize error messages and responses to remove internal IP addresses.",
            "CWE-200"))

    if content_type and "html" in content_type.lower():
        m = RE_ERROR.search(body)
        if m:
            results.append(_found(
                "Improper Error Handling", SEVERITY_MEDIUM,
                "Detailed error messages or stack traces are returned in the response, "
                "revealing internal implementation details useful to attackers.",
                "Error pattern found: " + _trunc(m.group()),
                "Implement custom error pages (400, 403, 404, 500). Log errors server-side only.",
                "CWE-209"))

    return results


# -- 5. HTML Analyzer -----------------------------------------------------------

RE_PWD_FIELD    = re.compile(r'<input[^>]+type=[\'"]password[\'"][^>]*>', re.IGNORECASE)
RE_CHARSET      = re.compile(r'<meta[^>]+charset', re.IGNORECASE)
RE_INPUT        = re.compile(r'<input[^>]+type=[\'"](?:text|password|email|number|tel)[\'"][^>]*>', re.IGNORECASE)
RE_REL_CSS      = re.compile(r'<link[^>]+href=[\'"](?!https?://|//)[^/][^\'"]*\.css[\'"]', re.IGNORECASE)
RE_FILE_INPUT   = re.compile(r'<input[^>]+type=[\'"]file[\'"][^>]*>', re.IGNORECASE)
# Tightened: Indian mobile (starts 6-9, 10 digits) or international E.164 with + prefix only
# Word boundaries prevent matching arbitrary large integers or IDs
RE_PHONE        = re.compile(r'(?<!\d)(?:\+91[\s\-]?[6-9]\d{9}|(?<!\d)[6-9]\d{9}(?!\d)|\+[1-9]\d{7,14})(?!\d)')

def check_html(body, content_type):
    results = []
    if not body or not content_type or "html" not in content_type.lower():
        return results

    # Password autocomplete
    for m in RE_PWD_FIELD.finditer(body):
        field = m.group()
        if 'autocomplete="off"' not in field.lower() and "autocomplete='off'" not in field.lower():
            results.append(_found(
                "Password Autocomplete Enabled", SEVERITY_LOW,
                "A password field lacks autocomplete=off. Browsers may cache the password, "
                "risking exposure on shared or public devices.",
                "Password field without autocomplete=off: " + _trunc(field),
                "Add autocomplete=\"off\" to all password input fields.",
                "CWE-522"))
            break

    # Charset not specified
    if not RE_CHARSET.search(body):
        results.append(_found(
            "HTML Does Not Specify Charset", SEVERITY_INFO,
            "No character encoding is specified. Can lead to charset sniffing attacks in older browsers.",
            "No <meta charset> tag found in HTML.",
            "Add <meta charset=\"UTF-8\"> in the <head> section of all HTML pages.",
            "CWE-116"))

    # Input without maxlength
    for m in RE_INPUT.finditer(body):
        field = m.group()
        if "maxlength" not in field.lower():
            results.append(_found(
                "Character Limit Not Set on Input Field", SEVERITY_LOW,
                "One or more input fields lack a maxlength attribute, potentially allowing "
                "oversized input and application-layer DoS.",
                "Input without maxlength: " + _trunc(field),
                "Add maxlength attribute to all text input fields. Enforce limits server-side.",
                "CWE-400"))
            break

    # Path-relative CSS
    if RE_REL_CSS.search(body):
        results.append(_found(
            "Path-Relative Stylesheet Import", SEVERITY_LOW,
            "CSS stylesheets are imported using relative paths, which can be exploited "
            "for cross-site content injection in certain browser configurations.",
            "Relative CSS import detected in HTML.",
            "Use absolute paths for stylesheet imports (e.g., href=\"/assets/style.css\").",
            "CWE-693"))

    # File upload without size hints
    m = RE_FILE_INPUT.search(body)
    if m:
        field = m.group()
        if "accept" not in field.lower() and "maxsize" not in body.lower():
            results.append(_found(
                "Uploaded File Size Limit Not Defined", SEVERITY_LOW,
                "A file upload field has no apparent size restriction. Can lead to storage "
                "exhaustion and DoS attacks.",
                "File input without size restriction: " + _trunc(field),
                "Enforce file size limits client-side (accept attr) and server-side. "
                "Validate file type, size, and content.",
                "CWE-400"))

    # Phone number disclosure
    m = RE_PHONE.search(body)
    if m:
        results.append(_found(
            "Phone Number Disclosure in View Page Source", SEVERITY_INFO,
            "A phone number is visible in the page source. May expose internal contact details.",
            "Phone number found: " + m.group(),
            "Review whether phone numbers in page source are intentional. "
            "Remove internal/admin contact numbers from client-facing responses.",
            "CWE-200"))

    return results


# -- 6. Request Checker ---------------------------------------------------------

RE_BEARER_JWT = re.compile(
    r'Bearer\s+(ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    re.IGNORECASE)

def check_request(req_headers):
    results = []
    auth = req_headers.get("authorization", "")
    if not auth:
        return results

    m = RE_BEARER_JWT.search(auth)
    if m:
        token = m.group(1)
        try:
            parts = token.split(".")
            if len(parts) >= 2:
                # (4 - n%4) % 4 correctly yields 0 when already aligned (avoids '====')
                padding = (4 - len(parts[1]) % 4) % 4
                payload_b64 = parts[1] + ("=" * padding)
                try:
                    payload = base64.urlsafe_b64decode(payload_b64).decode("utf-8", errors="replace")
                except Exception:
                    payload = ""
                pii_fields = ["email", "phone", "ssn", "dob", "mobile", "address"]
                if any(f in payload.lower() for f in pii_fields):
                    results.append(_found(
                        "Sensitive Data in Authorization Bearer", SEVERITY_HIGH,
                        "The JWT Bearer token payload contains sensitive user attributes (PII). "
                        "JWTs are base64-encoded, not encrypted -- anyone can decode them.",
                        "JWT payload contains PII: " + _trunc(payload),
                        "Remove PII from JWT payloads. Store only opaque identifiers. "
                        "Use JWE if sensitive data must be included.",
                        "CWE-312"))
        except Exception:
            pass

    return results


# -- 7. Method Checker ----------------------------------------------------------

DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}

def check_methods(resp_headers):
    results = []
    h = {k.lower(): v for k, v in resp_headers.items()}
    allow = h.get("allow") or h.get("access-control-allow-methods") or ""
    if not allow:
        return results

    allow_upper = allow.upper()

    if "OPTIONS" in allow_upper:
        results.append(_found(
            "OPTIONS Method Enabled", SEVERITY_LOW,
            "HTTP OPTIONS method is enabled, allowing clients to enumerate supported methods "
            "and aiding attack surface mapping.",
            "Allow: " + allow,
            "Disable OPTIONS method if not required. Restrict to GET and POST only.",
            "CWE-16"))

    found_dangerous = [m for m in DANGEROUS_METHODS if m in allow_upper]
    if found_dangerous:
        results.append(_found(
            "Dangerous HTTP Methods Enabled", SEVERITY_CRITICAL,
            "The server allows dangerous HTTP methods: {}. These can be abused to modify "
            "server-side resources.".format(", ".join(found_dangerous)),
            "Allow: " + allow,
            "Disable PUT, DELETE, TRACE, CONNECT at web server or WAF level.",
            "CWE-650"))

    return results


# -- 8. Secrets Detector --------------------------------------------------------
# Detects hardcoded secrets in response bodies and inline scripts.
# Each pattern has: label, regex, severity, cwe, redact_fn (masks most of the match)

# (label, compiled_regex, severity, cwe, description_suffix)
SECRET_PATTERNS = [

    # ---- AWS ----------------------------------------------------------------
    (
        "AWS Access Key ID",
        re.compile(r'(?<![A-Z0-9])(AKIA|AIPA|ASIA|AROA|ANPA|ANVA|APKA)[A-Z0-9]{16}'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "An AWS Access Key ID was found in the response. Combined with the secret key, "
        "this grants full programmatic access to AWS services.",
        "Remove the key from source/response. Rotate immediately via AWS IAM console. "
        "Use IAM roles or environment variables instead of hardcoded credentials."
    ),
    (
        "AWS Secret Access Key",
        re.compile(r'(?i)aws.{0,20}?secret.{0,20}?[=:"\s]+([A-Za-z0-9/+]{40})'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "An AWS Secret Access Key was found in the response. This enables full API "
        "access to the associated AWS account.",
        "Rotate the key immediately in AWS IAM. Never embed credentials in code or "
        "responses. Use AWS Secrets Manager or IAM roles."
    ),
    (
        "AWS S3 Bucket URL",
        re.compile(r's3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com/[a-zA-Z0-9._\-/]+'),
        SEVERITY_MEDIUM,
        "CWE-200",
        "An S3 bucket URL was found in the response. Publicly exposed bucket paths "
        "may allow enumeration or access to sensitive files.",
        "Verify the bucket is not publicly accessible. Use signed URLs for private "
        "content. Apply bucket policies restricting access."
    ),

    # ---- Google -------------------------------------------------------------
    (
        "Google API Key",
        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "A Google API key was found exposed in the response. Depending on enabled APIs "
        "(Maps, Gmail, Firebase, etc.) this may allow unauthorized usage and billing charges.",
        "Restrict the key to specific APIs and referrers in the Google Cloud Console. "
        "Rotate the key and remove it from client-side code."
    ),
    (
        "Google OAuth Client Secret",
        re.compile(r'GOCSPX-[0-9A-Za-z\-_]{28}'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "A Google OAuth client secret was found in the response. This can be used to "
        "impersonate your application in OAuth flows.",
        "Regenerate the secret in Google Cloud Console. Store it server-side only, "
        "never in client-facing responses."
    ),
    (
        "Firebase API Key",
        re.compile(r'(?i)firebase[^\n]{0,30}api[_-]?key[^\n]{0,10}[=:"\s]+([A-Za-z0-9\-_]{20,50})'),
        SEVERITY_MEDIUM,
        "CWE-798",
        "A Firebase API key was found. The key alone does not grant access -- exploitation "
        "requires misconfigured Firestore/Realtime DB security rules.",
        "Restrict Firebase security rules server-side. The API key alone is not secret "
        "but must be paired with strict Firestore/Realtime DB rules."
    ),

    # ---- GitHub / GitLab / Bitbucket ----------------------------------------
    (
        "GitHub Personal Access Token",
        re.compile(r'gh[pousr]_[A-Za-z0-9]{36,100}'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "A GitHub Personal Access Token (PAT) was found. This grants API access to "
        "GitHub repositories, potentially allowing code theft or modification.",
        "Revoke the token immediately at github.com/settings/tokens. "
        "Use fine-grained tokens scoped to minimum required permissions."
    ),
    (
        "GitHub App Token",
        re.compile(r'(ghs|ghu|ghr)_[A-Za-z0-9]{36}'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "A GitHub App installation or user token was found in the response.",
        "Revoke the token and audit GitHub App permissions. Tokens should be "
        "short-lived and never embedded in responses."
    ),
    (
        "GitLab Personal Access Token",
        re.compile(r'glpat-[A-Za-z0-9\-_]{20}'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "A GitLab Personal Access Token was found. This may allow full API access "
        "to GitLab repositories and CI/CD pipelines.",
        "Revoke the token in GitLab profile settings. Rotate and use scoped tokens."
    ),

    # ---- Stripe / Payment ---------------------------------------------------
    (
        "Stripe Secret Key",
        re.compile(r'sk_(live|test)_[0-9a-zA-Z]{24,128}'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "A Stripe secret key was found. This allows full access to Stripe APIs "
        "including charges, refunds, and customer data.",
        "Roll the key immediately in the Stripe dashboard. Secret keys must never "
        "appear in client-facing responses -- use publishable keys for frontend."
    ),
    (
        "Stripe Publishable Key",
        re.compile(r'pk_(live|test)_[0-9a-zA-Z]{24,128}'),
        SEVERITY_LOW,
        "CWE-200",
        "A Stripe publishable key was found. While intended for client-side use, "
        "live publishable keys in responses should be noted and monitored.",
        "Ensure no secret keys are mixed with publishable keys. "
        "Monitor for unexpected usage in the Stripe dashboard."
    ),

    # ---- Slack --------------------------------------------------------------
    (
        "Slack Bot Token",
        re.compile(r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),
        SEVERITY_HIGH,
        "CWE-798",
        "A Slack Bot token was found. This allows sending messages, reading channels, "
        "and accessing workspace data as the bot.",
        "Revoke the token at api.slack.com/apps. Rotate and store tokens server-side only."
    ),
    (
        "Slack User Token",
        re.compile(r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}'),
        SEVERITY_HIGH,
        "CWE-798",
        "A Slack User OAuth token was found. This grants user-level access to the "
        "Slack workspace including private channels.",
        "Revoke immediately at api.slack.com. Use bot tokens with minimal scopes."
    ),
    (
        "Slack Webhook URL",
        re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'),
        SEVERITY_MEDIUM,
        "CWE-200",
        "A Slack Incoming Webhook URL was found. Anyone with this URL can post "
        "messages to the associated Slack channel.",
        "Rotate the webhook URL in Slack app settings. Do not embed webhook URLs "
        "in client-facing code or responses."
    ),

    # ---- Twilio / SendGrid / Mailgun ----------------------------------------
    (
        "Twilio API Key",
        re.compile(r'SK[0-9a-fA-F]{32}'),
        SEVERITY_HIGH,
        "CWE-798",
        "A Twilio API Key SID was found. This may allow sending SMS, making calls, "
        "and accessing account data.",
        "Revoke the key in the Twilio console. Use environment variables for credentials."
    ),
    (
        "SendGrid API Key",
        re.compile(r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{40,}'),
        SEVERITY_HIGH,
        "CWE-798",
        "A SendGrid API key was found. This allows sending emails and accessing "
        "mailing lists on behalf of the account.",
        "Revoke the key in SendGrid settings. Store API keys in server-side environment "
        "variables, never in responses."
    ),
    (
        "Mailgun API Key",
        re.compile(r'key-[0-9a-zA-Z]{32}'),
        SEVERITY_HIGH,
        "CWE-798",
        "A Mailgun API key was found, allowing email sending and account access.",
        "Rotate the key in the Mailgun dashboard. Use restricted keys with domain scoping."
    ),

    # ---- Azure / GCP --------------------------------------------------------
    (
        "Azure Storage Connection String",
        re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "An Azure Storage connection string was found. This grants full access to the "
        "storage account including blobs, queues, and tables.",
        "Regenerate the storage account key in Azure Portal. Use SAS tokens or "
        "managed identities instead of connection strings."
    ),
    (
        "GCP Service Account Key",
        re.compile(r'"type"\s*:\s*"service_account"'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "A GCP service account key JSON fragment was detected in the response. "
        "This credential grants access to Google Cloud resources.",
        "Revoke the service account key in IAM & Admin. Use Workload Identity "
        "Federation instead of service account key files."
    ),

    # ---- Private Keys / Certs -----------------------------------------------
    (
        "RSA Private Key",
        re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
        SEVERITY_CRITICAL,
        "CWE-321",
        "An RSA private key header was found in the response. Exposure of a private "
        "key allows decryption of traffic and identity impersonation.",
        "Remove the private key from all server responses immediately. Revoke and "
        "reissue the associated certificate."
    ),
    (
        "Generic Private Key",
        re.compile(r'-----BEGIN (EC|DSA|OPENSSH|PGP|ENCRYPTED)? ?PRIVATE KEY-----'),
        SEVERITY_CRITICAL,
        "CWE-321",
        "A private key was found in the response. Exposure allows decryption and "
        "identity impersonation depending on key type.",
        "Remove from responses immediately. Rotate the key pair and revoke the old key."
    ),
    (
        "PGP Private Key Block",
        re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
        SEVERITY_CRITICAL,
        "CWE-321",
        "A PGP private key block was found in the response.",
        "Remove and rotate the PGP key immediately."
    ),

    # ---- Database / Connection Strings --------------------------------------
    (
        "Generic Database Connection String",
        re.compile(r'(?i)(mysql|postgresql|mongodb|mssql|oracle|jdbc)[+:]?://[^:\s@]+:[^@\s]+@[^\s"\']+'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "A database connection string with embedded credentials was found in the response. "
        "This exposes the database host, username, and password.",
        "Remove connection strings from all responses. Use environment variables or a "
        "secrets manager. Rotate the database password immediately."
    ),
    (
        "MongoDB Connection String",
        re.compile(r'mongodb(\+srv)?://[^:\s]+:[^@\s]+@[^\s"\'<>]+'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "A MongoDB connection string with credentials was found in the response.",
        "Rotate the MongoDB password immediately. Never expose connection strings "
        "in client-facing responses."
    ),

    # ---- Generic Secrets (high-confidence patterns) -------------------------
    (
        "Hardcoded Password in Source",
        re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,128})["\']'),
        SEVERITY_CRITICAL,
        "CWE-259",
        "A hardcoded password was found assigned to a variable in the response source. "
        "Hardcoded credentials are a critical security risk.",
        "Remove hardcoded passwords from all code and responses. Use environment "
        "variables or a secrets manager."
    ),
    (
        "Generic API Secret in Source",
        re.compile(r'(?i)(api_secret|app_secret|client_secret|secret_key)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{16,256})["\']'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "A hardcoded API or application secret was found in the response source.",
        "Remove the secret from source code and responses. Rotate the secret and "
        "store it in a secrets manager or environment variable."
    ),
    (
        "Bearer Token in Response Body",
        re.compile(r'(?i)["\']?bearer["\']?\s*[=:]\s*["\']?(ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["\']?'),
        SEVERITY_HIGH,
        "CWE-312",
        "A Bearer JWT token was found embedded in the response body. Tokens in "
        "responses can be cached, logged, or accessed by unintended parties.",
        "Avoid returning tokens in response bodies where avoidable. Use HttpOnly "
        "cookies or secure storage mechanisms."
    ),
    (
        "Encryption Key (Hex 256-bit)",
        re.compile(r'(?i)(aes|encryption|cipher|secret)[_\-]?key[^\n]{0,20}[=:\s]+["\' ]?([0-9a-fA-F]{64})'),
        SEVERITY_CRITICAL,
        "CWE-321",
        "A 256-bit hexadecimal encryption key was found in the response. Exposure of "
        "encryption keys allows decryption of protected data.",
        "Remove encryption keys from all responses. Use a Hardware Security Module "
        "(HSM) or secrets manager for key storage."
    ),
    (
        "Encryption Key (Base64)",
        re.compile(r'(?i)(aes|encryption|cipher|secret)[_\-]?key[^\n]{0,20}[=:"\s]+([A-Za-z0-9+/]{43}=)'),
        SEVERITY_CRITICAL,
        "CWE-321",
        "A base64-encoded encryption key was found in the response.",
        "Rotate the key immediately. Never expose encryption keys in HTTP responses."
    ),

    # ---- Miscellaneous ------------------------------------------------------
    (
        "NPM Auth Token",
        re.compile(r'//registry\.npmjs\.org/:_authToken=[A-Za-z0-9\-]+'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "An NPM registry auth token was found. This allows publishing packages "
        "and accessing private packages under the associated account.",
        "Revoke the token at npmjs.com. Never commit .npmrc files with auth tokens."
    ),
    (
        "SSH Private Key",
        re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        SEVERITY_CRITICAL,
        "CWE-321",
        "An OpenSSH private key was found in the response. This allows SSH access "
        "to any server configured with the corresponding public key.",
        "Remove immediately. Revoke the key from all authorized_keys files and "
        "generate a new key pair."
    ),
    (
        "JSON Web Token Secret (HS256 weak)",
        re.compile(r'(?i)jwt[_\-]?secret\s*[=:]\s*["\']([^"\']{8,256})["\']'),
        SEVERITY_CRITICAL,
        "CWE-798",
        "A JWT signing secret was found hardcoded in the response source. Knowing "
        "the secret allows forging arbitrary JWT tokens.",
        "Remove the JWT secret from all responses. Rotate immediately. Use RS256 "
        "(asymmetric) signing instead of HS256 where possible."
    ),
]


def check_secrets(body):
    """
    Scan response body for hardcoded secrets using the SECRET_PATTERNS bank.
    Returns one finding per distinct secret type found (deduped by pattern label).
    """
    results = []
    if not body:
        return results

    seen_labels = set()

    for (label, pattern, severity, cwe, description, remediation) in SECRET_PATTERNS:
        if label in seen_labels:
            continue
        m = pattern.search(body)
        if m:
            seen_labels.add(label)
            # Build safe evidence: show match context with value redacted
            start  = max(0, m.start() - 30)
            end    = min(len(body), m.end() + 30)
            ctx    = body[start:end].replace("\n", " ").replace("\r", "")
            # Mask the matched secret value (keep first 6 chars)
            matched = m.group(0)
            visible = matched[:6]
            masked  = visible + ("*" * min(len(matched) - 6, 24))
            evidence = "Pattern matched: {}  |  Context: ...{}...".format(
                masked, _trunc(ctx, 80))

            results.append(_found(
                "Secret Detected: " + label,
                severity,
                description,
                evidence,
                remediation,
                cwe
            ))

    return results



def dispatch(req_headers, resp_headers, set_cookies, body, content_type,
             method, host, url, status_code=0):
    raw = []
    # Pass req_headers to check_headers so CORS guard can inspect Origin header
    raw += check_headers(resp_headers, req_headers)
    raw += check_cookies(set_cookies)
    raw += check_versions(body)
    raw += check_body(body, content_type)
    raw += check_html(body, content_type)
    raw += check_request(req_headers)
    raw += check_methods(resp_headers)
    raw += check_secrets(body)

    findings = []
    for r in raw:
        findings.append(Finding(
            r["name"], r["severity"], r["description"],
            r["evidence"], r["remediation"], r["cwe"],
            host, url, status_code))
    return findings


# ===============================================================================
# EXPORTER
# ===============================================================================

def export_csv(findings, filepath):
    """
    Write CSV. Uses 'w' text mode (not 'wb') for Jython 2.7 compatibility.
    All values are encoded to utf-8 strings to avoid unicode write errors.
    """
    def safe(val):
        if val is None:
            return ""
        try:
            return val.encode("utf-8") if isinstance(val, unicode) else str(val)
        except Exception:
            return str(val)

    def sanitize_csv(val):
        """Prevent CSV formula injection by prefixing dangerous leading chars with apostrophe."""
        s = safe(val)
        if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
            return "'" + s
        return s

    with open(filepath, "w") as f:
        writer = csv.writer(f)
        writer.writerow(["#", "Finding Name", "Severity", "CWE", "Host",
                          "Endpoints Count", "Affected Endpoints (endpoint | HTTP status)",
                          "Description", "Evidence", "Remediation"])
        for i, fi in enumerate(findings, 1):
            eps = fi.affected_endpoints if fi.affected_endpoints else [{"endpoint": fi.url, "status_code": fi.status_code}]
            ep_count = len(eps)
            ep_list  = " ; ".join(
                "{} [{}]".format(ep["endpoint"], ep.get("status_code") or "-")
                for ep in eps)
            writer.writerow([
                i,
                sanitize_csv(fi.name),
                sanitize_csv(fi.severity),
                sanitize_csv(fi.cwe),
                sanitize_csv(fi.host),
                ep_count,
                sanitize_csv(ep_list),
                sanitize_csv(fi.description),
                sanitize_csv(fi.evidence),
                sanitize_csv(fi.remediation),
            ])


def export_docx_simple(findings, filepath):
    """
    Generates a well-structured DOCX using raw XML (no external POI dependency).
    Opens correctly in Microsoft Word and LibreOffice.
    """
    import zipfile

    SEV_COLORS = {
        SEVERITY_CRITICAL: "7B0000",
        SEVERITY_HIGH:     "CC0000",
        SEVERITY_MEDIUM:   "E06000",
        SEVERITY_LOW:      "B8860B",
        SEVERITY_INFO:     "1A5276",
    }

    def esc(s):
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def para(text, bold=False, size=24, color="000000", indent=0):
        b = "<w:b/>" if bold else ""
        ind = '<w:ind w:left="{}"/>'.format(indent) if indent else ""
        return (
            "<w:p>"
            "<w:pPr>{}</w:pPr>"
            "<w:r><w:rPr>{}<w:sz w:val=\"{}\"/>"
            "<w:color w:val=\"{}\"/><w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/>"
            "</w:rPr><w:t xml:space=\"preserve\">{}</w:t></w:r>"
            "</w:p>"
        ).format(ind, b, size, color, esc(text))

    def row(label, value, label_bg="1F5C5C", value_bg="F0F8F8"):
        return (
            "<w:tr>"
            "<w:tc><w:tcPr><w:shd w:fill=\"{lb}\" w:val=\"clear\"/></w:tcPr>"
            "<w:p><w:r><w:rPr><w:b/><w:color w:val=\"FFFFFF\"/>"
            "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/><w:sz w:val=\"20\"/></w:rPr>"
            "<w:t>{lv}</w:t></w:r></w:p></w:tc>"
            "<w:tc><w:tcPr><w:shd w:fill=\"{vb}\" w:val=\"clear\"/></w:tcPr>"
            "<w:p><w:r><w:rPr><w:color w:val=\"000000\"/>"
            "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/><w:sz w:val=\"20\"/></w:rPr>"
            "<w:t xml:space=\"preserve\">{vv}</w:t></w:r></w:p></w:tc>"
            "</w:tr>"
        ).format(lb=label_bg, lv=esc(label), vb=value_bg, vv=esc(value))

    body_xml = []

    # Title
    body_xml.append(para("AutoVuln - Passive Scan Findings Report",
                          bold=True, size=36, color="1F5C5C"))
    body_xml.append(para("Generated: {}  |  Total Findings: {}".format(
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), len(findings)),
        size=18, color="666666"))
    body_xml.append(para(""))

    # Summary
    body_xml.append(para("Executive Summary", bold=True, size=28, color="1F5C5C"))
    summary = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0, SEVERITY_LOW: 0, SEVERITY_INFO: 0}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

    for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]:
        body_xml.append(para("  {} : {}".format(sev, summary[sev]),
                              size=22, color=SEV_COLORS.get(sev, "000000")))
    body_xml.append(para(""))

    # Detailed Findings
    body_xml.append(para("Detailed Findings", bold=True, size=28, color="1F5C5C"))
    body_xml.append(para(""))

    for idx, f in enumerate(findings, 1):
        color = SEV_COLORS.get(f.severity, "000000")
        body_xml.append(para("{}. {}".format(idx, f.name),
                              bold=True, size=26, color=color))

        # Build affected endpoints string for the DOCX table row
        eps = f.affected_endpoints if f.affected_endpoints else [{"endpoint": f.url, "status_code": f.status_code}]
        if len(eps) == 1:
            ep_value = "{} (HTTP {})".format(eps[0]["endpoint"], eps[0].get("status_code") or "-")
        else:
            ep_value = "  ".join(
                "{}. {} (HTTP {})".format(n, ep["endpoint"], ep.get("status_code") or "-")
                for n, ep in enumerate(eps, 1))

        ep_label = "Affected Endpoints ({})".format(len(eps)) if len(eps) > 1 else "Affected Endpoint"

        body_xml.append(
            "<w:tbl>"
            "<w:tblPr><w:tblW w:w=\"9000\" w:type=\"dxa\"/>"
            "<w:tblBorders>"
            "<w:top w:val=\"single\" w:sz=\"4\" w:color=\"AAAAAA\"/>"
            "<w:left w:val=\"single\" w:sz=\"4\" w:color=\"AAAAAA\"/>"
            "<w:bottom w:val=\"single\" w:sz=\"4\" w:color=\"AAAAAA\"/>"
            "<w:right w:val=\"single\" w:sz=\"4\" w:color=\"AAAAAA\"/>"
            "<w:insideH w:val=\"single\" w:sz=\"4\" w:color=\"AAAAAA\"/>"
            "<w:insideV w:val=\"single\" w:sz=\"4\" w:color=\"AAAAAA\"/>"
            "</w:tblBorders></w:tblPr>" +
            row("Severity",    f.severity) +
            row("CWE",         f.cwe, value_bg="FFFFFF") +
            row("Host",        f.host) +
            row(ep_label,      ep_value, value_bg="FFFFFF") +
            row("Description", f.description) +
            row("Evidence",    f.evidence, value_bg="FFFFFF") +
            row("Remediation", f.remediation) +
            "</w:tbl>")
        body_xml.append(para(""))

    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body>' + "".join(body_xml) +
        '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>'
        '<w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080"/>'
        '</w:sectPr></w:body></w:document>')

    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/></Relationships>')

    word_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '</Relationships>')

    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '</Types>')

    with zipfile.ZipFile(filepath, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels_xml)
        z.writestr("word/document.xml", doc_xml)
        z.writestr("word/_rels/document.xml.rels", word_rels)



# ===============================================================================
# UI TAB - AutoVuln dark design (matches autovuln_scanner_redesign.html)
# ===============================================================================

# Background layers
C_ROOT       = Color(11,  15,  26)   # #0b0f1a  page bg
C_HEADER_BG  = Color(13,  18,  32)   # #0d1220  header / detail panel bg
C_SURFACE    = Color(22,  30,  46)   # slightly lighter surface for cards
C_DEEP       = Color(7,   12,  20)   # #070c14  code block bg inside detail
C_SEL_ROW    = Color(20,  45,  85)   # selected row -- more visible blue tint
C_TOOLBAR_BD = Color(30,  40,  60)   # toolbar bottom border

# Border colours
C_BORDER     = Color(40,  60,  90)   # #1e2d45 -- lifted so lines are visible
C_BORDER2    = Color(25,  35,  55)   # table row divider

# Text colours -- all lifted for readability on dark bg
C_TEXT       = Color(226, 232, 240)  # #e2e8f0  primary text (fine)
C_TEXT_DIM   = Color(180, 192, 210)  # lifted from 148 -- visible on dark
C_TEXT_MUTED = Color(120, 145, 175)  # lifted from 74 -- column headers
C_BRAND_SUB  = Color(120, 140, 165)  # lifted subtitle
C_ACCENT_BLU = Color(96,  165, 250)  # #60a5fa  endpoint blue (fine)
C_TEXT_HEAD  = Color(241, 245, 249)  # bold headings (fine)

# Severity colours -- vivid, unchanged
C_CRITICAL   = Color(255, 80,  80)   # #ff5050  bright crimson for Critical
C_HIGH       = Color(248, 113, 113)  # #f87171
C_MEDIUM     = Color(251, 146, 60)   # #fb923c
C_LOW        = Color(250, 204, 21)   # #facc15
C_INFO       = Color(96,  165, 250)  # #60a5fa

# Badge backgrounds -- FIXED: raised so text is visible
# Old values were (40,18,18) which is near-black; lifted to 25% opacity equivalent
C_BADGE_CRIT_BG  = Color(100, 15,  15)   # deep crimson   -- CRITICAL text #ff5050 readable
C_BADGE_HIGH_BG  = Color(80,  28,  28)   # warm dark red  -- HIGH text #f87171 readable
C_BADGE_MED_BG   = Color(75,  40,  12)   # dark amber     -- MEDIUM text #fb923c readable
C_BADGE_LOW_BG   = Color(70,  58,  5)    # dark yellow    -- LOW text #facc15 readable
C_BADGE_INFO_BG  = Color(20,  45,  80)   # dark blue      -- INFO text #60a5fa readable
C_BADGE_CRIT_BD  = Color(160, 30,  30)   # border brighter than crit bg
C_BADGE_HIGH_BD  = Color(120, 50,  50)   # border slightly brighter than bg
C_BADGE_MED_BD   = Color(120, 70,  25)
C_BADGE_LOW_BD   = Color(110, 90,  10)
C_BADGE_INFO_BD  = Color(40,  80,  130)

# CWE tag -- FIXED: lifted bg so blue text is readable
C_CWE_BG     = Color(20,  45,  80)    # dark navy  (was 30,45,69 too close to text)
C_CWE_FG     = Color(130, 190, 255)   # lighter blue for contrast on dark navy

# Status chip -- FIXED: stronger contrast
C_STATUS_OK_BG  = Color(15,  60,  30)   # dark green
C_STATUS_OK_FG  = Color(110, 240, 150)  # bright green text
C_STATUS_3XX_BG = Color(30,  40,  60)   # muted blue-grey
C_STATUS_3XX_FG = Color(160, 180, 210)  # light grey-blue
C_STATUS_4XX_BG = Color(70,  35,  10)   # dark amber
C_STATUS_4XX_FG = Color(255, 175, 90)   # bright amber

# Buttons (unchanged -- already readable)
C_BTN_PRIMARY    = Color(29,  78,  216)
C_BTN_PRIMARY_FG = Color.WHITE
C_BTN_GHOST_BG   = Color(30,  41,  59)
C_BTN_GHOST_FG   = Color(180, 195, 215)  # lifted from 148
C_BTN_GHOST_BD   = Color(55,  78,  105)  # lifted border
C_BTN_DANGER_BG  = Color(60,  18,  18)   # lifted from 30
C_BTN_DANGER_FG  = Color(248, 113, 113)
C_BTN_DANGER_BD  = Color(100, 35,  35)   # lifted border

# Scanning dot
C_DOT = Color(34, 197, 94)

COLS = ["#", "Severity", "Finding", "Endpoint", "Status", "CWE"]
COL_WIDTHS = [36, 90, 260, 360, 60, 80]

SEV_BG = {
    SEVERITY_CRITICAL: C_BADGE_CRIT_BG,
    SEVERITY_HIGH:     C_BADGE_HIGH_BG,
    SEVERITY_MEDIUM:   C_BADGE_MED_BG,
    SEVERITY_LOW:      C_BADGE_LOW_BG,
    SEVERITY_INFO:     C_BADGE_INFO_BG,
}
SEV_FG = {
    SEVERITY_CRITICAL: C_CRITICAL,
    SEVERITY_HIGH:     C_HIGH,
    SEVERITY_MEDIUM:   C_MEDIUM,
    SEVERITY_LOW:      C_LOW,
    SEVERITY_INFO:     C_INFO,
}
SEV_BD = {
    SEVERITY_CRITICAL: C_BADGE_CRIT_BD,
    SEVERITY_HIGH:     C_BADGE_HIGH_BD,
    SEVERITY_MEDIUM:   C_BADGE_MED_BD,
    SEVERITY_LOW:      C_BADGE_LOW_BD,
    SEVERITY_INFO:     C_BADGE_INFO_BD,
}


class SeverityRenderer(DefaultTableCellRenderer):
    """Badge: coloured bg + border + bold monospaced text, centered."""
    def getTableCellRendererComponent(self, table, value, selected, focus, row, col):
        label = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, selected, focus, row, col)
        label.setHorizontalAlignment(SwingConstants.CENTER)
        sval = str(value)
        bg   = SEV_BG.get(sval, C_SURFACE)
        fg   = SEV_FG.get(sval, C_TEXT_DIM)
        bd   = SEV_BD.get(sval, C_BORDER)
        if not selected:
            label.setBackground(bg)
            label.setForeground(fg)
        else:
            label.setForeground(fg)  # keep severity colour even when selected
        label.setFont(Font("Monospaced", Font.BOLD, 11))
        label.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(bd, 1),
            BorderFactory.createEmptyBorder(3, 10, 3, 10)))
        return label


class StatusRenderer(DefaultTableCellRenderer):
    """Pill chip coloured by HTTP class."""
    def getTableCellRendererComponent(self, table, value, selected, focus, row, col):
        label = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, selected, focus, row, col)
        label.setHorizontalAlignment(SwingConstants.CENTER)
        label.setFont(Font("Monospaced", Font.BOLD, 11))
        if not selected:
            try:
                code = int(str(value))
                if 200 <= code < 300:
                    label.setBackground(C_STATUS_OK_BG)
                    label.setForeground(C_STATUS_OK_FG)
                elif 300 <= code < 400:
                    label.setBackground(C_STATUS_3XX_BG)
                    label.setForeground(C_STATUS_3XX_FG)
                elif 400 <= code < 500:
                    label.setBackground(C_STATUS_4XX_BG)
                    label.setForeground(C_STATUS_4XX_FG)
                else:
                    label.setBackground(C_SURFACE)
                    label.setForeground(C_TEXT_MUTED)
            except Exception:
                label.setBackground(C_SURFACE)
                label.setForeground(C_TEXT_MUTED)
        label.setBorder(BorderFactory.createEmptyBorder(3, 6, 3, 6))
        return label


class CweRenderer(DefaultTableCellRenderer):
    """CWE tag: navy bg, light blue text, monospaced."""
    def getTableCellRendererComponent(self, table, value, selected, focus, row, col):
        label = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, selected, focus, row, col)
        label.setHorizontalAlignment(SwingConstants.CENTER)
        label.setFont(Font("Monospaced", Font.BOLD, 10))
        if not selected:
            label.setBackground(C_CWE_BG)
            label.setForeground(C_CWE_FG)
        label.setBorder(BorderFactory.createEmptyBorder(3, 6, 3, 6))
        return label


class NumRenderer(DefaultTableCellRenderer):
    """Row number: centered, muted colour."""
    def getTableCellRendererComponent(self, table, value, selected, focus, row, col):
        label = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, selected, focus, row, col)
        label.setHorizontalAlignment(SwingConstants.CENTER)
        label.setFont(Font("Monospaced", Font.PLAIN, 11))
        if not selected:
            label.setBackground(C_ROOT)
            label.setForeground(C_TEXT_MUTED)
        label.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4))
        return label


class FindingNameRenderer(DefaultTableCellRenderer):
    """Finding name: bright primary text on dark bg."""
    def getTableCellRendererComponent(self, table, value, selected, focus, row, col):
        label = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, selected, focus, row, col)
        label.setFont(Font("Arial", Font.PLAIN, 12))
        if not selected:
            label.setBackground(C_ROOT)
        label.setForeground(C_TEXT)
        label.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8))
        return label


class EndpointRenderer(DefaultTableCellRenderer):
    """Endpoint URL: accent blue, monospaced small."""
    def getTableCellRendererComponent(self, table, value, selected, focus, row, col):
        label = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, selected, focus, row, col)
        label.setFont(Font("Monospaced", Font.PLAIN, 11))
        if not selected:
            label.setBackground(C_ROOT)
        label.setForeground(C_ACCENT_BLU)
        label.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8))
        return label


class BaseRowRenderer(DefaultTableCellRenderer):
    """Plain rows with dark background."""
    def getTableCellRendererComponent(self, table, value, selected, focus, row, col):
        label = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, selected, focus, row, col)
        if not selected:
            label.setBackground(C_ROOT)
            label.setForeground(C_TEXT_DIM)
        label.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8))
        return label


class UIBuilder(JRunnable):
    def __init__(self, store, extender=None):
        self.store        = store
        self.extender     = extender
        self.tbl_model    = None
        self.detail_model = None
        self.detail_table = None
        self.summary_lbl  = None
        self.table        = None
        self._filter_sev  = None
        self._selected_f  = None   # currently selected Finding
        self._visible     = []     # currently displayed findings (respects filter)
        # Stat card labels updated on refresh
        self._lbl_total = None
        self._lbl_crit  = None
        self._lbl_high  = None
        self._lbl_med   = None
        self._lbl_low   = None
        self._lbl_info  = None
        self._dot_lbl   = None
        self.panel = JPanel(BorderLayout())
        self.panel.setBackground(C_ROOT)

    def run(self):
        self._build()
        self.store.add_listener(lambda: SwingUtilities.invokeLater(UIRefresher(self)))

    def _build(self):
        self.panel.removeAll()
        self.panel.setBackground(C_ROOT)

        # ================================================================
        # HEADER  (#0d1220, border-bottom #1e2d45)
        # ================================================================
        hdr = JPanel(BorderLayout())
        hdr.setBackground(C_HEADER_BG)
        hdr.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, C_BORDER),
            BorderFactory.createEmptyBorder(12, 20, 12, 20)))

        # Left: icon square + brand name + subtitle
        brand = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        brand.setBackground(C_HEADER_BG)

        icon_lbl = JLabel("AV")
        icon_lbl.setFont(Font("Arial", Font.BOLD, 11))
        icon_lbl.setForeground(Color.WHITE)
        icon_lbl.setOpaque(True)
        icon_lbl.setBackground(Color(59, 130, 246))   # #3b82f6
        icon_lbl.setHorizontalAlignment(SwingConstants.CENTER)
        icon_lbl.setPreferredSize(Dimension(28, 28))
        icon_lbl.setBorder(BorderFactory.createLineBorder(Color(139, 92, 246), 1))
        brand.add(icon_lbl)

        name_block = JPanel()
        name_block.setLayout(BoxLayout(name_block, BoxLayout.Y_AXIS))
        name_block.setBackground(C_HEADER_BG)

        brand_name = JLabel("AutoVuln")
        brand_name.setFont(Font("Arial", Font.BOLD, 14))
        brand_name.setForeground(C_TEXT_HEAD)

        brand_sub = JLabel("passive security scanner")
        brand_sub.setFont(Font("Monospaced", Font.PLAIN, 10))
        brand_sub.setForeground(C_BRAND_SUB)

        name_block.add(brand_name)
        name_block.add(brand_sub)
        brand.add(name_block)
        hdr.add(brand, BorderLayout.WEST)

        # Right: scanning dot + label + finding count
        right_box = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 0))
        right_box.setBackground(C_HEADER_BG)

        # Animated scanning dot (static green circle label)
        self._dot_lbl = JLabel("*")
        self._dot_lbl.setFont(Font("Arial", Font.PLAIN, 10))
        self._dot_lbl.setForeground(C_DOT)
        right_box.add(self._dot_lbl)

        self._scan_lbl = JLabel("scanning")
        self._scan_lbl.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._scan_lbl.setForeground(C_TEXT_MUTED)
        right_box.add(self._scan_lbl)

        self.summary_lbl = JLabel("0 findings")
        self.summary_lbl.setFont(Font("Monospaced", Font.BOLD, 13))
        self.summary_lbl.setForeground(C_TEXT)
        right_box.add(self.summary_lbl)

        hdr.add(right_box, BorderLayout.EAST)
        self.panel.add(hdr, BorderLayout.NORTH)

        # ================================================================
        # MAIN CONTENT  (stat cards + toolbar + table + detail)
        # ================================================================
        main = JPanel(BorderLayout())
        main.setBackground(C_ROOT)

        # -- STAT CARDS ROW ---------------------------------------------
        # Four clickable cards: Total / High / Medium / Low
        cards_panel = JPanel(GridLayout(1, 5, 12, 0))
        cards_panel.setBackground(C_ROOT)
        cards_panel.setBorder(BorderFactory.createEmptyBorder(16, 20, 0, 20))

        ui_ref = self

        def _make_card(label, num_color, sev_filter):
            card = JPanel(BorderLayout())
            card.setBackground(C_SURFACE)
            card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(C_BORDER, 1),
                BorderFactory.createEmptyBorder(12, 14, 12, 14)))
            card.setPreferredSize(Dimension(0, 68))

            num_lbl = JLabel("0")
            num_lbl.setFont(Font("Monospaced", Font.BOLD, 22))
            num_lbl.setForeground(num_color)

            tag_lbl = JLabel(label.upper())
            tag_lbl.setFont(Font("Arial", Font.PLAIN, 9))
            tag_lbl.setForeground(C_TEXT_MUTED)

            top_part = JPanel(BorderLayout())
            top_part.setBackground(C_SURFACE)
            top_part.add(num_lbl, BorderLayout.CENTER)
            top_part.add(tag_lbl, BorderLayout.SOUTH)

            card.add(top_part, BorderLayout.CENTER)

            class CardClick(MouseAdapter):
                def mouseClicked(self, e):
                    ui_ref._filter_sev = sev_filter
                    SwingUtilities.invokeLater(UIRefresher(ui_ref))
                def mouseEntered(self, e):
                    card.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(Color(60, 80, 110), 1),
                        BorderFactory.createEmptyBorder(12, 14, 12, 14)))
                def mouseExited(self, e):
                    card.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(C_BORDER, 1),
                        BorderFactory.createEmptyBorder(12, 14, 12, 14)))
            card.addMouseListener(CardClick())
            card.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))

            return card, num_lbl

        card_total, self._lbl_total = _make_card("Total",    C_TEXT,     None)
        card_crit,  self._lbl_crit  = _make_card("Critical", C_CRITICAL, SEVERITY_CRITICAL)
        card_high,  self._lbl_high  = _make_card("High",     C_HIGH,     SEVERITY_HIGH)
        card_med,   self._lbl_med   = _make_card("Medium",   C_MEDIUM,   SEVERITY_MEDIUM)
        card_low,   self._lbl_low   = _make_card("Low",      C_LOW,      SEVERITY_LOW)

        cards_panel.add(card_total)
        cards_panel.add(card_crit)
        cards_panel.add(card_high)
        cards_panel.add(card_med)
        cards_panel.add(card_low)

        # -- TOOLBAR ---------------------------------------------------
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 10))
        toolbar.setBackground(C_ROOT)
        toolbar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, C_TOOLBAR_BD),
            BorderFactory.createEmptyBorder(0, 12, 0, 12)))

        clear_btn = self._ghost_btn("Clear")
        csv_btn   = self._primary_btn("Export CSV")
        docx_btn  = self._primary_btn("Export DOCX")

        pause_btn = self._danger_btn(u"\u23f8 Pause")

        store_r = self.store
        panel_r = self.panel
        ext_r   = self.extender

        class ClearAction(MouseAdapter):
            def mouseClicked(self, e):
                if e.getButton() != 1: return
                ans = JOptionPane.showConfirmDialog(
                    panel_r, "Clear all findings?", "Confirm",
                    JOptionPane.YES_NO_OPTION)
                if ans == JOptionPane.YES_OPTION:
                    store_r.clear()
                    ui_ref._selected_f = None
                    ui_ref._repeater_btn.setEnabled(False)
                    ui_ref._det_panel.setVisible(False)

        class CsvAction(MouseAdapter):
            def mouseClicked(self, e):
                if e.getButton() != 1: return
                _do_export(store_r, panel_r, "csv")

        class DocxAction(MouseAdapter):
            def mouseClicked(self, e):
                if e.getButton() != 1: return
                _do_export(store_r, panel_r, "docx")

        class PauseAction(MouseAdapter):
            def mouseClicked(self, e):
                if ext_r is not None:
                    ext_r._paused = not ext_r._paused
                    if ext_r._paused:
                        pause_btn.setText(u"\u23f8 Paused")
                        ui_ref._scan_lbl.setText("paused")
                        ui_ref._scan_lbl.setForeground(C_BTN_DANGER_FG)
                        ui_ref._dot_lbl.setForeground(C_BTN_DANGER_FG)
                    else:
                        pause_btn.setText(u"\u23f8 Pause")
                        ui_ref._scan_lbl.setText("scanning")
                        ui_ref._scan_lbl.setForeground(C_TEXT_MUTED)
                        ui_ref._dot_lbl.setForeground(C_DOT)

        clear_btn.addMouseListener(ClearAction())
        csv_btn.addMouseListener(CsvAction())
        docx_btn.addMouseListener(DocxAction())
        pause_btn.addMouseListener(PauseAction())

        toolbar.add(clear_btn)
        toolbar.add(csv_btn)
        toolbar.add(docx_btn)
        toolbar.add(pause_btn)

        # -- TABLE ----------------------------------------------------
        class ReadOnlyModel(DefaultTableModel):
            def isCellEditable(self, row, col): return False

        self.tbl_model = ReadOnlyModel(COLS, 0)

        table = JTable(self.tbl_model)
        table.setRowHeight(38)
        table.setBackground(C_ROOT)
        table.setForeground(C_TEXT_DIM)
        table.setSelectionBackground(C_SEL_ROW)
        table.setSelectionForeground(C_TEXT)
        table.setShowVerticalLines(False)
        table.setShowHorizontalLines(True)
        table.setGridColor(C_BORDER2)
        table.setFont(Font("Monospaced", Font.PLAIN, 11))
        table.setAutoCreateRowSorter(True)
        table.setFillsViewportHeight(True)
        table.setIntercellSpacing(Dimension(0, 0))

        hdr2 = table.getTableHeader()
        hdr2.setBackground(C_SURFACE)
        hdr2.setForeground(C_TEXT_MUTED)   # now 120,145,175 -- readable on dark
        hdr2.setFont(Font("Arial", Font.BOLD, 10))
        hdr2.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, C_BORDER))
        hdr2.setReorderingAllowed(False)
        hdr2.setResizingAllowed(True)

        for i, w in enumerate(COL_WIDTHS):
            table.getColumnModel().getColumn(i).setPreferredWidth(w)

        table.getColumnModel().getColumn(0).setCellRenderer(NumRenderer())
        table.getColumnModel().getColumn(1).setCellRenderer(SeverityRenderer())
        table.getColumnModel().getColumn(2).setCellRenderer(FindingNameRenderer())
        table.getColumnModel().getColumn(3).setCellRenderer(EndpointRenderer())
        table.getColumnModel().getColumn(4).setCellRenderer(StatusRenderer())
        table.getColumnModel().getColumn(5).setCellRenderer(CweRenderer())

        self.table = table

        # Right-click menu
        popup   = JPopupMenu()
        popup.setBackground(C_SURFACE)
        mi_ep   = JMenuItem("Copy Endpoint URL")
        mi_full = JMenuItem("Copy Full URL")
        mi_ev   = JMenuItem("Copy Evidence")
        for mi in [mi_ep, mi_full, mi_ev]:
            mi.setBackground(C_SURFACE)
            mi.setForeground(C_TEXT_DIM)
            mi.setFont(Font("Monospaced", Font.PLAIN, 11))
            popup.add(mi)

        store_ref2 = self.store

        def _clip(text):
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                StringSelection(text), None)

        class PopupTrigger(MouseAdapter):
            def mousePressed(self, e):  self._chk(e)
            def mouseReleased(self, e): self._chk(e)
            def _chk(self, e):
                if e.isPopupTrigger():
                    r = table.rowAtPoint(e.getPoint())
                    if r >= 0:
                        table.setRowSelectionInterval(r, r)
                        popup.show(e.getComponent(), e.getX(), e.getY())

        class CpEp(MouseAdapter):
            def mouseClicked(self, e):
                r = table.getSelectedRow()
                if r >= 0:
                    mr = table.convertRowIndexToModel(r)
                    fl = store_ref2.get_all()
                    if mr < len(fl): _clip(fl[mr].endpoint)

        class CpFull(MouseAdapter):
            def mouseClicked(self, e):
                r = table.getSelectedRow()
                if r >= 0:
                    mr = table.convertRowIndexToModel(r)
                    fl = store_ref2.get_all()
                    if mr < len(fl): _clip(fl[mr].url)

        class CpEv(MouseAdapter):
            def mouseClicked(self, e):
                r = table.getSelectedRow()
                if r >= 0:
                    mr = table.convertRowIndexToModel(r)
                    fl = store_ref2.get_all()
                    if mr < len(fl): _clip(fl[mr].evidence)

        mi_ep.addMouseListener(CpEp())
        mi_full.addMouseListener(CpFull())
        mi_ev.addMouseListener(CpEv())
        table.addMouseListener(PopupTrigger())

        tbl_scroll = JScrollPane(table)
        tbl_scroll.setBorder(BorderFactory.createEmptyBorder())
        tbl_scroll.getViewport().setBackground(C_ROOT)
        tbl_scroll.setBackground(C_ROOT)

        # -- DETAIL PANEL  (#0d1220 card with border + grid layout) --
        # Header row: badge + finding name
        self._det_panel = JPanel(BorderLayout())
        self._det_panel.setBackground(C_HEADER_BG)
        self._det_panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(C_BORDER, 1),
            BorderFactory.createEmptyBorder(0, 0, 0, 0)))
        self._det_panel.setVisible(False)

        det_hdr = JPanel(BorderLayout())
        det_hdr.setBackground(C_HEADER_BG)
        det_hdr.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, C_BORDER))

        # Left side: badge + title
        det_hdr_left = JPanel(FlowLayout(FlowLayout.LEFT, 10, 10))
        det_hdr_left.setBackground(C_HEADER_BG)

        self._det_badge = JLabel("")
        self._det_badge.setFont(Font("Monospaced", Font.BOLD, 10))
        self._det_badge.setOpaque(True)
        self._det_badge.setBackground(C_BADGE_HIGH_BG)
        self._det_badge.setForeground(C_HIGH)
        self._det_badge.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(C_BADGE_HIGH_BD, 1),
            BorderFactory.createEmptyBorder(2, 8, 2, 8)))

        self._det_title = JLabel("")
        self._det_title.setFont(Font("Arial", Font.BOLD, 12))
        self._det_title.setForeground(C_TEXT_HEAD)

        det_hdr_left.add(self._det_badge)
        det_hdr_left.add(self._det_title)
        det_hdr.add(det_hdr_left, BorderLayout.WEST)

        # Right side: Send to Repeater button
        det_hdr_right = JPanel(FlowLayout(FlowLayout.RIGHT, 10, 8))
        det_hdr_right.setBackground(C_HEADER_BG)

        self._repeater_btn = self._primary_btn(u"▶  Send to Repeater")
        self._repeater_btn.setEnabled(False)

        ui_ref2 = self
        extender_ref = self.extender

        class RepeaterAction(MouseAdapter):
            def mouseClicked(self, e):
                if e.getButton() != 1:   # left-click only
                    return
                if not ui_ref2._repeater_btn.isEnabled():
                    return
                f = ui_ref2._selected_f
                if f is None or f.raw_request is None or f.http_service is None:
                    JOptionPane.showMessageDialog(
                        ui_ref2.panel,
                        "No request data available for this finding.\nOnly findings captured during this session can be sent to Repeater.",
                        "Send to Repeater", JOptionPane.INFORMATION_MESSAGE)
                    return
                try:
                    svc = f.http_service
                    extender_ref._cb.sendToRepeater(
                        svc.getHost(), svc.getPort(),
                        svc.getProtocol() == "https",
                        f.raw_request,
                        f.name[:50])
                except Exception as ex:
                    JOptionPane.showMessageDialog(
                        ui_ref2.panel,
                        "Failed to send to Repeater: " + str(ex),
                        "Error", JOptionPane.ERROR_MESSAGE)

        self._repeater_btn.addMouseListener(RepeaterAction())
        det_hdr_right.add(self._repeater_btn)
        det_hdr.add(det_hdr_right, BorderLayout.EAST)

        self._det_panel.add(det_hdr, BorderLayout.NORTH)

        # Two-column grid: Target | Classification
        meta_grid = JPanel(GridLayout(1, 2, 0, 0))
        meta_grid.setBackground(C_HEADER_BG)

        self._meta_left  = self._detail_section("Target")
        self._meta_right = self._detail_section("Classification")
        meta_grid.add(self._meta_left[0])
        meta_grid.add(self._meta_right[0])

        # Description strip
        desc_strip = JPanel(BorderLayout())
        desc_strip.setBackground(C_HEADER_BG)
        desc_strip.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, C_BORDER),
            BorderFactory.createEmptyBorder(12, 16, 12, 16)))

        desc_tag = JLabel("DESCRIPTION")
        desc_tag.setFont(Font("Arial", Font.BOLD, 9))
        desc_tag.setForeground(C_TEXT_MUTED)
        desc_strip.add(desc_tag, BorderLayout.NORTH)

        self._det_desc = JTextArea()
        self._det_desc.setFont(Font("Arial", Font.PLAIN, 12))
        self._det_desc.setForeground(C_TEXT)
        self._det_desc.setBackground(C_HEADER_BG)
        self._det_desc.setLineWrap(True)
        self._det_desc.setWrapStyleWord(True)
        self._det_desc.setEditable(False)
        self._det_desc.setBorder(BorderFactory.createEmptyBorder(6, 0, 0, 0))
        desc_strip.add(self._det_desc, BorderLayout.CENTER)

        # Evidence | Remediation two-column
        blocks_grid = JPanel(GridLayout(1, 2, 0, 0))
        blocks_grid.setBackground(C_HEADER_BG)
        blocks_grid.setBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, C_BORDER))

        self._ev_area  = self._code_block("Evidence")
        self._rem_area = self._code_block("Remediation")
        blocks_grid.add(self._ev_area[0])
        blocks_grid.add(self._rem_area[0])

        # Affected Endpoints strip (visible only when >1 endpoint)
        self._affected_strip = JPanel(BorderLayout())
        self._affected_strip.setBackground(C_HEADER_BG)
        self._affected_strip.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, C_BORDER),
            BorderFactory.createEmptyBorder(12, 16, 12, 16)))

        affected_hdr = JPanel(BorderLayout())
        affected_hdr.setBackground(C_HEADER_BG)

        affected_tag = JLabel("AFFECTED ENDPOINTS")
        affected_tag.setFont(Font("Arial", Font.BOLD, 9))
        affected_tag.setForeground(C_TEXT_MUTED)
        affected_hdr.add(affected_tag, BorderLayout.WEST)

        self._affected_count_lbl = JLabel("")
        self._affected_count_lbl.setFont(Font("Monospaced", Font.BOLD, 10))
        self._affected_count_lbl.setForeground(C_MEDIUM)
        affected_hdr.add(self._affected_count_lbl, BorderLayout.EAST)

        self._affected_strip.add(affected_hdr, BorderLayout.NORTH)

        self._affected_area = JTextArea()
        self._affected_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._affected_area.setForeground(C_ACCENT_BLU)
        self._affected_area.setBackground(C_DEEP)
        self._affected_area.setLineWrap(True)
        self._affected_area.setWrapStyleWord(False)
        self._affected_area.setEditable(False)
        self._affected_area.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10))

        affected_scroll = JScrollPane(self._affected_area)
        affected_scroll.setBorder(BorderFactory.createLineBorder(Color(19, 30, 46), 1))
        affected_scroll.getViewport().setBackground(C_DEEP)
        affected_scroll.setPreferredSize(Dimension(0, 90))
        self._affected_strip.add(affected_scroll, BorderLayout.CENTER)
        self._affected_strip.setVisible(False)

        det_body = JPanel()
        det_body.setLayout(BoxLayout(det_body, BoxLayout.Y_AXIS))
        det_body.setBackground(C_HEADER_BG)
        det_body.add(meta_grid)
        det_body.add(desc_strip)
        det_body.add(blocks_grid)
        det_body.add(self._affected_strip)

        det_scroll = JScrollPane(det_body)
        det_scroll.setBorder(BorderFactory.createEmptyBorder())
        det_scroll.getViewport().setBackground(C_HEADER_BG)

        self._det_panel.add(det_scroll, BorderLayout.CENTER)

        # Row selection listener -> populate detail panel
        store_ref = self.store
        det_panel_ref = self._det_panel

        class RowListener(MouseAdapter):
            def mouseClicked(self, e):
                row = table.getSelectedRow()
                if row >= 0:
                    mr = table.convertRowIndexToModel(row)
                    fl = ui_ref._visible
                    if mr < len(fl):
                        ui_ref._populate_detail(fl[mr])
                        det_panel_ref.setVisible(True)

        table.addMouseListener(RowListener())

        # -- ASSEMBLE LAYOUT ------------------------------------------
        top_controls = JPanel(BorderLayout())
        top_controls.setBackground(C_ROOT)
        top_controls.add(cards_panel, BorderLayout.NORTH)
        top_controls.add(toolbar,     BorderLayout.SOUTH)

        tbl_wrap = JPanel(BorderLayout())
        tbl_wrap.setBackground(C_ROOT)
        tbl_wrap.setBorder(BorderFactory.createEmptyBorder(0, 20, 0, 20))
        tbl_wrap.add(tbl_scroll, BorderLayout.CENTER)

        det_wrap = JPanel(BorderLayout())
        det_wrap.setBackground(C_ROOT)
        det_wrap.setBorder(BorderFactory.createEmptyBorder(12, 20, 16, 20))
        det_wrap.add(self._det_panel, BorderLayout.CENTER)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, tbl_wrap, det_wrap)
        split.setResizeWeight(0.58)
        split.setDividerSize(3)
        split.setBackground(C_ROOT)
        split.setBorder(BorderFactory.createEmptyBorder())

        main.add(top_controls, BorderLayout.NORTH)
        main.add(split,        BorderLayout.CENTER)

        self.panel.add(main, BorderLayout.CENTER)

    # ----------------------------------------------------------------
    # DETAIL PANEL HELPERS
    # ----------------------------------------------------------------
    def _detail_section(self, title):
        """Returns (panel, dict of JLabel values keyed by field name)."""
        panel = JPanel(BorderLayout())
        panel.setBackground(C_HEADER_BG)
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 1, C_BORDER),
            BorderFactory.createEmptyBorder(12, 16, 12, 16)))

        tag = JLabel(title.upper())
        tag.setFont(Font("Arial", Font.BOLD, 9))
        tag.setForeground(C_TEXT_MUTED)
        tag.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0))
        panel.add(tag, BorderLayout.NORTH)

        kv_panel = JPanel()
        kv_panel.setLayout(BoxLayout(kv_panel, BoxLayout.Y_AXIS))
        kv_panel.setBackground(C_HEADER_BG)
        panel.add(kv_panel, BorderLayout.CENTER)

        return panel, kv_panel

    def _make_kv_row(self, key_text, parent_panel):
        """Add a key-value row to parent_panel and return the value JLabel."""
        row = JPanel(BorderLayout())
        row.setBackground(C_HEADER_BG)
        row.setBorder(BorderFactory.createEmptyBorder(3, 0, 3, 0))

        key_lbl = JLabel(key_text)
        key_lbl.setFont(Font("Monospaced", Font.PLAIN, 10))
        key_lbl.setForeground(C_TEXT_MUTED)
        key_lbl.setPreferredSize(Dimension(90, 18))

        val_lbl = JLabel("")
        val_lbl.setFont(Font("Monospaced", Font.PLAIN, 12))
        val_lbl.setForeground(C_TEXT)

        row.add(key_lbl, BorderLayout.WEST)
        row.add(val_lbl, BorderLayout.CENTER)
        parent_panel.add(row)
        return val_lbl

    def _code_block(self, title):
        """Evidence / Remediation block with dark code bg."""
        panel = JPanel(BorderLayout())
        panel.setBackground(C_HEADER_BG)
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 0, 1, C_BORDER),
            BorderFactory.createEmptyBorder(12, 16, 12, 16)))

        tag = JLabel(title.upper())
        tag.setFont(Font("Arial", Font.BOLD, 9))
        tag.setForeground(C_TEXT_MUTED)
        tag.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0))
        panel.add(tag, BorderLayout.NORTH)

        area = JTextArea()
        area.setFont(Font("Monospaced", Font.PLAIN, 11))
        area.setForeground(C_TEXT_DIM)
        area.setBackground(C_DEEP)
        area.setLineWrap(True)
        area.setWrapStyleWord(True)
        area.setEditable(False)
        area.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10))

        scroll = JScrollPane(area)
        scroll.setBorder(BorderFactory.createLineBorder(Color(19, 30, 46), 1))
        scroll.getViewport().setBackground(C_DEEP)
        panel.add(scroll, BorderLayout.CENTER)
        return panel, area

    def _populate_detail(self, f):
        """Fill all detail panel widgets from a Finding object."""
        # Track selected finding for Repeater
        self._selected_f = f
        # Enable/disable repeater button based on whether raw request is available
        has_req = f.raw_request is not None and f.http_service is not None
        self._repeater_btn.setEnabled(has_req)
        self._repeater_btn.setToolTipText(
            None if has_req else
            "Request not available - only findings captured in this session can be sent to Repeater")

        # Badge
        sev = f.severity
        self._det_badge.setText(sev.upper())
        self._det_badge.setBackground(SEV_BG.get(sev, C_SURFACE))
        self._det_badge.setForeground(SEV_FG.get(sev, C_TEXT_DIM))
        self._det_badge.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(SEV_BD.get(sev, C_BORDER), 1),
            BorderFactory.createEmptyBorder(2, 8, 2, 8)))

        self._det_title.setText(f.name)

        # Rebuild meta sections
        left_kv  = self._meta_left[1]
        right_kv = self._meta_right[1]
        left_kv.removeAll()
        right_kv.removeAll()

        h_lbl  = self._make_kv_row("Host",        left_kv)
        sc_lbl = self._make_kv_row("HTTP Status",  left_kv)
        url_lbl = self._make_kv_row("URL",         left_kv)
        h_lbl.setText(f.host)
        first_ep = f.affected_endpoints[0] if f.affected_endpoints else {}
        sc_lbl.setText(str(first_ep.get("status_code", "")) if first_ep.get("status_code") else "-")
        url_lbl.setText(_trunc(first_ep.get("endpoint", f.url), 60))
        url_lbl.setForeground(C_ACCENT_BLU)

        cwe_lbl = self._make_kv_row("CWE",     right_kv)
        sev_lbl = self._make_kv_row("Severity", right_kv)
        cwe_lbl.setText(f.cwe)
        cwe_lbl.setForeground(C_ACCENT_BLU)
        sev_lbl.setText(sev)
        sev_lbl.setForeground(SEV_FG.get(sev, C_TEXT_DIM))

        left_kv.revalidate()
        left_kv.repaint()
        right_kv.revalidate()
        right_kv.repaint()

        self._det_desc.setText(f.description)
        self._ev_area[1].setText(f.evidence)
        self._rem_area[1].setText(f.remediation)
        self._ev_area[1].setCaretPosition(0)
        self._rem_area[1].setCaretPosition(0)

        # Affected endpoints section
        eps = f.affected_endpoints
        if len(eps) > 1:
            lines = []
            for idx, ep in enumerate(eps, 1):
                sc = str(ep["status_code"]) if ep.get("status_code") else "-"
                lines.append("[{}]  {}  (HTTP {})".format(idx, ep["endpoint"], sc))
            self._affected_area.setText("\n".join(lines))
            self._affected_area.setCaretPosition(0)
            self._affected_count_lbl.setText("{} endpoints affected".format(len(eps)))
            self._affected_strip.setVisible(True)
        else:
            self._affected_strip.setVisible(False)

    # ----------------------------------------------------------------
    # BUTTON FACTORIES
    # ----------------------------------------------------------------
    def _primary_btn(self, text):
        b = JButton(text)
        b.setBackground(C_BTN_PRIMARY)
        b.setForeground(C_BTN_PRIMARY_FG)
        b.setFont(Font("Monospaced", Font.BOLD, 11))
        b.setFocusPainted(False)
        b.setBorderPainted(False)
        b.setBorder(BorderFactory.createEmptyBorder(6, 14, 6, 14))
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        b.setOpaque(True)
        return b

    def _ghost_btn(self, text):
        b = JButton(text)
        b.setBackground(C_BTN_GHOST_BG)
        b.setForeground(C_BTN_GHOST_FG)
        b.setFont(Font("Monospaced", Font.BOLD, 11))
        b.setFocusPainted(False)
        b.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(C_BTN_GHOST_BD, 1),
            BorderFactory.createEmptyBorder(5, 13, 5, 13)))
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        b.setOpaque(True)
        return b

    def _danger_btn(self, text):
        b = JButton(text)
        b.setBackground(C_BTN_DANGER_BG)
        b.setForeground(C_BTN_DANGER_FG)
        b.setFont(Font("Monospaced", Font.BOLD, 11))
        b.setFocusPainted(False)
        b.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(C_BTN_DANGER_BD, 1),
            BorderFactory.createEmptyBorder(5, 13, 5, 13)))
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        b.setOpaque(True)
        return b

    # ----------------------------------------------------------------
    # REFRESH  (called on every new finding)
    # ----------------------------------------------------------------
    def refresh(self):
        self.tbl_model.setRowCount(0)
        all_findings = self.store.get_all()
        if self._filter_sev is not None:
            visible = [f for f in all_findings if f.severity == self._filter_sev]
        else:
            visible = all_findings

        self._visible = visible
        for i, f in enumerate(visible, 1):
            n = len(f.affected_endpoints)
            ep_cell = "{} endpoints".format(n) if n > 1 else f.endpoint
            sc_cell = str(f.affected_endpoints[0]["status_code"]) if f.affected_endpoints and f.affected_endpoints[0]["status_code"] else "-"
            self.tbl_model.addRow([
                i, f.severity, f.name, ep_cell,
                sc_cell,
                f.cwe
            ])

        s = self.store.summary()
        total = self.store.size()
        self._lbl_total.setText(str(total))
        self._lbl_crit.setText(str(s[SEVERITY_CRITICAL]))
        self._lbl_high.setText(str(s[SEVERITY_HIGH]))
        self._lbl_med.setText(str(s[SEVERITY_MEDIUM]))
        self._lbl_low.setText(str(s[SEVERITY_LOW]))

        filt = " [{}]".format(self._filter_sev) if self._filter_sev else ""
        self.summary_lbl.setText("{} findings{}".format(total, filt))


class UIRefresher(JRunnable):
    def __init__(self, builder): self.builder = builder
    def run(self): self.builder.refresh()




def _do_export(store, parent, fmt):
    findings = store.get_all()
    if not findings:
        JOptionPane.showMessageDialog(parent, "No findings to export.",
                                      "Export", JOptionPane.INFORMATION_MESSAGE)
        return
    chooser = JFileChooser()
    chooser.setSelectedFile(File("autovuln_findings." + fmt))
    if chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION:
        return
    path = chooser.getSelectedFile().getAbsolutePath()
    try:
        if fmt == "csv":
            export_csv(findings, path)
        else:
            export_docx_simple(findings, path)
        JOptionPane.showMessageDialog(
            parent,
            "Exported {} findings to: {}".format(len(findings), path),
            "Export Complete", JOptionPane.INFORMATION_MESSAGE)
    except Exception as ex:
        JOptionPane.showMessageDialog(parent, "Export failed: " + str(ex),
                                      "Error", JOptionPane.ERROR_MESSAGE)


# ===============================================================================
# BURP EXTENSION ENTRY POINT
# ===============================================================================

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._cb      = callbacks
        self._helpers = callbacks.getHelpers()
        self._store   = FindingStore()
        self._out     = PrintWriter(callbacks.getStdout(), True)
        self._err     = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName(EXT_NAME)
        self._paused = False

        # Build UI
        self._ui = UIBuilder(self._store, self)
        SwingUtilities.invokeLater(self._ui)

        # Register
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        self._out.println("[AutoVuln] v{} loaded. Passive scanning active.".format(VERSION))

    # -- ITab ------------------------------------------------------------------
    def getTabCaption(self): return "AutoVuln"
    def getUiComponent(self): return self._ui.panel

    # -- IHttpListener ---------------------------------------------------------
    def processHttpMessage(self, tool_flag, is_request, message_info):
        if is_request:
            return
        try:
            self._process(message_info)
        except Exception as e:
            self._err.println("[AutoVuln] Error: " + str(e))

    def _process(self, message_info):
        req  = message_info.getRequest()
        resp = message_info.getResponse()
        if not resp:
            return

        # Scope check
        url_obj = self._helpers.analyzeRequest(message_info).getUrl()
        if not self._cb.isInScope(url_obj):
            return

        # Skip if scanning is paused
        if self._paused:
            return

        url  = str(url_obj)
        host = url_obj.getHost()

        # Parse response status code
        resp_info   = self._helpers.analyzeResponse(resp)
        status_code = resp_info.getStatusCode()

        # Skip responses unlikely to yield meaningful findings:
        # 404 -- page not found (boilerplate headers, not the real app surface)
        # 5xx -- server errors (may flood findings with same error page headers)
        if status_code == 404 or status_code >= 500:
            return

        # Parse request headers
        req_info = self._helpers.analyzeRequest(req)
        req_hdrs = {}
        for h in req_info.getHeaders()[1:]:
            if ":" in h:
                k, v = h.split(":", 1)
                req_hdrs[k.strip().lower()] = v.strip()

        method = req_info.getMethod()

        # Parse response headers
        resp_hdrs   = {}
        set_cookies = []

        for h in resp_info.getHeaders()[1:]:
            if ":" in h:
                k, v = h.split(":", 1)
                key = k.strip().lower()
                val = v.strip()
                resp_hdrs[key] = val
                if key == "set-cookie":
                    set_cookies.append(val)

        # Response body (limit 512KB)
        body_offset = resp_info.getBodyOffset()
        body_bytes  = resp[body_offset:body_offset + 512000]
        try:
            body = self._helpers.bytesToString(body_bytes)
        except Exception:
            body = ""

        content_type = resp_hdrs.get("content-type", "")

        # Dispatch
        findings = dispatch(req_hdrs, resp_hdrs, set_cookies,
                            body, content_type, method, host, url, status_code)

        svc = message_info.getHttpService()
        for f in findings:
            # Attach raw request to the first (and only, at creation time) affected_endpoint entry
            f.affected_endpoints[0]["raw_request"]  = req
            f.affected_endpoints[0]["http_service"] = svc
            if self._store.add(f):
                self._out.println(u"[AutoVuln] {} | {} | {} [HTTP {}]".format(
                    f.severity.upper(), f.name, f.endpoint, f.status_code))

