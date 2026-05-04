#!/usr/bin/env python3
"""
WebVulnScanner - Automated Web Vulnerability Scanner
Detects: SQL Injection, XSS, Open Redirects, Sensitive Files, Security Headers
Author: Your Name
License: MIT
"""

import requests
import argparse
import sys
import json
import time
from urllib.parse import urlparse, urlencode, urljoin
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ──────────────────────────────────────────────
# PAYLOADS
# ──────────────────────────────────────────────

SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--",
    "\" OR \"1\"=\"1", "'; DROP TABLE users--",
    "1' AND SLEEP(3)--", "1 AND 1=2 UNION SELECT NULL--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
]

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/config.php", "/wp-config.php",
    "/admin", "/admin/login", "/phpmyadmin", "/server-status",
    "/.htaccess", "/backup.sql", "/dump.sql", "/robots.txt",
    "/sitemap.xml", "/.DS_Store", "/web.config",
]

SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# ──────────────────────────────────────────────
# COLORS & OUTPUT
# ──────────────────────────────────────────────

def banner():
    print(Fore.CYAN + r"""
 __        __   _  __     _____     _ ___ 
 \ \      / /__| | \ \   / / _ \  / / __|
  \ \ /\ / / _ \ |__\ \ / / | | |/ /\__ \
   \ V  V /  __/ |__ \ V /| |_| / / ___) |
    \_/\_/ \___|_____| \_/  \___/_/  |____/

  Web Vulnerability Scanner v1.0
  ⚠  For authorized targets only ⚠
""" + Style.RESET_ALL)

def ok(msg):    print(Fore.GREEN  + f"  [✓] {msg}")
def warn(msg):  print(Fore.YELLOW + f"  [!] {msg}")
def vuln(msg):  print(Fore.RED    + f"  [✗] VULN  » {msg}")
def info(msg):  print(Fore.BLUE   + f"  [i] {msg}")
def head(msg):  print(Fore.MAGENTA + f"\n{'─'*55}\n  {msg}\n{'─'*55}")

# ──────────────────────────────────────────────
# CORE SCANNER CLASS
# ──────────────────────────────────────────────

class WebVulnScanner:
    def __init__(self, target: str, timeout: int = 10, delay: float = 0.5):
        self.target  = target.rstrip("/")
        self.timeout = timeout
        self.delay   = delay
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (WebVulnScanner/1.0)"
        })
        self.findings = []

    # ── helpers ────────────────────────────────

    def _get(self, url, params=None):
        try:
            r = self.session.get(url, params=params, timeout=self.timeout, allow_redirects=True)
            time.sleep(self.delay)
            return r
        except requests.RequestException:
            return None

    def _record(self, severity, category, detail, url=""):
        entry = {"severity": severity, "category": category, "detail": detail, "url": url}
        self.findings.append(entry)

    # ── 1. SQL INJECTION ───────────────────────

    def check_sqli(self, url, params):
        head("1 — SQL Injection")
        errors = [
            "you have an error in your sql syntax",
            "warning: mysql", "unclosed quotation mark",
            "quoted string not properly terminated",
            "sqlstate", "ORA-", "pg_query()", "syntax error",
        ]
        vulnerable = False
        for param in params:
            for payload in SQLI_PAYLOADS:
                test_params = dict(params)
                test_params[param] = payload
                r = self._get(url, params=test_params)
                if r and any(e in r.text.lower() for e in errors):
                    vuln(f"SQLi in param '{param}' → payload: {payload}")
                    self._record("HIGH", "SQL Injection", f"param={param}, payload={payload}", url)
                    vulnerable = True
                    break
        if not vulnerable:
            ok("No obvious SQL Injection found")

    # ── 2. CROSS-SITE SCRIPTING ────────────────

    def check_xss(self, url, params):
        head("2 — Cross-Site Scripting (XSS)")
        vulnerable = False
        for param in params:
            for payload in XSS_PAYLOADS:
                test_params = dict(params)
                test_params[param] = payload
                r = self._get(url, params=test_params)
                if r and payload in r.text:
                    vuln(f"Reflected XSS in param '{param}' → payload: {payload}")
                    self._record("HIGH", "XSS", f"param={param}, payload={payload}", url)
                    vulnerable = True
                    break
        if not vulnerable:
            ok("No reflected XSS found")

    # ── 3. OPEN REDIRECT ──────────────────────

    def check_open_redirect(self, url, params):
        head("3 — Open Redirect")
        redirect_payloads = [
            "https://evil.com", "//evil.com",
            "https://evil.com%2F%2F", "/\\evil.com",
        ]
        redirect_params = [p for p in params if any(
            k in p.lower() for k in ["url", "redirect", "next", "return", "goto", "dest"]
        )]
        if not redirect_params:
            info("No redirect-like params found — skipping")
            return
        vulnerable = False
        for param in redirect_params:
            for payload in redirect_payloads:
                test_params = dict(params)
                test_params[param] = payload
                r = self._get(url, params=test_params)
                if r and "evil.com" in r.url:
                    vuln(f"Open Redirect via param '{param}'")
                    self._record("MEDIUM", "Open Redirect", f"param={param}", url)
                    vulnerable = True
        if not vulnerable:
            ok("No Open Redirect found")

    # ── 4. SENSITIVE FILES ────────────────────

    def check_sensitive_files(self):
        head("4 — Sensitive Files & Directories")
        found_any = False
        for path in SENSITIVE_PATHS:
            url = self.target + path
            r = self._get(url)
            if r and r.status_code == 200:
                vuln(f"Exposed: {url}  (HTTP {r.status_code})")
                self._record("MEDIUM", "Sensitive File Exposure", path, url)
                found_any = True
            elif r and r.status_code in (301, 302):
                warn(f"Redirect on {path} → {r.headers.get('Location', '?')}")
        if not found_any:
            ok("No sensitive files exposed")

    # ── 5. SECURITY HEADERS ───────────────────

    def check_security_headers(self):
        head("5 — Security Headers")
        r = self._get(self.target)
        if not r:
            warn("Could not fetch target for header analysis")
            return
        for h in SECURITY_HEADERS:
            if h.lower() in [k.lower() for k in r.headers]:
                ok(f"Present : {h}")
            else:
                vuln(f"Missing : {h}")
                self._record("LOW", "Missing Security Header", h, self.target)

    # ── 6. CLICKJACKING ───────────────────────

    def check_clickjacking(self):
        head("6 — Clickjacking")
        r = self._get(self.target)
        if not r:
            return
        xfo = r.headers.get("X-Frame-Options", "")
        csp = r.headers.get("Content-Security-Policy", "")
        if xfo or "frame-ancestors" in csp.lower():
            ok(f"Protected (X-Frame-Options: {xfo or 'via CSP'})")
        else:
            vuln("No clickjacking protection detected")
            self._record("MEDIUM", "Clickjacking", "Missing X-Frame-Options / CSP frame-ancestors", self.target)

    # ── REPORT ────────────────────────────────

    def print_report(self):
        head("SCAN REPORT")
        totals = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            totals[f["severity"]] = totals.get(f["severity"], 0) + 1

        print(f"  Target  : {self.target}")
        print(f"  Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Findings: {len(self.findings)}")
        print(f"  HIGH={totals['HIGH']}  MEDIUM={totals['MEDIUM']}  LOW={totals['LOW']}\n")

        if not self.findings:
            ok("No vulnerabilities found. Target appears clean.")
            return

        for f in self.findings:
            color = Fore.RED if f["severity"]=="HIGH" else (Fore.YELLOW if f["severity"]=="MEDIUM" else Fore.CYAN)
            print(color + f"  [{f['severity']}] {f['category']}: {f['detail']}")
            if f["url"]:
                print(Fore.WHITE + f"         URL: {f['url']}")

    def save_json(self, filename="report.json"):
        report = {
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": self.findings,
        }
        with open(filename, "w") as fh:
            json.dump(report, fh, indent=2)
        ok(f"Report saved → {filename}")

    # ── RUN ALL ───────────────────────────────

    def run(self, params=None):
        banner()
        info(f"Target  : {self.target}")
        info(f"Timeout : {self.timeout}s  |  Delay: {self.delay}s\n")

        params = params or {}

        self.check_sensitive_files()
        self.check_security_headers()
        self.check_clickjacking()

        if params:
            self.check_sqli(self.target, params)
            self.check_xss(self.target, params)
            self.check_open_redirect(self.target, params)
        else:
            warn("No --params given — skipping SQLi / XSS / Open Redirect checks")

        self.print_report()


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def parse_params(raw: str) -> dict:
    """Parse 'key=value,key2=value2' into a dict."""
    result = {}
    for pair in raw.split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def main():
    parser = argparse.ArgumentParser(
        description="WebVulnScanner — automated web vulnerability scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python scanner.py -u https://example.com
  python scanner.py -u https://example.com -p "id=1,search=test"
  python scanner.py -u https://example.com -p "id=1" --save report.json
        """
    )
    parser.add_argument("-u", "--url",     required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("-p", "--params",  default="",    help="GET params to fuzz: 'key=val,key2=val2'")
    parser.add_argument("-t", "--timeout", default=10,    type=int, help="Request timeout in seconds")
    parser.add_argument("-d", "--delay",   default=0.5,   type=float, help="Delay between requests")
    parser.add_argument("--save",          default="",    help="Save JSON report to file")
    args = parser.parse_args()

    scanner = WebVulnScanner(args.url, timeout=args.timeout, delay=args.delay)
    params  = parse_params(args.params) if args.params else {}
    scanner.run(params=params)

    if args.save:
        scanner.save_json(args.save)


if __name__ == "__main__":
    main()
