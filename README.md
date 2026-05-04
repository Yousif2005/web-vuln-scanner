# 🔍 WebVulnScanner

> Automated Web Vulnerability Scanner — built for ethical hackers, students, and bug bounty hunters.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## ⚠️ Disclaimer

> **This tool is for educational purposes and authorized penetration testing only.**  
> Never scan targets you don't own or have explicit written permission to test.  
> The author is not responsible for misuse.

---

## ✨ Features

| Module | What it detects |
|---|---|
| 🧨 SQL Injection | Error-based & time-based SQLi in GET parameters |
| 💥 XSS | Reflected Cross-Site Scripting via GET parameters |
| 🔀 Open Redirect | Unvalidated redirects via URL parameters |
| 📂 Sensitive Files | `.env`, `.git/config`, `wp-config.php`, admin panels, etc. |
| 🛡️ Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc. |
| 🖱️ Clickjacking | Missing frame protection headers |

---

## 📦 Installation

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/web-vuln-scanner.git
cd web-vuln-scanner

# 2. (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

### Basic scan (headers + sensitive files)
```bash
python scanner.py -u https://example.com
```

### Full scan with parameters (SQLi + XSS + Redirect)
```bash
python scanner.py -u https://example.com -p "id=1,search=hello"
```

### Save JSON report
```bash
python scanner.py -u https://example.com -p "id=1" --save report.json
```

### All options
```
  -u / --url       Target URL (required)
  -p / --params    GET params to fuzz: "key=val,key2=val2"
  -t / --timeout   Request timeout in seconds (default: 10)
  -d / --delay     Delay between requests (default: 0.5s)
  --save           Save findings to JSON file
```

---

## 📸 Sample Output

```
 __        __   _  __     _____     _ ___
 \ \      / /__| | \ \   / / _ \  / / __|
  ...

  [i] Target  : https://testphp.vulnweb.com
  [i] Timeout : 10s  |  Delay: 0.5s

  ───────────────────────────────────────
  4 — Sensitive Files & Directories
  ───────────────────────────────────────
  [✗] VULN  » Exposed: https://testphp.vulnweb.com/.git/config

  ───────────────────────────────────────
  5 — Security Headers
  ───────────────────────────────────────
  [✗] VULN  » Missing : Content-Security-Policy
  [✗] VULN  » Missing : Strict-Transport-Security
  [✓] Present : X-Frame-Options
```

---

## 🗂️ Project Structure

```
web-vuln-scanner/
├── scanner.py          # Main scanner script
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── report.json         # (Generated) JSON report
```

---

## 🧪 Safe Test Target

Practice legally on this intentionally vulnerable site:
```bash
python scanner.py -u http://testphp.vulnweb.com -p "id=1,searchFor=test"
```

---

## 🛣️ Roadmap

- [ ] Form parameter discovery (POST support)
- [ ] CSRF token detection
- [ ] Directory brute-forcing
- [ ] HTML report output
- [ ] Multi-threaded scanning
- [ ] CVE lookup integration

---

## 🤝 Contributing

1. Fork the repo
2. Create your branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Your Name**  
GitHub: [@YOUR_USERNAME](https://github.com/YOUR_USERNAME)
