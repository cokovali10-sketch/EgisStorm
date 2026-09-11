<div align="center">

# EgisStorm

### Comprehensive Security Audit Suite — 24 Tools, Zero Trust Assumptions

[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=githubactions&logoColor=white)](#)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-17+-green.svg)](#testing)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](#docker)

A local-first security audit platform with 24 tools spanning breach analysis, network intelligence, cryptographic utilities, and web security — all running entirely on your machine with nothing stored externally.

> **Purpose:** Audit *your own* infrastructure and data. OSINT tools use only public data (DNS, RDAP, SSL certificates) and never expose third-party personal information.

</div>

---

## Features

### Breach & Password Analysis
| Tool | Description |
|------|-------------|
| **Email Breach Check** | Check your email against HaveIBeenPwned with year-by-year breach timeline |
| **Password Strength** | Pwned Passwords frequency check + cryptographic strength scoring |
| **Password Generator** | Cryptographically secure passwords via Python `secrets` |

### Network Intelligence
| Tool | Description |
|------|-------------|
| **My IP** | External address, geolocation, and ISP identification |
| **DNS Records** | A / AAAA / CNAME / NS / MX / TXT record enumeration |
| **WHOIS / RDAP** | Registrar, creation/expiry dates, domain status flags |
| **IP Info** | Geolocation, ASN, reverse DNS via ipwho.is |
| **IP Owner** | Organization and network range lookup via RDAP |
| **TCP Port Check** | Port scan + common service detection |
| **SSL Certificate** | Issuer, SANs, validity period, TLS version |
| **Security Headers** | HSTS, CSP, X-Frame-Options audit with scoring |
| **Subnet / CIDR** | Subnet calculator and CIDR notation converter |
| **MX Validator** | Mail server inspection + disposable domain detection |

### Cryptography & Encoding
| Tool | Description |
|------|-------------|
| **Hashing** | MD5 / SHA-1 / SHA-2 / SHA-3 with algorithm identification |
| **Base64** | Encode / decode with format detection |
| **AES Encryption** | AES-256-CBC with PKCS7 padding (educational) |
| **2FA / TOTP** | Secret generation, QR code, and auto-refreshing browser code |

### Web & API Security
| Tool | Description |
|------|-------------|
| **JWT Decoder** | `alg=none` detection, `exp` / `nbf` validation |
| **URL Analyzer** | Phishing indicators — HTTPS, IP-host, punycode, shorteners |
| **URL Unwrapper** | Full redirect chain resolution for shortened URLs |
| **robots.txt** | Site rules and sitemap inspection |
| **CVE Search** | Vulnerability lookup by product via NVD |
| **WireGuard VPN** | Client config and Curve25519 key generation |

### Interactive Features
- SVG charts (donut, bar, gauge, line) — zero external dependencies
- Check history (localStorage + server-side SQLite)
- JSON export of all results
- Toast notifications for action feedback

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    BROWSER (SPA)                        │
│   HTML/CSS/JS · SVG Charts · WebCrypto TOTP             │
└──────────────────────┬──────────────────────────────────┘
                       │ REST API
┌──────────────────────▼──────────────────────────────────┐
│                  FLASK APPLICATION                       │
│          Rate Limiting · Basic Auth · CORS              │
├──────────┬──────────┬──────────┬──────────┬────────────┤
│ network  │  cert    │ webcheck │  crypto  │ portcheck  │
│   .py    │   .py    │   .py    │   .py    │    .py     │
└──────────┴──────────┴──────────┴──────────┴────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│              SQLite (History · Audit Logs)               │
└─────────────────────────────────────────────────────────┘
```

**Key Design Decisions:**
- **Local-first:** No data leaves your machine unless you configure external API keys
- **Rate-limited:** 120 requests/hour global, stricter on external API tools
- **Zero frontend dependencies:** Vanilla JS with SVG charting — no npm, no build step

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, Flask, flask-limiter |
| Database | SQLite (audit history, masked passwords/keys in logs) |
| Frontend | HTML5 / CSS3 / Vanilla JavaScript |
| Cryptography | `cryptography`, `PyNaCl`, `pyotp`, `qrcode` |
| Networking | `requests`, `dnspython`, `phonenumbers` |
| Infrastructure | Docker, docker-compose, GitHub Actions CI |

---

## Quick Start

### Prerequisites
- Python 3.12+
- (Optional) Docker & Docker Compose
- (Optional) HIBP API key for live breach checks

### Local Installation

```bash
# Clone the repository
git clone https://github.com/yourname/EgisStorm.git
cd EgisStorm

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate    # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Launch
python run.py                  # http://127.0.0.1:5000
```

### Docker

```bash
docker compose up --build      # http://localhost
```

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `HIBP_API_KEY` | No | HaveIBeenPwned API key (without it: demo mode) |
| `APP_PASSWORD` | No | Basic Auth password (unset: open access) |

### HIBP Live Data

Without an API key, breach checks run in demo mode. For live verification:

```bash
# Windows PowerShell
set HIBP_API_KEY=your_key_here

# Linux/macOS
export HIBP_API_KEY=your_key_here
```

---

## Testing

```bash
pip install pytest flake8
pytest -q                       # 17 tests
flake8 app.py run.py tools db.py --select=E9,F63,F7,F82
```

---

## Project Structure

```
EgisStorm/
├── app.py                  # Flask app, API routes, rate limiting, auth
├── run.py                  # Entry point (no reloader)
├── db.py                   # SQLite history layer
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── templates/
│   └── index.html          # Single-page interface
├── static/
│   ├── style.css
│   ├── app.js              # UI logic
│   ├── charts.js           # SVG: donut / bar / gauge / line
│   └── totp.js             # Client-side TOTP (WebCrypto)
├── tests/
│   ├── conftest.py
│   └── test_app.py         # 17 tests
├── .github/workflows/
│   └── ci.yml              # Lint + test pipeline
└── tools/
    ├── network.py          # DNS, RDAP, IP, CIDR, MX, CVE
    ├── cert.py             # SSL certificates
    ├── webcheck.py         # Headers, URL analysis, redirects
    ├── crypto_tools.py     # Hashes, Base64, passwords
    ├── crypt_tool.py       # AES-256-CBC
    ├── jwt_tool.py         # JWT decoder
    └── portcheck.py        # TCP ports, robots.txt
```

---

## Roadmap

- [x] Docker + docker-compose
- [x] Rate limiting (flask-limiter)
- [x] Server-side audit history (SQLite)
- [x] Optional Basic Auth
- [x] CI pipeline (lint + tests)
- [ ] Telegram bot wrapper for key tools
- [ ] PDF report export

---

## License

[Apache License 2.0](LICENSE)

> **Disclaimer:** This toolset is for authorized security auditing of your own systems. Always obtain proper authorization before testing infrastructure you do not own.
