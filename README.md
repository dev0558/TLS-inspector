# TLS.INSPECTOR

> Self-hosted SSL/TLS reconnaissance console with severity-graded findings, a JSON API, and a dark amber operator UI.

Inspect any TLS endpoint. Walk the certificate chain. Enumerate protocols and ciphers. Audit HTTP security headers. Findings are graded instantly so blue team operators can triage at scale.

![Version](https://img.shields.io/badge/version-1.0-fbbf24)
![Python](https://img.shields.io/badge/python-3.11+-3776ab)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-stable-success)

---

## Table of Contents

- [Why TLS.INSPECTOR](#why-tlsinspector)
- [Features](#features)
- [Screenshots](#screenshots)
- [Quick Start](#quick-start)
  - [Docker (recommended)](#docker-recommended)
  - [Local Python](#local-python)
- [Usage](#usage)
  - [Web Interface](#web-interface)
  - [JSON API](#json-api)
- [Inspection Modules](#inspection-modules)
- [Severity Model and Grading](#severity-model-and-grading)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Limitations](#limitations)
- [Security Notes](#security-notes)
- [Author](#author)
- [License](#license)

---

## Why TLS.INSPECTOR

Qualys SSL Labs is the industry reference for TLS server assessment, but it operates as a cloud service: scans run from Qualys infrastructure, results live on Qualys servers, and the service cannot reach endpoints that aren't exposed to the public internet. `testssl.sh` is excellent but terminal-only. `nmap` does protocol and cipher enumeration but isn't severity-graded.

TLS.INSPECTOR is built for the gap in the middle: a self-hosted, audit-friendly, severity-graded console that you can point at internal endpoints, integrate with your SOAR or SIEM, and run completely offline inside a firewalled subnet. Zero telemetry. No account required. MIT licensed.

## Features

- **Eight independent inspection modules**, all toggleable per scan:
  - Leaf certificate introspection
  - Full chain analysis
  - TLS 1.0 / 1.1 / 1.2 / 1.3 protocol matrix
  - Cipher suite enumeration
  - HTTP security header audit
  - Certificate Transparency log lookup
  - DNS posture (A / AAAA / MX / NS / CAA / TXT)
  - Common TLS port sweep
- **Deterministic A-F grading** derived from finding distribution
- **JSON REST API** for automation, CI/CD, and SOAR integration
- **Bulk scanning** of up to 25 hosts in a single request
- **In-memory scan history** (last 50, thread-safe deque)
- **Self-hosted** — no telemetry, no accounts, no external dependencies beyond optional crt.sh lookups
- **Docker-ready** — single `docker compose up -d` to deploy
- **Dark operator UI** — JetBrains Mono + Space Grotesk typography, tactical-console aesthetic

## Screenshots

Scan interface with form-first layout and quick-target buttons:

![Scan interface](docs/screenshots/01_home_scan.png)

Report view with overall grade and severity counts:

![Report view](docs/screenshots/02_report_grade.png)

Severity-graded findings list:

![Findings](docs/screenshots/03_findings_list.png)

Leaf certificate detail and protocol matrix:

![Certificate detail](docs/screenshots/04_leaf_certificate.png)

> Drop your screenshots in `docs/screenshots/` after cloning, or remove this section if you prefer.

## Quick Start

### Docker (recommended)

```bash
docker compose up -d
```

Then open http://localhost:5000

To stop:

```bash
docker compose down
```

### Local Python

Requires Python 3.11+ and the `openssl` command-line tool (already present on macOS and most Linux distributions).

```bash
git clone https://github.com/<your-username>/tls-inspector.git
cd tls-inspector

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python app.py
```

The server binds to `http://127.0.0.1:5000` by default.

> **macOS note:** Port 5000 is taken by the AirPlay Receiver on recent macOS. Use a different port:
>
> ```bash
> PORT=8000 python app.py
> ```

## Usage

### Web Interface

1. Open the running app in a browser
2. Enter a target host (e.g. `example.com`)
3. Select which inspection modules to run (defaults are sensible for most scans)
4. Click **PROBE**
5. Review the graded report

Quick-target buttons pre-fill the form with common test endpoints:

- `github.com` — well-administered production endpoint
- `cloudflare.com` — production endpoint with legacy compatibility
- `expired.badssl.com` — expired certificate (grade F)
- `self-signed.badssl.com` — self-signed certificate (grade C–D)

### JSON API

**Single-target scan:**

```bash
curl -X POST http://localhost:5000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "host": "example.com",
    "port": 443,
    "options": {
      "chain":     true,
      "protocols": true,
      "ciphers":   false,
      "headers":   true,
      "ct":        false,
      "dns":       true,
      "ports":     false
    }
  }'
```

**Bulk scan (up to 25 hosts):**

```bash
curl -X POST http://localhost:5000/api/scan/bulk \
  -H 'Content-Type: application/json' \
  -d '{
    "hosts": ["example.com", "exploit3rs.com", "cloudflare.com"],
    "options": { "headers": true, "chain": true }
  }'
```

**Fetch a saved report:**

```bash
curl http://localhost:5000/report/<report-id>.json > scan-report.json
```

**Liveness probe:**

```bash
curl http://localhost:5000/healthz
```

**Response shape (abridged):**

```json
{
  "host": "example.com",
  "port": 443,
  "ip":   "93.184.216.34",
  "grade": "A",
  "elapsed_ms": 1284,

  "severity_counts": {
    "CRITICAL": 0, "HIGH": 0,
    "MEDIUM":   1, "LOW":  0, "INFO": 0
  },

  "findings": [
    {
      "severity": "MEDIUM",
      "category": "config",
      "message":  "Lifetime over 398 days"
    }
  ],

  "certificate": {
    "subject":     { "commonName": "example.com" },
    "issuer":      { "commonName": "DigiCert" },
    "san":         ["example.com", "www.example.com"],
    "valid_from":  "2026-01-01T00:00:00+00:00",
    "valid_until": "2027-01-01T00:00:00+00:00",
    "signature_algorithm": "sha256",
    "public_key":  { "type": "RSA", "size": 2048 }
  },

  "chain":        { "certs": [/* ... */] },
  "protocols":    { "supported": ["TLSv1.3", "TLSv1.2"] },
  "ciphers":      { "tls13_supported": [/* ... */] },
  "http_headers": { "headers": { /* ... */ } },
  "dns":          { "A": [/* ... */], "CAA": [/* ... */] },
  "ct_logs":      { "total": 142, "entries": [/* ... */] },
  "ports":        [{ "port": 443, "tls": true }]
}
```

## Inspection Modules

| Module          | What it does                                                                                              | Default |
| --------------- | --------------------------------------------------------------------------------------------------------- | ------- |
| `core`          | TLS handshake, X.509 parse, SANs, key params, OCSP staple, expiry checks                                  | always  |
| `chain`         | Full chain retrieval via `openssl s_client`, intermediate validation, ordering check                      | on      |
| `protocols`     | Independent handshake at each of TLS 1.0 / 1.1 / 1.2 / 1.3 to map supported versions                      | on      |
| `ciphers`       | Cipher suite enumeration against a curated list of ~15 common suites including known-weak families       | off     |
| `headers`       | HTTPS HEAD request and audit of HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, etc. | on      |
| `ct_logs`       | Certificate Transparency log lookup via crt.sh                                                            | off     |
| `dns_lookup`    | A, AAAA, MX, NS, CAA, TXT resolution via dnspython                                                        | on      |
| `ports`         | TCP connect + TLS handshake sweep across common TLS ports (443, 465, 587, 636, 993, 995, 8443, ...)       | off     |

Modules disabled by default either incur additional latency (ciphers, ct_logs) or are intended for explicit operator-initiated reconnaissance (ports).

## Severity Model and Grading

Each finding belongs to one of five tiers:

| Severity   | Examples                                                                          |
| ---------- | --------------------------------------------------------------------------------- |
| `CRITICAL` | Certificate expired, weak signature hash (MD5/SHA1), expiring within 7 days       |
| `HIGH`     | Self-signed cert, weak RSA <2048, hostname mismatch, deprecated TLS, HSTS missing |
| `MEDIUM`   | Lifetime > 398 days, no SAN, no CAA records, CSP missing                          |
| `LOW`     | Missing minor security headers, TLS 1.3 not supported                              |
| `INFO`     | Wildcard SAN, root not in chain (typical), CT log statistics                      |

Overall grade is derived deterministically:

| Grade | Condition                                                                       |
| ----- | ------------------------------------------------------------------------------- |
| **A**     | No HIGH or CRITICAL; at most one MEDIUM and at most one LOW                |
| **B+**    | At most one MEDIUM or LOW finding                                          |
| **B**     | Exactly one MEDIUM; no HIGH or CRITICAL                                    |
| **C**     | At least one HIGH, or two or more MEDIUMs                                  |
| **D**     | Three or more HIGH findings                                                |
| **F**     | At least one CRITICAL finding                                              |

A single CRITICAL finding immediately collapses the grade to F, on the principle that fundamental trust breaches must be addressed before lower-severity issues become relevant.

## Architecture

```
ssl-inspector/
├── app.py                    Flask routes, request handlers, in-memory history
├── inspector/                Inspection engine (independent of Flask)
│   ├── __init__.py           run_full_scan() orchestrator + grader
│   ├── core.py               Leaf TLS handshake + cert analysis
│   ├── chain.py              Full chain via openssl s_client
│   ├── protocols.py          TLS 1.0-1.3 version probing
│   ├── ciphers.py            Cipher suite enumeration
│   ├── headers.py            HTTP security header audit
│   ├── ct_logs.py            crt.sh Certificate Transparency lookup
│   ├── dns_lookup.py         A, AAAA, MX, NS, CAA, TXT resolution
│   ├── ports.py              Common TLS port sweep
│   └── utils.py              Shared helpers, severity ordering
├── templates/                Jinja2 templates
│   ├── base.html
│   ├── index.html            Scan form
│   ├── report.html           Report view
│   ├── history.html          Scan archive
│   └── about.html            API documentation
├── static/
│   ├── css/style.css
│   ├── js/app.js
│   └── brand/                Logo, favicons, OG image
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── LICENSE
```

The inspection engine has no dependency on Flask and can be imported into any Python context — command-line tools, Jupyter notebooks, batch jobs. Each module follows a uniform contract: accept `(host, port, timeout)`, return `(structured_data, findings_list)`.

**Tech stack:**

- Python 3.11
- Flask 3.0
- cryptography (PyCA) — X.509 parsing and signature introspection
- dnspython — DNS queries beyond stdlib coverage
- gunicorn — production WSGI server
- openssl (system binary) — chain retrieval and cipher enumeration

## Configuration

Environment variables:

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `PORT`     | `5000`    | Port the Flask app binds to                 |
| `HOST`     | `0.0.0.0` | Bind address                                |
| `DEBUG`    | `false`   | Enable Flask debug mode (development only)  |
| `TIMEOUT`  | `10`      | Per-module network timeout in seconds       |

Module defaults are configured in `inspector/__init__.py`.

## Testing

The system has been validated against:

- **badssl.com test infrastructure** — expired, self-signed, wrong-host, weak-key, deprecated-protocol endpoints all detected correctly
- **Production endpoints** — cloudflare.com, example.com, and others used to confirm sensible results on well-administered infrastructure

A reference scan against `cloudflare.com:443` completes in ~6.8 seconds and returns grade C with two HIGH findings (TLS 1.0 and 1.1 enabled), two MEDIUM (CSP missing, no CAA), three LOW (minor headers), and three INFO findings.

## Roadmap

Planned for future versions (contributions welcome):

- [ ] Persistent storage (SQLite for single-instance, Postgres for multi-instance)
- [ ] Scheduled scans with Slack / email / webhook notifications
- [ ] STARTTLS support for SMTP, IMAP, POP3, LDAP
- [ ] Active OCSP responder querying (in addition to stapling-presence check)
- [ ] PDF export of reports
- [ ] Basic auth / OIDC for shared-infrastructure deployment
- [ ] Exhaustive cipher enumeration mode
- [ ] HTTP/2 and HTTP/3 negotiation reporting

## Limitations

- Scan history is in-memory only and wipes on process restart
- Cipher enumeration probes a curated subset, not the full IANA cipher list
- No authentication layer — intended for single-tenant deployment behind a trusted network
- No rate limiting on the API
- DNS module inherits any caching or filtering from the configured resolvers
- crt.sh queries can be slow; the `ct_logs` module is off by default for that reason

## Security Notes

TLS.INSPECTOR is a defensive reconnaissance tool. It performs:

- Standard TLS handshakes (no fuzzing, no protocol abuse)
- HTTP HEAD requests
- DNS queries
- TCP connect probes on common service ports

It is **not** a vulnerability scanner. It does not exploit anything. It will not trigger most IDS/IPS systems. However:

- **Only scan systems you own or have explicit written permission to test.** TLS scans are generally non-intrusive but unauthorized scanning may still violate computer misuse laws in your jurisdiction.
- The port-sweep module touches multiple TCP ports per scan; some intrusion detection systems treat this as reconnaissance and may alert.
- Self-host only on trusted networks. The application has no authentication layer.

## Author

**Bhargav Raj Dutta**
Information Technology Manager
Exploit3rs Cyber Risk Management Services, Dubai, UAE

## License

MIT — see [LICENSE](LICENSE) for the full text.

---

> Built for blue teams.
