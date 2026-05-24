<p align="center">
  <img src="static/brand/horiz_logo.png" alt="TLS.INSPECTOR" width="640">
</p>

<p align="center">
  <em>A self-hosted SSL/TLS reconnaissance console. Inspect any HTTPS endpoint, walk the certificate chain,<br>
  enumerate protocols and ciphers, audit HTTP security headers, query CT logs and DNS posture.<br>
  Findings are severity-graded.</em>
</p>

---

# TLS.INSPECTOR

```
   ___ _    ___       ___                          _
  |_ _( )  |_ _|_ __ / __| _ __  ___  __  ___  ___| |_  ___  _ _
   | || |   | || '_ \\__ \| '_ \/ -_)/ _|/ _ \/ -_)  _|/ _ \| '_|
  |___|_|  |___|.__/|___/| .__/\___|\__|\___/\___|\__|\___/|_|
                         |_|
```

## Features

| Module | What it does |
|--------|--------------|
| **Certificate introspection** | Subject, issuer, SAN, key type/size, signature hash, lifetime, fingerprints, expiry tracking |
| **Full chain analysis** | Walks intermediates via `openssl s_client`, detects misordering, missing intermediates, expired CA links |
| **Protocol matrix** | Probes TLS 1.0 / 1.1 / 1.2 / 1.3 independently — flags deprecated versions left enabled |
| **Cipher enumeration** | Tests common TLS 1.2 + 1.3 cipher suites, flags RC4 / 3DES / NULL / EXPORT / anonymous |
| **Security headers** | HSTS (max-age + includeSubDomains), CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **CT log lookup** | Pulls certificate transparency history from crt.sh |
| **DNS posture** | Resolves A / AAAA / MX / NS / CAA / TXT; flags missing CAA |
| **Port sweep** | Probes common TLS ports (443, 465, 587, 636, 993, 995, 8443, 5061, 8883, 3306, 5432) |
| **Web UI + JSON API** | Dark amber/terminal aesthetic, full REST API for automation |
| **Bulk scanning** | Scan up to 25 hosts in a single API call |
| **Grading** | A / B+ / B / C / D / F overall grade based on finding severity |

## Quick start

### Docker (recommended)

```bash
git clone <your-fork-url> ssl-inspector
cd ssl-inspector
docker compose up -d
open http://localhost:5000
```

### Local Python

```bash
git clone <your-fork-url> ssl-inspector
cd ssl-inspector
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open <http://localhost:5000>.

## JSON API

### Single scan

```bash
curl -X POST http://localhost:5000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "host": "example.com",
    "port": 443,
    "options": {
      "chain": true,
      "protocols": true,
      "ciphers": false,
      "headers": true,
      "ct": false,
      "dns": true,
      "ports": false
    }
  }'
```

### Bulk scan

```bash
curl -X POST http://localhost:5000/api/scan/bulk \
  -H 'Content-Type: application/json' \
  -d '{
    "hosts": ["example.com", "github.com", "cloudflare.com"],
    "options": { "headers": true }
  }'
```

### Health check

```
GET /healthz
```

## Response shape

```json
{
  "host": "example.com",
  "port": 443,
  "ip": "93.184.216.34",
  "grade": "A",
  "elapsed_ms": 1284,
  "severity_counts": {
    "CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0
  },
  "findings": [
    { "severity": "MEDIUM", "category": "policy",
      "message": "Certificate lifetime 480d exceeds CA/B Forum maximum (398d)" }
  ],
  "certificate":  { "subject": {...}, "issuer": {...}, "san": [...], ... },
  "chain":        { "certs": [ ... ] },
  "protocols":    { "supported": ["TLSv1.3","TLSv1.2"], "unsupported": [...] },
  "ciphers":      { "tls12_supported": [...], "tls13_supported": [...], "weak_supported": [] },
  "http_headers": { "headers": { ... } },
  "dns":          { "A": [...], "CAA": [...], ... },
  "ct_logs":      { "total": 142, "entries": [...] },
  "ports":        [ { "port": 443, "tls": true, "tls_version": "TLSv1.3" } ]
}
```

## Severity model

| Severity | Examples |
|----------|----------|
| `CRITICAL` | Cert expired, weak signature hash (MD5/SHA1), expiring inside 7 days, expired intermediate |
| `HIGH`     | Self-signed, weak RSA (<2048) / EC (<256) key, hostname mismatch, deprecated TLS (1.0/1.1) enabled, weak cipher accepted, HSTS missing |
| `MEDIUM`   | Lifetime over 398 days, no SAN, no intermediates returned, no CAA records, CSP missing |
| `LOW`      | Missing Basic Constraints / EKU, only TLS 1.2 supported, missing minor headers |
| `INFO`     | Wildcard SAN, root not in chain (typical), CT log statistics |

## Grading

| Grade | Rule |
|-------|------|
| `A`   | No findings worse than INFO |
| `B+`  | At most 1 MEDIUM or 1 LOW |
| `B`   | 1 MEDIUM finding |
| `C`   | 1 HIGH or 2 MEDIUMs |
| `D`   | Multiple HIGH |
| `F`   | Any CRITICAL |

## Architecture

```
ssl-inspector/
├── app.py                # Flask app + routes
├── inspector/
│   ├── __init__.py       # Orchestrator + grading
│   ├── core.py           # Leaf-cert fetch + analysis
│   ├── chain.py          # Full chain via openssl s_client
│   ├── protocols.py      # TLS version probing
│   ├── ciphers.py        # Cipher suite enumeration
│   ├── headers.py        # HTTP security headers
│   ├── ct_logs.py        # crt.sh integration
│   ├── dns_lookup.py     # A/AAAA/MX/NS/CAA/TXT
│   ├── ports.py          # Common TLS port sweep
│   └── utils.py          # Shared helpers
├── templates/            # Jinja2
├── static/css, static/js
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

Modules are independent — disable any of them via the `options` flags.

## Production notes

- The included `Dockerfile` uses `gunicorn` with 2 workers and a 60s timeout. Tune for your load.
- Scan history is held **in-memory** (deque, last 50). Restart wipes it. For persistent storage, swap `_history` in `app.py` for SQLite/Postgres.
- Some modules (ciphers, CT logs) are slow and **off by default** — opt in per scan.
- The host validation regex restricts inputs to hostnames and IPs only. There is no SSRF surface beyond the user-specified host:port.
- No authentication is bundled. If exposing publicly, put it behind a reverse proxy with auth (Caddy basicauth, oauth2-proxy, etc.).

## Roadmap

- [ ] Persistent SQLite/Postgres history with search and trends
- [ ] Webhook / Slack / email alerts for expiring certs (cron-style scheduled scans)
- [ ] PDF report export
- [ ] Subdomain expansion via crt.sh
- [ ] STARTTLS support for SMTP / IMAP / LDAP probes
- [ ] CSV export of findings for tickets
- [ ] OCSP responder fetch (not just stapled status)

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Issues and PRs welcome. Add tests for new check modules in `inspector/`.
