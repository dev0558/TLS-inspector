"""
Probe HTTP security headers on the target host (HTTPS GET to /).
"""

import socket
import ssl
from urllib.parse import urlparse

from .utils import finding


IMPORTANT_HEADERS = {
    "strict-transport-security": ("HSTS missing - HTTP Strict Transport Security not enforced", "HIGH"),
    "content-security-policy":  ("CSP missing - no Content Security Policy", "MEDIUM"),
    "x-frame-options":          ("X-Frame-Options missing (clickjacking protection)", "LOW"),
    "x-content-type-options":   ("X-Content-Type-Options missing (MIME-sniffing protection)", "LOW"),
    "referrer-policy":          ("Referrer-Policy missing", "LOW"),
    "permissions-policy":       ("Permissions-Policy missing", "INFO"),
}


def _raw_https_head(host, port, timeout):
    """Tiny HEAD request via raw socket so we don't need requests."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: SSL-Inspector/2.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            ss.sendall(req)
            buf = b""
            while True:
                try:
                    chunk = ss.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
                if b"\r\n\r\n" in buf and len(buf) > 16:
                    break
                if len(buf) > 65536:
                    break
    return buf.decode("latin-1", errors="ignore")


def check_security_headers(host, port=443, timeout=8):
    """Return headers dict + findings for missing/weak security headers."""
    try:
        raw = _raw_https_head(host, port, timeout)
    except Exception as e:
        return {
            "headers": {},
            "status": None,
            "findings": [finding("INFO", f"Security-headers probe failed: {e.__class__.__name__}", "headers")],
        }

    head, _, _ = raw.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()

    findings = []
    for key, (msg, sev) in IMPORTANT_HEADERS.items():
        if key not in headers:
            findings.append(finding(sev, msg, "headers"))

    # Inspect HSTS for max-age and includeSubDomains
    hsts = headers.get("strict-transport-security")
    if hsts:
        lowered = hsts.lower()
        m_age = 0
        for part in lowered.split(";"):
            part = part.strip()
            if part.startswith("max-age="):
                try:
                    m_age = int(part.split("=", 1)[1])
                except ValueError:
                    pass
        if m_age < 15552000:  # 180 days
            findings.append(finding(
                "MEDIUM",
                f"HSTS max-age is {m_age}s; recommended >= 15552000 (180d)",
                "headers"
            ))
        if "includesubdomains" not in lowered:
            findings.append(finding("LOW", "HSTS missing includeSubDomains directive", "headers"))

    return {
        "headers": headers,
        "status": status_line,
        "findings": findings,
    }
