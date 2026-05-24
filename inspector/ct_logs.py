"""
Certificate Transparency lookup via crt.sh (free public CT log aggregator).
"""

import json
import socket
import ssl
from urllib.parse import quote

from .utils import finding


def _https_get(host, path, timeout=10):
    ctx = ssl.create_default_context()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: SSL-Inspector/2.0\r\n"
        f"Accept: application/json\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    with socket.create_connection((host, 443), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            ss.sendall(req)
            buf = b""
            while True:
                try:
                    chunk = ss.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 4 * 1024 * 1024:
                    break
    raw = buf.decode("utf-8", errors="ignore")
    head, _, body = raw.partition("\r\n\r\n")
    # Handle chunked transfer encoding minimally: strip hex line markers
    if "Transfer-Encoding: chunked" in head:
        cleaned = []
        for line in body.split("\r\n"):
            if line and not all(c in "0123456789abcdefABCDEF" for c in line):
                cleaned.append(line)
        body = "\n".join(cleaned)
    return body


def ct_lookup(domain, timeout=10, max_results=25):
    """
    Query crt.sh for CT log entries covering this domain.
    Returns list of recent issuances and a finding count.
    """
    try:
        path = f"/?q={quote(domain)}&output=json"
        body = _https_get("crt.sh", path, timeout=timeout)
        # crt.sh sometimes returns malformed JSON if chunked; try to find first [
        start = body.find("[")
        end = body.rfind("]")
        if start == -1 or end == -1:
            raise ValueError("Unexpected response shape from crt.sh")
        data = json.loads(body[start:end + 1])
    except Exception as e:
        return {
            "entries": [],
            "total": 0,
            "findings": [finding("INFO", f"CT log lookup failed: {e.__class__.__name__}", "ct")],
        }

    # Dedup by serial number
    seen = set()
    entries = []
    for row in data:
        key = (row.get("serial_number"), row.get("issuer_name"))
        if key in seen:
            continue
        seen.add(key)
        entries.append({
            "issuer": row.get("issuer_name"),
            "common_name": row.get("common_name"),
            "name_value": row.get("name_value"),
            "not_before": row.get("not_before"),
            "not_after": row.get("not_after"),
            "serial_number": row.get("serial_number"),
            "entry_timestamp": row.get("entry_timestamp"),
        })
        if len(entries) >= max_results:
            break

    findings = []
    findings.append(finding("INFO", f"Found {len(data)} CT log entries (showing top {len(entries)})", "ct"))
    # Look for suspicious recent issuance variety
    issuers = {e["issuer"] for e in entries}
    if len(issuers) > 5:
        findings.append(finding(
            "LOW",
            f"Many distinct issuers seen in CT logs ({len(issuers)}) - investigate if unexpected",
            "ct"
        ))
    return {"entries": entries, "total": len(data), "findings": findings}
