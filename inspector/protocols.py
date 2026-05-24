"""
Probe which TLS protocol versions the target server supports by forcing
a single version per handshake.
"""

import socket
import ssl

from .utils import finding


# Map our label -> (min, max) protocol versions to force
VERSION_MAP = {
    "TLSv1.3": (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
    "TLSv1.2": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    "TLSv1.1": (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
    "TLSv1":   (ssl.TLSVersion.TLSv1,   ssl.TLSVersion.TLSv1),
}

DEPRECATED = {"TLSv1.1", "TLSv1", "SSLv3"}


def _try_version(host, port, min_v, max_v, timeout, sni):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = min_v
        ctx.maximum_version = max_v
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ss:
                return ss.version()
    except Exception:
        return None


def probe_protocols(host, port=443, timeout=5, sni=None):
    """
    Returns:
      {
        "supported": ["TLSv1.3", "TLSv1.2"],
        "unsupported": ["TLSv1.1", "TLSv1"],
        "findings": [...]
      }
    """
    sni = sni or host
    supported, unsupported = [], []
    for label, (mn, mx) in VERSION_MAP.items():
        result = _try_version(host, port, mn, mx, timeout, sni)
        if result == label:
            supported.append(label)
        else:
            unsupported.append(label)

    findings = []
    if not supported:
        findings.append(finding("HIGH", "No TLS versions could be negotiated", "protocol"))
    for v in supported:
        if v in DEPRECATED:
            findings.append(finding("HIGH", f"Deprecated protocol enabled: {v}", "protocol"))
    if "TLSv1.3" not in supported and "TLSv1.2" in supported:
        findings.append(finding("LOW", "TLS 1.3 not supported (only TLS 1.2 available)", "protocol"))

    return {"supported": supported, "unsupported": unsupported, "findings": findings}
