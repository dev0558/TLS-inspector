"""
Enumerate cipher suites supported by the target.

We rely on openssl s_client and try common TLS 1.2 and 1.3 cipher suites
one at a time. This is slower than nmap's ssl-enum-ciphers but has no
extra dependencies.
"""

import shutil
import subprocess

from .utils import finding


TLS12_CIPHERS = [
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
    # CBC (older, still common)
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-AES128-SHA256",
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    # Weak / deprecated probes
    "DES-CBC3-SHA",
    "RC4-SHA",
    "RC4-MD5",
    "NULL-SHA",
]

TLS13_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
]

WEAK_KEYWORDS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "anon")


def has_openssl():
    return shutil.which("openssl") is not None


def _try_tls12(host, port, cipher, timeout, sni):
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-servername", sni, "-tls1_2", "-cipher", cipher],
            input=b"", capture_output=True, timeout=timeout,
        )
    except Exception:
        return False
    out = proc.stdout.decode("utf-8", errors="ignore") + proc.stderr.decode("utf-8", errors="ignore")
    # successful negotiation includes the cipher name and "BEGIN CERTIFICATE"
    return ("Cipher    : " + cipher in out) or (f"Cipher is {cipher}" in out)


def _try_tls13(host, port, cipher, timeout, sni):
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-servername", sni, "-tls1_3", "-ciphersuites", cipher],
            input=b"", capture_output=True, timeout=timeout,
        )
    except Exception:
        return False
    out = proc.stdout.decode("utf-8", errors="ignore") + proc.stderr.decode("utf-8", errors="ignore")
    return cipher in out and "BEGIN CERTIFICATE" in out


def enumerate_ciphers(host, port=443, timeout=4, sni=None, quick=True):
    """
    Returns:
      {
        "tls12_supported": [...],
        "tls13_supported": [...],
        "weak_supported": [...],
        "findings": [...]
      }

    `quick=True` skips a small subset to keep latency reasonable in the web UI.
    """
    sni = sni or host
    if not has_openssl():
        return {
            "tls12_supported": [],
            "tls13_supported": [],
            "weak_supported": [],
            "findings": [finding("INFO", "Cipher enumeration skipped (openssl not on PATH)", "crypto")],
        }

    tls12_list = TLS12_CIPHERS if not quick else TLS12_CIPHERS[:10] + TLS12_CIPHERS[-3:]
    tls12 = [c for c in tls12_list if _try_tls12(host, port, c, timeout, sni)]
    tls13 = [c for c in TLS13_CIPHERS if _try_tls13(host, port, c, timeout, sni)]

    weak = [c for c in tls12 if any(w in c.upper() for w in WEAK_KEYWORDS)]
    findings = []
    if weak:
        findings.append(finding(
            "HIGH",
            f"Server accepts weak cipher suite(s): {', '.join(weak)}",
            "crypto"
        ))
    if not tls13:
        findings.append(finding("LOW", "Server does not appear to support any TLS 1.3 cipher suite", "crypto"))

    return {
        "tls12_supported": tls12,
        "tls13_supported": tls13,
        "weak_supported": weak,
        "findings": findings,
    }
