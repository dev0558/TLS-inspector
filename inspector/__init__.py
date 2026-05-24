"""
Inspector package: orchestrates the full SSL/TLS scan.
"""

import socket
import ssl
import time
from datetime import datetime, timezone

from .core import fetch_handshake, analyze_certificate
from .chain import fetch_chain, chain_summary, analyze_chain
from .protocols import probe_protocols
from .ciphers import enumerate_ciphers
from .headers import check_security_headers
from .ct_logs import ct_lookup
from .dns_lookup import lookup_records
from .ports import scan_ports
from .utils import sort_findings


def run_full_scan(host, port=443, timeout=10, options=None):
    """
    Run a complete inspection pass.

    `options` is a dict of booleans:
        - chain      (default True)
        - protocols  (default True)
        - ciphers    (default False - slow)
        - headers    (default True)
        - ct         (default False - slow, depends on crt.sh)
        - dns        (default True)
        - ports      (default False)
    """
    options = options or {}
    do_chain     = options.get("chain", True)
    do_protocols = options.get("protocols", True)
    do_ciphers   = options.get("ciphers", False)
    do_headers   = options.get("headers", True)
    do_ct        = options.get("ct", False)
    do_dns       = options.get("dns", True)
    do_ports     = options.get("ports", False)

    started = time.monotonic()
    report = {
        "host": host,
        "port": port,
        "started": datetime.now(timezone.utc).isoformat(),
        "findings": [],
        "modules": [],
    }

    # --- Resolve & connect ---
    try:
        ip = socket.gethostbyname(host)
        report["ip"] = ip
    except socket.gaierror as e:
        report["error"] = f"DNS resolution failed: {e}"
        report["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        return report

    # --- Leaf certificate ---
    try:
        der, cipher, version, ocsp = fetch_handshake(host, port, timeout)
    except (socket.timeout, socket.gaierror, ConnectionError, OSError, ssl.SSLError) as e:
        report["error"] = f"TLS handshake failed: {e.__class__.__name__}: {e}"
        report["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        return report

    cert_info, cert_findings = analyze_certificate(host, der, cipher, version)
    report["certificate"] = cert_info
    report["tls_version"] = version
    report["cipher"] = {
        "name": cipher[0] if cipher else None,
        "protocol": cipher[1] if cipher else None,
        "bits": cipher[2] if cipher else None,
    }
    report["ocsp_stapled"] = bool(ocsp)
    report["findings"].extend(cert_findings)
    report["modules"].append("certificate")

    # --- Chain ---
    if do_chain:
        chain, err = fetch_chain(host, port, timeout)
        if err:
            report["chain"] = {"error": err, "certs": []}
        else:
            report["chain"] = {"error": None, "certs": chain_summary(chain)}
            report["findings"].extend(analyze_chain(chain))
        report["modules"].append("chain")

    # --- Protocols ---
    if do_protocols:
        proto = probe_protocols(host, port, timeout=5)
        report["protocols"] = {"supported": proto["supported"], "unsupported": proto["unsupported"]}
        report["findings"].extend(proto["findings"])
        report["modules"].append("protocols")

    # --- Ciphers ---
    if do_ciphers:
        ciph = enumerate_ciphers(host, port, timeout=4, quick=True)
        report["ciphers"] = {
            "tls12_supported": ciph["tls12_supported"],
            "tls13_supported": ciph["tls13_supported"],
            "weak_supported": ciph["weak_supported"],
        }
        report["findings"].extend(ciph["findings"])
        report["modules"].append("ciphers")

    # --- Headers ---
    if do_headers:
        hdr = check_security_headers(host, port, timeout=8)
        report["http_headers"] = {"status": hdr["status"], "headers": hdr["headers"]}
        report["findings"].extend(hdr["findings"])
        report["modules"].append("headers")

    # --- CT logs ---
    if do_ct:
        ct = ct_lookup(host, timeout=10)
        report["ct_logs"] = {"total": ct["total"], "entries": ct["entries"]}
        report["findings"].extend(ct["findings"])
        report["modules"].append("ct")

    # --- DNS ---
    if do_dns:
        dns_info = lookup_records(host, timeout=5)
        dns_findings = dns_info.pop("findings", [])
        report["dns"] = dns_info
        report["findings"].extend(dns_findings)
        report["modules"].append("dns")

    # --- Ports ---
    if do_ports:
        report["ports"] = scan_ports(host, timeout=2)
        report["modules"].append("ports")

    # --- Finalise ---
    report["findings"] = sort_findings(report["findings"])
    report["severity_counts"] = _severity_counts(report["findings"])
    report["grade"] = _grade(report["severity_counts"])
    report["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return report


def _severity_counts(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def _grade(counts):
    if counts["CRITICAL"] > 0:
        return "F"
    if counts["HIGH"] >= 3:
        return "D"
    if counts["HIGH"] >= 1:
        return "C"
    if counts["MEDIUM"] >= 2:
        return "B"
    if counts["MEDIUM"] >= 1 or counts["LOW"] >= 2:
        return "B+"
    return "A"
