"""
Certificate chain fetch + analysis.

Uses `openssl s_client -showcerts` to retrieve the chain (since Python's
ssl module exposes the peer chain only on 3.10+ and not on all platforms).
"""

import re
import shutil
import subprocess
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from .utils import finding, utc, name_to_dict


CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def has_openssl():
    return shutil.which("openssl") is not None


def fetch_chain(host, port=443, timeout=10, sni=None):
    """Run openssl s_client -showcerts and parse all certificates returned."""
    if not has_openssl():
        return [], "openssl binary not available on host"

    sni = sni or host
    cmd = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", sni,
        "-showcerts",
    ]
    try:
        proc = subprocess.run(
            cmd, input=b"", capture_output=True,
            timeout=timeout + 2,
        )
    except subprocess.TimeoutExpired:
        return [], "openssl s_client timed out"
    except Exception as e:
        return [], f"openssl s_client failed: {e}"

    text = proc.stdout.decode("utf-8", errors="ignore")
    pem_blocks = CERT_RE.findall(text)
    if not pem_blocks:
        return [], "no certificates returned by s_client"

    chain = []
    for pem in pem_blocks:
        try:
            cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
            chain.append(cert)
        except Exception:
            continue
    return chain, None


def chain_summary(chain):
    """Produce a JSON-friendly summary of every cert in the chain."""
    out = []
    for i, c in enumerate(chain):
        not_before = utc(getattr(c, "not_valid_before_utc", None) or c.not_valid_before)
        not_after = utc(getattr(c, "not_valid_after_utc", None) or c.not_valid_after)
        subj = name_to_dict(c.subject)
        iss = name_to_dict(c.issuer)
        out.append({
            "index": i,
            "position": "leaf" if i == 0 else ("root" if c.issuer == c.subject else "intermediate"),
            "subject_cn": subj.get("commonName"),
            "subject_o": subj.get("organizationName"),
            "issuer_cn": iss.get("commonName"),
            "issuer_o": iss.get("organizationName"),
            "valid_from": not_before.isoformat(),
            "valid_until": not_after.isoformat(),
            "sig_alg": c.signature_hash_algorithm.name if c.signature_hash_algorithm else None,
            "fingerprint_sha256": c.fingerprint(hashes.SHA256()).hex(),
            "self_signed": c.issuer == c.subject,
        })
    return out


def analyze_chain(chain):
    """Findings derived from the chain as a whole."""
    findings = []
    if not chain:
        findings.append(finding("MEDIUM", "Certificate chain not available", "chain"))
        return findings

    now = datetime.now(timezone.utc)

    # Check ordering: each cert (after leaf) should be the issuer of the previous.
    for i in range(len(chain) - 1):
        if chain[i].issuer != chain[i + 1].subject:
            findings.append(finding(
                "MEDIUM",
                f"Chain ordering issue: cert #{i} issuer does not match cert #{i + 1} subject",
                "chain"
            ))
            break

    # Any expired intermediates?
    for i, c in enumerate(chain[1:], start=1):
        na = utc(getattr(c, "not_valid_after_utc", None) or c.not_valid_after)
        if na < now:
            cn = name_to_dict(c.subject).get("commonName", f"cert #{i}")
            findings.append(finding("CRITICAL", f"Intermediate '{cn}' is EXPIRED", "chain"))
        elif (na - now).days < 30:
            cn = name_to_dict(c.subject).get("commonName", f"cert #{i}")
            findings.append(finding("HIGH", f"Intermediate '{cn}' expires in {(na - now).days} days", "chain"))

    # Does the chain end with a root (self-signed)?
    last = chain[-1]
    if last.issuer != last.subject:
        findings.append(finding(
            "INFO",
            "Chain does not include a self-signed root (typical; root usually in trust store)",
            "chain"
        ))

    # Single-cert chain
    if len(chain) == 1:
        findings.append(finding(
            "MEDIUM",
            "Server returned only the leaf certificate (no intermediates) - clients may fail to build a path",
            "chain"
        ))

    return findings
