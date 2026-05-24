"""
Core certificate inspection: TLS handshake, leaf cert parsing, basic findings.
"""

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import ExtensionOID

from .utils import finding, utc, name_to_dict, host_matches, sort_findings


WEAK_SIG_ALGS = {"md5", "sha1"}
DEPRECATED_TLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
WEAK_CIPHER_KEYWORDS = ("RC4", "3DES", "_DES_", "NULL", "EXPORT", "anon", "MD5")
MIN_RSA_KEY_SIZE = 2048
MIN_EC_KEY_SIZE = 256
EXPIRY_WARN_DAYS = 30
EXPIRY_CRITICAL_DAYS = 7
MAX_LIFETIME_DAYS = 398


def fetch_handshake(host, port=443, timeout=10, sni=None):
    """
    TLS handshake without verification (so we can inspect bad certs too).
    Returns (cert_der, cipher_tuple, tls_version, ocsp_response_bytes_or_none).
    """
    sni = sni or host
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        ssock = ctx.wrap_socket(sock, server_hostname=sni)
        try:
            der = ssock.getpeercert(binary_form=True)
            cipher = ssock.cipher()
            version = ssock.version()
            # OCSP response (Python 3.10+ exposes it via ssock.ocsp_response on some platforms)
            ocsp = None
            try:
                # Not all OpenSSL builds expose this; ignore failures
                ocsp = getattr(ssock, "ocsp_response", lambda: None)()
            except Exception:
                ocsp = None
        finally:
            try:
                ssock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            ssock.close()
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return der, cipher, version, ocsp


def get_pubkey_info(cert):
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return {"type": "RSA", "size": pk.key_size}
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return {"type": "EC", "size": pk.curve.key_size, "curve": pk.curve.name}
    if isinstance(pk, dsa.DSAPublicKey):
        return {"type": "DSA", "size": pk.key_size}
    return {"type": type(pk).__name__, "size": None}


def get_san(cert):
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return [n for n in ext.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        return []


def cert_to_dict(cert):
    """Serialise a parsed leaf certificate to a JSON-friendly dict."""
    not_before = utc(getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before)
    not_after = utc(getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after)

    subj = name_to_dict(cert.subject)
    iss = name_to_dict(cert.issuer)
    san = get_san(cert)
    pk_info = get_pubkey_info(cert)

    return {
        "subject": subj,
        "issuer": iss,
        "serial": format(cert.serial_number, "x"),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "fingerprint_sha1": cert.fingerprint(hashes.SHA1()).hex(),
        "valid_from": not_before.isoformat(),
        "valid_until": not_after.isoformat(),
        "lifetime_days": (not_after - not_before).days,
        "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
        "public_key": pk_info,
        "san": san,
        "version": cert.version.name,
    }


def analyze_certificate(host, der, cipher, version):
    """Build the findings + structured cert info from a fetched certificate."""
    cert = x509.load_der_x509_certificate(der, default_backend())
    info = cert_to_dict(cert)

    findings = []
    now = datetime.now(timezone.utc)
    not_after = utc(getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after)
    not_before = utc(getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before)

    # Validity window
    if not_after < now:
        findings.append(finding("CRITICAL", f"Certificate EXPIRED on {not_after.date()}", "validity"))
    else:
        days_left = (not_after - now).days
        info["days_until_expiry"] = days_left
        if days_left <= EXPIRY_CRITICAL_DAYS:
            findings.append(finding("CRITICAL", f"Certificate expires in {days_left} days", "validity"))
        elif days_left <= EXPIRY_WARN_DAYS:
            findings.append(finding("HIGH", f"Certificate expires in {days_left} days", "validity"))

    if not_before > now:
        findings.append(finding("HIGH", f"Certificate not yet valid (starts {not_before.date()})", "validity"))

    # Self-signed
    if cert.issuer == cert.subject:
        findings.append(finding("HIGH", "Certificate is self-signed (issuer == subject)", "trust"))

    # Signature hash
    sig_alg = info["signature_algorithm"]
    if sig_alg.lower() in WEAK_SIG_ALGS:
        findings.append(finding("CRITICAL", f"Weak signature hash algorithm: {sig_alg.upper()}", "crypto"))

    # Key strength
    pk = info["public_key"]
    if pk["type"] == "RSA" and pk.get("size") and pk["size"] < MIN_RSA_KEY_SIZE:
        findings.append(finding("HIGH", f"Weak RSA key size: {pk['size']} bits (min {MIN_RSA_KEY_SIZE})", "crypto"))
    if pk["type"] == "EC" and pk.get("size") and pk["size"] < MIN_EC_KEY_SIZE:
        findings.append(finding("HIGH", f"Weak EC key size: {pk['size']} bits (min {MIN_EC_KEY_SIZE})", "crypto"))
    if pk["type"] == "DSA":
        findings.append(finding("MEDIUM", "DSA keys are deprecated; prefer RSA-2048+ or ECDSA", "crypto"))

    # TLS protocol
    if version in DEPRECATED_TLS:
        findings.append(finding("HIGH", f"Deprecated TLS protocol negotiated: {version}", "protocol"))
    elif version == "TLSv1.2":
        findings.append(finding("LOW", "Server fell back to TLS 1.2 (TLS 1.3 not negotiated)", "protocol"))

    # Cipher
    cname = (cipher[0] if cipher else "") or ""
    if cname and any(w in cname.upper() for w in WEAK_CIPHER_KEYWORDS):
        findings.append(finding("HIGH", f"Weak cipher negotiated: {cname}", "crypto"))

    # Hostname / SAN
    cn = info["subject"].get("commonName")
    if not host_matches(host, info["san"], cn):
        findings.append(finding("HIGH", f"Hostname '{host}' does not match SAN/CN", "trust"))
    if not info["san"]:
        findings.append(finding("MEDIUM", "Certificate has no Subject Alternative Name (SAN) extension", "config"))

    # Lifetime
    if info["lifetime_days"] > MAX_LIFETIME_DAYS:
        findings.append(finding(
            "MEDIUM",
            f"Certificate lifetime {info['lifetime_days']}d exceeds CA/B Forum maximum ({MAX_LIFETIME_DAYS}d)",
            "policy"
        ))

    # Wildcards
    wildcards = [s for s in info["san"] if s.startswith("*.")]
    if wildcards:
        findings.append(finding("INFO", f"Wildcard SAN(s) present: {', '.join(wildcards)}", "config"))

    # Basic Constraints / EKU
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        if bc.ca:
            findings.append(finding("HIGH", "Leaf certificate has CA:TRUE (should not be a CA cert)", "config"))
    except x509.ExtensionNotFound:
        findings.append(finding("LOW", "Missing Basic Constraints extension", "config"))

    try:
        cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    except x509.ExtensionNotFound:
        findings.append(finding("LOW", "Missing Extended Key Usage extension", "config"))

    return info, sort_findings(findings)
