"""
Quick TLS port reachability scan for common services.
"""

import socket
import ssl


COMMON_TLS_PORTS = [
    (443,  "HTTPS"),
    (8443, "HTTPS-alt"),
    (465,  "SMTPS"),
    (587,  "Submission/STARTTLS"),
    (993,  "IMAPS"),
    (995,  "POP3S"),
    (636,  "LDAPS"),
    (5061, "SIP-TLS"),
    (8883, "MQTT-TLS"),
    (3306, "MySQL-TLS"),
    (5432, "Postgres-TLS"),
]


def scan_ports(host, timeout=2):
    """For each common TLS port, report whether TCP connects and whether TLS
    handshake succeeds. Returns list of dicts."""
    results = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for port, name in COMMON_TLS_PORTS:
        entry = {"port": port, "service": name, "tcp": False, "tls": False, "tls_version": None}
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                entry["tcp"] = True
                try:
                    with ctx.wrap_socket(sock, server_hostname=host) as ss:
                        entry["tls"] = True
                        entry["tls_version"] = ss.version()
                except Exception:
                    pass
        except Exception:
            pass
        results.append(entry)
    return results
