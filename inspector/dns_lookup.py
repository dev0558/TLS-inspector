"""
DNS lookups for the target domain (A, AAAA, MX, NS, CAA).

Uses dnspython if available; falls back to socket for A/AAAA.
"""

import socket

from .utils import finding


try:
    import dns.resolver
    HAVE_DNSPYTHON = True
except ImportError:  # pragma: no cover
    HAVE_DNSPYTHON = False


def lookup_records(domain, timeout=5):
    out = {
        "A": [], "AAAA": [], "MX": [], "NS": [], "CAA": [], "TXT": [],
        "findings": [],
    }

    if HAVE_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        for rrtype in ("A", "AAAA", "MX", "NS", "CAA", "TXT"):
            try:
                ans = resolver.resolve(domain, rrtype)
                if rrtype == "MX":
                    out[rrtype] = [f"{r.preference} {r.exchange.to_text()}" for r in ans]
                elif rrtype == "CAA":
                    out[rrtype] = [f'{r.flags} {r.tag.decode()} "{r.value.decode()}"' for r in ans]
                else:
                    out[rrtype] = [r.to_text() for r in ans]
            except Exception:
                out[rrtype] = []
    else:
        # Bare socket fallback (A/AAAA only)
        try:
            infos = socket.getaddrinfo(domain, None)
            seen_a, seen_aaaa = set(), set()
            for family, *_rest, sockaddr in infos:
                ip = sockaddr[0]
                if family == socket.AF_INET and ip not in seen_a:
                    out["A"].append(ip); seen_a.add(ip)
                elif family == socket.AF_INET6 and ip not in seen_aaaa:
                    out["AAAA"].append(ip); seen_aaaa.add(ip)
        except Exception:
            pass
        out["findings"].append(finding(
            "INFO",
            "dnspython not installed; CAA/MX/NS lookups skipped",
            "dns"
        ))

    if not out["CAA"] and HAVE_DNSPYTHON:
        out["findings"].append(finding(
            "MEDIUM",
            "No CAA records published - any public CA may issue certs for this domain",
            "dns"
        ))
    if not out["A"] and not out["AAAA"]:
        out["findings"].append(finding("LOW", "No A or AAAA records resolved", "dns"))

    return out
