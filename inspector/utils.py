"""Shared utilities for the inspector package."""

from datetime import datetime, timezone


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def finding(severity, message, category=None):
    """Build a finding dict."""
    return {
        "severity": severity,
        "message": message,
        "category": category or "general",
    }


def utc(dt):
    """Normalise a possibly-naive datetime to UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def sort_findings(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))


def name_to_dict(name):
    """Convert an x509.Name to a flat dict of attr_name -> value."""
    out = {}
    for attr in name:
        try:
            out[attr.oid._name] = attr.value
        except Exception:
            pass
    return out


def host_matches(host, san_list, cn):
    """RFC 6125 hostname match against SAN, falling back to CN."""
    def matches(pattern, h):
        pattern, h = pattern.lower(), h.lower()
        if pattern == h:
            return True
        if pattern.startswith("*."):
            base = pattern[2:]
            return h.endswith("." + base) and h.count(".") == base.count(".") + 1
        return False

    candidates = list(san_list) or ([cn] if cn else [])
    return any(matches(p, host) for p in candidates if p)
