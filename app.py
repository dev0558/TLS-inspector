"""
SSL/TLS Certificate Inspector - Flask application
"""

import json
import os
import re
import threading
import uuid
from collections import deque
from datetime import datetime, timezone

from flask import (
    Flask, render_template, request, jsonify, abort, redirect, url_for, Response
)

from inspector import run_full_scan


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

# ---- In-memory scan history (last 50). Swap for SQLite if persistence needed.
HISTORY_LIMIT = 50
_history = deque(maxlen=HISTORY_LIMIT)
_history_lock = threading.Lock()


HOST_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,253}$")


def valid_host(h):
    if not h or len(h) > 253:
        return False
    return bool(HOST_RE.match(h))


def valid_port(p):
    try:
        p = int(p)
    except (TypeError, ValueError):
        return False
    return 1 <= p <= 65535


def _store(report):
    with _history_lock:
        _history.appendleft({
            "id": str(uuid.uuid4()),
            "host": report.get("host"),
            "port": report.get("port"),
            "grade": report.get("grade", "?"),
            "started": report.get("started"),
            "severity_counts": report.get("severity_counts", {}),
            "report": report,
        })


# ---------------- Routes ------------------------------------------------------

@app.route("/")
def index():
    with _history_lock:
        history = list(_history)[:10]
    return render_template("index.html", history=history)


@app.route("/scan", methods=["POST"])
def scan():
    host = (request.form.get("host") or "").strip()
    port = request.form.get("port", "443").strip()
    if not valid_host(host):
        return render_template("index.html", error=f"Invalid host: {host!r}", history=list(_history)[:10]), 400
    if not valid_port(port):
        return render_template("index.html", error=f"Invalid port: {port!r}", history=list(_history)[:10]), 400

    options = {
        "chain":     bool(request.form.get("opt_chain")),
        "protocols": bool(request.form.get("opt_protocols")),
        "ciphers":   bool(request.form.get("opt_ciphers")),
        "headers":   bool(request.form.get("opt_headers")),
        "ct":        bool(request.form.get("opt_ct")),
        "dns":       bool(request.form.get("opt_dns")),
        "ports":     bool(request.form.get("opt_ports")),
    }

    report = run_full_scan(host, int(port), timeout=12, options=options)
    _store(report)
    return render_template("report.html", report=report)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """JSON API. Accepts JSON: {"host": "...", "port": 443, "options": {...}}"""
    payload = request.get_json(silent=True) or {}
    host = (payload.get("host") or "").strip()
    port = payload.get("port", 443)
    if not valid_host(host):
        return jsonify({"error": "invalid host"}), 400
    if not valid_port(port):
        return jsonify({"error": "invalid port"}), 400
    options = payload.get("options") or {}
    report = run_full_scan(host, int(port), timeout=12, options=options)
    _store(report)
    return jsonify(report)


@app.route("/api/scan/bulk", methods=["POST"])
def api_bulk():
    """Bulk scan from JSON: {"hosts": [...], "options": {...}}"""
    payload = request.get_json(silent=True) or {}
    hosts = payload.get("hosts") or []
    if not isinstance(hosts, list) or not hosts:
        return jsonify({"error": "provide a non-empty 'hosts' list"}), 400
    if len(hosts) > 25:
        return jsonify({"error": "max 25 hosts per bulk request"}), 400
    options = payload.get("options") or {}

    results = []
    for h in hosts:
        if not valid_host(str(h).strip()):
            results.append({"host": h, "error": "invalid host"})
            continue
        r = run_full_scan(str(h).strip(), 443, timeout=10, options=options)
        _store(r)
        results.append(r)
    return jsonify({"results": results})


@app.route("/history")
def history():
    with _history_lock:
        items = list(_history)
    return render_template("history.html", history=items)


@app.route("/report/<rid>")
def view_report(rid):
    with _history_lock:
        for item in _history:
            if item["id"] == rid:
                return render_template("report.html", report=item["report"])
    abort(404)


@app.route("/report/<rid>.json")
def download_report(rid):
    with _history_lock:
        for item in _history:
            if item["id"] == rid:
                body = json.dumps(item["report"], indent=2, default=str)
                return Response(
                    body, mimetype="application/json",
                    headers={"Content-Disposition": f'attachment; filename="ssl-inspector-{item["host"]}.json"'},
                )
    abort(404)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "time": datetime.now(timezone.utc).isoformat()})


# ---- Template helpers --------------------------------------------------------

@app.template_filter("sev_class")
def sev_class(sev):
    return {
        "CRITICAL": "sev-critical",
        "HIGH":     "sev-high",
        "MEDIUM":   "sev-medium",
        "LOW":      "sev-low",
        "INFO":     "sev-info",
    }.get(sev, "sev-info")


@app.template_filter("grade_class")
def grade_class(g):
    return {
        "A": "grade-a", "B+": "grade-a", "B": "grade-b",
        "C": "grade-c", "D": "grade-d", "F": "grade-f",
    }.get(g, "grade-c")


@app.template_filter("nice_dt")
def nice_dt(iso_str):
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso_str


@app.template_filter("commonname")
def commonname(d):
    if not d:
        return ""
    return d.get("commonName") or d.get("organizationName") or "?"


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", 5000)),
        debug=bool(os.environ.get("FLASK_DEBUG")),
    )
