#!/usr/bin/env python3
"""
Intrusion Response Engine for the Network Intrusion Detection System.

Processes Suricata EVE JSON alert events and takes automated response actions
based on the severity and classification of detected threats.

Response actions:
  - High severity: Block source IP via iptables and log incident
  - Medium severity: Add source IP to a watchlist for manual review
  - Low severity: Log alert for statistical analysis

Usage:
  python3 respond.py '<eve_json_alert>' [LOG_DIR]
  python3 respond.py --daemon [LOG_DIR]
"""

import sys
import os
import json
import subprocess
import time
import signal
from datetime import datetime
from pathlib import Path
from collections import defaultdict

try:
    from flask import Flask, jsonify, render_template_string
except ImportError:
    Flask = None

PROJECT_DIR = Path(__file__).resolve().parent.parent
ALERTS_DIR = PROJECT_DIR / "alerts"
WATCHLIST_FILE = ALERTS_DIR / "watchlist.txt"
INCIDENT_LOG = ALERTS_DIR / "incidents.log"
BLOCKED_IPS_FILE = ALERTS_DIR / "blocked-ips.json"

ALERTS_DIR.mkdir(exist_ok=True)

BLOCK_THRESHOLD = {
    "high": 3,
    "medium": 10,
    "low": 50,
}

HIGH_PRIORITY_RULES = [
    "1000001", "1000002", "2000001", "2000002", "2000040", "3000001",
    "4000001", "4000034", "5000001", "5000003", "6000060", "6000100",
    "6000110",
]

MEDIUM_PRIORITY_RULES = [
    "1000005", "1000006", "1000007", "1000008", "2000010", "2000030",
    "2000050", "3000002", "3000011", "4000020", "4000022", "5000011",
    "6000010", "6000050", "6000070",
]


def parse_alert(eve_json_str):
    try:
        return json.loads(eve_json_str)
    except json.JSONDecodeError:
        return None


def extract_source_ip(alert):
    for key in ("src_ip", "srcip", "src_ip"):
        if alert.get(key):
            return alert[key]
    if "src_ip" in alert:
        return alert["src_ip"]
    return None


def extract_rule_id(alert):
    return str(alert.get("alert", {}).get("signature_id", "unknown"))


def get_severity(alert):
    rule_id = extract_rule_id(alert)
    if rule_id in HIGH_PRIORITY_RULES:
        return "high"
    if rule_id in MEDIUM_PRIORITY_RULES:
        return "medium"
    priority = alert.get("alert", {}).get("priority", 3)
    if priority <= 1:
        return "high"
    if priority <= 2:
        return "medium"
    return "low"


def block_ip(ip_address, rule_id, signature):
    try:
        result = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
                capture_output=True, text=True, check=True
            )
            return True
        return False
    except Exception:
        return False


def add_to_watchlist(ip_address):
    WATCHLIST_FILE.parent.mkdir(exist_ok=True)
    existing = set()
    if WATCHLIST_FILE.exists():
        existing = set(line.strip() for line in WATCHLIST_FILE.read_text().splitlines())
    if ip_address not in existing:
        with open(WATCHLIST_FILE, "a") as f:
            f.write(f"{ip_address}\n")


def log_incident(alert, severity, action_taken):
    timestamp = datetime.now().isoformat()
    src_ip = extract_source_ip(alert)
    rule_id = extract_rule_id(alert)
    signature = alert.get("alert", {}).get("signature", "Unknown")
    classification = alert.get("alert", {}).get("classification", "unknown")

    incident = {
        "timestamp": timestamp,
        "severity": severity,
        "src_ip": src_ip,
        "rule_id": rule_id,
        "signature": signature,
        "classification": classification,
        "action": action_taken,
    }

    with open(INCIDENT_LOG, "a") as f:
        f.write(json.dumps(incident) + "\n")


def update_blocked_ips():
    blocked = {}
    if BLOCKED_IPS_FILE.exists():
        try:
            blocked = json.loads(BLOCKED_IPS_FILE.read_text())
        except (json.JSONDecodeError, IOError):
            blocked = {}

    try:
        result = subprocess.run(
            ["iptables", "-L", "INPUT", "-n"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "DROP" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[3]
                        if ip not in blocked:
                            blocked[ip] = {
                                "blocked_at": datetime.now().isoformat(),
                                "reason": "manually blocked or persisted"
                            }
            BLOCKED_IPS_FILE.write_text(json.dumps(blocked, indent=2))
    except Exception:
        pass


def process_alert(alert):
    src_ip = extract_source_ip(alert)
    if not src_ip:
        return

    severity = get_severity(alert)
    rule_id = extract_rule_id(alert)
    action = "logged"

    if severity == "high":
        if block_ip(src_ip, rule_id, alert.get("alert", {}).get("signature", "")):
            action = f"blocked_ip:{src_ip}"
        else:
            action = f"already_blocked_or_unavailable:{src_ip}"

    add_to_watchlist(src_ip)
    log_incident(alert, severity, action)

    return severity, action


_ip_alert_counts = defaultdict(lambda: defaultdict(int))


def process_alert_with_counting(alert):
    src_ip = extract_source_ip(alert)
    if not src_ip:
        return

    severity = get_severity(alert)
    rule_id = extract_rule_id(alert)
    _ip_alert_counts[src_ip][rule_id] += 1
    count = _ip_alert_counts[src_ip][rule_id]

    threshold = BLOCK_THRESHOLD.get(severity, 50)
    action = f"logged(count={count})"

    if count >= threshold:
        if block_ip(src_ip, rule_id, alert.get("alert", {}).get("signature", "")):
            action = f"blocked_ip:{src_ip}(threshold={threshold})"
            _ip_alert_counts[src_ip] = defaultdict(int)

    add_to_watchlist(src_ip)
    log_incident(alert, severity, action)

    return severity, action, count


def get_incident_summary():
    incidents = []
    if INCIDENT_LOG.exists():
        for line in INCIDENT_LOG.read_text().splitlines():
            try:
                incidents.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    summary = {
        "total": len(incidents),
        "by_severity": defaultdict(int),
        "by_rule": defaultdict(int),
        "top_source_ips": defaultdict(int),
        "recent": [],
    }

    for inc in reversed(incidents):
        summary["by_severity"][inc["severity"]] += 1
        summary["by_rule"][inc["rule_id"]] += 1
        summary["top_source_ips"][inc["src_ip"]] += 1
        if len(summary["recent"]) < 10:
            summary["recent"].append(inc)

    summary["top_source_ips"] = dict(
        sorted(summary["top_source_ips"].items(), key=lambda x: x[1], reverse=True)[:10]
    )
    summary["by_severity"] = dict(summary["by_severity"])
    summary["by_rule"] = dict(summary["by_rule"])

    return summary


if Flask is not None:
    app = Flask(__name__)

    @app.route("/")
    def index():
        summary = get_incident_summary()
        return render_template_string("""
<!DOCTYPE html>
<html>
<head>
  <title>NIDS Response Dashboard</title>
  <meta charset="utf-8">
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
    h1 { color: #333; }
    .card { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .stat { font-size: 2em; font-weight: bold; }
    .high { color: #d32f2f; }
    .medium { color: #f57c00; }
    .low { color: #689f38; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
    th { background: #f0f0f0; }
  </style>
</head>
<body>
  <h1>Network Intrusion Detection System - Response Dashboard</h1>
  <div class="card">
    <h2>Incident Summary</h2>
    <p class="stat">{{ summary.total }} total incidents</p>
    <p><span class="high">High: {{ summary.by_severity.high|default(0) }}</span> |
       <span class="medium">Medium: {{ summary.by_severity.medium|default(0) }}</span> |
       <span class="low">Low: {{ summary.by_severity.low|default(0) }}</span></p>
  </div>
  <div class="card">
    <h2>Top Source IPs</h2>
    <table>
      <tr><th>IP Address</th><th>Alert Count</th></tr>
      {% for ip, count in summary.top_source_ips.items() %}
      <tr><td>{{ ip }}</td><td>{{ count }}</td></tr>
      {% endfor %}
    </table>
  </div>
  <div class="card">
    <h2>Recent Incidents</h2>
    <table>
      <tr><th>Time</th><th>IP</th><th>Rule</th><th>Severity</th><th>Action</th></tr>
      {% for inc in summary.recent %}
      <tr>
        <td>{{ inc.timestamp }}</td>
        <td>{{ inc.src_ip }}</td>
        <td>{{ inc.rule_id }}</td>
        <td class="{{ inc.severity }}">{{ inc.severity }}</td>
        <td>{{ inc.action }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
</body>
</html>
""", summary=summary)

    @app.route("/api/incidents")
    def api_incidents():
        return jsonify(get_incident_summary())

    @app.route("/api/block/<ip>")
    def api_block(ip):
        success = block_ip(ip, "manual", "")
        if success:
            return jsonify({"status": "blocked", "ip": ip}), 200
        return jsonify({"status": "error", "ip": ip}), 500


def run_api_server():
    if Flask is None:
        print("Flask is not installed. Cannot run API server.")
        sys.exit(1)
    app.run(host="0.0.0.0", port=5000, debug=False)


def tail_file(filepath, on_line, from_beginning=False):
    first_open = True
    while True:
        try:
            with open(filepath, "r") as f:
                if from_beginning and first_open:
                    first_open = False
                else:
                    f.seek(0, 2)
                while True:
                    line = f.readline()
                    if line:
                        on_line(line.strip())
                    else:
                        time.sleep(0.5)
        except FileNotFoundError:
            print(f"[WARN] File not found: {filepath}, retrying in 2s...")
            time.sleep(2)
        except Exception as e:
            print(f"[ERROR] Tail error: {e}, retrying in 2s...")
            time.sleep(2)


def daemon_monitor(eve_file):
    print(f"[*] Monitoring {eve_file} for alerts...")

    def handle_alert(line):
        if not line:
            return
        alert = parse_alert(line)
        if not alert:
            return
        if alert.get("event_type") == "alert":
            result = process_alert_with_counting(alert)
            if result:
                severity, action, count = result
                if severity == "high":
                    print(f"[!][HIGH] {alert.get('src_ip')} -> {action}")

    def handle_signal(signum, frame):
        print("\n[*] Stopping response engine...")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    tail_file(eve_file, handle_alert, from_beginning=True)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: respond.py <eve_json_line> [LOG_DIR]")
        print("       respond.py --daemon [LOG_DIR]")
        print("       respond.py --api")
        sys.exit(1)

    if sys.argv[1] == "--daemon":
        eve_file = sys.argv[2] if len(sys.argv) > 2 else "/var/log/suricata/eve.json"
        if os.path.isdir(eve_file):
            eve_file = os.path.join(eve_file, "eve.json")
        daemon_monitor(eve_file)
    elif sys.argv[1] == "--api":
        run_api_server()
    else:
        alert = parse_alert(sys.argv[1])
        if alert:
            result = process_alert(alert)
            if result:
                severity, action = result
                print(f"{severity}|{action}")
