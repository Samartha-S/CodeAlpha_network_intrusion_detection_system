#!/usr/bin/env python3
"""
Attack Visualization Dashboard for the Network Intrusion Detection System.

A Flask-based web application that reads Suricata EVE JSON output and
provides real-time visualizations of detected attacks.

Features:
  - Real-time alert feed
  - Attack type breakdown (pie chart)
  - Alerts over time (timeline)
  - Top attacking source IPs (bar chart)
  - Interactive alert detail table
  - Auto-refresh via Server-Sent Events (SSE)

Usage:
  python3 dashboard.py [--eve-file /var/log/suricata/eve.json] [--port 5001]
"""

import argparse
import json
import os
import threading
import time
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template_string, jsonify, Response

try:
    from flask_socketio import SocketIO
    HAS_SOCKETIO = True
except ImportError:
    HAS_SOCKETIO = False

app = Flask(__name__)
if HAS_SOCKETIO:
    socketio = SocketIO(app, cors_allowed_origins="*")
else:
    socketio = None

PROJECT_DIR = Path(__file__).resolve().parent.parent
ALERTS_DIR = PROJECT_DIR / "alerts"
DEFAULT_EVE_FILE = os.environ.get("EVE_FILE", "/var/log/suricata/eve.json")

SEVERITY_COLORS = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}

SEVERITY_NAMES = {
    1: "Critical",
    2: "High",
    3: "Medium",
    4: "Low",
}

RULE_CATEGORIES = {
    (1000000, 1999999): "Network Scan",
    (2000000, 2999999): "Web Application Attack",
    (3000000, 3999999): "Authentication Attack",
    (4000000, 4999999): "Malware / C2",
    (5000000, 5999999): "DoS / DDoS",
    (6000000, 6999999): "Protocol Anomaly",
}


def categorize_rule(sid):
    try:
        sid_int = int(sid)
    except (ValueError, TypeError):
        return "Unknown"
    for (low, high), name in RULE_CATEGORIES.items():
        if low <= sid_int <= high:
            return name
    return "Other"


class AlertStore:
    def __init__(self):
        self.alerts = []
        self._lock = threading.Lock()
        self._max_alerts = 10000

    def add(self, alert):
        with self._lock:
            self.alerts.append(alert)
            if len(self.alerts) > self._max_alerts:
                self.alerts = self.alerts[-self._max_alerts:]

    def get_all(self):
        with self._lock:
            return list(self.alerts)

    def get_recent(self, count=100):
        with self._lock:
            return list(self.alerts[-count:])

    def clear(self):
        with self._lock:
            self.alerts.clear()

    def get_stats(self):
        with self._lock:
            alerts = list(self.alerts)

        if not alerts:
            return {
                "total": 0,
                "by_category": {},
                "by_severity": {},
                "top_source_ips": [],
                "timeline": [],
            }

        by_category = Counter()
        by_severity = Counter()
        source_ip_counter = Counter()
        timeline = defaultdict(int)

        for alert in alerts:
            sid = alert.get("alert", {}).get("signature_id", "unknown")
            by_category[categorize_rule(str(sid))] += 1

            priority = alert.get("alert", {}).get("priority", 3)
            by_severity[SEVERITY_NAMES.get(priority, "Unknown")] += 1

            src_ip = alert.get("src_ip", "unknown")
            if src_ip != "unknown":
                source_ip_counter[src_ip] += 1

            ts = alert.get("timestamp", "")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    hour_key = dt.strftime("%H:00")
                    timeline[hour_key] += 1
                except Exception:
                    pass

        return {
            "total": len(alerts),
            "by_category": dict(by_category.most_common(10)),
            "by_severity": dict(by_severity),
            "top_source_ips": [
                {"ip": ip, "count": count}
                for ip, count in source_ip_counter.most_common(10)
            ],
            "timeline": [
                {"hour": hour, "count": count}
                for hour, count in sorted(timeline.items())
            ],
        }


store = AlertStore()
_subscribers = []


def parse_eve_line(line):
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def tail_eve_file(eve_file):
    print(f"[*] Tailing EVE file: {eve_file}")

    def reconnect():
        while True:
            try:
                with open(eve_file, "r") as f:
                    f.seek(0, 2)
                    while True:
                        line = f.readline()
                        if line:
                            yield line.strip()
                        else:
                            time.sleep(0.3)
            except FileNotFoundError:
                print(f"[WARN] EVE file not found: {eve_file}, retrying...")
                time.sleep(2)
            except Exception as e:
                print(f"[ERROR] Tail error: {e}, retrying...")
                time.sleep(2)

    for line in reconnect():
        event = parse_eve_line(line)
        if event and event.get("event_type") == "alert":
            store.add(event)
            for cb in list(_subscribers):
                try:
                    cb(event)
                except Exception:
                    pass


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NIDS Attack Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; }
    .header { background: #1e293b; padding: 20px 30px; border-bottom: 2px solid #3b82f6; }
    .header h1 { font-size: 1.5em; color: #3b82f6; }
    .container { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; padding: 20px 30px; }
    .card { background: #1e293b; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
    .card h2 { font-size: 1.1em; color: #94a3b8; margin-bottom: 15px; border-bottom: 1px solid #334155; padding-bottom: 10px; }
    .card.full { grid-column: 1 / -1; }
    .stat-value { font-size: 2.5em; font-weight: bold; color: #3b82f6; }
    .chart-canvas { max-height: 250px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
    th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #334155; }
    th { color: #94a3b8; font-weight: 600; }
    tr:hover { background: #283548; }
    .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
    .badge.critical { background: #7f1d1d; color: #fecaca; }
    .badge.high { background: #991b1b; color: #fecaca; }
    .badge.medium { background: #92400e; color: #fde68a; }
    .badge.low { background: #14532d; color: #bbf7d0; }
    .badge.Unknown { background: #374151; color: #d1d5db; }
    .feed-item { border-bottom: 1px solid #334155; padding: 10px; }
    .feed-item:last-child { border-bottom: none; }
    .feed-time { color: #94a3b8; font-size: 0.8em; }
    .feed-sig { color: #f8fafc; font-weight: 500; }
    .feed-ip { color: #f59e0b; }
    #live-feed { max-height: 400px; overflow-y: auto; }
    .pulse { animation: pulse 2s infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
  </style>
</head>
<body>
  <div class="header">
    <h1>Network Intrusion Detection System - Attack Visualization</h1>
    <span id="alert-count" class="stat-value" style="font-size:1.2em">0 alerts</span>
  </div>
  <div class="container">
    <div class="card">
      <h2>Total Alerts</h2>
      <div class="stat-value" id="total-alerts">0</div>
    </div>
    <div class="card">
      <h2>By Severity</h2>
      <canvas id="severity-chart" class="chart-canvas"></canvas>
    </div>
    <div class="card" style="min-height:250px">
      <h2>Attack Type Breakdown</h2>
      <canvas id="category-chart" class="chart-canvas"></canvas>
    </div>
    <div class="card">
      <h2>Top Source IPs</h2>
      <canvas id="source-ip-chart" class="chart-canvas"></canvas>
    </div>
    <div class="card full">
      <h2>Alerts Timeline (Last 24h)</h2>
      <canvas id="timeline-chart" class="chart-canvas" style="max-height:200px"></canvas>
    </div>
    <div class="card" style="min-height:400px">
      <h2>Live Alert Feed</h2>
      <div id="live-feed"></div>
    </div>
  </div>
  <script>
    let severityChart, categoryChart, sourceIpChart, timelineChart;

    function initCharts() {
      const ctxS = document.getElementById('severity-chart').getContext('2d');
      severityChart = new Chart(ctxS, {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e'] }] },
        options: { plugins: { legend: { labels: { color: '#94a3b8' } } } }
      });

      const ctxC = document.getElementById('category-chart').getContext('2d');
      categoryChart = new Chart(ctxC, {
        type: 'pie',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#3b82f6','#ef4444','#f59e0b','#8b5cf6','#ec4899','#22c55e'] }] },
        options: { plugins: { legend: { labels: { color: '#94a3b8' } } } }
      });

      const ctxI = document.getElementById('source-ip-chart').getContext('2d');
      sourceIpChart = new Chart(ctxI, {
        type: 'bar',
        data: { labels: [], datasets: [{ data: [], backgroundColor: '#f59e0b' }] },
        options: { indexAxis: 'y', plugins: { legend: { labels: { color: '#94a3b8' } } }, scales: { x: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } }, y: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } } } }
      });

      const ctxT = document.getElementById('timeline-chart').getContext('2d');
      timelineChart = new Chart(ctxT, {
        type: 'line',
        data: { labels: [], datasets: [{ data: [], borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.2)', fill: true, tension: 0.3 }] },
        options: { plugins: { legend: { labels: { color: '#94a3b8' } } }, scales: { x: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } }, y: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } } } }
      });
    }

    function updateStats() {
      fetch('/api/stats').then(r => r.json()).then(data => {
        document.getElementById('total-alerts').textContent = data.total;
        document.getElementById('alert-count').textContent = data.total + ' alerts';

        severityChart.data.labels = Object.keys(data.by_severity);
        severityChart.data.datasets[0].data = Object.values(data.by_severity);
        severityChart.update();

        categoryChart.data.labels = Object.keys(data.by_category);
        categoryChart.data.datasets[0].data = Object.values(data.by_category);
        categoryChart.update();

        const ips = data.top_source_ips.map(e => e.ip);
        const counts = data.top_source_ips.map(e => e.count);
        sourceIpChart.data.labels = ips;
        sourceIpChart.data.datasets[0].data = counts;
        sourceIpChart.update();

        timelineChart.data.labels = data.timeline.map(t => t.hour);
        timelineChart.data.datasets[0].data = data.timeline.map(t => t.count);
        timelineChart.update();
      });
    }

    function addAlertToFeed(alert) {
      const feed = document.getElementById('live-feed');
      const time = new Date(alert.timestamp).toLocaleTimeString();
      const sig = alert.alert?.signature || 'Unknown';
      const ip = alert.src_ip || 'unknown';
      const priority = alert.alert?.priority || 3;
      const sevClass = [{1:'critical',2:'high',3:'medium',4:'low'}[priority] || 'Unknown'];

      const div = document.createElement('div');
      div.className = 'feed-item';
      div.innerHTML = '<span class="feed-time">' + time + '</span> ' +
        '<span class="badge ' + sevClass + '">' + sevClass.toUpperCase() + '</span> ' +
        '<span class="feed-sig">' + sig + '</span> ' +
        '<span class="feed-ip">[' + ip + ']</span>';
      feed.insertBefore(div, feed.firstChild);

      while (feed.children.length > 50) {
        feed.removeChild(feed.lastChild);
      }
    }

    if (typeof EventSource !== 'undefined') {
      const evtSource = new EventSource('/alerts/stream');
      evtSource.onmessage = function(event) {
        try {
          const alert = JSON.parse(event.data);
          addAlertToFeed(alert);
          updateStats();
        } catch(e) {}
      };
    }

    initCharts();
    updateStats();
    setInterval(updateStats, 5000);
  </script>
</body>
</html>
"""


@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/stats")
def api_stats():
    stats = store.get_stats()
    return jsonify(stats)


@app.route("/api/alerts/recent")
def api_alerts_recent():
    alerts = store.get_recent(100)
    return jsonify({"alerts": alerts})


@app.route("/alerts/stream")
def alert_stream():
    def event_stream():
        q = [None]
        def broadcast(alert):
            q[0] = json.dumps(alert)
        _subscribers.append(broadcast)
        try:
            while True:
                if q[0] is not None:
                    yield f"data: {q[0]}\n\n"
                    q[0] = None
                time.sleep(1)
        finally:
            if broadcast in _subscribers:
                _subscribers.remove(broadcast)

    return Response(event_stream(), mimetype="text/event-stream")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIDS Attack Visualization Dashboard")
    parser.add_argument("--eve-file", default=DEFAULT_EVE_FILE,
                        help="Path to Suricata EVE JSON log file")
    parser.add_argument("--port", type=int, default=5001,
                        help="Port for the dashboard server")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Host interface to bind to")
    args = parser.parse_args()

    tail_thread = threading.Thread(target=tail_eve_file, args=(args.eve_file,), daemon=True)
    tail_thread.start()

    print(f"[*] Dashboard available at http://{args.host}:{args.port}")
    print(f"[*] Tailing EVE file: {args.eve_file}")

    if socketio:
        socketio.run(app, host=args.host, port=args.port)
    else:
        app.run(host=args.host, port=args.port, debug=False, threaded=True)
