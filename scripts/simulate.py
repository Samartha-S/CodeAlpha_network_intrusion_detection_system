#!/usr/bin/env python3
"""
Simulates Suricata EVE JSON alert output for testing the NIDS dashboard
and response engine without requiring actual Suricata or network traffic.

Generates realistic alert events matching the project rule SIDs.
"""

import json
import time
import random
import os
from datetime import datetime
import threading

EVE_FILE = os.environ.get("EVE_FILE", "/var/log/suricata/eve.json")
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if "var/log/suricata" in EVE_FILE:
    EVE_FILE = os.path.join(PROJECT_DIR, "logs", "eve.json")

os.makedirs(os.path.dirname(EVE_FILE), exist_ok=True)

SAMPLE_ALERTS = [
    {
        "timestamp": "2025-01-15T10:00:00.000000Z",
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "dest_ip": "10.0.0.5",
        "src_port": 54321,
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "signature_id": 1000001,
            "revision": 1,
            "signature": "NIDS-NMAP TCP Port Scan",
            "category": "Attempted Information Leak",
            "severity": 2,
        },
        "flow_id": 123456789,
    },
    {
        "timestamp": "2025-01-15T10:01:30.000000Z",
        "event_type": "alert",
        "src_ip": "10.1.2.3",
        "dest_ip": "10.0.0.5",
        "src_port": 33333,
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "signature_id": 2000001,
            "revision": 2,
            "signature": "NIDS-SQL Injection Attempt - UNION SELECT",
            "category": "Web Application Attack",
            "severity": 1,
        },
        "flow_id": 123456790,
    },
    {
        "timestamp": "2025-01-15T10:02:15.000000Z",
        "event_type": "alert",
        "src_ip": "172.16.0.50",
        "dest_ip": "10.0.0.5",
        "src_port": 22222,
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "signature_id": 2000010,
            "revision": 1,
            "signature": "NIDS-XSS Script Tag Injection",
            "category": "Web Application Attack",
            "severity": 1,
        },
        "flow_id": 123456791,
    },
    {
        "timestamp": "2025-01-15T10:03:00.000000Z",
        "event_type": "alert",
        "src_ip": "192.168.1.200",
        "dest_ip": "10.0.0.5",
        "src_port": 44444,
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "signature_id": 3000001,
            "revision": 1,
            "signature": "NIDS-SSH Brute Force Attempt",
            "category": "Attempted User Privilege Gain",
            "severity": 2,
        },
        "flow_id": 123456792,
    },
    {
        "timestamp": "2025-01-15T10:04:30.000000Z",
        "event_type": "alert",
        "src_ip": "203.0.113.50",
        "dest_ip": "10.0.0.5",
        "src_port": 55555,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature_id": 4000001,
            "revision": 1,
            "signature": "NIDS-Tor Exit Node Connection",
            "category": "A Network Trojan was detected",
            "severity": 1,
        },
        "flow_id": 123456793,
    },
    {
        "timestamp": "2025-01-15T10:05:00.000000Z",
        "event_type": "alert",
        "src_ip": "198.51.100.25",
        "dest_ip": "10.0.0.5",
        "src_port": 33333,
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "signature_id": 5000001,
            "revision": 1,
            "signature": "NIDS-SYN Flood Attack",
            "category": "Attempted Denial of Service",
            "severity": 2,
        },
        "flow_id": 123456794,
    },
    {
        "timestamp": "2025-01-15T10:05:45.000000Z",
        "event_type": "alert",
        "src_ip": "45.227.255.206",
        "dest_ip": "10.0.0.5",
        "src_port": 66666,
        "dest_port": 1234,
        "proto": "TCP",
        "alert": {
            "signature_id": 6000060,
            "revision": 1,
            "signature": "NIDS-SMB Null Session Access",
            "category": "Attempted Administrator Privilege Gain",
            "severity": 1,
        },
        "flow_id": 123456795,
    },
    {
        "timestamp": "2025-01-15T10:06:20.000000Z",
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "dest_ip": "10.0.0.5",
        "src_port": 54322,
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "signature_id": 2000002,
            "revision": 1,
            "signature": "NIDS-SQL Injection Attempt - OR 1=1",
            "category": "Web Application Attack",
            "severity": 1,
        },
        "flow_id": 123456796,
    },
    {
        "timestamp": "2025-01-15T10:07:10.000000Z",
        "event_type": "alert",
        "src_ip": "172.16.0.50",
        "dest_ip": "10.0.0.5",
        "src_port": 22223,
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "signature_id": 3000070,
            "revision": 1,
            "signature": "NIDS-Default SSH Credential Attempt",
            "category": "Attempted User Privilege Gain",
            "severity": 2,
        },
        "flow_id": 123456797,
    },
    {
        "timestamp": "2025-01-15T10:08:00.000000Z",
        "event_type": "alert",
        "src_ip": "203.0.113.50",
        "dest_ip": "10.0.0.5",
        "src_port": 44444,
        "dest_port": 53,
        "proto": "UDP",
        "alert": {
            "signature_id": 4000020,
            "revision": 1,
            "signature": "NIDS-DNS Tunneling - Long Subdomain",
            "category": "Potentially Bad Traffic",
            "severity": 3,
        },
        "flow_id": 123456798,
    },
]


def simulate_alerts(duration=30, interval=3):
    print(f"[*] Simulating Suricata EVE alerts to {EVE_FILE}")

    with open(EVE_FILE, "w") as f:
        f.write("")

    end_time = time.time() + duration
    cycle = 0

    while time.time() < end_time:
        alert = SAMPLE_ALERTS[cycle % len(SAMPLE_ALERTS)].copy()
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        alert["timestamp"] = now
        alert["flow_id"] = random.randint(1000000, 9999999)
        alert["src_port"] = random.randint(1024, 65535)

        with open(EVE_FILE, "a") as f:
            f.write(json.dumps(alert) + "\n")

        print(f"    [{now}] Alert: {alert['alert']['signature']} from {alert['src_ip']}")

        cycle += 1
        time.sleep(interval)

    print(f"[*] Simulation complete. {cycle} alerts written to {EVE_FILE}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Simulate Suricata EVE JSON alerts")
    parser.add_argument("--duration", type=int, default=30, help="Simulation duration in seconds")
    parser.add_argument("--interval", type=int, default=3, help="Seconds between alerts")
    args = parser.parse_args()
    simulate_alerts(args.duration, args.interval)
