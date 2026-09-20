# Network Intrusion Detection System (NIDS)

A Suricata-based Network Intrusion Detection System for real-time threat detection, automated response, and attack visualization.

## Components

| Component | Description |
|-----------|-------------|
| **Suricata** | Network IDS engine that inspects live traffic |
| **Detection Rules** | 6 rule files covering 6 threat categories with 91 rules |
| **Monitoring Script** | `scripts/monitor.sh` - starts Suricata and processes alerts in real-time |
| **Response Engine** | `scripts/respond.py` - blocks malicious IPs, maintains watchlist, logs incidents |
| **Visualization Dashboard** | `scripts/dashboard.py` - Flask web app with charts and live alert feed |
| **Docker** | Containerized Suricata, dashboard, and responder services |

## Detection Coverage

| Category | Rules File | Threats Detected |
|----------|-----------|-----------------|
| Network Scans | `network-scans.rules` | TCP/UDP scans, Xmas/Null/FIN scans, ICMP sweeps, OS fingerprinting |
| Web Attacks | `web-attacks.rules` | SQL injection, XSS, LFI/RFI, command injection, PHP attacks, Shellshock |
| Auth Attacks | `auth-attacks.rules` | SSH/FTP/RDP/Telnet brute force, default credentials, DB brute force |
| Malware/C2 | `malware-c2.rules` | Tor exit nodes, DNS tunneling/exfiltration, executable downloads, C2 beacons |
| DoS/DDoS | `dos-ddos.rules` | SYN/UDP/ICMP floods, DNS amplification, HTTP floods, Slowloris, Smurf |
| Protocol Anomalies | `protocol-anomalies.rules` | ICMP tunneling, non-standard protocols, DNS zone transfer, SMB attacks, Heartbleed |

## Quick Start

### Prerequisites
- Linux (Ubuntu/Debian or RHEL/CentOS)
- Root/sudo access
- Network interface in promiscuous mode

### Quick Setup (Docker)

```bash
# From the project root
cd docker
SURICATA_INTERFACE=eth0 docker-compose up -d
```

Access the dashboard at `http://localhost:5001`.

### Manual Setup

```bash
# 1. Install Suricata and dependencies
sudo scripts/setup.sh

# 2. Start monitoring on your interface
sudo scripts/monitor.sh eth0

# 3. Start the visualization dashboard (separate terminal)
pip install -r requirements.txt
python3 scripts/dashboard.py --eve-file /var/log/suricata/eve.json

# 4. (Optional) Start the response engine in daemon mode
python3 scripts/respond.py --daemon /var/log/suricata/eve.json

# 5. (Optional) Start the response API server
python3 scripts/respond.py --api
```

## Configuration

Edit `config/suricata.yaml` to customize:
- `HOME_NET` (line 18): Define your internal network range
- `EXTERNAL_NET` (line 24): Define external/untrusted networks
- `HTTP_PORTS` (line 42): Set the HTTP server port
- Interface: Override with `SURICATA_INTERFACE` environment variable

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SURICATA_INTERFACE` | `eth0` | Network interface to monitor |
| `SURICATA_CONFIG_PATH` | `/etc/suricata` | Path to config files |
| `SURICATA_RULE_PATH` | `/var/lib/suricata/rules` | Path to rules directory |
| `SURICATA_LOG_DIR` | `/var/log/suricata` | Path for Suricata output logs |
| `EVE_FILE` | `/var/log/suricata/eve.json` | Path to EVE JSON log for dashboard |

## Alert Outputs

Suricata writes alerts in two formats:
- **fast.log** - Human-readable alerts (classic Snort format)
- **eve.json** - JSON-formatted events with full packet/flow context

The response engine processes `eve.json` and writes to:
- `alerts/incidents.log` - All processed incidents
- `alerts/watchlist.txt` - Source IPs flagged for review
- `alerts/blocked-ips.json` - IPs blocked via iptables

## Project Structure

```
.
├── config/
│   ├── suricata.yaml          # Main Suricata configuration
│   ├── classification.config   # Custom threat classifications
│   ├── reference.config        # Reference URL mappings
│   ├── threshold.config        # Thresholding/suppression rules
│   └── rules/
│       ├── suricata.rules      # Main rules file (includes others)
│       ├── network-scans.rules
│       ├── web-attacks.rules
│       ├── auth-attacks.rules
│       ├── malware-c2.rules
│       ├── dos-ddos.rules
│       └── protocol-anomalies.rules
├── scripts/
│   ├── setup.sh                # Installation and configuration script
│   ├── monitor.sh              # Continuous monitoring launcher
│   ├── respond.py              # Intrusion response engine + API
│   └── dashboard.py            # Attack visualization dashboard
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── alerts/                     # Incident logs and blocked IPs (runtime)
├── logs/                       # Suricata output logs (runtime)
└── requirements.txt
```

## Testing Rules

```bash
# Validate configuration
suricata -T -c config/suricata.yaml

# Test with a sample pcap
suricata -r samples/test.pcap -l /tmp/suricata-test -c config/suricata.yaml
```
