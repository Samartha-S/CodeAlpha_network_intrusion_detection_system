#!/bin/bash
#
# Continuous Network Traffic Monitoring Script
#
# Starts Suricata in continuous monitoring mode with the NIDS configuration.
# Monitors network traffic on the specified interface and processes alerts
# in real-time for response and visualization.
#
# Usage: ./monitor.sh [INTERFACE] [CONFIG_PATH] [LOG_DIR]
# Example: ./monitor.sh eth0 /opt/nids/config /var/log/suricata
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="${2:-${PROJECT_DIR}/config}"
LOG_DIR="${3:-/var/log/suricata}"
INTERFACE="${1:-${SURICATA_INTERFACE:-eth0}}"
RULE_PATH="${CONFIG_DIR}/rules"

export SURICATA_CONFIG_PATH="${CONFIG_DIR}"
export SURICATA_RULE_PATH="${RULE_PATH}"
export SURICATA_INTERFACE="${INTERFACE}"
export SURICATA_LOG_DIR="${LOG_DIR}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

if ! command -v suricata &>/dev/null; then
    log_error "Suricata is not installed. Run setup.sh first."
    exit 1
fi

mkdir -p "${LOG_DIR}"
mkdir -p "${PROJECT_DIR}/alerts"

log_info "Starting NIDS monitoring on interface: ${INTERFACE}"
log_info "Config directory: ${CONFIG_DIR}"
log_info "Rule path: ${RULE_PATH}"
log_info "Log directory: ${LOG_DIR}"
log_info "Alert output: ${PROJECT_DIR}/alerts/active-alerts.log"

SURICATA_PID=""

cleanup() {
    log_info "Shutting down NIDS monitoring..."
    if [ -n "${SURICATA_PID}" ] && kill -0 "${SURICATA_PID}" 2>/dev/null; then
        kill "${SURICATA_PID}" 2>/dev/null || true
        wait "${SURICATA_PID}" 2>/dev/null || true
    fi
    log_info "NIDS monitoring stopped."
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start Suricata in IDS mode (no inline/IPS)
suricata -c "${CONFIG_DIR}/suricata.yaml" -i "${INTERFACE}" -l "${LOG_DIR}" &
SURICATA_PID=$!

log_info "Suricata started with PID: ${SURICATA_PID}"

# Wait for Suricata to initialize
sleep 3

if ! kill -0 "${SURICATA_PID}" 2>/dev/null; then
    log_error "Suricata failed to start."
    exit 1
fi

log_info "NIDS is actively monitoring. Press Ctrl+C to stop."
log_info "Monitoring alerts: tail -f ${LOG_DIR}/fast.log"
log_info "EVE JSON alerts: tail -f ${LOG_DIR}/eve.json"

# Continuous alert processing loop
# Monitors the EVE JSON log for alerts and pipes them to the response handler
tail -F "${LOG_DIR}/eve.json" 2>/dev/null | while IFS= read -r line; do
    # Check if this is an alert event
    if echo "${line}" | python3 -c "import sys,json; json.loads(sys.stdin.read())['event_type']=='alert'" 2>/dev/null; then
        echo "${line}" >> "${PROJECT_DIR}/alerts/active-alerts.log"
        log_warn "ALERT DETECTED - $(echo "${line}" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('alert',{}).get('signature','Unknown'))" 2>/dev/null || echo 'Unknown')"
        # Trigger response handler
        python3 "${SCRIPT_DIR}/respond.py" "${line}" "${LOG_DIR}" &
    fi
done
