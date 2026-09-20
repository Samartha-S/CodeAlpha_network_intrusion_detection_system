#!/bin/bash
#
# NIDS Setup Script
#
# Installs Suricata and its dependencies, downloads the Emerging Threats
# ruleset, and configures the NIDS for the local environment.
#
# Usage: sudo ./setup.sh
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="${PROJECT_DIR}/config"

if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root (use sudo)."
    exit 1
fi

log_info "Setting up Network Intrusion Detection System..."

# Detect OS
if [ -f /etc/debian_version ]; then
    OS="debian"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
else
    log_error "Unsupported OS. This script supports Debian/Ubuntu and RHEL/CentOS."
    exit 1
fi

# Install Suricata
log_info "Installing Suricata..."
if [ "$OS" = "debian" ]; then
    apt-get update -qq
    apt-get install -y -qq suricata python3 python3-pip curl > /dev/null
elif [ "$OS" = "redhat" ]; then
    if command -v dnf &>/dev/null; then
        dnf install -y -q suricata python3 curl
    else
        yum install -y -q suricata python3 curl
    fi
fi

log_info "Installing Python dependencies..."
pip3 install flask flask-socketio pandas --break-system-packages 2>/dev/null || pip3 install flask flask-socketio pandas

# Create log directory
mkdir -p /var/log/suricata
mkdir -p "${PROJECT_DIR}/alerts"
mkdir -p "${PROJECT_DIR}/logs"

# Set environment for Suricata to find local config files
log_info "Configuring Suricata environment..."
SYMLINK_DIR="/etc/suricata"
if [ ! -d "${SYMLINK_DIR}" ]; then
    mkdir -p "${SYMLINK_DIR}"
fi

# Symlink config files to standard Suricata location
ln -sf "${CONFIG_DIR}/suricata.yaml" "${SYMLINK_DIR}/suricata.yaml"
ln -sf "${CONFIG_DIR}/classification.config" "${SYMLINK_DIR}/classification.config"
ln -sf "${CONFIG_DIR}/reference.config" "${SYMLINK_DIR}/reference.config"
ln -sf "${CONFIG_DIR}/threshold.config" "${SYMLINK_DIR}/threshold.config"

# Create rules directory at standard location
mkdir -p /var/lib/suricata/rules
ln -sf "${CONFIG_DIR}/rules/suricata.rules" /var/lib/suricata/rules/suricata.rules
ln -sf "${CONFIG_DIR}/rules/"*.rules /var/lib/suricata/rules/ 2>/dev/null || true

# Make scripts executable
chmod +x "${PROJECT_DIR}/scripts/monitor.sh"
chmod +x "${PROJECT_DIR}/scripts/respond.py"
chmod +x "${PROJECT_DIR}/scripts/dashboard.py"

log_info "Setup complete!"
log_info "Available interfaces:"
ip link show | grep "^[0-9]" | awk -F': ' '{print $2}'

echo ""
log_info "To start monitoring: sudo ${PROJECT_DIR}/scripts/monitor.sh [INTERFACE]"
log_info "To start the dashboard: ${PROJECT_DIR}/scripts/dashboard.py"
log_info "To test rules: sudo suricata -T -c ${CONFIG_DIR}/suricata.yaml"
