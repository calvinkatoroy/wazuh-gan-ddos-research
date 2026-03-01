#!/usr/bin/env bash
# setup_wazuh.sh — Deploy GANDD-Bridge Blue Team stack on Ubuntu 22.04 LTS (VMware)
#
# Run on VM2 (Victim) as root after cloning the repository.
# VM3 (Manager) must already have Wazuh Manager installed and running.
#
# Usage:
#   sudo bash scripts/setup_wazuh.sh [--mode victim|manager] [--manager-ip <IP>] [--iface <NIC>]
#
# Blue Team component — Calvin Wirathama Katoroy (2306242395)

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
MODE="victim"           # victim | manager
MANAGER_IP="192.168.100.10"
VICTIM_IP="192.168.100.100"
IFACE="ens33"           # VMware default NIC name on Ubuntu 22.04
WAZUH_VERSION="4.9"
SURICATA_VERSION="7.0"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)        MODE="$2";       shift 2 ;;
    --manager-ip)  MANAGER_IP="$2"; shift 2 ;;
    --iface)       IFACE="$2";      shift 2 ;;
    *)             echo "Unknown arg: $1"; exit 1 ;;
  esac
done

log()  { echo "[$(date '+%T')] $*"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] || die "Run as root (sudo)"

# ── Shared: system packages ───────────────────────────────────────────────────
install_base_packages() {
  log "Installing base packages …"
  apt-get update -qq
  apt-get install -y --no-install-recommends \
    curl wget gnupg lsb-release software-properties-common \
    python3 python3-pip python3-venv \
    iptables sysstat net-tools jq
}

# ══════════════════════════════════════════════════════════════════════════════
# MANAGER MODE — install Wazuh Manager on VM3
# ══════════════════════════════════════════════════════════════════════════════
setup_manager() {
  log "=== Setting up Wazuh Manager (VM3) ==="

  # 1. Add Wazuh repository
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor \
    -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
    https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq

  # 2. Install Wazuh Manager + Indexer + Dashboard (single-node)
  log "Installing Wazuh Manager …"
  WAZUH_MANAGER_IP="$MANAGER_IP" apt-get install -y wazuh-manager

  # 3. Deploy custom rules
  log "Deploying GANDD custom rules …"
  cp "$REPO_ROOT/config/wazuh/rules.xml" \
     /var/ossec/etc/rules/local_rules.xml

  # 4. Patch ossec.conf with Active Response + global whitelist
  log "Patching ossec.conf …"
  # Insert GANDD active-response block before the closing </ossec_config> tag
  SNIPPET="$REPO_ROOT/config/wazuh/ossec.conf"
  # Extract only the <active-response> and <global> blocks (not the localfile blocks)
  python3 - "$SNIPPET" /var/ossec/etc/ossec.conf <<'PYEOF'
import sys, re

with open(sys.argv[1]) as fh:
    snippet = fh.read()

# Keep only active-response and global blocks from the snippet
keep = []
for block in re.findall(r'<active-response>.*?</active-response>|<global>.*?</global>',
                         snippet, re.DOTALL):
    keep.append(block)

with open(sys.argv[2]) as fh:
    cfg = fh.read()

insert = '\n'.join(keep) + '\n'
cfg = cfg.replace('</ossec_config>', insert + '</ossec_config>', 1)

with open(sys.argv[2], 'w') as fh:
    fh.write(cfg)
print("ossec.conf patched OK")
PYEOF

  # 5. Enable + start
  systemctl enable wazuh-manager
  systemctl restart wazuh-manager
  log "Wazuh Manager started. Check status: systemctl status wazuh-manager"
}

# ══════════════════════════════════════════════════════════════════════════════
# VICTIM MODE — install Suricata, Wazuh Agent, GANDD-Bridge on VM2
# ══════════════════════════════════════════════════════════════════════════════
setup_victim() {
  log "=== Setting up Victim stack (VM2) ==="

  # ── 1. Suricata ─────────────────────────────────────────────────────────────
  log "Installing Suricata …"
  add-apt-repository -y ppa:oisf/suricata-stable
  apt-get update -qq
  apt-get install -y suricata suricata-update

  # Update Emerging Threats ruleset
  suricata-update --no-reload || true

  # Patch suricata.yaml: enable flow events, set interface
  # Pass IFACE as argv[2] so bash variable expands correctly outside the heredoc
  python3 - /etc/suricata/suricata.yaml "$IFACE" <<'PYEOF'
import sys, re

with open(sys.argv[1]) as fh:
    cfg = fh.read()

iface = sys.argv[2]

# Ensure af-packet uses the correct VMware interface
cfg = re.sub(r'(af-packet:\s*\n\s*- interface:)\s*\S+', r'\1 ' + iface, cfg)

# Ensure flow events are enabled in eve-log
if 'flow' not in cfg[cfg.find('eve-log'):cfg.find('eve-log')+500]:
    cfg = cfg.replace(
        "        types:\n          - alert",
        "        types:\n          - flow\n          - alert\n          - http\n          - dns"
    )

with open(sys.argv[1], 'w') as fh:
    fh.write(cfg)
print(f"suricata.yaml patched OK (interface={iface})")
PYEOF

  systemctl enable suricata
  systemctl restart suricata
  log "Suricata started on $IFACE"

  # ── 2. Wazuh Agent ──────────────────────────────────────────────────────────
  log "Installing Wazuh Agent …"
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor \
    -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
    https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
  WAZUH_MANAGER="$MANAGER_IP" apt-get install -y wazuh-agent

  # Add GANDD and Suricata log monitors to agent ossec.conf
  log "Configuring Wazuh Agent log sources …"
  python3 - /var/ossec/etc/ossec.conf "$REPO_ROOT/config/wazuh/ossec.conf" <<'PYEOF'
import sys, re

with open(sys.argv[2]) as fh:
    snippet = fh.read()

# Keep only <localfile> blocks from the snippet
localfiles = re.findall(r'<localfile>.*?</localfile>', snippet, re.DOTALL)

with open(sys.argv[1]) as fh:
    cfg = fh.read()

insert = '\n'.join(localfiles) + '\n'
cfg = cfg.replace('</ossec_config>', insert + '</ossec_config>', 1)

with open(sys.argv[1], 'w') as fh:
    fh.write(cfg)
print("Agent ossec.conf patched OK")
PYEOF

  systemctl enable wazuh-agent
  systemctl restart wazuh-agent
  log "Wazuh Agent started → Manager at $MANAGER_IP"

  # ── 3. GANDD-Bridge Python environment ──────────────────────────────────────
  log "Setting up GANDD-Bridge Python environment …"
  python3 -m venv "$REPO_ROOT/venv"
  "$REPO_ROOT/venv/bin/pip" install -q --upgrade pip
  "$REPO_ROOT/venv/bin/pip" install -q \
    numpy pandas scikit-learn scipy

  # ── 4. GANDD-Bridge log directory ───────────────────────────────────────────
  mkdir -p /var/log/gandd
  touch /var/log/gandd/alerts.log
  chmod 644 /var/log/gandd/alerts.log

  # ── 5. GANDD-Bridge systemd service ──────────────────────────────────────────
  log "Installing GANDD-Bridge systemd service …"
  VENV_PYTHON="$REPO_ROOT/venv/bin/python3"

  cat > /etc/systemd/system/gandd-bridge.service <<EOF
[Unit]
Description=GANDD-Bridge ML DDoS Detection Middleware
After=network.target suricata.service
Requires=suricata.service

[Service]
Type=simple
User=root
ExecStart=${VENV_PYTHON} ${REPO_ROOT}/src/gandd_bridge.py \\
    --eve-log /var/log/suricata/eve.json \\
    --alert-log /var/log/gandd/alerts.log \\
    --model ${REPO_ROOT}/data/processed/rf_model.pkl \\
    --threshold 0.6
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable gandd-bridge
  log "GANDD-Bridge service installed (not started — train model first)"

  # ── 6. nginx for service degradation measurement ──────────────────────────
  log "Installing nginx …"
  apt-get install -y nginx
  systemctl enable nginx
  systemctl start nginx

  # ── 7. sysstat for resource monitoring ───────────────────────────────────
  apt-get install -y sysstat
  sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat || true
  systemctl enable sysstat
  systemctl start sysstat

  log ""
  log "=== VM2 setup complete ==="
  log "Next steps:"
  log "  1. Collect benign traffic: sudo tcpdump -i $IFACE -w data/raw/benign.pcap"
  log "  2. Extract features:       python src/preprocessing/feature_extraction.py"
  log "  3. Train RF model:         python src/train_rf.py"
  log "  4. Start GANDD-Bridge:     sudo systemctl start gandd-bridge"
  log "  5. Verify alerts:          tail -f /var/log/gandd/alerts.log"
}

# ── Main ──────────────────────────────────────────────────────────────────────
install_base_packages

case "$MODE" in
  manager) setup_manager ;;
  victim)  setup_victim  ;;
  *)       die "Unknown mode: $MODE (use victim|manager)" ;;
esac
