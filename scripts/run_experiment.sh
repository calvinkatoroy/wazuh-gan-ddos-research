#!/usr/bin/env bash
# run_experiment.sh — Automate GANDD-Bridge 2×3 experimental trials
#
# Runs the 6 scenarios (3 attack types × 2 configurations) with 15 trials each
# for a total of 90 trials. Logs all data to data/results/.
#
# Run on VM2 (Victim) as root. VM1 (Attacker) must be reachable.
#
# Usage:
#   sudo bash scripts/run_experiment.sh [options]
#
#   --scenario    1A|1B|2A|2B|3A|3B|all   (default: all)
#   --trials      N                         (default: 15)
#   --duration    N_seconds                 (default: 300 = 5 min)
#   --attacker    IP                        (default: 192.168.100.50)
#   --victim      IP                        (default: 192.168.100.100)
#
# Blue Team component — Calvin Wirathama Katoroy (2306242395)

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
SCENARIO="all"
TRIALS=15
DURATION=300          # seconds per trial
BASELINE_DURATION=120 # benign baseline recording before each trial
ATTACKER_IP="192.168.100.50"
VICTIM_IP="192.168.100.100"
RESULTS_DIR="data/results"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_TS="$(date '+%Y%m%d_%H%M%S')"

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario)  SCENARIO="$2";    shift 2 ;;
    --trials)    TRIALS="$2";      shift 2 ;;
    --duration)  DURATION="$2";    shift 2 ;;
    --attacker)  ATTACKER_IP="$2"; shift 2 ;;
    --victim)    VICTIM_IP="$2";   shift 2 ;;
    *)           echo "Unknown arg: $1"; exit 1 ;;
  esac
done

log() { echo "[$(date '+%T')] $*" | tee -a "$RESULTS_DIR/experiment_${LOG_TS}.log"; }
die() { echo "[ERROR] $*" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] || die "Run as root (sudo)"

mkdir -p "$RESULTS_DIR"

# ── Helpers ───────────────────────────────────────────────────────────────────

enable_gandd() {
  systemctl start gandd-bridge 2>/dev/null || true
  sleep 2
  log "GANDD-Bridge: ENABLED"
}

disable_gandd() {
  systemctl stop gandd-bridge 2>/dev/null || true
  log "GANDD-Bridge: DISABLED"
}

reset_state() {
  # Flush any iptables rules left by previous Active Response
  iptables -F INPUT 2>/dev/null || true
  # Rotate Wazuh alert log so trial boundaries are clear
  cp /var/ossec/logs/alerts/alerts.json \
     "$RESULTS_DIR/wazuh_alerts_${SCENARIO}_trial_${TRIAL_NUM}_pre.json" 2>/dev/null || true
  > /var/log/gandd/alerts.log
  log "State reset: iptables flushed, logs rotated"
}

record_baseline() {
  log "Recording ${BASELINE_DURATION}s benign baseline …"
  local out="$RESULTS_DIR/${SCENARIO}_trial_${TRIAL_NUM}_baseline.sar"
  sar -n DEV 1 "$BASELINE_DURATION" > "$out" 2>/dev/null &
  sleep "$BASELINE_DURATION"
  log "Baseline recorded → $out"
}

start_resource_monitor() {
  local out="$RESULTS_DIR/${SCENARIO}_trial_${TRIAL_NUM}_resources.sar"
  sar -u -r -n DEV 1 "$DURATION" > "$out" 2>/dev/null &
  MONITOR_PID=$!
  log "Resource monitor started (PID $MONITOR_PID) → $out"
}

stop_resource_monitor() {
  kill "$MONITOR_PID" 2>/dev/null || true
}

collect_wazuh_alerts() {
  local out="$RESULTS_DIR/${SCENARIO}_trial_${TRIAL_NUM}_wazuh_alerts.json"
  cp /var/ossec/logs/alerts/alerts.json "$out" 2>/dev/null || touch "$out"
  log "Wazuh alerts → $out"
}

collect_suricata_flows() {
  local out="$RESULTS_DIR/${SCENARIO}_trial_${TRIAL_NUM}_eve.json"
  cp /var/log/suricata/eve.json "$out" 2>/dev/null || touch "$out"
  log "Suricata eve.json → $out"
}

collect_gandd_alerts() {
  local out="$RESULTS_DIR/${SCENARIO}_trial_${TRIAL_NUM}_gandd_alerts.log"
  cp /var/log/gandd/alerts.log "$out" 2>/dev/null || touch "$out"
  log "GANDD alerts → $out"
}

measure_service_response() {
  # Ping nginx and record response time during attack
  local out="$RESULTS_DIR/${SCENARIO}_trial_${TRIAL_NUM}_http_response.csv"
  echo "time,status,latency_ms" > "$out"
  local end_ts=$(( $(date +%s) + DURATION ))
  while [[ $(date +%s) -lt $end_ts ]]; do
    local start_ms=$(date +%s%3N)
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" \
             --max-time 5 "http://${VICTIM_IP}/" 2>/dev/null || echo "000")
    local end_ms=$(date +%s%3N)
    local latency=$(( end_ms - start_ms ))
    echo "$(date '+%T'),$status,$latency" >> "$out"
    sleep 1
  done &
  HTTP_MONITOR_PID=$!
}

stop_http_monitor() {
  kill "$HTTP_MONITOR_PID" 2>/dev/null || true
}

signal_attacker() {
  # Signal VM1 to launch an attack by writing to a shared trigger file via SSH
  # (assumes passwordless SSH key auth from VM2 to VM1)
  local attack_type="$1"
  log "Signalling VM1 ($ATTACKER_IP) to launch attack type: $attack_type"

  case "$attack_type" in
    volumetric)
      ssh -o StrictHostKeyChecking=no root@"$ATTACKER_IP" \
        "nohup hping3 -S -p 80 --flood --rand-source $VICTIM_IP > /tmp/attack.log 2>&1 &
         echo \$! > /tmp/attack.pid" || log "[WARN] Could not SSH to attacker"
      ;;
    low-rate)
      ssh -o StrictHostKeyChecking=no root@"$ATTACKER_IP" \
        "nohup hping3 -S -p 80 --rand-source -i u10000 $VICTIM_IP > /tmp/attack.log 2>&1 &
         echo \$! > /tmp/attack.pid" || log "[WARN] Could not SSH to attacker"
      ;;
    adversarial)
      ssh -o StrictHostKeyChecking=no root@"$ATTACKER_IP" \
        "cd /opt/gandd-research && nohup python3 src/gan/gan_attack_sim.py \
         --target $VICTIM_IP --port 80 --duration $DURATION \
         > /tmp/attack.log 2>&1 & echo \$! > /tmp/attack.pid" \
        || log "[WARN] Could not SSH to attacker"
      ;;
  esac
}

stop_attacker() {
  log "Stopping attack on VM1 …"
  ssh -o StrictHostKeyChecking=no root@"$ATTACKER_IP" \
    "kill \$(cat /tmp/attack.pid 2>/dev/null) 2>/dev/null; rm -f /tmp/attack.pid" \
    || log "[WARN] Could not stop attacker"
}

verify_active_response() {
  local out="$RESULTS_DIR/${SCENARIO}_trial_${TRIAL_NUM}_iptables.txt"
  iptables -L INPUT -n --line-numbers > "$out" 2>/dev/null || true
  if grep -q "$ATTACKER_IP" "$out" 2>/dev/null; then
    log "Active Response CONFIRMED: $ATTACKER_IP blocked in iptables"
  else
    log "[WARN] Active Response NOT detected in iptables"
  fi
}

# ── Single trial ──────────────────────────────────────────────────────────────

run_trial() {
  local scenario="$1"   # e.g. "1A"
  local trial="$2"      # 1-15
  TRIAL_NUM="${scenario}_t${trial}"

  log ""
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "SCENARIO $scenario  |  TRIAL $trial / $TRIALS"
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  local attack_type config
  case "$scenario" in
    1?) attack_type="volumetric"  ;;
    2?) attack_type="low-rate"    ;;
    3?) attack_type="adversarial" ;;
    *)  die "Unknown scenario: $scenario" ;;
  esac
  case "$scenario" in
    ?A) config="without-gandd" ;;
    ?B) config="with-gandd"    ;;
    *)  die "Unknown scenario: $scenario" ;;
  esac

  # 1. Setup
  [[ "$config" == "with-gandd" ]] && enable_gandd || disable_gandd
  reset_state

  # 2. Benign baseline
  record_baseline

  # 3. Launch attack phase
  log "Starting attack: type=$attack_type  duration=${DURATION}s"
  start_resource_monitor
  measure_service_response
  signal_attacker "$attack_type"

  # 4. Wait for attack duration
  sleep "$DURATION"

  # 5. Stop attack + monitors
  stop_attacker
  sleep 5   # allow final alerts to propagate
  stop_resource_monitor
  stop_http_monitor

  # 6. Collect results
  collect_wazuh_alerts
  collect_suricata_flows
  [[ "$config" == "with-gandd" ]] && collect_gandd_alerts
  verify_active_response

  # 7. Recovery — wait for service to recover
  log "Waiting 30s for service recovery …"
  iptables -F INPUT 2>/dev/null || true
  sleep 30

  log "Trial $scenario/$trial complete"
}

# ── Scenario runner ───────────────────────────────────────────────────────────

run_scenario() {
  local s="$1"
  log ""
  log "╔══════════════════════════════╗"
  log "║  SCENARIO $s (${TRIALS} trials)        ║"
  log "╚══════════════════════════════╝"
  for trial in $(seq 1 "$TRIALS"); do
    run_trial "$s" "$trial"
  done
  log "Scenario $s: all $TRIALS trials complete"
}

# ── Main ──────────────────────────────────────────────────────────────────────

log "Experiment run started: $LOG_TS"
log "  Scenario : $SCENARIO"
log "  Trials   : $TRIALS"
log "  Duration : ${DURATION}s per trial"
log "  Attacker : $ATTACKER_IP"
log "  Victim   : $VICTIM_IP"

if [[ "$SCENARIO" == "all" ]]; then
  for s in 1A 1B 2A 2B 3A 3B; do
    run_scenario "$s"
  done
else
  run_scenario "$SCENARIO"
fi

log ""
log "All experiments complete. Results in: $RESULTS_DIR/"
log "Run analysis: python notebooks/03_evaluation.ipynb"
