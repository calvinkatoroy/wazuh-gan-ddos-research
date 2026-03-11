# CLAUDE.md — Project Context for Claude Code

## Project
**Evaluation of SIEM Wazuh Detection Against GAN-Based DDoS Attacks**
Author: Calvin Wirathama Katoroy (2306242395) — Blue Team Lead

## Team
| Name | NPM | Role |
|---|---|---|
| Reyhan Ahnaf Deannova | 2306267100 | Red Team Lead |
| Aidan Ardhazizi | 2406430483 | — |
| Calvin Wirathama Katoroy | 2306242395 | Blue Team Lead |
| Wesley Frederick Oh | 2306202763 | AI/ML Engineer |

## Testbed VMs (VMware Workstation Pro 17)
| VM | Role | OS | IP |
|---|---|---|---|
| VM1 | Attacker | Kali Linux | 192.168.100.50 |
| VM2 | Victim | Ubuntu 22.04 | 192.168.100.100 |
| VM3 | SIEM Manager | Ubuntu 22.04 | 192.168.100.10 |

- Network: VMnet2 (Host-only, 192.168.100.0/24) + NAT adapter for internet
- VM2 NIC: `ens33` (lab), `ens37` (NAT)
- VM3 NIC: `ens33` (lab), `ens37` (NAT)
- VM1 NIC: `eth0` (lab, static 192.168.100.50), `eth1` (NAT)

## Current Setup Status
- [x] Phase 1: Static IPs set on all VMs, connectivity VM2↔VM3 verified
- [x] Phase 2: Wazuh Manager installed on VM3 (v4.14.3), rules deployed, active response configured
- [x] Phase 3: Suricata + Wazuh Agent installed on VM2, agent registered (ID 001)
- [x] Phase 4: hping3 on VM1, repo cloned; `gan_attack_sim.py` deployed to VM1
- [x] Phase 5: RF model (`rf_model.pkl`) received from Wesley, deployed to VM2 ✅
- [x] Phase 6: End-to-end smoke test PASSED with RF model (2026-03-11)
- [ ] Phase 7: Full experiment run — 90 trials (pending Ahnaf VM1 passwordless SSH)

## Fixes Applied (2026-03-11)

### Wazuh Agent Bottleneck
- Root cause: Default 500 EPS agent buffer overflows during flood → AR delayed until after attack
- Fix 1: Suricata SID 9000001 — added `threshold:type limit,track by_src,count 1,seconds 30`
- Fix 2: Wazuh agent `client_buffer` on VM2 — `queue_size=100000`, `events_per_second=1000`
- File: `/var/ossec/etc/ossec.conf` on VM2 (appended `<client_buffer>` block)
- Repo: `config/suricata/local.rules`

### Suricata TCP Flow Timeout
- Changed `tcp: new: 60` → `tcp: new: 5` in `/etc/suricata/suricata.yaml` on VM2
- Allows GANDD-Bridge to see SYN flood flows within 5s instead of 60s

### GANDD-Bridge False Positive Filters
All filters applied in `src/gandd_bridge.py` (committed to repo):
- Skip non-TCP/UDP protocols (was triggering on IPv6-ICMP neighbor discovery)
- Skip IPv6 source addresses (mDNS flows)
- Skip DNS traffic (dest_port 53)
- Skip multicast destinations (224.x, 239.x) — SSDP/UPnP
- Skip broadcast destinations (.255) — NetBIOS/LLMNR
- Skip VMware host adapter (src_ip 192.168.100.1)
- Skip single-packet flows (pkts_toserver < 2)

### Model Loading Fix
- Switched `pickle.load()` → `joblib.load()` in GANDD-Bridge
- Root cause: Wesley's model saved with `joblib.dump()`, incompatible with raw pickle

### Suricata Unix Socket
- Socket dir missing → `suricatasc` commands fail
- Fix: `sudo mkdir -p /var/run/suricata && sudo chown suricata:suricata /var/run/suricata`

## Smoke Test Results (2026-03-11) ✅ FULL PASS
- RF model loaded: `/opt/gandd-research/data/processed/rf_model.pkl` (2.7MB) ✅
- GANDD-Bridge running in RF mode (confidence ~0.75-0.97) ✅
- Type 1 flood (hping3): detected within 5-10s, AR blocks 192.168.100.50 ✅
- No false positives during idle (no attack) ✅
- Type 3 adversarial (gan_attack_sim.py + --rand-source): NOT detected — expected, evades per-src-IP classification ✅ (research finding)

## Known Issues / Gotchas
- **VM2 DNS broken**: `systemd-resolved` disabled, `/etc/resolv.conf` set to 8.8.8.8 but ens37 NAT not routing. Fix: restart VMware NAT Service from Windows host, then `sudo ip route del default via 192.168.100.1 dev ens33` on VM2
- **VM1 internet**: needs `sudo ip route del default via 192.168.100.1 dev eth0` to use NAT for git pull
- **VM2 gandd_bridge.py**: manually patched (not git-pulled) — matches repo at commit `5de016c`. When DNS fixed, do `sudo git pull` on VM2
- **AR duplicate aborts**: normal — Wazuh queues multiple alerts from flood, processes 1/min, each aborts because IP already blocked. Only first `firewall-drop: Starting` (non-abort) matters for latency measurement
- **Suricata socket**: `/var/run/suricata/` dir needs to exist for `suricatasc` to work

## Key File Locations

### On VM3 (Manager)
- Rules: `/var/ossec/etc/rules/local_rules.xml`
- Config: `/var/ossec/etc/ossec.conf`
- Decoder: `/var/ossec/etc/decoders/local_decoder.xml`
- Alerts: `/var/ossec/logs/alerts/alerts.json`
- Active response log: `/var/ossec/logs/active-responses.log`

### On VM2 (Victim)
- Suricata config: `/etc/suricata/suricata.yaml`
- Suricata rules: `/var/lib/suricata/rules/suricata.rules`
- Eve log: `/var/log/suricata/eve.json`
- GANDD alerts: `/var/log/gandd/alerts.log`
- RF model: `/opt/gandd-research/data/processed/rf_model.pkl`
- Custom AR script: `/var/ossec/active-response/bin/suricata-firewall-drop`
- Wazuh agent config: `/var/ossec/etc/ossec.conf`
- GANDD-Bridge service: `sudo systemctl start gandd-bridge`

### On VM1 (Attacker)
- Attack scripts: `/opt/gandd-research/src/gan/gan_attack_sim.py`
- Dataset: `/opt/gandd-research/data/raw/synthetic_cicddos2019.csv`

### Repo on VMs
- `/opt/gandd-research/` on VM2 and VM3

## Wazuh Rules (local_rules.xml)
- 100200 (lvl 12): GANDD_ALERT match → firewall-drop 60s
- 100201 (lvl 15): GANDD confidence >= 0.90 → firewall-drop 300s
- 100202 (lvl 12): GANDD src_ip extracted → firewall-drop 60s ← AR triggers here
- 100210 (lvl 12): Suricata ET DROP
- 100211 (lvl 12): Suricata Attempted DoS
- 100212 (lvl 12): Suricata Misc Attack priority 1/2

## Active Response Config (ossec.conf on VM3)
- `firewall-drop` → rules 100200, 100201, 100202, 100210, 100211, 100212
- `suricata-firewall-drop` → rules 100210, 100211, 100212 (custom script for Suricata srcip)
- Whitelist: 192.168.100.10 (VM3), 127.0.0.1

## Research Design
- **Config A (Baseline):** Wazuh + Suricata only, no GANDD-Bridge
- **Config B (Enhanced):** + GANDD-Bridge ML middleware
- 2×3 matrix: 3 attack types × 2 configs = 6 scenarios × 15 trials = 90 total
- Attack types: Volumetric (hping3 --flood), Low-rate, Adversarial (gan_attack_sim.py)
- Metrics: Detection Rate, Latency, FPR — compared with paired t-test, Cohen's d

## Key Research Findings (so far)
1. Wazuh agent buffer overflow during flood invalidates real-time AR — fixed via Suricata thresholding
2. Config B (GANDD-Bridge) is architecturally immune to the bottleneck — reads flow records not per-packet alerts
3. Type 3 adversarial (--rand-source) evades both configs — per-src-IP classification breaks under spoofed sources
4. FP sources: IPv6 NDP, mDNS, SSDP/UPnP, NetBIOS from VMware host adapter — all filtered

## Next Steps
1. Fix VM2 internet (restart VMware NAT Service) → `sudo git pull` on VM2
2. Set up passwordless SSH from VM2 root → VM1 root (needed for `run_experiment.sh`)
3. Confirm Ahnaf: Type 1, 2, 3 attacks launchable from VM1
4. Test single trial: `sudo bash scripts/run_experiment.sh --scenario 1B --trials 1`
5. Execute full experiment: `sudo bash scripts/run_experiment.sh --scenario all`
