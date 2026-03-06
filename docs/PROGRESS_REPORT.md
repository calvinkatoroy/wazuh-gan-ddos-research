# Progress Report
**Project:** Evaluation of SIEM Wazuh Detection Effectiveness Against GAN-Based DDoS Attacks With and Without GANDD Integration
**Institution:** Universitas Indonesia — Computer Engineering
**Date:** 2026-03-07

---

## Team

| Name | NPM | Role |
|---|---|---|
| Reyhan Ahnaf Deannova | 2306267100 | Red Team Lead |
| Aidan Ardhazizi | 2406430483 | — |
| Calvin Wirathama Katoroy | 2306242395 | Blue Team Lead |
| Wesley Frederick Oh | 2306202763 | AI/ML Engineer |

---

## Phase Status

| Phase | Description | Status |
|---|---|---|
| 1 | VMware network + VM setup | Complete |
| 2 | Wazuh Manager on VM3 | Complete |
| 3 | Suricata + Wazuh Agent + GANDD-Bridge on VM2 | Complete |
| 4 | hping3 + repo clone on VM1 | Complete |
| 5 | RF model training | Pending — awaiting `rf_model.pkl` from Wesley |
| 6 | Smoke tests | Partially complete (see below) |
| 7 | Full experiment run (90 trials) | Pending |

---

## Blue Team Deliverables — Completed (Calvin)

### Infrastructure (VM2 + VM3)

- **VM2 (Victim):** Suricata v7.0 configured on `ens33`, writing flow + alert events to `eve.json`. Wazuh Agent registered as ID 001, connected to Manager. nginx running on port 80 for service degradation measurement.
- **VM3 (Manager):** Wazuh Manager v4.14.3 running. Custom detection rules deployed (`local_rules.xml`). Active Response configured with 60s and 300s timeout.
- **GANDD-Bridge:** Python middleware implemented (`src/gandd_bridge.py`). Tails `eve.json` in real-time, extracts 7 behavioral features, classifies flows using a trained RF model (heuristic fallback active until model is delivered). Writes `GANDD_ALERT` lines to `/var/log/gandd/alerts.log`.

### Wazuh Rules (`config/wazuh/rules.xml`)

| Rule ID | Level | Trigger | Action |
|---|---|---|---|
| 100200 | 12 | `GANDD_ALERT` match | firewall-drop (60s) |
| 100201 | 15 | confidence >= 0.90 | firewall-drop (300s) |
| 100202 | 12 | src_ip extracted from GANDD_ALERT | firewall-drop (60s) |
| 100210 | 12 | Suricata ET DROP | firewall-drop (60s) |
| 100211 | 12 | Suricata Attempted DoS | firewall-drop (60s) |
| 100212 | 12 | Suricata Misc Attack priority 1/2 | firewall-drop (60s) |

### Fixes Applied (2026-03-07)

1. **Suricata rule 9000001** — Added `flow:to_server,stateless` to suppress direction warning and ensure rule loads cleanly.
2. **Wazuh decoder** — Added `gandd-alert` decoder to `local_decoder.xml` on VM3 with `<regex>src_ip=(\S+) </regex>` to correctly extract the full IPv4 address as `srcip`.
3. **Active Response** — Added rule `100202` to `firewall-drop` active response config. Previously only rules 100200 and 100201 were listed; since Wazuh fires the child rule (100202) rather than the parent when both match, the active response was never triggered.

---

## Smoke Test Results (2026-03-07)

| Test | Description | Result |
|---|---|---|
| Connectivity | VM1 ↔ VM2 ↔ VM3 ping | Pass |
| Services | Suricata, Wazuh Agent, Wazuh Manager all active | Pass |
| Agent registration | Agent 001 shows Active on VM3 | Pass |
| eve.json output | Suricata writes flow events on live traffic | Pass |
| Suricata rule 9000001 | Loads without warning after fix | Pass |
| Wazuh Agent log monitoring | Both `eve.json` and `alerts.log` monitored | Pass |
| GANDD-Bridge startup | Starts with heuristic fallback (no model yet) | Pass |
| GANDD alert → VM3 | Alert reaches VM3, rule 100202 fires, `data.srcip` extracted correctly | Pass |
| Active response (firewall-drop) | `iptables DROP` rule added for `192.168.100.50` after GANDD alert | Pass |
| End-to-end with RF model | Not yet testable — pending `rf_model.pkl` | Pending |

---

## Pending — Waiting on Team Members

### Wesley Frederick Oh (AI/ML Engineer)

Deliverable: `data/processed/rf_model.pkl`

The RF model must be a scikit-learn `RandomForestClassifier` serialized with `pickle`. It must accept the following 7-feature input vector in this exact order:

```
["pkt_count", "byte_ratio", "pkt_rate", "iat_var", "size_var", "entropy", "syn_ratio"]
```

`model.predict_proba(X)` must return `[P(benign), P(attack)]` with class index 1 = attack.

Once delivered, drop the file to `data/processed/rf_model.pkl` on VM2 and restart the service:
```bash
sudo systemctl restart gandd-bridge
```

### Reyhan Ahnaf Deannova (Red Team Lead)

Deliverables:
- VM1 fully configured with `gan_attack_sim.py` at `/opt/gandd-research/src/gan/gan_attack_sim.py`
- SSH key from VM2 authorized on VM1 root account (required for `run_experiment.sh` to trigger attacks remotely)
- Confirmation that Type 1 (hping3 --flood), Type 2 (low-rate hping3), and Type 3 (gan_attack_sim.py) attacks can be launched from VM1

---

## Next Steps (in order)

1. **Wesley delivers `rf_model.pkl`** → drop to `data/processed/` on VM2 → restart gandd-bridge → re-run smoke test end-to-end with fixed-IP attack
2. **Ahnaf confirms VM1 ready** → set up passwordless SSH from VM2 to VM1 → test `run_experiment.sh --scenario 1A --trials 1`
3. **Execute full experiment** → `run_experiment.sh --scenario all` → 90 trials, results in `data/results/`
4. **Analysis** → `src/analysis/evaluate.py` → DR, FPR, latency, Cohen's d per scenario pair
5. **Paper** → fill in Chapter 4 (Results) and Chapter 5 (Discussion/Conclusion)

---

## Repository

**URL:** https://github.com/calvinkatoroy/wazuh-gan-ddos-research

**Key files:**

| File | Description |
|---|---|
| `src/gandd_bridge.py` | GANDD-Bridge middleware |
| `src/train_rf.py` | RF model training script |
| `src/preprocessing/feature_extraction.py` | Feature extraction from eve.json |
| `src/analysis/evaluate.py` | Evaluation metrics (DR, FPR, latency) |
| `config/wazuh/rules.xml` | Custom Wazuh detection rules |
| `config/wazuh/ossec.conf` | Manager configuration with active response |
| `config/wazuh/local_decoder.xml` | GANDD alert decoder |
| `config/suricata/local.rules` | Custom Suricata rule for lab traffic |
| `scripts/setup_wazuh.sh` | Automated VM2/VM3 deployment script |
| `scripts/run_experiment.sh` | Automated 90-trial experiment runner |
| `docs/BLUE_TEAM_DEPLOYMENT.md` | Step-by-step deployment guide |
| `docs/paper/` | LaTeX paper source (IEEEtran format) |