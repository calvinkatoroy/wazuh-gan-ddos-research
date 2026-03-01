# Blue Team Deployment & Testing Guide

**Author:** Calvin Wirathama Katoroy (2306242395)
**Role:** Blue Team Lead — GANDD-Bridge Implementation
**Project:** Evaluation of SIEM Wazuh Detection Against GAN-Based DDoS Attacks
**Hypervisor:** VMware Workstation Pro 17

---

## Overview

```
Phase 1: VMware network + VM setup
Phase 2: VM3 (Manager)  — Wazuh Manager installation
Phase 3: VM2 (Victim)   — Suricata + Wazuh Agent + GANDD-Bridge
Phase 4: VM1 (Attacker) — hping3 + repo clone
Phase 5: RF model training (collect traffic → extract features → train)
Phase 6: Smoke tests (local and on-VM)
Phase 7: Full experiment run
```

---

## Phase 1: VMware Network Setup

### 1.1 Create a Custom Host-Only Network

VMware's Virtual Network Editor lets you create a private subnet shared only between VMs — equivalent to VirtualBox's NAT Network but with more control.

1. Open **VMware Workstation Pro**
2. Go to **Edit → Virtual Network Editor**
3. Click **Add Network…** → select an unused VMnet (e.g. `VMnet2`)
4. Set it to **Host-only**
5. Uncheck **Use local DHCP service** (you'll assign static IPs manually)
6. Set **Subnet IP** to `192.168.100.0` and **Subnet mask** to `255.255.255.0`
7. Click **Apply → OK**

> **Why Host-only?** The VMs can only talk to each other and the host machine — not the internet. This isolates attack traffic to the lab, which is required for the experiment. Add a second NAT adapter temporarily when you need internet for package installation.

### 1.2 Create the Three VMs

| VM | Role | OS | vCPUs | RAM | Disk | IP to assign |
|---|---|---|---|---|---|---|
| VM1 | Attacker | Kali Linux 2025.x | 2 | 4 GB | 30 GB | 192.168.100.50 |
| VM2 | Victim | Ubuntu 22.04 LTS | 4 | 8 GB | 50 GB | 192.168.100.100 |
| VM3 | SIEM Manager | Ubuntu 22.04 LTS | 4 | 8 GB | 80 GB | 192.168.100.10 |

For each VM:

1. Open VM Settings → **Network Adapter**
2. Set **Network connection** to **Custom: Specific virtual network → VMnet2**
3. To allow internet during initial setup, click **Add…** → Network Adapter → **NAT** (remove this adapter after setup is done)

### 1.3 Install VMware Tools on VM2 and VM3

After booting Ubuntu, run:

```bash
sudo apt-get install -y open-vm-tools open-vm-tools-desktop
```

This improves clipboard sharing, display scaling, and network stability inside VMware.

### 1.4 Set Static IPs

> **VMware NIC name:** Ubuntu 22.04 running in VMware typically names the first adapter `ens33`. Confirm yours with `ip link show`.

**On VM2** — edit `/etc/netplan/00-installer-config.yaml`:

```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: no
      addresses: [192.168.100.100/24]
      gateway4: 192.168.100.1
      nameservers:
        addresses: [8.8.8.8]
```

**On VM3** — same file, use `192.168.100.10/24`

**On VM1 (Kali)** — use `nmtui` (Network Manager TUI) or edit `/etc/network/interfaces`:

```bash
iface ens33 inet static
  address 192.168.100.50
  netmask 255.255.255.0
  gateway 192.168.100.1
```

Apply on Ubuntu VMs:

```bash
sudo netplan apply
```

### 1.5 Verify Connectivity

From VM2, ping all others:

```bash
ping -c 3 192.168.100.10   # VM3 must respond
ping -c 3 192.168.100.50   # VM1 must respond
```

---

## Phase 2: VM3 — Wazuh Manager

> **Note:** Wazuh 4.9 requires the full stack (Manager + Indexer + Dashboard) for the web UI.
> Two options are provided — Option A is recommended.

### Option A — Full Stack via Official Wazuh Installer (Recommended)

SSH into VM3 (or open a terminal in the VM), then:

```bash
# Clone your repo
git clone <your-repo-url> /opt/gandd-research
cd /opt/gandd-research

# Download Wazuh's official install assistant
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.9/config.yml

# Edit config.yml — set the node IP to your VM3 address
nano config.yml
# Change:  ip: "<indexer-node-ip>"  →  ip: "192.168.100.10"

sudo bash wazuh-install.sh -a   # all-in-one install, takes 5–10 min
# Save the admin password printed at the end
```

### Option B — Manager Package Only

```bash
sudo bash /opt/gandd-research/scripts/setup_wazuh.sh --mode manager
```

### 2.1 Deploy GANDD Custom Rules

```bash
sudo cp /opt/gandd-research/config/wazuh/rules.xml \
        /var/ossec/etc/rules/local_rules.xml

# Validate the XML is correct
sudo /var/ossec/bin/wazuh-logtest -t < /dev/null
```

### 2.2 Patch ossec.conf with Active Response

Open `/var/ossec/etc/ossec.conf` and add these blocks **before** `</ossec_config>`:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100200</rules_id>
  <timeout>60</timeout>
</active-response>

<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100201</rules_id>
  <timeout>300</timeout>
</active-response>

<global>
  <white_list>192.168.100.10</white_list>
  <white_list>127.0.0.1</white_list>
</global>
```

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager   # must show "active (running)"
```

---

## Phase 3: VM2 — Victim Stack

### 3.1 Clone Repo and Run Setup Script

```bash
git clone <your-repo-url> /opt/gandd-research
cd /opt/gandd-research

# --iface ens33 is the VMware default — confirm with: ip link show
sudo bash scripts/setup_wazuh.sh --mode victim \
  --manager-ip 192.168.100.10 \
  --iface ens33
```

This installs: Suricata 7.0 (configured for `ens33`), Wazuh Agent, nginx, sysstat, and GANDD-Bridge as a systemd service. Takes ~5 minutes.

> If your NIC is named differently (e.g. `ens160` or `eth0`), find it with `ip link show` and pass it via `--iface`.

### 3.2 Register Wazuh Agent with the Manager

**On VM3:**

```bash
sudo /var/ossec/bin/manage_agents
# A  → add agent
# Name: vm2-victim
# IP:   192.168.100.100
# ID:   accept default (e.g. 001)
# E  → extract key → copy the full key string
```

**On VM2:**

```bash
sudo /var/ossec/bin/manage_agents
# I  → import key → paste key from VM3
sudo systemctl restart wazuh-agent
```

**Verify on VM3:**

```bash
sudo /var/ossec/bin/agent_control -l
# Agent 001 must show as "Active"
```

### 3.3 Set Up SSH Key Auth from VM2 to VM1

The experiment script triggers attacks on VM1 via SSH. Passwordless auth is required:

```bash
# On VM2:
sudo ssh-keygen -t ed25519 -f /root/.ssh/id_gandd -N ""
sudo ssh-copy-id -i /root/.ssh/id_gandd.pub root@192.168.100.50

# Test:
sudo ssh -i /root/.ssh/id_gandd root@192.168.100.50 "echo OK"
```

---

## Phase 4: VM1 — Attacker Setup

```bash
# hping3 is pre-installed on Kali — verify:
hping3 --version

# Clone repo (for gan_attack_sim.py)
git clone <your-repo-url> /opt/gandd-research

# Install Python deps for attack sim
pip3 install scapy numpy scipy
```

---

## Phase 5: RF Model Training

The RF model must be trained before GANDD-Bridge can perform ML classification.
Until a model exists it runs on the heuristic fallback, which is less accurate.

### 5.1 Collect Benign Traffic (on VM2)

Verify Suricata is running and writing flow events:

```bash
sudo systemctl status suricata
sudo tail -f /var/log/suricata/eve.json | grep '"event_type":"flow"'
```

Generate normal HTTP traffic for 5–10 minutes:

```bash
for i in $(seq 1 200); do
  curl -s http://192.168.100.100/ > /dev/null
  sleep 1
done
```

Save the benign eve.json:

```bash
sudo cp /var/log/suricata/eve.json \
        /opt/gandd-research/data/raw/benign_eve.json
```

### 5.2 Collect Attack Traffic (on VM2)

From **VM1**, run a brief hping3 attack for 2–3 minutes:

```bash
# VM1:
sudo hping3 -S -p 80 --rand-source 192.168.100.100 -i u1000 &
sleep 180
sudo kill %1
```

Back on **VM2**, save the attack-period eve.json:

```bash
sudo cp /var/log/suricata/eve.json \
        /opt/gandd-research/data/raw/attack_eve.json
```

### 5.3 Extract Features and Train the Model

```bash
cd /opt/gandd-research
source venv/bin/activate

# Extract labelled features from both eve.json files
python -m src.preprocessing.feature_extraction \
  --benign data/raw/benign_eve.json \
  --attack data/raw/attack_eve.json \
  --output data/processed/features.csv

# Check row count (should be hundreds to thousands)
wc -l data/processed/features.csv

# Train the Random Forest
python src/train_rf.py \
  --data       data/processed/features.csv \
  --model-out  data/processed/rf_model.pkl \
  --scaler-out data/processed/scaler.pkl
```

Expected output includes: Accuracy, F1, AUC-ROC, DR, FPR, confusion matrix, feature importances.

### 5.4 Start GANDD-Bridge

```bash
sudo systemctl start gandd-bridge
sudo systemctl status gandd-bridge   # must show "active (running)"

# Watch live alerts:
sudo tail -f /var/log/gandd/alerts.log
```

---

## Phase 6: Smoke Tests

Run these to verify each component before the full experiment. Tests 1 and 2 can be run on any machine — even Windows — before the VMs are ready.

### Test 1 — Feature Extraction Produces Valid Output

```bash
cd /opt/gandd-research
source venv/bin/activate

python -c "
from src.preprocessing.feature_extraction import extract_from_eve_json
df = extract_from_eve_json('data/raw/benign_eve.json', label=0)
print('Rows:', len(df))
print(df[['pkt_count','byte_ratio','pkt_rate','syn_ratio']].describe())
"
```

**Expected:** Non-zero row count, sensible ranges (pkt_count ≥ 1, syn_ratio ∈ [0, 1]).

---

### Test 2 — GANDD-Bridge Classifies a Mock Flow Correctly

Create a small mock eve.json with one obvious attack flow and one benign flow:

```bash
cat > /tmp/test_eve.json << 'EOF'
{"timestamp":"2024-01-15T10:00:00.000000+0000","event_type":"flow","src_ip":"192.168.100.50","dest_ip":"192.168.100.100","dest_port":80,"proto":"TCP","flow":{"pkts_toserver":5000,"bytes_toserver":320000,"bytes_toclient":1000,"start":"2024-01-15T10:00:00.000000+0000","end":"2024-01-15T10:00:05.000000+0000"},"tcp":{"syn":true}}
{"timestamp":"2024-01-15T10:00:01.000000+0000","event_type":"flow","src_ip":"10.0.0.1","dest_ip":"192.168.100.100","dest_port":80,"proto":"TCP","flow":{"pkts_toserver":3,"bytes_toserver":180,"bytes_toclient":4200,"start":"2024-01-15T10:00:00.000000+0000","end":"2024-01-15T10:00:00.500000+0000"},"tcp":{"syn":false}}
EOF
```

Run the classifier against it:

```bash
cd /opt/gandd-research
source venv/bin/activate

python - << 'EOF'
import json, sys
sys.path.insert(0, 'src')
from gandd_bridge import extract_features, RFDiscriminator

clf = RFDiscriminator("data/processed/rf_model.pkl", threshold=0.6)

with open("/tmp/test_eve.json") as f:
    for line in f:
        ev = json.loads(line.strip())
        if ev.get("event_type") == "flow":
            features = extract_features(ev)
            is_attack, score = clf.predict(features)
            print(f"src={ev['src_ip']}  score={score:.4f}  attack={is_attack}")
EOF
```

**Expected:**
```
src=192.168.100.50  score=0.xxxx  attack=True    ← high-rate SYN flood detected
src=10.0.0.1        score=0.xxxx  attack=False   ← normal small flow
```

---

### Test 3 — Wazuh Rule 100200 Fires

On **VM2**, manually inject a fake GANDD_ALERT into the log file:

```bash
echo "GANDD_ALERT timestamp=2024-01-15T10:00:00 src_ip=192.168.100.50 dest_ip=192.168.100.100 dest_port=80 proto=TCP confidence=0.8500" \
  | sudo tee -a /var/log/gandd/alerts.log
```

Wait 10–15 seconds, then on **VM3**:

```bash
sudo grep "100200\|GANDD" /var/ossec/logs/alerts/alerts.json | tail -20
```

**Expected:** A JSON alert entry containing `rule.id: 100200`.

---

### Test 4 — Active Response Blocks the IP

After Test 3 triggers Rule 100200, check iptables on **VM2**:

```bash
sudo iptables -L INPUT -n | grep 192.168.100.50
```

**Expected:** A `DROP` rule for `192.168.100.50`. Clears automatically after 60 seconds.

If nothing appears, debug on VM3:

```bash
sudo tail -100 /var/ossec/logs/active-responses.log
```

---

### Test 5 — End-to-End Single Trial (Manual)

Confirms the full pipeline before running the automated script.

```bash
# VM2 — start monitoring
sudo systemctl start gandd-bridge
sudo tail -f /var/log/gandd/alerts.log &
TAIL_PID=$!

# VM1 — 60-second attack
sudo hping3 -S -p 80 --flood --rand-source 192.168.100.100 &
ATTACK_PID=$!
sleep 60
sudo kill $ATTACK_PID

# VM2 — check results
kill $TAIL_PID
sudo grep "GANDD_ALERT" /var/log/gandd/alerts.log | wc -l   # must be > 0
sudo iptables -L INPUT -n                                    # must show DROP rule

# VM3 — check Wazuh
sudo grep "100200" /var/ossec/logs/alerts/alerts.json | wc -l
```

---

## Phase 7: Running the Full Experiments

All smoke tests must pass before proceeding.

```bash
# On VM2 — validate automation with one trial first
sudo bash /opt/gandd-research/scripts/run_experiment.sh \
  --scenario 3B \
  --trials   1 \
  --duration 300

# Inspect the trial output
ls data/results/
cat data/results/3B_t1_wazuh_alerts.json  | python3 -m json.tool | head -40
cat data/results/3B_t1_gandd_alerts.log
cat data/results/3B_t1_http_response.csv  | head -20

# If the trial looks correct, run all 90 trials (6 scenarios × 15 trials)
sudo bash /opt/gandd-research/scripts/run_experiment.sh --scenario all
```

---

## Troubleshooting Reference

| Symptom | Where to check | Fix |
|---|---|---|
| GANDD-Bridge not starting | `systemctl status gandd-bridge` | Verify model exists: `ls data/processed/rf_model.pkl` |
| No GANDD_ALERT in log | `tail -f /var/log/gandd/alerts.log` | Verify Suricata writes flows: `tail -f /var/log/suricata/eve.json \| grep flow` |
| Rule 100200 not firing | `sudo /var/ossec/bin/wazuh-logtest` on VM3 | Paste a GANDD_ALERT line — check if rule 100200 matches |
| Agent not connecting to Manager | `systemctl status wazuh-agent` on VM2 | Re-run `manage_agents` key import; check port 1514 is open |
| iptables not blocking | `cat /var/ossec/logs/active-responses.log` on VM3 | Confirm `firewall-drop` exists at `/var/ossec/active-response/bin/` |
| Suricata not seeing traffic | `sudo suricata --list-runmodes` | Wrong NIC — verify with `ip link show` and re-run setup with `--iface <correct-name>` |
| feature_extraction gives 0 rows | Check eve.json for `"event_type":"flow"` lines | Let Suricata run longer; verify the correct NIC is monitored |
| RF model classifies everything as benign | Run `python src/train_rf.py` — check confusion matrix | Collect more attack samples; verify attack eve.json has high-pkt_rate flows |

---

## Summary — Order of Operations

```
VMware  →  Create VMnet2 (Host-only, 192.168.100.0/24, DHCP off)
        →  Assign VMnet2 adapter to all 3 VMs
        →  Add NAT adapter temporarily for internet during setup

VM3  →  Install open-vm-tools
     →  Set static IP 192.168.100.10 on ens33
     →  Install Wazuh Manager (Option A recommended)
     →  Deploy rules.xml
     →  Patch ossec.conf (active-response + whitelist)
     →  Restart wazuh-manager

VM2  →  Install open-vm-tools
     →  Set static IP 192.168.100.100 on ens33
     →  Run setup_wazuh.sh --mode victim --iface ens33
     →  Register Wazuh Agent with Manager
     →  Set up SSH key to VM1

VM1  →  Set static IP 192.168.100.50
     →  Verify hping3 installed
     →  Clone repo

VM2  →  Collect benign eve.json (normal HTTP traffic, 5–10 min)
     →  Collect attack eve.json (brief hping3 run, 3 min)
     →  python feature_extraction.py  →  features.csv
     →  python train_rf.py            →  rf_model.pkl
     →  systemctl start gandd-bridge

     →  Run Smoke Tests 1–5
     →  run_experiment.sh --scenario 3B --trials 1   (validate automation)
     →  run_experiment.sh --scenario all              (full 90 trials)
```
