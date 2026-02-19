# Evaluation of Wazuh SIEM Detection Against GAN-Based DDoS Attacks

Research project evaluating whether integrating a GAN-discriminator middleware (GANDD-Bridge) into a Wazuh SIEM deployment improves detection of adversarial-style DDoS attacks that evade signature-based rules.

**Institution**: Universitas Indonesia — Computer Engineering
**Course**: Semester 5 Research Project

## Authors

| Name | NPM | Role |
| ------ | ----- | ------ |
| Reyhan Ahnaf Deannova | 2306267100 | Red Team Lead |
| Aidan Ardhazizi | 2406430483 | — |
| Calvin Wirathama Katoroy | 2306242395 | Blue Team Lead |
| Wesley Frederick Oh | 2306202763  | AI/ML Engineer |

## Research Overview

Traditional Wazuh SIEM relies on signature-based rules that flag traffic exceeding fixed thresholds. GAN-generated attack traffic evades this by mimicking benign traffic distributions (inter-arrival time, packet size, TCP flags), making it statistically indistinguishable from legitimate flows.

This research evaluates a three-VM testbed comparing:

- **Config A** — Wazuh v4.9 + Suricata v7.0, signature-based only
- **Config B** — Config A + GANDD-Bridge middleware (Random Forest discriminator on Suricata flow features)

Across three attack types: volumetric SYN flood, low-rate evasive, and adversarial-style (PDF-sampled).

## Project Structure

```
├── docs/
│   ├── paper/                  # LaTeX source (IEEEtran format)
│   │   ├── main.tex
│   │   ├── chapters/           # chapter1.tex – chapter5.tex
│   │   ├── figures/            # fig1.png, workflow_diagram.pdf
│   │   ├── references.bib
│   │   ├── packages.tex
│   │   ├── settings.tex
│   │   └── title.tex
│   └── notes/                  # Literature review, meeting notes, research notes
├── src/
│   ├── gan/                    # GAN model: generator.py, discriminator.py, train.py
│   ├── analysis/               # evaluate.py, visualize.py
│   ├── preprocessing/          # data_loader.py, feature_extraction.py
│   └── utils/                  # helpers.py, logger.py
├── config/
│   ├── environment/            # requirements.txt, environment.yml
│   └── wazuh/                  # ossec.conf, rules.xml (custom rule 100200)
├── data/
│   ├── raw/                    # Raw packet captures (.pcap)
│   ├── processed/              # Extracted feature CSVs
│   └── results/                # Experiment output logs
├── notebooks/
│   ├── 01_exploratory_analysis.ipynb
│   ├── 02_model_training.ipynb
│   └── 03_evaluation.ipynb
├── scripts/
│   ├── setup_wazuh.sh          # Wazuh Manager/Agent deployment
│   └── run_experiment.sh       # Trial execution automation
├── tests/
│   ├── test_gan.py
│   └── test_preprocessing.py
└── config.yaml                 # Global experiment parameters
```

## Testbed Architecture

Three VirtualBox VMs on NAT network `192.168.100.0/24`:

| VM | Role | OS | IP |
| ---- | ------ | ---- | -- |
| VM1 | Attacker | Kali Linux 2025.3 | 192.168.100.50 |
| VM2 | Victim | Ubuntu 22.04 LTS | 192.168.100.100 |
| VM3 | SIEM Manager | Ubuntu 22.04 LTS | 192.168.100.10 |

**VM2 detection stack:** Suricata v7.0 → eve.json → GANDD-Bridge → Wazuh Agent → VM3
**Active Response:** `firewall-drop` (iptables, 60s timeout) triggered by Rule 100200

## Setup

### Prerequisites

- Python 3.9+
- VirtualBox 7.0 (for VM testbed)
- MiKTeX or TeX Live (to compile the paper)

### Python environment

```bash
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r config/environment/requirements.txt
```

### Wazuh deployment

```bash
bash scripts/setup_wazuh.sh
```

Copy `config/wazuh/ossec.conf` to `/var/ossec/etc/ossec.conf` on VM3, and `config/wazuh/rules.xml` to `/var/ossec/etc/rules/local_rules.xml`.

## Running Experiments

```bash
bash scripts/run_experiment.sh
```

Each trial runs 5 minutes of attack traffic and collects Wazuh alert logs, Suricata eve.json, GANDD-Bridge detections, and system resource metrics. 15 independent trials per scenario cell (90 total: 2 configs × 3 attack types × 15 trials).

## Compiling the Paper

Open `docs/paper/main.tex` in VS Code with the **LaTeX Workshop** extension and press `Ctrl+Alt+B`, or:

```bash
cd docs/paper
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

## Evaluation Metrics

| Metric | Formula |
| -------- | --------- |
| Detection Rate (DR) | TP / (TP + FN) |
| False Positive Rate (FPR) | FP / (FP + TN) |
| Detection Latency | Time from attack start to Wazuh alert |
| Time-to-Block (TTB) | Time from alert to Active Response firewall rule |
| Resource Overhead | CPU / RAM delta with vs. without GANDD-Bridge |

Statistical validation: paired t-test (α = 0.05) + Cohen's d per scenario pair.

## License

MIT
