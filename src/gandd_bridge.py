#!/usr/bin/env python3
"""
GANDD-Bridge: GAN Discriminator-based DDoS Detection Bridge Middleware

Tails Suricata eve.json in real-time, extracts 7 behavioral features from
flow events, classifies flows using a trained Random Forest discriminator,
and writes GANDD_ALERT lines to /var/log/gandd/alerts.log for Wazuh Agent pickup.

Blue Team component — Calvin Wirathama Katoroy (2306242395)
"""

import json
import math
import os
import pickle
import time
import logging
import argparse
from datetime import datetime
from pathlib import Path

import numpy as np

# ── Default paths (override via CLI args or env vars) ─────────────────────────
EVE_LOG      = os.getenv("GANDD_EVE_LOG",   "/var/log/suricata/eve.json")
ALERT_LOG    = os.getenv("GANDD_ALERT_LOG", "/var/log/gandd/alerts.log")
MODEL_PATH   = os.getenv("GANDD_MODEL",
               os.path.join(os.path.dirname(__file__),
                            "../data/processed/rf_model.pkl"))
THRESHOLD    = float(os.getenv("GANDD_THRESHOLD", "0.6"))

# Feature vector order (must match training)
FEATURE_NAMES = [
    "pkt_count", "byte_ratio", "pkt_rate",
    "iat_var",   "size_var",   "entropy", "syn_ratio"
]


# ── Feature extraction ─────────────────────────────────────────────────────────

def _parse_ts(ts_str: str) -> float:
    """Parse a Suricata ISO-8601 timestamp to a UNIX timestamp."""
    if not ts_str:
        return 0.0
    try:
        # Suricata format: "2024-01-15T10:23:45.123456+0000"
        ts_str = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str).timestamp()
    except ValueError:
        return 0.0


def _shannon_entropy(data: str) -> float:
    """Compute Shannon entropy (bits) of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def extract_features(event: dict) -> list[float]:
    """
    Extract 7 behavioral features from a Suricata flow event.

    Features
    --------
    pkt_count  : packets sent to server
    byte_ratio : bytes_toserver / (bytes_toclient + 1)
    pkt_rate   : pkt_count / flow_duration_seconds
    iat_var    : proxy inter-arrival time variance (duration/pkts)^2 * 0.25
    size_var   : |mean_pkt_size - 64|  (deviation from min TCP SYN size)
    entropy    : Shannon entropy of payload_printable field (bits)
    syn_ratio  : fraction of packets with SYN flag set (0 or 1 from flow meta)
    """
    flow = event.get("flow", {})

    # — Volumetric features —
    pkt_count      = max(int(flow.get("pkts_toserver", 0)), 1)
    bytes_toserver = float(flow.get("bytes_toserver", 0))
    bytes_toclient = float(flow.get("bytes_toclient", 0))
    byte_ratio     = bytes_toserver / (bytes_toclient + 1.0)

    # — Temporal features —
    start_ts = _parse_ts(flow.get("start", ""))
    end_ts   = _parse_ts(flow.get("end",   ""))
    duration = max(end_ts - start_ts, 0.001)
    pkt_rate = pkt_count / duration

    # IAT variance proxy: (mean_iat)^2 * 0.25 — captures bursty vs uniform flows
    mean_iat = duration / max(pkt_count - 1, 1)
    iat_var  = (mean_iat ** 2) * 0.25

    # — Payload / size features —
    avg_pkt_size = bytes_toserver / pkt_count
    size_var     = abs(avg_pkt_size - 64.0)   # 64 bytes = bare TCP SYN

    payload   = event.get("payload_printable", "") or ""
    entropy   = _shannon_entropy(payload)

    # — Protocol features (from Suricata tcp object) —
    tcp = event.get("tcp", {})
    syn_flag   = 1 if tcp.get("syn", False) else 0
    syn_ratio  = syn_flag / pkt_count   # per-packet contribution of this SYN event

    return [
        float(pkt_count),
        float(byte_ratio),
        float(pkt_rate),
        float(iat_var),
        float(size_var),
        float(entropy),
        float(syn_ratio),
    ]


# ── Classifier ────────────────────────────────────────────────────────────────

class RFDiscriminator:
    """
    Random Forest discriminator wrapper.

    Falls back to a threshold-based heuristic if no trained model is found,
    so the bridge is functional even before training data is collected.
    """

    def __init__(self, model_path: str, threshold: float):
        self.threshold = threshold
        self.model = self._load(model_path)

    def _load(self, path: str):
        if os.path.exists(path):
            with open(path, "rb") as fh:
                model = pickle.load(fh)
            logging.getLogger("gandd").info("RF model loaded from %s", path)
            return model
        logging.getLogger("gandd").warning(
            "No model at %s — using heuristic fallback", path
        )
        return None

    def predict(self, features: list[float]) -> tuple[bool, float]:
        """Return (is_attack, confidence_score ∈ [0, 1])."""
        if self.model is not None:
            X = np.array(features, dtype=float).reshape(1, -1)
            proba = self.model.predict_proba(X)[0]
            # class order: [benign=0, attack=1]
            score = float(proba[1]) if len(proba) > 1 else float(proba[0])
            return score >= self.threshold, score

        # ── Heuristic fallback ──────────────────────────────────────────────
        pkt_count, byte_ratio, pkt_rate, iat_var, size_var, entropy, syn_ratio \
            = features
        score = 0.0
        if pkt_rate   > 100:  score += 0.40   # high packet rate
        if syn_ratio  > 0.5:  score += 0.30   # mostly SYN packets
        if byte_ratio > 5.0:  score += 0.15   # heavily asymmetric flow
        if entropy    < 1.0 and pkt_count > 10:
                              score += 0.10   # low-entropy payload (padding)
        if size_var   < 5.0 and pkt_rate > 50:
                              score += 0.05   # fixed-size packets at high rate
        score = min(score, 1.0)
        return score >= self.threshold, score


# ── Alert writer ──────────────────────────────────────────────────────────────

class AlertWriter:
    """Appends GANDD_ALERT lines to the alert log file."""

    TEMPLATE = (
        "GANDD_ALERT timestamp={ts} src_ip={src_ip} dest_ip={dest_ip} "
        "dest_port={dest_port} proto={proto} confidence={score:.4f}\n"
    )

    def __init__(self, alert_log: str):
        Path(alert_log).parent.mkdir(parents=True, exist_ok=True)
        self.alert_log = alert_log

    def write(self, event: dict, score: float) -> None:
        line = self.TEMPLATE.format(
            ts        = event.get("timestamp", datetime.utcnow().isoformat()),
            src_ip    = event.get("src_ip",    "unknown"),
            dest_ip   = event.get("dest_ip",   "unknown"),
            dest_port = event.get("dest_port", 0),
            proto     = event.get("proto",     "unknown"),
            score     = score,
        )
        with open(self.alert_log, "a") as fh:
            fh.write(line)


# ── Core bridge ───────────────────────────────────────────────────────────────

class GANDDBridge:
    """Main GANDD-Bridge service: monitor eve.json → extract → classify → alert."""

    def __init__(
        self,
        eve_log:    str   = EVE_LOG,
        alert_log:  str   = ALERT_LOG,
        model_path: str   = MODEL_PATH,
        threshold:  float = THRESHOLD,
    ):
        self.eve_log      = eve_log
        self.discriminator = RFDiscriminator(model_path, threshold)
        self.alert_writer  = AlertWriter(alert_log)
        self.logger        = logging.getLogger("gandd")

    # ── eve.json tail ─────────────────────────────────────────────────────────

    def _tail_eve(self):
        """Generator that yields parsed JSON events from a live eve.json."""
        # Wait for file to exist (Suricata may not have started yet)
        while not os.path.exists(self.eve_log):
            self.logger.info("Waiting for %s …", self.eve_log)
            time.sleep(2)

        with open(self.eve_log, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, 2)   # jump to end — we only care about new events
            self.logger.info("Tailing %s", self.eve_log)
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(0.05)
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        self.logger.info(
            "GANDD-Bridge started | threshold=%.2f",
            self.discriminator.threshold,
        )
        stats = {"processed": 0, "alerts": 0}

        for event in self._tail_eve():
            if event.get("event_type") != "flow":
                continue

            stats["processed"] += 1
            features            = extract_features(event)
            is_attack, score    = self.discriminator.predict(features)

            if is_attack:
                self.alert_writer.write(event, score)
                stats["alerts"] += 1
                self.logger.warning(
                    "ATTACK detected | src=%s dst=%s:%s confidence=%.4f",
                    event.get("src_ip"),
                    event.get("dest_ip"),
                    event.get("dest_port"),
                    score,
                )

            # Periodic stats log every 1000 flows
            if stats["processed"] % 1000 == 0:
                self.logger.info(
                    "Stats: flows_processed=%d alerts_generated=%d",
                    stats["processed"], stats["alerts"],
                )


# ── Entry point ───────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="GANDD-Bridge: ML-based DDoS detection middleware for Wazuh"
    )
    p.add_argument("--eve-log",   default=EVE_LOG,    help="Suricata eve.json path")
    p.add_argument("--alert-log", default=ALERT_LOG,  help="GANDD alert output path")
    p.add_argument("--model",     default=MODEL_PATH, help="Trained RF model (.pkl)")
    p.add_argument("--threshold", type=float,
                   default=THRESHOLD,                 help="Detection confidence threshold")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    logging.basicConfig(
        level   = getattr(logging, args.log_level),
        format  = "%(asctime)s GANDD-Bridge %(levelname)s %(message)s",
        datefmt = "%Y-%m-%dT%H:%M:%S",
    )
    bridge = GANDDBridge(
        eve_log    = args.eve_log,
        alert_log  = args.alert_log,
        model_path = args.model,
        threshold  = args.threshold,
    )
    bridge.run()


if __name__ == "__main__":
    main()
