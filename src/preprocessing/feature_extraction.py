"""
Feature extraction from Suricata eve.json for GANDD-Bridge training data.

Reads an eve.json file (one JSON object per line), filters flow events,
and returns a pandas DataFrame with the 7 behavioural features used by
the Random Forest discriminator, plus an optional label column.

Blue Team component — Calvin Wirathama Katoroy (2306242395)
"""

import json
import math
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

FEATURE_NAMES = [
    "pkt_count",
    "byte_ratio",
    "pkt_rate",
    "iat_var",
    "size_var",
    "entropy",
    "syn_ratio",
]


# ── Low-level helpers ─────────────────────────────────────────────────────────

def _parse_ts(ts_str: str) -> float:
    if not ts_str:
        return 0.0
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ── Per-event feature extraction ──────────────────────────────────────────────

def flow_event_to_features(event: dict) -> Optional[dict]:
    """
    Convert a single Suricata flow event dict into a feature dict.

    Returns None if the event is not a flow event or is malformed.
    """
    if event.get("event_type") != "flow":
        return None

    flow           = event.get("flow", {})
    pkt_count      = max(int(flow.get("pkts_toserver", 0)), 1)
    bytes_toserver = float(flow.get("bytes_toserver", 0))
    bytes_toclient = float(flow.get("bytes_toclient", 0))
    byte_ratio     = bytes_toserver / (bytes_toclient + 1.0)

    start_ts  = _parse_ts(flow.get("start", ""))
    end_ts    = _parse_ts(flow.get("end",   ""))
    duration  = max(end_ts - start_ts, 0.001)
    pkt_rate  = pkt_count / duration

    mean_iat = duration / max(pkt_count - 1, 1)
    iat_var  = (mean_iat ** 2) * 0.25

    avg_pkt_size = bytes_toserver / pkt_count
    size_var     = abs(avg_pkt_size - 64.0)

    payload  = event.get("payload_printable", "") or ""
    entropy  = _shannon_entropy(payload)

    tcp       = event.get("tcp", {})
    syn_flag  = 1 if tcp.get("syn", False) else 0
    syn_ratio = syn_flag / pkt_count

    return {
        "pkt_count":  float(pkt_count),
        "byte_ratio": float(byte_ratio),
        "pkt_rate":   float(pkt_rate),
        "iat_var":    float(iat_var),
        "size_var":   float(size_var),
        "entropy":    float(entropy),
        "syn_ratio":  float(syn_ratio),
        # metadata (not used as features — useful for debugging)
        "src_ip":     event.get("src_ip", ""),
        "dest_ip":    event.get("dest_ip", ""),
        "dest_port":  event.get("dest_port", 0),
        "proto":      event.get("proto", ""),
        "timestamp":  event.get("timestamp", ""),
    }


# ── File-level helpers ────────────────────────────────────────────────────────

def extract_from_eve_json(
    eve_path: str,
    label: Optional[int] = None,
) -> pd.DataFrame:
    """
    Parse an entire eve.json file and return a DataFrame of flow features.

    Parameters
    ----------
    eve_path : str
        Path to a Suricata eve.json file.
    label : int or None
        If provided (0 = benign, 1 = attack), a ``label`` column is appended.
        Useful when building labeled training datasets.

    Returns
    -------
    pd.DataFrame
        One row per flow event. Columns: FEATURE_NAMES + metadata + optional label.
    """
    records: list[dict] = []
    path = Path(eve_path)
    if not path.exists():
        raise FileNotFoundError(f"eve.json not found: {eve_path}")

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            row = flow_event_to_features(event)
            if row is not None:
                records.append(row)

    df = pd.DataFrame(records)
    if df.empty:
        return df

    if label is not None:
        df["label"] = int(label)

    return df


def build_training_dataset(
    benign_paths: list[str],
    attack_paths: list[str],
    output_csv:   Optional[str] = None,
) -> pd.DataFrame:
    """
    Combine benign and attack eve.json files into a labelled training DataFrame.

    Parameters
    ----------
    benign_paths : list of str
        Paths to eve.json files captured during normal (benign) operation.
    attack_paths : list of str
        Paths to eve.json files captured during attack sessions.
    output_csv : str or None
        If given, save the combined DataFrame to this CSV path.

    Returns
    -------
    pd.DataFrame
        Combined DataFrame with columns FEATURE_NAMES + label (0/1).
    """
    frames: list[pd.DataFrame] = []

    for path in benign_paths:
        df = extract_from_eve_json(path, label=0)
        frames.append(df)
        print(f"[benign] {path}: {len(df)} flow events")

    for path in attack_paths:
        df = extract_from_eve_json(path, label=1)
        frames.append(df)
        print(f"[attack] {path}: {len(df)} flow events")

    if not frames:
        raise ValueError("No data found in provided paths.")

    combined = pd.concat(frames, ignore_index=True)
    combined = combined.dropna(subset=FEATURE_NAMES)

    if output_csv:
        Path(output_csv).parent.mkdir(parents=True, exist_ok=True)
        combined.to_csv(output_csv, index=False)
        print(f"Dataset saved to {output_csv} ({len(combined)} rows)")

    return combined


# ── FeatureExtractor class (preserves existing interface) ─────────────────────

class FeatureExtractor:
    """
    Wrapper class providing extract_features / extract_flow_features APIs.

    Can be used standalone or as part of the training pipeline.
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    def extract_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Extract GANDD features from a DataFrame of raw Suricata flow records.

        Expected columns (subset of Suricata flow schema):
          pkts_toserver, bytes_toserver, bytes_toclient,
          flow_start, flow_end, tcp_syn, payload_printable

        Returns a DataFrame with FEATURE_NAMES columns.
        """
        rows = []
        for _, row in data.iterrows():
            # Build a minimal event dict from the DataFrame row
            event = {
                "event_type": "flow",
                "flow": {
                    "pkts_toserver":  row.get("pkts_toserver",  0),
                    "bytes_toserver": row.get("bytes_toserver", 0),
                    "bytes_toclient": row.get("bytes_toclient", 0),
                    "start":          str(row.get("flow_start", "")),
                    "end":            str(row.get("flow_end",   "")),
                },
                "tcp": {"syn": bool(row.get("tcp_syn", False))},
                "payload_printable": str(row.get("payload_printable", "")),
                "src_ip":    str(row.get("src_ip",    "")),
                "dest_ip":   str(row.get("dest_ip",   "")),
                "dest_port": int(row.get("dest_port", 0)),
                "proto":     str(row.get("proto",     "")),
                "timestamp": str(row.get("timestamp", "")),
            }
            feat = flow_event_to_features(event)
            if feat is not None:
                rows.append({k: feat[k] for k in FEATURE_NAMES})

        return pd.DataFrame(rows, columns=FEATURE_NAMES)

    def extract_flow_features(self, flow_data: pd.DataFrame) -> pd.DataFrame:
        """Alias for extract_features — operates on flow-level records."""
        return self.extract_features(flow_data)

    def extract_from_file(
        self,
        eve_path: str,
        label: Optional[int] = None,
    ) -> pd.DataFrame:
        """Parse an eve.json file directly."""
        return extract_from_eve_json(eve_path, label=label)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Extract GANDD features from Suricata eve.json files"
    )
    parser.add_argument(
        "--benign", nargs="+", default=[],
        help="Paths to benign eve.json files (label=0)",
    )
    parser.add_argument(
        "--attack", nargs="+", default=[],
        help="Paths to attack eve.json files (label=1)",
    )
    parser.add_argument(
        "--output", default="data/processed/features.csv",
        help="Output CSV path",
    )
    args = parser.parse_args()

    if not args.benign and not args.attack:
        parser.print_help()
        sys.exit(1)

    df = build_training_dataset(args.benign, args.attack, args.output)
    print(f"\nClass distribution:\n{df['label'].value_counts()}")
    print(f"\nFeature statistics:\n{df[FEATURE_NAMES].describe()}")
