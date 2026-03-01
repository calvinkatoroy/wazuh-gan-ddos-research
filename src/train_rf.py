#!/usr/bin/env python3
"""
Random Forest discriminator training script for GANDD-Bridge.

Loads a labelled feature CSV (produced by feature_extraction.py),
trains a Random Forest classifier, evaluates it, and saves the model
to data/processed/rf_model.pkl for use by gandd_bridge.py.

Usage
-----
    # Build feature CSV from eve.json files first:
    python -m src.preprocessing.feature_extraction \
        --benign data/raw/benign_eve.json \
        --attack data/raw/attack_eve.json \
        --output data/processed/features.csv

    # Then train the classifier:
    python src/train_rf.py --data data/processed/features.csv

Blue Team component — Calvin Wirathama Katoroy (2306242395)
"""

import argparse
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler

FEATURE_NAMES = [
    "pkt_count",
    "byte_ratio",
    "pkt_rate",
    "iat_var",
    "size_var",
    "entropy",
    "syn_ratio",
]

DEFAULT_DATA    = "data/processed/features.csv"
DEFAULT_MODEL   = "data/processed/rf_model.pkl"
DEFAULT_SCALER  = "data/processed/scaler.pkl"


# ── Data loading ──────────────────────────────────────────────────────────────

def load_data(csv_path: str) -> tuple[np.ndarray, np.ndarray]:
    """Load feature CSV and return (X, y) arrays."""
    df = pd.read_csv(csv_path)
    missing = [c for c in FEATURE_NAMES if c not in df.columns]
    if missing:
        raise ValueError(f"CSV is missing columns: {missing}")
    if "label" not in df.columns:
        raise ValueError("CSV must have a 'label' column (0=benign, 1=attack).")

    df = df.dropna(subset=FEATURE_NAMES + ["label"])
    X = df[FEATURE_NAMES].values.astype(float)
    y = df["label"].values.astype(int)
    return X, y


# ── Training ──────────────────────────────────────────────────────────────────

def train(
    X: np.ndarray,
    y: np.ndarray,
    n_estimators: int = 200,
    max_depth: int    = None,
    test_size: float  = 0.20,
    random_state: int = 42,
) -> tuple[RandomForestClassifier, StandardScaler, dict]:
    """
    Train a Random Forest on (X, y) and return the fitted model,
    fitted scaler, and an evaluation metrics dict.
    """
    print(f"\nDataset: {len(y)} samples  |  benign={sum(y==0)}  attack={sum(y==1)}")

    # — Train / test split —
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )

    # — Feature scaling (RF doesn't strictly need it, but helps heuristic fallback) —
    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # — Model —
    clf = RandomForestClassifier(
        n_estimators = n_estimators,
        max_depth    = max_depth,
        class_weight = "balanced",   # handles class imbalance
        n_jobs       = -1,
        random_state = random_state,
    )

    # — 5-fold cross-validation on training split —
    print("\nRunning 5-fold cross-validation …")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=random_state)
    cv_f1 = cross_val_score(clf, X_train, y_train, cv=cv, scoring="f1", n_jobs=-1)
    print(f"  CV F1: {cv_f1.mean():.4f} ± {cv_f1.std():.4f}")

    # — Final fit —
    clf.fit(X_train, y_train)

    # — Evaluation on held-out test set —
    y_pred  = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy":  accuracy_score(y_test, y_pred),
        "f1":        f1_score(y_test, y_pred),
        "auc_roc":   roc_auc_score(y_test, y_proba),
        "cv_f1_mean": float(cv_f1.mean()),
        "cv_f1_std":  float(cv_f1.std()),
    }

    print(f"\n{'='*50}")
    print(f"  Accuracy : {metrics['accuracy']:.4f}")
    print(f"  F1 Score : {metrics['f1']:.4f}")
    print(f"  AUC-ROC  : {metrics['auc_roc']:.4f}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['benign','attack'])}")

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    dr  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    print(f"  Detection Rate (DR)  : {dr:.4f}")
    print(f"  False Positive Rate  : {fpr:.4f}")
    print(f"  Confusion Matrix:\n    TN={tn}  FP={fp}\n    FN={fn}  TP={tp}")
    print(f"{'='*50}\n")

    metrics.update({"dr": dr, "fpr": fpr, "tn": int(tn), "fp": int(fp),
                    "fn": int(fn), "tp": int(tp)})

    # — Feature importances —
    importances = sorted(
        zip(FEATURE_NAMES, clf.feature_importances_), key=lambda x: x[1], reverse=True
    )
    print("Feature importances:")
    for name, imp in importances:
        print(f"  {name:<14} {imp:.4f}")

    return clf, scaler, metrics


# ── Persistence ───────────────────────────────────────────────────────────────

def save_model(clf, scaler, model_path: str, scaler_path: str) -> None:
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    with open(model_path,  "wb") as fh:
        pickle.dump(clf,    fh)
    with open(scaler_path, "wb") as fh:
        pickle.dump(scaler, fh)
    print(f"\nModel  saved → {model_path}")
    print(f"Scaler saved → {scaler_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Train the GANDD-Bridge Random Forest discriminator"
    )
    p.add_argument("--data",         default=DEFAULT_DATA,
                   help="Labelled feature CSV (from feature_extraction.py)")
    p.add_argument("--model-out",    default=DEFAULT_MODEL,
                   help="Output path for trained model .pkl")
    p.add_argument("--scaler-out",   default=DEFAULT_SCALER,
                   help="Output path for fitted StandardScaler .pkl")
    p.add_argument("--n-estimators", type=int, default=200,
                   help="Number of RF trees (default: 200)")
    p.add_argument("--max-depth",    type=int, default=None,
                   help="Max tree depth (default: unlimited)")
    p.add_argument("--test-size",    type=float, default=0.20,
                   help="Fraction held out for evaluation (default: 0.20)")
    p.add_argument("--seed",         type=int, default=42,
                   help="Random seed")
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    if not Path(args.data).exists():
        print(f"[ERROR] Feature CSV not found: {args.data}")
        print(
            "Generate it first:\n"
            "  python -m src.preprocessing.feature_extraction \\\n"
            "    --benign data/raw/benign_eve.json \\\n"
            "    --attack data/raw/attack_eve.json \\\n"
            "    --output data/processed/features.csv"
        )
        sys.exit(1)

    X, y = load_data(args.data)
    clf, scaler, _ = train(
        X, y,
        n_estimators = args.n_estimators,
        max_depth    = args.max_depth,
        test_size    = args.test_size,
        random_state = args.seed,
    )
    save_model(clf, scaler, args.model_out, args.scaler_out)


if __name__ == "__main__":
    main()
