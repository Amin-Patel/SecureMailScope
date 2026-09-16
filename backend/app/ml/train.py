"""
Trains the risk classifier and anomaly detector and writes both model
artifacts plus a plain-text evaluation report.

Run from backend/: python -m app.ml.train
"""

import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

sys.path.insert(0, str(Path(__file__).parent.parent))  # make `core`/`utils` bare-importable

from app.ml.dataset_builder import generate_synthetic_dataset, extract_real_sessions
from app.ml.risk_classifier import RiskClassifier
from app.ml.anomaly_detector import AnomalyDetector

REPORT_PATH = Path(__file__).parent.parent.parent / "models" / "training_report.txt"


def _load_real_demo_sessions() -> Tuple[List[List[float]], List[str]]:
    """Run our own demo PCAPs through the real extraction pipeline and
    fold their sessions into the training set. Best-effort: if TShark
    isn't available in this environment, skip real data rather than fail
    the whole training run -- synthetic data alone is still a valid,
    if less-grounded, dataset."""
    try:
        from utils.tshark_helper import TSharkHelper
        from utils.cert_analyzer import CertificateAnalyzer
    except Exception as e:
        print(f"[!] Could not import extraction pipeline ({e}); skipping real demo sessions.")
        return [], []

    test_data_dir = Path(__file__).parent.parent.parent / "test-data"
    demo_files = ["smtp.pcap", "rsasnakeoil2.cap", "secure_mail.pcap"]

    vectors: List[List[float]] = []
    labels: List[str] = []

    for filename in demo_files:
        pcap_path = test_data_dir / filename
        if not pcap_path.exists():
            continue
        try:
            handshakes = TSharkHelper.extract_tls_handshakes(str(pcap_path))
            certificates = CertificateAnalyzer.extract_certificates(str(pcap_path))
        except Exception as e:
            print(f"[!] Skipping {filename}: {e}")
            continue
        v, l = extract_real_sessions(handshakes, certificates)
        vectors.extend(v)
        labels.extend(l)
        print(f"    {filename}: {len(v)} real session(s) extracted")

    return vectors, labels


def _dedupe(vectors: List[List[float]], labels: List[str]) -> Tuple[List[List[float]], List[str], int]:
    """Remove duplicate feature-vector rows before splitting -- the same
    guard TeamPort587's leakage audit checks for. A duplicate row landing
    in both train and test would let the model "recognize" the test
    example rather than generalize to it."""
    seen: Dict[Tuple[float, ...], str] = {}
    for v, l in zip(vectors, labels):
        seen[tuple(v)] = l
    removed = len(vectors) - len(seen)
    return [list(k) for k in seen.keys()], list(seen.values()), removed


def main():
    print("[1/5] Generating synthetic dataset from rule-engine distillation...")
    synth_vectors, synth_labels = generate_synthetic_dataset()
    print(f"    {len(synth_vectors)} synthetic sessions")

    print("[2/5] Extracting real sessions from demo captures...")
    real_vectors, real_labels = _load_real_demo_sessions()

    all_vectors = synth_vectors + real_vectors
    all_labels = synth_labels + real_labels

    print("[3/5] Deduplicating combined dataset (leakage guard)...")
    all_vectors, all_labels, removed = _dedupe(all_vectors, all_labels)
    print(f"    {len(all_vectors)} unique sessions ({removed} duplicate row(s) removed)")
    print(f"    Label distribution: {dict(Counter(all_labels))}")

    X_train, X_test, y_train, y_test = train_test_split(
        all_vectors, all_labels, test_size=0.25, random_state=42, stratify=all_labels
    )
    print(f"    Train: {len(X_train)}  Test: {len(X_test)}")

    print("[4/5] Training risk classifier (RandomForest)...")
    clf = RiskClassifier()
    clf.train(X_train, y_train)
    y_pred = clf.model.predict(X_test)
    test_accuracy = accuracy_score(y_test, y_pred)
    report_text = classification_report(y_test, y_pred, zero_division=0)
    importances = clf.feature_importances()

    print("[5/5] Training anomaly detector (IsolationForest)...")
    det = AnomalyDetector()
    det.train(all_vectors)

    clf.save()
    det.save()

    report_lines = [
        "SecureMailScope ML Training Report",
        "=" * 60,
        f"Total unique sessions: {len(all_vectors)} "
        f"(synthetic: {len(synth_vectors)}, real: {len(real_vectors)}, "
        f"duplicates removed: {removed})",
        f"Label distribution: {dict(Counter(all_labels))}",
        f"Train/test split: {len(X_train)}/{len(X_test)} (stratified, seed=42)",
        "",
        f"Held-out test accuracy: {test_accuracy:.4f}",
        "",
        "Note on accuracy: labels are a deterministic function of the",
        "features (rule-engine distillation, not noisy real-world",
        "ground truth), so near-1.0 held-out accuracy is expected and is",
        "not itself a leakage signal -- the leakage guard here is the",
        "duplicate-row removal above, which runs before the train/test",
        "split so no row appears in both.",
        "",
        "Classification report (held-out test set):",
        report_text,
        "Feature importances:",
    ]
    for name, importance in importances.items():
        report_lines.append(f"  {name}: {importance:.4f}")

    report_text_full = "\n".join(report_lines)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report_text_full, encoding="utf-8")

    print("\n" + report_text_full)
    print(f"\n[+] Models saved to {REPORT_PATH.parent}")
    print(f"[+] Report saved to {REPORT_PATH}")


if __name__ == "__main__":
    main()
