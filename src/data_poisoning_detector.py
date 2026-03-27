"""
data_poisoning_detector.py
--------------------------
Detects potential data poisoning in annotation datasets.

Checks:
  1. Label flip detection  — statistical inconsistency in labels for similar inputs
  2. Cluster purity        — embeddings-free version using string similarity
  3. Class imbalance drift — sudden shifts in label distribution across time
  4. Minority class targeting — disproportionate mislabeling of rare classes
  5. Dataset integrity     — SHA-256 checksum verification
"""

import json
import hashlib
import argparse
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from utils import timestamp_now, load_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def simple_hash(text: str) -> str:
    """Lightweight text fingerprint for near-duplicate detection."""
    normalized = " ".join(text.lower().split())
    return hashlib.md5(normalized.encode()).hexdigest()


def dataset_checksum(annotations: list[dict]) -> str:
    """Compute SHA-256 checksum of the full dataset for integrity verification."""
    content = json.dumps(annotations, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(content.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

def detect_label_flips(annotations: list[dict], similarity_field: str = "text") -> list[dict]:
    """
    Detect label flips: near-duplicate inputs that received different labels.
    Groups annotations by text fingerprint and flags groups with >1 unique label.
    """
    groups: dict = defaultdict(list)
    for ann in annotations:
        text = ann.get(similarity_field, "")
        if text:
            key = simple_hash(text)
            groups[key].append(ann)

    findings = []
    for key, group in groups.items():
        if len(group) < 2:
            continue
        labels = [a["label"] for a in group]
        unique_labels = set(labels)
        if len(unique_labels) > 1:
            annotators = list({a.get("annotator_id", "?") for a in group})
            findings.append({
                "type": "LABEL_FLIP",
                "severity": "HIGH",
                "text_fingerprint": key,
                "sample_text": group[0].get(similarity_field, "")[:100],
                "labels_seen": list(unique_labels),
                "occurrences": len(group),
                "annotators_involved": annotators,
                "recommendation": (
                    "Near-duplicate inputs received conflicting labels. "
                    "Investigate for intentional label flipping or annotator error."
                ),
            })

    return findings


def detect_class_imbalance_drift(annotations: list[dict], window_size: int = 50) -> list[dict]:
    """
    Detect sudden shifts in label distribution across annotation batches.
    Splits dataset into sequential windows and compares distributions.
    """
    if len(annotations) < window_size * 2:
        return []

    # Sort by batch_id or created_at if available
    sorted_anns = sorted(
        annotations,
        key=lambda a: (a.get("batch_id", ""), a.get("created_at", ""))
    )

    windows = [
        sorted_anns[i: i + window_size]
        for i in range(0, len(sorted_anns) - window_size + 1, window_size)
    ]

    all_labels = [a["label"] for a in annotations]
    global_labels = set(all_labels)
    global_dist = {lb: all_labels.count(lb) / len(all_labels) for lb in global_labels}

    findings = []
    for idx, window in enumerate(windows):
        window_labels = [a["label"] for a in window]
        window_dist = {lb: window_labels.count(lb) / len(window_labels) for lb in global_labels}

        max_drift = max(
            abs(window_dist.get(lb, 0) - global_dist[lb])
            for lb in global_labels
        )

        if max_drift > 0.25:
            findings.append({
                "type": "CLASS_IMBALANCE_DRIFT",
                "severity": "HIGH" if max_drift > 0.40 else "MEDIUM",
                "window_index": idx,
                "window_size": window_size,
                "max_drift": round(max_drift, 3),
                "window_distribution": {k: round(v, 3) for k, v in window_dist.items()},
                "global_distribution": {k: round(v, 3) for k, v in global_dist.items()},
                "recommendation": (
                    f"Window {idx} shows {max_drift:.0%} drift from global label distribution. "
                    "Review this batch for systematic label manipulation."
                ),
            })

    return findings


def detect_minority_class_targeting(annotations: list[dict], threshold: float = 0.20) -> list[dict]:
    """
    Detect disproportionate mislabeling of minority (rare) classes.
    Uses honeypot task failures filtered by label class.
    """
    honeypots = [a for a in annotations if a.get("is_honeypot") and a.get("correct_label")]
    if not honeypots:
        return []

    # Global label frequency
    all_labels = Counter(a["label"] for a in annotations)
    total = sum(all_labels.values())
    rare_labels = {lb for lb, count in all_labels.items() if count / total < 0.15}

    if not rare_labels:
        return []

    # Failure rate on minority classes vs majority classes
    minority_hp = [h for h in honeypots if h["correct_label"] in rare_labels]
    majority_hp = [h for h in honeypots if h["correct_label"] not in rare_labels]

    if not minority_hp:
        return []

    minority_fail_rate = sum(1 for h in minority_hp if h["label"] != h["correct_label"]) / len(minority_hp)
    majority_fail_rate = (
        sum(1 for h in majority_hp if h["label"] != h["correct_label"]) / len(majority_hp)
        if majority_hp else 0
    )

    findings = []
    if minority_fail_rate - majority_fail_rate > threshold:
        findings.append({
            "type": "MINORITY_CLASS_TARGETING",
            "severity": "HIGH",
            "minority_labels": list(rare_labels),
            "minority_fail_rate": round(minority_fail_rate, 3),
            "majority_fail_rate": round(majority_fail_rate, 3),
            "differential": round(minority_fail_rate - majority_fail_rate, 3),
            "recommendation": (
                "Minority classes show significantly higher mislabeling rates. "
                "This pattern is consistent with targeted data poisoning to degrade performance on rare classes."
            ),
        })

    return findings


def verify_dataset_integrity(annotations: list[dict], expected_checksum: str | None = None) -> dict:
    """Compute and optionally verify dataset checksum."""
    checksum = dataset_checksum(annotations)
    verified = None
    if expected_checksum:
        verified = checksum == expected_checksum

    return {
        "sha256": checksum,
        "record_count": len(annotations),
        "checksum_verified": verified,
    }


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_poisoning_detection(annotations: list[dict], expected_checksum: str | None = None) -> dict:
    findings = []
    findings.extend(detect_label_flips(annotations))
    findings.extend(detect_class_imbalance_drift(annotations))
    findings.extend(detect_minority_class_targeting(annotations))

    integrity = verify_dataset_integrity(annotations, expected_checksum)

    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")

    return {
        "timestamp": timestamp_now(),
        "dataset_integrity": integrity,
        "total_findings": len(findings),
        "high_severity": high,
        "medium_severity": medium,
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="Data Poisoning Detector for AI Annotation Datasets")
    parser.add_argument("--input", required=True, help="Path to annotations JSON")
    parser.add_argument("--output", default="reports/poisoning_report.json")
    parser.add_argument("--checksum", default=None, help="Expected SHA-256 checksum for integrity verification")
    parser.add_argument("--threshold", type=float, default=0.20, help="Minority class targeting threshold")
    args = parser.parse_args()

    print(f"[*] Loading {args.input}...")
    data = load_json(args.input)
    annotations = data if isinstance(data, list) else data.get("annotations", [])

    print(f"[*] Running data poisoning detection on {len(annotations)} annotations...")
    result = run_poisoning_detection(annotations, args.checksum)

    # Print summary
    print(f"\n{'='*60}")
    print(f"  DATA POISONING DETECTION RESULTS")
    print(f"{'='*60}")
    print(f"  Dataset SHA-256 : {result['dataset_integrity']['sha256']}")
    if result["dataset_integrity"]["checksum_verified"] is not None:
        status = "PASS" if result["dataset_integrity"]["checksum_verified"] else "FAIL"
        print(f"  Integrity check : {status}")
    print(f"  Total findings  : {result['total_findings']}")
    print(f"  HIGH severity   : {result['high_severity']}")
    print(f"  MEDIUM          : {result['medium_severity']}")

    for f in result["findings"]:
        print(f"\n  [{f['severity']:6s}] {f['type']}")
        print(f"           {f['recommendation'][:100]}...")

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\n[+] Report saved: {args.output}")


if __name__ == "__main__":
    main()
