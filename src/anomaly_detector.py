"""
anomaly_detector.py
-------------------
Statistical anomaly detection on annotation batches.

Detects:
  - Label distribution anomalies (annotator label bias / poisoning)
  - Speed anomalies (suspiciously fast annotation = low quality / scripted)
  - Inter-annotator agreement outliers
  - Honeypot task failures
"""

import json
import argparse
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from utils import timestamp_now, load_json


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

def detect_label_distribution_anomaly(annotations: list[dict], threshold: float = 0.15) -> list[dict]:
    """
    Flag annotators whose label distribution differs significantly from the group.

    Args:
        annotations: list of annotation records
        threshold: max allowed deviation from mean label ratio before flagging

    Returns:
        List of anomaly findings
    """
    # Group annotations by annotator
    by_annotator = defaultdict(list)
    for ann in annotations:
        by_annotator[ann["annotator_id"]].append(ann["label"])

    # Compute global label distribution
    all_labels = [ann["label"] for ann in annotations]
    global_counts = Counter(all_labels)
    total = len(all_labels)
    global_dist = {label: count / total for label, count in global_counts.items()}

    findings = []
    for annotator_id, labels in by_annotator.items():
        if len(labels) < 5:
            continue  # Skip annotators with too few samples
        ann_counts = Counter(labels)
        ann_total = len(labels)
        ann_dist = {label: count / ann_total for label, count in ann_counts.items()}

        # Check deviation from global distribution for each label
        max_deviation = 0.0
        deviating_labels = []
        for label, global_ratio in global_dist.items():
            ann_ratio = ann_dist.get(label, 0.0)
            deviation = abs(ann_ratio - global_ratio)
            if deviation > threshold:
                deviating_labels.append({
                    "label": label,
                    "annotator_ratio": round(ann_ratio, 3),
                    "global_ratio": round(global_ratio, 3),
                    "deviation": round(deviation, 3),
                })
                max_deviation = max(max_deviation, deviation)

        if deviating_labels:
            findings.append({
                "type": "LABEL_DISTRIBUTION_ANOMALY",
                "severity": "HIGH" if max_deviation > 0.30 else "MEDIUM",
                "annotator_id": annotator_id,
                "sample_count": ann_total,
                "deviating_labels": deviating_labels,
                "recommendation": (
                    f"Review annotations from {annotator_id}. "
                    "Consider honeypot validation and inter-annotator agreement check."
                ),
            })

    return findings


def detect_speed_anomalies(annotations: list[dict], z_threshold: float = 2.5) -> list[dict]:
    """
    Flag annotations completed suspiciously quickly (possible scripted/bot submission).

    Args:
        annotations: list of annotation records (must include 'duration_seconds')
        z_threshold: z-score cutoff for flagging

    Returns:
        List of anomaly findings
    """
    # Filter records with duration data
    timed = [a for a in annotations if "duration_seconds" in a and a["duration_seconds"] is not None]
    if len(timed) < 10:
        return []

    durations = [a["duration_seconds"] for a in timed]
    mean_dur = statistics.mean(durations)
    stdev_dur = statistics.stdev(durations)

    findings = []
    flagged_annotators = defaultdict(int)

    for ann in timed:
        dur = ann["duration_seconds"]
        if stdev_dur == 0:
            continue
        z = (dur - mean_dur) / stdev_dur
        if z < -z_threshold:  # Much faster than average
            flagged_annotators[ann["annotator_id"]] += 1

    for annotator_id, count in flagged_annotators.items():
        annotator_tasks = sum(1 for a in timed if a["annotator_id"] == annotator_id)
        fast_ratio = count / annotator_tasks if annotator_tasks else 0
        if fast_ratio > 0.3:  # >30% of tasks are suspiciously fast
            findings.append({
                "type": "SPEED_ANOMALY",
                "severity": "HIGH" if fast_ratio > 0.6 else "MEDIUM",
                "annotator_id": annotator_id,
                "fast_tasks": count,
                "total_tasks": annotator_tasks,
                "fast_ratio": round(fast_ratio, 2),
                "mean_duration_seconds": round(mean_dur, 1),
                "recommendation": (
                    f"Annotator {annotator_id} completed {fast_ratio:.0%} of tasks "
                    f"at >2.5σ below mean speed. Audit sample for quality."
                ),
            })

    return findings


def detect_honeypot_failures(annotations: list[dict]) -> list[dict]:
    """
    Detect annotators who fail honeypot tasks (tasks with known correct labels).

    Args:
        annotations: list of annotation records (honeypots have 'is_honeypot': True and 'correct_label')

    Returns:
        List of anomaly findings
    """
    honeypots = [a for a in annotations if a.get("is_honeypot", False)]
    if not honeypots:
        return []

    by_annotator = defaultdict(list)
    for hp in honeypots:
        correct = hp.get("correct_label")
        given = hp.get("label")
        by_annotator[hp["annotator_id"]].append(correct == given)

    findings = []
    for annotator_id, results in by_annotator.items():
        total = len(results)
        failures = results.count(False)
        fail_rate = failures / total if total else 0
        if fail_rate > 0.2:  # >20% honeypot failure rate
            findings.append({
                "type": "HONEYPOT_FAILURE",
                "severity": "HIGH" if fail_rate > 0.5 else "MEDIUM",
                "annotator_id": annotator_id,
                "honeypot_tasks": total,
                "failures": failures,
                "failure_rate": round(fail_rate, 2),
                "recommendation": (
                    f"Annotator {annotator_id} failed {fail_rate:.0%} of honeypot tasks. "
                    "Consider account suspension and audit of all submissions."
                ),
            })

    return findings


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_anomaly_detection(annotations: list[dict], threshold: float = 0.15) -> dict:
    findings = []
    findings.extend(detect_label_distribution_anomaly(annotations, threshold))
    findings.extend(detect_speed_anomalies(annotations))
    findings.extend(detect_honeypot_failures(annotations))

    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")

    return {
        "timestamp": timestamp_now(),
        "total_annotations": len(annotations),
        "total_findings": len(findings),
        "high_severity": high,
        "medium_severity": medium,
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="Annotation Anomaly Detector")
    parser.add_argument("--input", required=True, help="Path to annotations JSON")
    parser.add_argument("--output", default="reports/anomaly_report.json")
    parser.add_argument("--threshold", type=float, default=0.15, help="Label distribution deviation threshold")
    args = parser.parse_args()

    print(f"[*] Loading annotations from {args.input}...")
    data = load_json(args.input)
    annotations = data if isinstance(data, list) else data.get("annotations", [])

    print(f"[*] Running anomaly detection on {len(annotations)} annotations...")
    result = run_anomaly_detection(annotations, args.threshold)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n[+] Anomaly detection complete.")
    print(f"    Findings      : {result['total_findings']}")
    print(f"    HIGH severity : {result['high_severity']}")
    print(f"    MEDIUM        : {result['medium_severity']}")
    print(f"    Report saved  : {args.output}")

    if result["findings"]:
        print("\n[!] Findings summary:")
        for f in result["findings"]:
            print(f"    [{f['severity']:6s}] {f['type']} — Annotator: {f['annotator_id']}")


if __name__ == "__main__":
    main()
