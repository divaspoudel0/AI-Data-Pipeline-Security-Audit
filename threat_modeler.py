"""
threat_modeler.py
-----------------
STRIDE-based threat modeling engine for AI/ML annotation pipelines.

STRIDE categories:
  S - Spoofing
  T - Tampering
  R - Repudiation
  I - Information Disclosure
  D - Denial of Service
  E - Elevation of Privilege
"""

import yaml
import json
import argparse
from datetime import datetime
from pathlib import Path
from utils import load_config, severity_label, timestamp_now


# ---------------------------------------------------------------------------
# Threat knowledge base
# ---------------------------------------------------------------------------

PIPELINE_THREATS = {
    "data_collection": [
        {
            "threat_id": "T-COL-001",
            "stride": "S",
            "name": "Fake Annotator Identity",
            "description": "Malicious actors submit annotations under compromised or fake accounts to inject bad data.",
            "attack_vector": "Identity spoofing via stolen credentials or account sharing.",
            "likelihood": 3,
            "impact": 4,
            "iso_controls": ["A.5.15", "A.5.16"],
            "mitigations": [
                "Enforce multi-factor authentication for all annotators.",
                "Log annotator identity metadata (IP, device fingerprint) per task.",
                "Implement velocity checks — flag accounts submitting unusually fast.",
            ],
        },
        {
            "threat_id": "T-COL-002",
            "stride": "T",
            "name": "Malicious Data Injection at Source",
            "description": "Adversary injects crafted inputs (prompt injection payloads) into raw data before annotation.",
            "attack_vector": "Unsanitized input fields in data collection forms or APIs.",
            "likelihood": 3,
            "impact": 5,
            "iso_controls": ["A.8.29", "A.8.8"],
            "mitigations": [
                "Validate and sanitize all input fields before pipeline ingestion.",
                "Use allowlists for expected content types and character sets.",
                "Hash raw inputs at collection time and verify integrity downstream.",
            ],
        },
    ],
    "annotation": [
        {
            "threat_id": "T-ANN-001",
            "stride": "T",
            "name": "Data Poisoning via Label Flipping",
            "description": "Annotators deliberately assign incorrect labels to corrupt downstream model training.",
            "attack_vector": "Insider threat or compromised annotator account flipping minority-class labels.",
            "likelihood": 3,
            "impact": 5,
            "iso_controls": ["A.8.8", "A.6.6"],
            "mitigations": [
                "Cross-annotate a random sample (10–15%) per batch; compare inter-annotator agreement.",
                "Compute per-annotator label distribution; flag statistical outliers.",
                "Honeypot tasks with known correct labels to detect bad actors.",
            ],
        },
        {
            "threat_id": "T-ANN-002",
            "stride": "T",
            "name": "Prompt Injection in Annotation Inputs",
            "description": "Adversarial text in source data manipulates downstream LLM-assisted annotation tools.",
            "attack_vector": "Crafted instructions embedded in annotated text that override LLM system prompts.",
            "likelihood": 4,
            "impact": 4,
            "iso_controls": ["A.8.29"],
            "mitigations": [
                "Scan all text inputs for known prompt injection patterns before LLM processing.",
                "Sandbox LLM annotation tools; prevent tool-use or external API calls from prompted content.",
                "Log and alert on LLM outputs that deviate significantly from expected response schema.",
            ],
        },
        {
            "threat_id": "T-ANN-003",
            "stride": "I",
            "name": "Sensitive Data Leakage to Annotators",
            "description": "Annotators gain unnecessary access to PII or confidential content beyond their task scope.",
            "attack_vector": "Over-permissive data access; no task-based data segmentation.",
            "likelihood": 3,
            "impact": 4,
            "iso_controls": ["A.5.12", "A.5.15"],
            "mitigations": [
                "Apply data minimization — annotators see only fields required for their specific task.",
                "Redact PII before annotation where possible.",
                "Enforce need-to-know access control per annotator role.",
            ],
        },
    ],
    "quality_assurance": [
        {
            "threat_id": "T-QA-001",
            "stride": "T",
            "name": "QA Bypass / Tampering",
            "description": "QA reviewer approves batches without proper review, or annotations are modified post-QA.",
            "attack_vector": "Insider collusion between annotator and QA reviewer; tampered audit logs.",
            "likelihood": 2,
            "impact": 5,
            "iso_controls": ["A.8.15", "A.5.35"],
            "mitigations": [
                "Immutable audit log for all annotation edits and QA decisions.",
                "Enforce dual-review for high-risk or high-value batches.",
                "Randomly reassign QA reviewers across batches to prevent collusion.",
            ],
        },
        {
            "threat_id": "T-QA-002",
            "stride": "R",
            "name": "Repudiation of QA Actions",
            "description": "QA reviewers deny having approved a batch; no reliable audit trail exists.",
            "attack_vector": "Weak or missing logging; shared QA accounts.",
            "likelihood": 2,
            "impact": 3,
            "iso_controls": ["A.8.15"],
            "mitigations": [
                "Require individual, non-shared QA accounts with signed audit entries.",
                "Store QA action logs in append-only, tamper-evident storage.",
            ],
        },
    ],
    "data_export": [
        {
            "threat_id": "T-EXP-001",
            "stride": "I",
            "name": "Data Exfiltration During Export",
            "description": "Annotated datasets intercepted or exfiltrated during transfer to model training environment.",
            "attack_vector": "Unencrypted transfer channels; misconfigured cloud storage permissions.",
            "likelihood": 3,
            "impact": 5,
            "iso_controls": ["A.8.24", "A.5.14"],
            "mitigations": [
                "Enforce TLS 1.2+ for all data transfers.",
                "Use signed, expiring pre-signed URLs for cloud storage access.",
                "Encrypt datasets at rest with AES-256; manage keys via dedicated KMS.",
            ],
        },
    ],
    "model_ingestion": [
        {
            "threat_id": "T-ING-001",
            "stride": "T",
            "name": "Model Training Data Poisoning (Supply Chain)",
            "description": "Corrupted dataset fed into model training, producing a backdoored or degraded model.",
            "attack_vector": "Compromised dataset at any upstream stage; no integrity verification before ingestion.",
            "likelihood": 2,
            "impact": 5,
            "iso_controls": ["A.8.8", "A.5.19"],
            "mitigations": [
                "Compute and verify SHA-256 checksums of datasets before ingestion.",
                "Sign datasets with GPG/Sigstore; reject unsigned inputs.",
                "Run automated statistical checks on label distributions before training.",
            ],
        },
    ],
}


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------

def model_threats(config: dict) -> list[dict]:
    """Run threat modeling against all pipeline stages defined in config."""
    active_stages = config.get("pipeline", {}).get("stages", list(PIPELINE_THREATS.keys()))
    results = []
    for stage in active_stages:
        threats = PIPELINE_THREATS.get(stage, [])
        for threat in threats:
            score = threat["likelihood"] * threat["impact"]
            results.append({
                **threat,
                "stage": stage,
                "severity_score": score,
                "severity_label": severity_label(score),
            })
    return results


def print_threat_summary(threats: list[dict]) -> None:
    print(f"\n{'='*60}")
    print(f"  THREAT MODEL SUMMARY — {timestamp_now()}")
    print(f"{'='*60}")
    for t in sorted(threats, key=lambda x: x["severity_score"], reverse=True):
        print(f"\n[{t['severity_label']:11s}] {t['threat_id']} — {t['name']}")
        print(f"  Stage     : {t['stage'].replace('_', ' ').title()}")
        print(f"  STRIDE    : {t['stride']}")
        print(f"  Score     : {t['severity_score']} (L={t['likelihood']} × I={t['impact']})")
        print(f"  ISO Ctrls : {', '.join(t['iso_controls'])}")
        print(f"  Description: {t['description']}")


def save_results(threats: list[dict], output_path: str) -> None:
    output = {
        "generated_at": timestamp_now(),
        "total_threats": len(threats),
        "high_risks": sum(1 for t in threats if t["severity_score"] >= 12),
        "threats": threats,
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[+] Results saved to {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="AI Pipeline STRIDE Threat Modeler")
    parser.add_argument("--config", default="configs/pipeline_config.yaml", help="Pipeline config YAML")
    parser.add_argument("--output", default="reports/threat_model.json", help="Output JSON path")
    parser.add_argument("--quiet", action="store_true", help="Suppress console output")
    args = parser.parse_args()

    config = load_config(args.config)
    threats = model_threats(config)

    if not args.quiet:
        print_threat_summary(threats)

    save_results(threats, args.output)
    print(f"\n[+] Threat modeling complete. {len(threats)} threats identified.")


if __name__ == "__main__":
    main()
