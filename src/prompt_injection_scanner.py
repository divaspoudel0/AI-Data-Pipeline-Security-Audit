"""
prompt_injection_scanner.py
---------------------------
Scans annotation datasets for prompt injection payloads.

Detects both:
  - Direct prompt injection: adversarial instructions targeting LLM annotation tools
  - Indirect injection: encoded / obfuscated payloads in annotated text

Pattern library covers common attack categories:
  - Role override ("ignore previous instructions")
  - System prompt extraction ("reveal your system prompt")
  - Tool/code execution triggers
  - Jailbreak patterns (DAN, AIM, etc.)
  - Data exfiltration hooks
"""

import re
import json
import argparse
from pathlib import Path
from utils import timestamp_now, load_json


# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------

INJECTION_PATTERNS = [
    # Role override
    {"id": "PI-001", "severity": "HIGH", "category": "Role Override",
     "pattern": r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?",
     "description": "Classic role override — instructs LLM to ignore prior context."},

    {"id": "PI-002", "severity": "HIGH", "category": "Role Override",
     "pattern": r"(disregard|forget|override)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?)",
     "description": "Instruction to disregard system-level directives."},

    {"id": "PI-003", "severity": "HIGH", "category": "Role Override",
     "pattern": r"you\s+are\s+now\s+(a\s+)?(new|different|unrestricted|jailbroken)",
     "description": "Attempts to redefine LLM identity/role."},

    # System prompt extraction
    {"id": "PI-004", "severity": "HIGH", "category": "System Prompt Extraction",
     "pattern": r"(print|reveal|show|output|repeat|tell me)\s+(your\s+)?(system\s+prompt|instructions?|initial prompt)",
     "description": "Attempts to extract system prompt or hidden instructions."},

    {"id": "PI-005", "severity": "MEDIUM", "category": "System Prompt Extraction",
     "pattern": r"what\s+(are|were)\s+your\s+(original\s+)?(instructions?|rules?|guidelines?)",
     "description": "Social engineering to reveal configuration."},

    # Jailbreak patterns
    {"id": "PI-006", "severity": "HIGH", "category": "Jailbreak",
     "pattern": r"\bDAN\b.{0,50}(mode|enabled|activated|prompt)",
     "description": "DAN (Do Anything Now) jailbreak pattern."},

    {"id": "PI-007", "severity": "HIGH", "category": "Jailbreak",
     "pattern": r"developer\s+mode|jailbreak(\s+mode)?|unrestricted\s+mode",
     "description": "Generic jailbreak mode activation attempt."},

    {"id": "PI-008", "severity": "MEDIUM", "category": "Jailbreak",
     "pattern": r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(AI\s+)?(without|that\s+has\s+no)\s+restrictions?",
     "description": "Roleplay-based restriction bypass."},

    # Code/tool execution
    {"id": "PI-009", "severity": "HIGH", "category": "Code Execution",
     "pattern": r"(run|execute|eval|exec)\s+(this\s+)?(code|script|command|python|bash|shell)",
     "description": "Attempts to trigger code execution via annotation tool."},

    {"id": "PI-010", "severity": "HIGH", "category": "Code Execution",
     "pattern": r"<script[\s>]|javascript:|onerror=|onload=|eval\(",
     "description": "XSS/script injection payload detected."},

    # Data exfiltration
    {"id": "PI-011", "severity": "HIGH", "category": "Data Exfiltration",
     "pattern": r"(send|post|fetch|http(s)?://|curl\s|wget\s).{0,50}(api|endpoint|server|hook)",
     "description": "Attempts to exfiltrate data via HTTP requests from LLM tool."},

    {"id": "PI-012", "severity": "MEDIUM", "category": "Data Exfiltration",
     "pattern": r"(list|show|return|output)\s+(all\s+)?(user|annotator|client|private)\s+(data|records?|files?)",
     "description": "Attempts to retrieve private data from context."},

    # Delimiter injection
    {"id": "PI-013", "severity": "MEDIUM", "category": "Delimiter Injection",
     "pattern": r"(###\s*system|<\|system\|>|\[SYSTEM\]|<<SYS>>)",
     "description": "Attempts to inject fake system message delimiters."},

    {"id": "PI-014", "severity": "MEDIUM", "category": "Delimiter Injection",
     "pattern": r"(###\s*instruction|<\|instruction\|>|\[INST\]|<\|im_start\|>)",
     "description": "LLM instruction delimiter injection (Llama/Mistral format)."},
]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan_text(text: str) -> list[dict]:
    """Scan a single text string for injection patterns."""
    if not text or not isinstance(text, str):
        return []
    findings = []
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern["pattern"], text, re.IGNORECASE):
            findings.append({
                "pattern_id": pattern["id"],
                "severity": pattern["severity"],
                "category": pattern["category"],
                "description": pattern["description"],
            })
    return findings


def scan_annotation(annotation: dict, text_fields: list[str] = None) -> dict | None:
    """Scan a single annotation record across all text fields."""
    if text_fields is None:
        text_fields = ["text", "source_text", "annotation", "label_reason", "comment", "content", "input"]

    all_findings = []
    fields_scanned = []

    for field in text_fields:
        value = annotation.get(field)
        if isinstance(value, str) and value.strip():
            findings = scan_text(value)
            if findings:
                for f in findings:
                    f["field"] = field
                    f["excerpt"] = value[:120] + ("..." if len(value) > 120 else "")
                all_findings.extend(findings)
            fields_scanned.append(field)

    if all_findings:
        return {
            "annotation_id": annotation.get("id", annotation.get("annotation_id", "UNKNOWN")),
            "annotator_id": annotation.get("annotator_id", "UNKNOWN"),
            "fields_scanned": fields_scanned,
            "findings": all_findings,
            "max_severity": "HIGH" if any(f["severity"] == "HIGH" for f in all_findings) else "MEDIUM",
        }
    return None


def scan_dataset(annotations: list[dict]) -> dict:
    """Scan an entire annotation dataset."""
    results = []
    for annotation in annotations:
        result = scan_annotation(annotation)
        if result:
            results.append(result)

    high = sum(1 for r in results if r["max_severity"] == "HIGH")
    medium = sum(1 for r in results if r["max_severity"] == "MEDIUM")

    # Category breakdown
    category_counts: dict = {}
    for r in results:
        for f in r["findings"]:
            cat = f["category"]
            category_counts[cat] = category_counts.get(cat, 0) + 1

    return {
        "timestamp": timestamp_now(),
        "total_scanned": len(annotations),
        "total_flagged": len(results),
        "high_severity": high,
        "medium_severity": medium,
        "category_breakdown": category_counts,
        "flagged_annotations": results,
    }


def print_summary(result: dict) -> None:
    print(f"\n{'='*60}")
    print(f"  PROMPT INJECTION SCAN RESULTS")
    print(f"{'='*60}")
    print(f"  Scanned       : {result['total_scanned']} annotations")
    print(f"  Flagged       : {result['total_flagged']}")
    print(f"  HIGH severity : {result['high_severity']}")
    print(f"  MEDIUM        : {result['medium_severity']}")
    if result["category_breakdown"]:
        print(f"\n  Category breakdown:")
        for cat, count in sorted(result["category_breakdown"].items(), key=lambda x: -x[1]):
            print(f"    {cat:<30} {count} occurrences")
    if result["flagged_annotations"]:
        print(f"\n  Flagged records:")
        for r in result["flagged_annotations"]:
            print(f"    [{r['max_severity']:6s}] ID={r['annotation_id']} | Annotator={r['annotator_id']} | {len(r['findings'])} pattern(s)")
            for f in r["findings"]:
                print(f"           -> [{f['pattern_id']}] {f['category']} in field '{f['field']}'")


def main():
    parser = argparse.ArgumentParser(description="Prompt Injection Scanner for AI Annotation Datasets")
    parser.add_argument("--input", required=True, help="Path to annotations JSON file")
    parser.add_argument("--output", default="reports/injection_scan.json")
    parser.add_argument("--fields", nargs="*", default=None, help="Text fields to scan (default: auto-detect)")
    args = parser.parse_args()

    print(f"[*] Loading {args.input}...")
    data = load_json(args.input)
    annotations = data if isinstance(data, list) else data.get("annotations", [])

    print(f"[*] Scanning {len(annotations)} annotations for prompt injection patterns...")
    result = scan_dataset(annotations)

    print_summary(result)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\n[+] Scan report saved: {args.output}")


if __name__ == "__main__":
    main()
