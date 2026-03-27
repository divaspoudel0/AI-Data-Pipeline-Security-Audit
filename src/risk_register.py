"""
risk_register.py
----------------
Generates and manages a structured risk register from threat model output.
Supports JSON export and Markdown table rendering.
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
from utils import severity_label, timestamp_now


def load_threat_model(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def build_risk_register(threat_model: dict, audit_id: str = None) -> dict:
    """Convert threat model output into a structured risk register."""
    threats = threat_model.get("threats", [])
    if audit_id is None:
        audit_id = f"AUDIT-{datetime.now().strftime('%Y%m%d')}-001"

    register_entries = []
    for idx, t in enumerate(threats, start=1):
        score = t["severity_score"]
        register_entries.append({
            "risk_id": f"R-{idx:03d}",
            "threat_id": t["threat_id"],
            "stage": t["stage"].replace("_", " ").title(),
            "threat_name": t["name"],
            "stride_category": t["stride"],
            "likelihood": t["likelihood"],
            "impact": t["impact"],
            "severity_score": score,
            "severity_label": severity_label(score),
            "iso_controls": t["iso_controls"],
            "mitigations": t["mitigations"],
            "status": "OPEN",
            "owner": "Security Team",
            "review_date": None,
        })

    # Sort by severity descending
    register_entries.sort(key=lambda x: x["severity_score"], reverse=True)

    high = sum(1 for r in register_entries if r["severity_label"] == "HIGH")
    medium = sum(1 for r in register_entries if r["severity_label"] == "MEDIUM")
    low = sum(1 for r in register_entries if r["severity_label"] == "LOW")

    return {
        "audit_id": audit_id,
        "generated_at": timestamp_now(),
        "summary": {
            "total_risks": len(register_entries),
            "high": high,
            "medium": medium,
            "low": low,
            "overall_rating": "HIGH" if high >= 3 else "MEDIUM" if high >= 1 else "LOW",
        },
        "risks": register_entries,
    }


def render_markdown_table(register: dict) -> str:
    """Render risk register as a Markdown table."""
    lines = [
        f"# Risk Register — {register['audit_id']}",
        f"_Generated: {register['generated_at']}_\n",
        "## Summary",
        f"- **Total Risks:** {register['summary']['total_risks']}",
        f"- **HIGH:** {register['summary']['high']}",
        f"- **MEDIUM:** {register['summary']['medium']}",
        f"- **LOW:** {register['summary']['low']}",
        f"- **Overall Rating:** **{register['summary']['overall_rating']}**\n",
        "## Risk Register\n",
        "| Risk ID | Stage | Threat | L | I | Score | Rating | ISO Controls |",
        "|---------|-------|--------|---|---|-------|--------|--------------|",
    ]
    for r in register["risks"]:
        iso = ", ".join(r["iso_controls"])
        lines.append(
            f"| {r['risk_id']} | {r['stage']} | {r['threat_name']} "
            f"| {r['likelihood']} | {r['impact']} | {r['severity_score']} "
            f"| **{r['severity_label']}** | {iso} |"
        )

    lines.append("\n## Mitigations by Risk\n")
    for r in register["risks"]:
        lines.append(f"### {r['risk_id']} — {r['threat_name']} ({r['severity_label']})")
        for m in r["mitigations"]:
            lines.append(f"- {m}")
        lines.append("")

    return "\n".join(lines)


def save_register(register: dict, json_path: str, md_path: str = None) -> None:
    Path(json_path).parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w") as f:
        json.dump(register, f, indent=2)
    print(f"[+] Risk register saved: {json_path}")

    if md_path:
        md = render_markdown_table(register)
        with open(md_path, "w") as f:
            f.write(md)
        print(f"[+] Markdown register saved: {md_path}")


def main():
    parser = argparse.ArgumentParser(description="Risk Register Generator")
    parser.add_argument("--threat-model", default="reports/threat_model.json")
    parser.add_argument("--output-json", default="reports/risk_register.json")
    parser.add_argument("--output-md", default="reports/risk_register.md")
    parser.add_argument("--audit-id", default=None)
    args = parser.parse_args()

    tm = load_threat_model(args.threat_model)
    register = build_risk_register(tm, args.audit_id)
    save_register(register, args.output_json, args.output_md)

    print(f"\n[+] Risk register complete.")
    print(f"    Total risks : {register['summary']['total_risks']}")
    print(f"    HIGH        : {register['summary']['high']}")
    print(f"    MEDIUM      : {register['summary']['medium']}")
    print(f"    LOW         : {register['summary']['low']}")
    print(f"    Rating      : {register['summary']['overall_rating']}")


if __name__ == "__main__":
    main()
