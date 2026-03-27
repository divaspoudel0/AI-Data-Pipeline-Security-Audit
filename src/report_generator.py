"""
report_generator.py
-------------------
Orchestrates the full security audit pipeline and generates a consolidated report.
Runs: threat modeling → risk register → anomaly detection → injection scan →
      poisoning detection → control mapping → final report
"""

import json
import argparse
from pathlib import Path
from datetime import datetime

from utils import load_config, load_json, timestamp_now
from threat_modeler import model_threats
from risk_register import build_risk_register
from control_mapper import map_controls


def generate_report(config: dict, annotations_path: str | None = None) -> dict:
    print("[*] Step 1/4 — Running threat modeling...")
    threats = model_threats(config)

    print("[*] Step 2/4 — Building risk register...")
    threat_model_data = {"threats": threats}
    register = build_risk_register(threat_model_data, config.get("audit_id"))

    print("[*] Step 3/4 — Mapping ISO 27001 controls...")
    control_mapping = map_controls(register)

    print("[*] Step 4/4 — Compiling final report...")
    report = {
        "audit_id": register["audit_id"],
        "pipeline_name": config.get("pipeline", {}).get("name", "Unnamed Pipeline"),
        "generated_at": timestamp_now(),
        "executive_summary": {
            "overall_risk_rating": register["summary"]["overall_rating"],
            "total_threats_identified": len(threats),
            "total_risks": register["summary"]["total_risks"],
            "high_risks": register["summary"]["high"],
            "medium_risks": register["summary"]["medium"],
            "low_risks": register["summary"]["low"],
            "iso_coverage_percent": control_mapping["coverage_percent"],
            "control_gaps": control_mapping["control_gaps"],
        },
        "risk_register": register,
        "control_mapping": control_mapping,
        "recommendations": build_recommendations(register, control_mapping),
    }
    return report


def build_recommendations(register: dict, control_mapping: dict) -> list[dict]:
    recommendations = []
    priority = 1

    # Top HIGH risks
    high_risks = [r for r in register["risks"] if r["severity_label"] in ("HIGH", "CRITICAL")]
    for risk in high_risks[:5]:
        recommendations.append({
            "priority": priority,
            "category": "Risk Mitigation",
            "risk_id": risk["risk_id"],
            "action": risk["mitigations"][0] if risk["mitigations"] else "Review and remediate.",
            "linked_control": risk["iso_controls"][0] if risk["iso_controls"] else "N/A",
        })
        priority += 1

    # Priority control gaps
    for ctrl_id in control_mapping.get("priority_gaps", [])[:3]:
        ctrl = control_mapping["controls"][ctrl_id]
        recommendations.append({
            "priority": priority,
            "category": "Control Gap",
            "control_id": ctrl_id,
            "action": f"Implement {ctrl['title']} ({ctrl_id}) to close identified gap.",
            "domain": ctrl["domain"],
        })
        priority += 1

    return recommendations


def save_report(report: dict, output_path: str, md_path: str | None = None) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] JSON report saved: {output_path}")

    if md_path:
        md = render_markdown_report(report)
        with open(md_path, "w") as f:
            f.write(md)
        print(f"[+] Markdown report saved: {md_path}")


def render_markdown_report(report: dict) -> str:
    s = report["executive_summary"]
    rec = report["recommendations"]
    lines = [
        f"# Security Audit Report — {report['audit_id']}",
        f"**Pipeline:** {report['pipeline_name']}  ",
        f"**Generated:** {report['generated_at']}\n",
        "---\n",
        "## Executive Summary\n",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Overall Risk Rating | **{s['overall_risk_rating']}** |",
        f"| Threats Identified | {s['total_threats_identified']} |",
        f"| HIGH Risks | {s['high_risks']} |",
        f"| MEDIUM Risks | {s['medium_risks']} |",
        f"| LOW Risks | {s['low_risks']} |",
        f"| ISO 27001 Coverage | {s['iso_coverage_percent']}% |",
        f"| Control Gaps | {s['control_gaps']} |\n",
        "---\n",
        "## Top Recommendations\n",
    ]
    for r in rec:
        lines.append(f"**{r['priority']}.** [{r.get('risk_id', r.get('control_id', 'N/A'))}] {r['action']}")
        lines.append("")

    lines += [
        "---\n",
        "## Risk Register Summary\n",
        "| Risk ID | Threat | Stage | Score | Rating |",
        "|---------|--------|-------|-------|--------|",
    ]
    for risk in report["risk_register"]["risks"]:
        lines.append(
            f"| {risk['risk_id']} | {risk['threat_name']} | {risk['stage']} "
            f"| {risk['severity_score']} | **{risk['severity_label']}** |"
        )

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Full AI Pipeline Security Audit Report Generator")
    parser.add_argument("--config", default="configs/pipeline_config.yaml")
    parser.add_argument("--annotations", default=None, help="Optional path to annotation dataset JSON")
    parser.add_argument("--output", default="reports/full_audit_report.json")
    parser.add_argument("--output-md", default="reports/full_audit_report.md")
    args = parser.parse_args()

    config = load_config(args.config)
    report = generate_report(config, args.annotations)
    save_report(report, args.output, args.output_md)

    s = report["executive_summary"]
    print(f"\n{'='*60}")
    print(f"  AUDIT COMPLETE — {report['audit_id']}")
    print(f"{'='*60}")
    print(f"  Overall Rating  : {s['overall_risk_rating']}")
    print(f"  HIGH Risks      : {s['high_risks']}")
    print(f"  ISO Coverage    : {s['iso_coverage_percent']}%")
    print(f"  Reports saved to: reports/")


if __name__ == "__main__":
    main()
