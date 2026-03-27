"""
control_mapper.py
-----------------
Maps identified risks to ISO 27001:2022 Annex A controls.
Generates a control coverage report showing which controls are addressed,
which are gaps, and recommended implementation priorities.
"""

import json
import argparse
from pathlib import Path
from utils import timestamp_now, load_json


# ---------------------------------------------------------------------------
# ISO 27001:2022 Annex A — Relevant controls for AI pipelines
# ---------------------------------------------------------------------------

ISO_27001_CONTROLS = {
    "A.5.1":  {"title": "Policies for information security", "domain": "Organizational"},
    "A.5.12": {"title": "Classification of information", "domain": "Organizational"},
    "A.5.14": {"title": "Information transfer", "domain": "Organizational"},
    "A.5.15": {"title": "Access control", "domain": "Organizational"},
    "A.5.16": {"title": "Identity management", "domain": "Organizational"},
    "A.5.19": {"title": "Information security in supplier relationships", "domain": "Organizational"},
    "A.5.35": {"title": "Independent review of information security", "domain": "Organizational"},
    "A.6.3":  {"title": "Information security awareness, education and training", "domain": "People"},
    "A.6.6":  {"title": "Confidentiality or non-disclosure agreements", "domain": "People"},
    "A.8.2":  {"title": "Privileged access rights", "domain": "Technological"},
    "A.8.8":  {"title": "Management of technical vulnerabilities", "domain": "Technological"},
    "A.8.15": {"title": "Logging", "domain": "Technological"},
    "A.8.16": {"title": "Monitoring activities", "domain": "Technological"},
    "A.8.24": {"title": "Use of cryptography", "domain": "Technological"},
    "A.8.29": {"title": "Security testing in development and acceptance", "domain": "Technological"},
    "A.8.32": {"title": "Change management", "domain": "Technological"},
}


def map_controls(risk_register: dict) -> dict:
    """Map each risk in the register to its ISO 27001 controls."""
    risks = risk_register.get("risks", [])
    control_to_risks: dict = {}

    for risk in risks:
        for control_id in risk.get("iso_controls", []):
            if control_id not in control_to_risks:
                control_to_risks[control_id] = []
            control_to_risks[control_id].append({
                "risk_id": risk["risk_id"],
                "threat_name": risk["threat_name"],
                "severity": risk["severity_label"],
            })

    addressed = set(control_to_risks.keys())
    all_controls = set(ISO_27001_CONTROLS.keys())
    gaps = all_controls - addressed

    mapped = {}
    for ctrl_id, info in ISO_27001_CONTROLS.items():
        mapped[ctrl_id] = {
            **info,
            "control_id": ctrl_id,
            "status": "ADDRESSED" if ctrl_id in addressed else "GAP",
            "linked_risks": control_to_risks.get(ctrl_id, []),
        }

    # Priority gaps — controls linked to no identified risk but critical for AI pipelines
    priority_gaps = [
        ctrl_id for ctrl_id in gaps
        if ctrl_id in {"A.5.1", "A.6.3", "A.8.16", "A.8.32"}
    ]

    return {
        "timestamp": timestamp_now(),
        "total_controls_evaluated": len(ISO_27001_CONTROLS),
        "controls_addressed": len(addressed),
        "control_gaps": len(gaps),
        "priority_gaps": priority_gaps,
        "coverage_percent": round(len(addressed) / len(ISO_27001_CONTROLS) * 100, 1),
        "controls": mapped,
    }


def render_markdown(mapping: dict) -> str:
    lines = [
        "# ISO 27001:2022 Control Coverage Report",
        f"_Generated: {mapping['timestamp']}_\n",
        "## Coverage Summary",
        f"- **Controls Evaluated:** {mapping['total_controls_evaluated']}",
        f"- **Addressed:** {mapping['controls_addressed']}",
        f"- **Gaps:** {mapping['control_gaps']}",
        f"- **Coverage:** {mapping['coverage_percent']}%\n",
    ]

    if mapping["priority_gaps"]:
        lines.append("## Priority Gaps (Recommended for Immediate Action)\n")
        for ctrl_id in mapping["priority_gaps"]:
            ctrl = mapping["controls"][ctrl_id]
            lines.append(f"- **{ctrl_id}** — {ctrl['title']}")
        lines.append("")

    lines += [
        "## Control Detail\n",
        "| Control ID | Title | Domain | Status | Linked Risks |",
        "|-----------|-------|--------|--------|--------------|",
    ]
    for ctrl_id, ctrl in sorted(mapping["controls"].items()):
        linked = ", ".join(r["risk_id"] for r in ctrl["linked_risks"]) or "—"
        status = "✅ Addressed" if ctrl["status"] == "ADDRESSED" else "⚠️ Gap"
        lines.append(f"| {ctrl_id} | {ctrl['title']} | {ctrl['domain']} | {status} | {linked} |")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="ISO 27001 Control Mapper")
    parser.add_argument("--risk-register", default="reports/risk_register.json")
    parser.add_argument("--output-json", default="reports/control_mapping.json")
    parser.add_argument("--output-md", default="reports/control_mapping.md")
    args = parser.parse_args()

    rr = load_json(args.risk_register)
    mapping = map_controls(rr)

    Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output_json, "w") as f:
        json.dump(mapping, f, indent=2)
    print(f"[+] Control mapping saved: {args.output_json}")

    md = render_markdown(mapping)
    with open(args.output_md, "w") as f:
        f.write(md)
    print(f"[+] Markdown report saved: {args.output_md}")

    print(f"\n[+] Coverage: {mapping['coverage_percent']}% ({mapping['controls_addressed']}/{mapping['total_controls_evaluated']} controls addressed)")
    if mapping["priority_gaps"]:
        print(f"[!] Priority gaps: {', '.join(mapping['priority_gaps'])}")


if __name__ == "__main__":
    main()
