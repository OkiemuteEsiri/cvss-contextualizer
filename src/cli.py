import argparse
import csv
from pathlib import Path
from cvss_contextualizer import Finding, assess_all


def load_csv(path: Path) -> list[Finding]:
    out = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            controls = tuple(x.strip() for x in row.get("compensating_controls", "").split(";") if x.strip())
            out.append(Finding(
                finding_id=row["finding_id"], cve=row["cve"], cvss=float(row["cvss"]),
                severity=row["severity"], asset=row["asset"], asset_criticality=int(row["asset_criticality"]),
                internet_exposed=row["internet_exposed"].lower() == "true", kev=row["kev"].lower() == "true",
                exploit_maturity=row["exploit_maturity"], compensating_controls=controls, owner=row["owner"]
            ))
    return out


def render(findings: list[Finding]) -> str:
    assessments = assess_all(findings)
    lines = ["# Contextual Vulnerability Assessment", "", "| Finding | Score | Priority | SLA | Drivers |", "|---|---:|---|---:|---|"]
    for a in assessments:
        lines.append(f"| {a.finding_id} | {a.contextual_score} | {a.priority} | {a.remediation_sla_days}d | {'; '.join(a.drivers)} |")
    return "\n".join(lines) + "\n"


def main():
    p = argparse.ArgumentParser(description="Contextualize CVSS findings using defensive business and exposure context.")
    p.add_argument("input", type=Path)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    report = render(load_csv(args.input))
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report)


if __name__ == "__main__":
    main()
