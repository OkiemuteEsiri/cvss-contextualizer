"""Defensive CVSS contextualization engine for synthetic vulnerability-management data."""
from dataclasses import dataclass
from typing import Iterable

SEVERITY_WEIGHT = {"LOW": 10, "MEDIUM": 30, "HIGH": 55, "CRITICAL": 75}


@dataclass(frozen=True)
class Finding:
    finding_id: str
    cve: str
    cvss: float
    severity: str
    asset: str
    asset_criticality: int
    internet_exposed: bool = False
    kev: bool = False
    exploit_maturity: str = "none"
    compensating_controls: tuple[str, ...] = ()
    owner: str = "unassigned"

    def __post_init__(self):
        if not self.finding_id.strip() or not self.asset.strip():
            raise ValueError("finding_id and asset are required")
        if not 0.0 <= self.cvss <= 10.0:
            raise ValueError("cvss must be between 0 and 10")
        if self.severity.upper() not in SEVERITY_WEIGHT:
            raise ValueError("unsupported severity")
        if not 1 <= self.asset_criticality <= 5:
            raise ValueError("asset_criticality must be 1..5")
        if self.exploit_maturity not in {"none", "poc", "functional", "weaponized"}:
            raise ValueError("unsupported exploit_maturity")


@dataclass(frozen=True)
class Assessment:
    finding_id: str
    contextual_score: int
    priority: str
    drivers: tuple[str, ...]
    remediation_sla_days: int


def _control_credit(controls: Iterable[str]) -> int:
    normalized = {c.strip().lower() for c in controls if c.strip()}
    credits = {
        "network segmentation": 8,
        "waf": 6,
        "edr": 5,
        "application allowlisting": 6,
        "mfa": 4,
    }
    return min(15, sum(credits.get(c, 0) for c in normalized))


def contextualize(f: Finding) -> Assessment:
    score = round(f.cvss * 7)
    drivers = [f"CVSS {f.cvss:.1f}"]

    criticality_add = (f.asset_criticality - 1) * 4
    score += criticality_add
    if criticality_add:
        drivers.append(f"asset criticality {f.asset_criticality}/5")

    if f.internet_exposed:
        score += 10
        drivers.append("internet exposed")
    if f.kev:
        score += 18
        drivers.append("CISA KEV context")

    exploit_add = {"none": 0, "poc": 4, "functional": 8, "weaponized": 12}[f.exploit_maturity]
    score += exploit_add
    if exploit_add:
        drivers.append(f"exploit maturity: {f.exploit_maturity}")

    credit = _control_credit(f.compensating_controls)
    if credit:
        score -= credit
        drivers.append(f"compensating-control credit -{credit}")

    if f.owner == "unassigned":
        score += 5
        drivers.append("no remediation owner")

    score = max(0, min(100, score))
    if score >= 85:
        priority, sla = "P0", 3
    elif score >= 70:
        priority, sla = "P1", 7
    elif score >= 50:
        priority, sla = "P2", 30
    else:
        priority, sla = "P3", 90

    return Assessment(f.finding_id, score, priority, tuple(drivers), sla)


def assess_all(findings: Iterable[Finding]) -> list[Assessment]:
    items = list(findings)
    ids = [f.finding_id for f in items]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate finding_id")
    return sorted((contextualize(f) for f in items), key=lambda a: (-a.contextual_score, a.finding_id))
