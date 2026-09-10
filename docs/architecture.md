# Architecture and Methodology

## Purpose

This project demonstrates how vulnerability teams can retain CVSS as a technical severity signal while adding business and exposure context for remediation prioritization. It is intentionally offline and uses synthetic data only.

## Flow

`CSV inventory -> strict model validation -> contextual scoring -> deterministic priority/SLA -> Markdown report`

## Context dimensions

- CVSS base score: technical severity anchor.
- Asset criticality: 1-5 business importance scale.
- Internet exposure: reachability/exposure multiplier.
- CISA KEV context: known-exploited-vulnerability urgency indicator.
- Exploit maturity: none, proof-of-concept, functional, or weaponized.
- Compensating controls: bounded risk-reduction credit rather than risk elimination.
- Ownership: unassigned findings receive a governance-risk increment.

## Risk model

The score is explainable and bounded to 0-100. It is a prioritization model, not a replacement for CVSS, EPSS, threat intelligence, or analyst judgment. Control credits are deliberately capped to prevent defensive controls from masking material inherent risk.

## Priority model

| Contextual score | Priority | Illustrative remediation SLA |
|---:|---|---:|
| 85-100 | P0 | 3 days |
| 70-84 | P1 | 7 days |
| 50-69 | P2 | 30 days |
| 0-49 | P3 | 90 days |

Organizations should replace these illustrative thresholds with approved policy.

## Remediation and validation workflow

1. Confirm asset identity, owner, exposure, and business criticality.
2. Confirm vulnerability evidence and applicable affected component.
3. Prioritize using contextual score and documented drivers.
4. Remediate by patching, upgrading, removing the vulnerable component, or applying an approved temporary control.
5. Re-scan or otherwise revalidate the affected component.
6. Re-run contextualization with updated evidence.
7. Close only after technical validation; do not treat a lower score as proof of remediation.

## MITRE ATT&CK context

Where applicable, prioritized exposure can support defensive analysis of techniques such as **T1190 - Exploit Public-Facing Application** and **T1210 - Exploitation of Remote Services**. ATT&CK mappings here are threat-model context, not evidence that exploitation occurred.

## Limitations

- No live scanner or asset-management integration.
- No external KEV/EPSS API calls.
- Synthetic data only.
- Weights are illustrative and require governance/calibration before enterprise use.
- A contextual score is not a probability of compromise.
