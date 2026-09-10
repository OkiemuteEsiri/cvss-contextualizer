# CVSS Contextualizer

A defensive Vulnerability Management / Security Engineering project that demonstrates how to retain **CVSS** as the technical severity anchor while adding operational context such as business criticality, internet exposure, CISA KEV relevance, exploit maturity, compensating controls, and remediation ownership.

This repository is intentionally offline and uses synthetic data only. It does not target production systems, perform exploitation, or claim compromise.

## Problem statement

CVSS is useful for expressing technical severity, but vulnerability programs often need additional context to decide what should be remediated first. Two findings with the same CVSS score can have materially different urgency when one is internet-facing, business-critical, known exploited, or unowned.

This project builds an explainable contextual scoring pipeline rather than replacing CVSS with an opaque score.

## Architecture

```text
Synthetic CSV findings
        |
        v
Strict validation model
        |
        v
Context enrichment
  - asset criticality
  - internet exposure
  - KEV context
  - exploit maturity
  - compensating controls
  - ownership
        |
        v
Bounded 0-100 score
        |
        v
P0-P3 priority + illustrative SLA
        |
        v
Markdown assessment report
```

See [`docs/architecture.md`](docs/architecture.md) for the detailed methodology, governance assumptions, remediation workflow, and limitations.

## Repository structure

```text
.
├── .github/workflows/security-quality.yml
├── data/synthetic_findings.csv
├── docs/architecture.md
├── reports/example_assessment.md
├── src/
│   ├── cli.py
│   └── cvss_contextualizer.py
└── tests/test_contextualizer.py
```

## Implemented controls and engineering features

- Immutable validated finding model.
- CVSS range and asset-criticality validation.
- Explainable contextual risk drivers.
- Capped compensating-control credits so controls cannot erase material risk.
- Additional governance risk for unassigned remediation ownership.
- Deterministic P0-P3 prioritization and illustrative remediation SLAs.
- Duplicate finding-ID rejection.
- Deterministic sorting by contextual risk.
- Offline CSV ingestion and Markdown reporting.
- Eight unit tests covering validation, risk drivers, controls, ordering, and duplicate handling.
- Least-privilege GitHub Actions workflow with source compilation, tests, and CLI smoke validation.

## Example usage

```bash
python src/cli.py data/synthetic_findings.csv
```

Write a report:

```bash
python src/cli.py data/synthetic_findings.csv --output contextual-report.md
```

Run the tests:

```bash
python -m unittest discover -s tests -v
```

## Risk methodology

The scoring engine uses CVSS as the baseline and then adjusts for operational context. Important design choices include:

- **Internet exposure** increases urgency because reachability can materially change exploitability.
- **KEV context** receives a strong uplift because known exploitation is a materially different threat condition.
- **Exploit maturity** differentiates theoretical exposure from more practical exploitability.
- **Asset criticality** incorporates business impact.
- **Compensating controls** reduce risk only within a bounded limit.
- **Missing ownership** increases governance risk because unowned findings are less likely to be remediated predictably.

The model is illustrative. Enterprise thresholds and weights should be approved through security governance and calibrated against historical remediation and incident data.

## Remediation and validation workflow

1. Validate finding identity, affected component, asset, owner, and exposure.
2. Confirm business criticality and threat context.
3. Prioritize remediation using the contextual score plus analyst judgment.
4. Patch, upgrade, remove the vulnerable component, or apply an approved temporary mitigation.
5. Re-scan or otherwise technically validate the affected component.
6. Re-run contextualization with the updated evidence.
7. Close only when remediation is technically verified; a lower score alone is not closure evidence.

## MITRE ATT&CK context

Where relevant, exposure prioritization can support defensive threat modelling for:

- **T1190 — Exploit Public-Facing Application**
- **T1210 — Exploitation of Remote Services**

These mappings provide defensive context only. They are not evidence that exploitation occurred.

## Example output

See [`reports/example_assessment.md`](reports/example_assessment.md) for a synthetic executive-style assessment showing how CVSS, exposure, KEV status, ownership, and controls influence prioritization.

## Skills demonstrated

- Vulnerability Management program design
- CVSS contextualization
- risk-based vulnerability prioritization
- asset criticality modelling
- exposure management
- KEV-aware remediation prioritization
- compensating-control governance
- remediation SLA design
- Python security engineering
- data validation
- unit testing
- CI/CD security-quality checks
- technical risk communication

## Limitations

- No live scanner, CMDB, or security-platform integration.
- No external KEV or EPSS API calls.
- No production asset data or credentials.
- Synthetic data only.
- Context weights are illustrative, not an enterprise policy recommendation.
- The score is not a probability of compromise.

## Roadmap

- Add EPSS as a separately explainable threat-likelihood signal.
- Add configurable policy files for score weights and SLA bands.
- Add exception-expiry and residual-risk tracking.
- Add historical trend comparisons between CVSS-only and contextual prioritization.
- Add JSON output for dashboard ingestion.
- Add schema-versioned adapters for common scanner exports using sanitized fixtures.

## Safety and ethics

This project is defensive. It contains no exploit payloads, credential harvesting, production targeting, or confidential employer/client data. All sample records are fictional.
