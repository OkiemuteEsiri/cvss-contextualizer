# Example Contextual Vulnerability Assessment

This static example illustrates the expected reporting format using only synthetic records.

| Finding | Context | Illustrative priority | Validation focus |
|---|---|---|---|
| F-1001 | Critical CVSS, internet exposed, KEV, weaponized exploit maturity, critical asset | P0 | Patch/upgrade, re-scan exposed component, confirm KEV condition cleared |
| F-1002 | High CVSS, critical business asset, internal, functional exploit maturity | P1/P2 depending on calibrated weights | Validate patch and segmentation boundary |
| F-1004 | Medium CVSS, internet exposed, no assigned owner | Elevated governance priority | Assign owner, remediate component, verify external exposure |

## Executive interpretation

CVSS alone does not express whether an asset is externally reachable, business-critical, associated with known exploitation, or protected by compensating controls. The contextual model preserves CVSS while surfacing those operational factors as transparent scoring drivers.

## Closure standard

A reduced contextual score is not closure evidence. Closure requires technical remediation plus revalidation of the affected component. Temporary controls should remain documented as exceptions until the underlying vulnerability is removed or formally accepted.
