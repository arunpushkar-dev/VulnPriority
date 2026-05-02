# Workflow: Scoring

## Objective
Apply the composite prioritization scoring formula to all enriched CVEs and assign priority categories with patch timelines. Produce a ranked summary for the CISO.

## Required Inputs
- `.tmp/enriched/` — directory of `EnrichedCVE` JSON files

## Tools Required
- `tools/calculate_score.py`

## Scoring Formula
```
CVSS_COMPONENT   = (cvss_base / 10.0) × 30    [max 30 pts, weights CVSS severity]
EPSS_COMPONENT   = epss_score × 35             [max 35 pts, weights exploitation probability]
BASE_SCORE       = CVSS_COMPONENT + EPSS_COMPONENT

KEV_BONUS        = +20 if in CISA KEV catalog
EXPLOIT_BONUS    = +15 if full public exploit available
                 = +8  if PoC only
RANSOMWARE_BONUS = +10 if KEV entry ransomware_use == "Known"

COMPOSITE_SCORE  = min(BASE + bonuses, 100)
```

**Why these weights?** EPSS is weighted slightly higher than CVSS because it is a better predictor of real-world exploitation. CVSS measures theoretical severity; EPSS measures actual exploitation likelihood based on live threat intelligence. KEV membership is the strongest single signal and receives a large fixed bonus.

## Priority Category Assignment
| Score    | Category | Patch Timeline |
|----------|----------|----------------|
| ≥ 80     | Critical | Patch within 24 hours |
| 60 – 79  | High     | Patch within 7 days |
| 40 – 59  | Medium   | Patch within 30 days |
| < 40     | Low      | Patch within 90 days |
| None     | Unscored | Manual review required |

## Process

### Step 1: Run scoring
```bash
python tools/calculate_score.py --enriched-dir .tmp/enriched/ --output-dir .tmp/scored/
```

### Step 2: Review summary
The tool writes `.tmp/score_summary.json` and prints a table. Review and log:
- Distribution across priority categories
- Top 5 CVEs by score
- Any CVEs flagged as `insufficient_data` (both CVSS and EPSS missing)

### Step 3: Do not modify formula weights
The formula weights are set. Do not adjust them unless explicitly instructed. If you believe a specific CVE is mis-prioritized, document the reasoning in the audit log rather than adjusting weights.

### Step 4: Log all scoring decisions
Each `ScoredCVE` output includes `score_reasoning` — a human-readable explanation of each component's contribution. This is the basis for the audit trail and CISO explainability.

### Step 5: Handle edge cases
- CVSS missing, EPSS present: score from EPSS only; flag `cvss_missing`
- EPSS missing, CVSS present: score from CVSS only; flag `epss_missing`
- Both missing: `composite_score = null`; show as "Unscored" in report; flag `insufficient_data`
- CVSS v4.0 available: prefer over v3.1; note which version was used

## Expected Outputs
- `.tmp/scored/CVE-XXXX.json` — `ScoredCVE` per CVE
- `.tmp/score_summary.json` — ranked list of all CVEs

## Quality Checks
- [ ] All CVEs from `.tmp/enriched/` have a corresponding scored file
- [ ] Every scored file has `priority_category` and `patch_timeline`
- [ ] `score_reasoning` field is populated (not empty) for all scored CVEs
- [ ] CVEs with `insufficient_data` are present in output but flagged, not silently dropped
- [ ] Score summary is sorted by `composite_score` descending
