# Workflow: Context Enrichment

## Objective
Map CVEs to MITRE ATT&CK techniques, and merge all raw per-source data into unified `EnrichedCVE` records that feed into scoring.

## Required Inputs
- `.tmp/validated_cves.json`
- `.tmp/nvd_raw/` (for CWE data)
- `.tmp/osv_raw/`
- `.tmp/kev_results.json`
- `.tmp/epss_raw/`
- `.tmp/exploitdb_raw/`

## Tools Required
- `tools/fetch_attack.py`
- `tools/merge_enrichment.py`

## Process

### Step 1: Download/refresh ATT&CK bundle
The MITRE ATT&CK enterprise STIX bundle is ~50MB and cached for 7 days.
```bash
python tools/fetch_attack.py --cache .tmp/attack_cache.json
```
The tool auto-refreshes if cache is older than 7 days. On first run, this downloads ~50MB from GitHub.

### Step 2: Map CVEs to ATT&CK techniques
```bash
python tools/fetch_attack.py --batch .tmp/validated_cves.json --cache .tmp/attack_cache.json --output-dir .tmp/attack_raw/
```
The mapping searches STIX technique objects for `external_references` where `source_name == "cve"` and `external_id` matches the CVE ID. Not all CVEs map to ATT&CK techniques — this is normal.

### Step 3: Merge all enrichment sources
```bash
python tools/merge_enrichment.py \
  --cves .tmp/validated_cves.json \
  --nvd-dir .tmp/nvd_raw/ \
  --osv-dir .tmp/osv_raw/ \
  --kev .tmp/kev_results.json \
  --epss-dir .tmp/epss_raw/ \
  --exploitdb-dir .tmp/exploitdb_raw/ \
  --attack-dir .tmp/attack_raw/ \
  --output-dir .tmp/enriched/
```

The merge tool:
- Reads each per-source file for a CVE
- Combines into a single `EnrichedCVE` JSON
- Records which sources contributed (enrichment completeness 0–6)
- Records errors for missing or failed sources

### Step 4: Review enrichment completeness
Log how many CVEs have ≥3 sources vs. partial enrichment. CVEs with only 1–2 sources are scored conservatively.

**Data authority rules:**
- NVD is authoritative for CVSS scores and CWE classification
- OSV is authoritative for package-level affected version ranges
- CISA KEV is authoritative for known exploitation status
- EPSS is the primary predictor of near-term exploitation

## Expected Outputs
- `.tmp/attack_raw/CVE-XXXX.json` — per-CVE ATT&CK mapping
- `.tmp/enriched/CVE-XXXX.json` — unified `EnrichedCVE` per CVE

## Edge Cases
| Situation | Action |
|-----------|--------|
| ATT&CK GitHub is down | Use existing cache; if no cache exists, skip ATT&CK and continue without it |
| CVE has no ATT&CK mapping | Write `techniques: []`; not an error |
| NVD file missing for a CVE | Write `nvd: null` in enriched; note in `enrichment_errors` |
| Multiple CWE IDs in NVD | Include all; scoring engine uses the first for action recommendations |
| OSV has package data, NVD doesn't | Use OSV affected_packages for product context |

## Quality Checks
- [ ] All CVEs have a file in `.tmp/enriched/`
- [ ] Enriched files have the `EnrichedCVE` structure
- [ ] Enrichment errors are populated (not missing) for each partial result
- [ ] Completeness summary logged (how many sources contributed per CVE)
