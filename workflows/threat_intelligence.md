# Workflow: Threat Intelligence

## Objective
Determine real-world threat context for each CVE: whether it is actively exploited (CISA KEV), how likely it is to be exploited soon (EPSS), and whether public exploit code exists (ExploitDB).

## Required Inputs
- `.tmp/validated_cves.json`

## Tools Required
- `tools/fetch_kev.py`
- `tools/fetch_epss.py`
- `tools/fetch_exploitdb.py`

## Process

### Step 1: Refresh the CISA KEV catalog
The full KEV catalog is ~2MB JSON and refreshes daily.
```bash
python tools/fetch_kev.py --refresh --output .tmp/kev_cache.json
```
The tool auto-skips refresh if the cache is less than 24 hours old.

### Step 2: Batch KEV lookup
```bash
python tools/fetch_kev.py --batch .tmp/validated_cves.json --cache .tmp/kev_cache.json --output .tmp/kev_results.json
```
Log the summary: how many CVEs are in the KEV catalog, and how many have known ransomware use.

### Step 3: Fetch EPSS scores
EPSS supports bulk queries (up to 100 CVEs per request). The tool chunks automatically.
```bash
python tools/fetch_epss.py --batch .tmp/validated_cves.json --output-dir .tmp/epss_raw/
```

**Interpreting EPSS:**
- Score > 0.7: Very high risk — flag to the user immediately
- Score > 0.3: Elevated risk — watch closely
- Score < 0.1: Low exploitation probability

When reporting to the user, always translate the raw score: "An EPSS score of 0.947 means there is a 94.7% probability this vulnerability will be exploited in the wild within the next 30 days based on threat intelligence models."

### Step 4: Check ExploitDB for public exploits
```bash
python tools/fetch_exploitdb.py --batch .tmp/validated_cves.json --output-dir .tmp/exploitdb_raw/ --delay 2.0
```
Use 2 seconds between requests to be a polite scraper. If ExploitDB blocks the scrape (HTTP 403 or connection reset), log the error as `source_error` in the output file but do NOT abort. Set `has_public_exploit=False` as a conservative assumption.

### Step 5: Log threat intel summary
Summarize for the user:
- N CVEs found in CISA KEV
- N CVEs with ransomware group association
- N CVEs with EPSS > 0.5
- N CVEs with public exploit code available

## Expected Outputs
- `.tmp/kev_cache.json` — full CISA KEV catalog
- `.tmp/kev_results.json` — per-CVE KEV lookup results
- `.tmp/epss_raw/CVE-XXXX.json` — per-CVE EPSS score
- `.tmp/exploitdb_raw/CVE-XXXX.json` — per-CVE exploit presence

## Edge Cases
| Situation | Action |
|-----------|--------|
| ExploitDB blocks scraping | Set `has_public_exploit=False`, log `source_error`; exploit bonus = 0 (conservative) |
| EPSS API down | Use previously cached `.tmp/epss_raw/` files if they exist; flag `epss_stale` |
| CVE not yet in EPSS | Write `epss_not_scored: true`, `epss_score: 0.0`; scoring engine handles gracefully |
| KEV API returns 5xx | Retry once after 10s; use stale cache if retry fails |
| Very new CVE (< 7 days old) | May not be in EPSS yet; expected; flag and continue |

## Quality Checks
- [ ] `.tmp/kev_results.json` exists and covers all validated CVEs
- [ ] All CVEs have an EPSS file (even if `epss_not_scored: true`)
- [ ] ExploitDB errors are noted but do not stop the pipeline
- [ ] Threat intel summary was logged with KEV and EPSS counts
