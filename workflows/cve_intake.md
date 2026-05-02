# Workflow: CVE Intake

## Objective
Accept a raw list of CVE IDs, validate their format, remove duplicates, and produce a clean ordered list ready for the enrichment pipeline.

## Required Inputs
- A file path to a `.txt` or `.csv` file containing CVE IDs (one per line or comma-separated), OR
- An inline comma-separated string of CVE IDs provided by the user

## Tools Required
- `tools/validate_cves.py`

## Process

### Step 1: Prepare input file
If the user provided CVE IDs inline (not a file path), write them to `.tmp/raw_input.txt`.

### Step 2: Run validation
```bash
python tools/validate_cves.py --input <input_file> --output .tmp/validated_cves.json
```

### Step 3: Review output
- Read `.tmp/validated_cves.json`
- Report validation summary to the user: total received, valid, invalid, duplicates removed
- Log any invalid entries with a note explaining the format requirement (`CVE-YYYY-NNNNN`)

### Step 4: Halt if no valid CVEs
If `total_valid == 0`, stop immediately and explain what valid CVE format looks like. Do not proceed to enrichment.

### Step 5: Warn on large batches
If `total_valid > 200`:
- Warn the user about estimated runtime:
  - Without NVD API key: ~200 CVEs × 6s delay = ~20 minutes for NVD alone
  - With NVD API key: ~200 CVEs × 0.65s = ~2.5 minutes
- Recommend obtaining a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key

## Expected Output
- `.tmp/validated_cves.json` — clean, deduplicated, sorted list

## Edge Cases
| Situation | Action |
|-----------|--------|
| Lowercase `cve-2024-1234` | Normalize to uppercase, accept |
| CVE IDs in a CSV column | Strip extra characters and commas, validate each token |
| GHSA IDs, RUSTSEC IDs | Log as invalid, do not accept |
| All inputs are duplicates | Return deduplicated list with warning |
| Mix of valid and invalid | Continue with valid subset, log invalid |
| File not found | Return clear error: "Input file not found: [path]" |

## Quality Checks
- [ ] All entries in `valid_cves` match `CVE-\d{4}-\d{4,}` format (uppercase)
- [ ] No duplicates in `valid_cves`
- [ ] Output file exists and is valid JSON
- [ ] User received a clear summary of validation results
