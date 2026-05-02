# Workflow: Report Generation

## Objective
Produce the final CISO-facing deliverable: a self-contained HTML report and/or Google Sheets workbook. These are the outputs the security team, CISO, and board will consume.

## Required Inputs
- `.tmp/scored/` — directory of `ScoredCVE` JSON files
- `.tmp/recommendations/` — directory of `RecommendationOutput` JSON files

## Tools Required
- `tools/generate_report.py` (for HTML output)
- `tools/export_to_sheets.py` (for Google Sheets output)

## Process

### Step 1: Generate HTML report
```bash
python tools/generate_report.py \
  --scored-dir .tmp/scored/ \
  --recommendations-dir .tmp/recommendations/ \
  --output reports/vuln_report_YYYYMMDD.html \
  --title "Q2 2026 Vulnerability Assessment"
```

Optional flags:
- `--logo /path/to/logo.png` — embeds org logo in the report header

### Step 2: Verify the report
Open the HTML file in a browser and verify:
- Header shows correct CVE counts per priority
- Donut chart proportions match the distribution
- Executive Summary Top 5 table shows the highest-scored CVEs
- Full table is sortable by clicking column headers
- Each CVE card shows all populated data (score breakdown, actions, references)
- Audit Trail section has entries

### Step 3: Export to Google Sheets (if requested)
```bash
python tools/export_to_sheets.py \
  --scored-dir .tmp/scored/ \
  --title "Vuln Prioritization 2026-04-24" \
  --share
```

For first-time Google Sheets setup:
1. Create a project in Google Cloud Console
2. Enable Google Sheets API and Google Drive API
3. Create OAuth credentials → Download `credentials.json`
4. Place `credentials.json` in the project root
5. Run the tool — a browser window will open for OAuth authorization
6. `token.json` is auto-saved for future runs

### Step 4: Share deliverables
- HTML report: Send the file or host it internally
- Sheets URL: Copy from tool output; share with stakeholders

### Step 5: Archive the run
Consider keeping `.tmp/` artifacts for 30 days for audit purposes before deletion.

## Expected Outputs
- `reports/vuln_report_YYYYMMDD_HHMM.html` — self-contained CISO HTML report
- Google Sheets URL (if `--output sheets` or `--output both`)

## HTML Report Sections
1. **Header** — title, date, CVE counts by priority
2. **Executive Summary** — donut chart, top 5 CVEs, key findings
3. **Full Vulnerability Table** — sortable table, color-coded by priority
4. **Detailed CVE Cards** — per-CVE deep-dive with score breakdown, actions, references
5. **Methodology** — scoring formula, source attribution, data freshness
6. **Audit Trail** — collapsible decision log appendix

## Google Sheets Tabs
1. **Executive Summary** — report header + top 10 critical/high CVEs
2. **All Vulnerabilities** — full scored list with all key fields
3. **Score Breakdown** — per-component score detail for every CVE
4. **Audit Trail** — decision log sourced from `audit_log.jsonl`

## Quality Checks
- [ ] HTML report opens without errors in Chrome/Edge/Firefox
- [ ] All CVEs appear in the full vulnerability table
- [ ] Score breakdown table shows correct point values
- [ ] At least one key finding is populated in the Executive Summary
- [ ] Google Sheets (if generated) has all 4 tabs with data
- [ ] Methodology section shows correct source URLs and timestamps
