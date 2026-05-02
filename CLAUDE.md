# Vulnerability Prioritization Application — Agent Instructions

## WAT Framework Overview

This is a WAT (Workflows, Agents, Tools) application for CISO-grade vulnerability prioritization. It follows the same pattern as the sibling "Agent Team" project.

**Layer 1: Workflows** (`workflows/`) — Markdown SOPs for each pipeline phase. Read the relevant workflow before taking action.
**Layer 2: Agents** (`.claude/agents/`) — Claude subagent definitions for specialized roles.
**Layer 3: Tools** (`tools/`) — Deterministic Python CLI scripts. Do the actual work by calling these.

## Pipeline Architecture

```
CVE Input File
     ↓
Phase 1: validate_cves.py          → .tmp/validated_cves.json
     ↓
Phase 2: fetch_nvd.py              → .tmp/nvd_raw/CVE-XXXX.json
         fetch_osv.py              → .tmp/osv_raw/CVE-XXXX.json
     ↓
Phase 3: fetch_kev.py              → .tmp/kev_cache.json + kev_results.json
         fetch_epss.py             → .tmp/epss_raw/CVE-XXXX.json
         fetch_exploitdb.py        → .tmp/exploitdb_raw/CVE-XXXX.json
     ↓
Phase 4: fetch_attack.py           → .tmp/attack_raw/CVE-XXXX.json
         merge_enrichment.py       → .tmp/enriched/CVE-XXXX.json
     ↓
Phase 5: calculate_score.py        → .tmp/scored/CVE-XXXX.json
     ↓
Phase 6: generate_recommendations.py → .tmp/recommendations/CVE-XXXX.json
     ↓
Phase 7: generate_report.py        → reports/vuln_report_YYYYMMDD.html
         export_to_sheets.py       → Google Sheets (optional)
```

## Running the Pipeline

```bash
# Install dependencies
pip install -r requirements.txt

# Copy .env template and add your NVD API key (optional but recommended)
cp .env.example .env

# Full run — HTML output
python main.py --input cves.txt --output html

# With NVD API key for faster processing (~10x faster)
python main.py --input cves.txt --output html --nvd-api-key YOUR_KEY

# Fast mode — skip slow optional steps for quick triage
python main.py --input cves.txt --output html --skip-exploitdb --skip-attack

# Both HTML + Google Sheets
python main.py --input cves.txt --output both --title "Q2 2026 Vuln Assessment"
```

## Critical Rules

1. **NVD rate limits MUST be respected.** Without API key: `--delay 6.0` (5 req/30s). With key: `--delay 0.65`. Never remove the delay or the NVD API will block the IP.

2. **Audit trail is mandatory.** Every scoring decision must be logged to `.tmp/audit_log.jsonl`. Do not skip this.

3. **Graceful failures only.** A failed enrichment source (ExploitDB blocked, OSV 404, ATT&CK download failed) does NOT stop the pipeline. Log the error and continue with available data.

4. **CISO-first language.** All user-facing output (summaries, recommendations) must be readable by a non-technical executive. No unexplained acronyms.

5. **Never modify scoring weights** without explicit instruction from the user. The formula is documented in `workflows/scoring.md`.

6. **No secrets outside `.env`.** API keys and credentials go only in `.env` (gitignored).

## Scoring Formula (authoritative)

```
Score = min((CVSS/10 × 30) + (EPSS × 35) + KEV(+20) + Exploit(+15/+8) + Ransomware(+10), 100)

Critical ≥ 80 → Patch within 24 hours
High 60–79    → Patch within 7 days
Medium 40–59  → Patch within 30 days
Low < 40      → Patch within 90 days
```

## File Organization

- `.tmp/` — All intermediate files. Disposable; auto-regenerated on each run.
- `reports/` — Final HTML reports. Keep for audit purposes.
- `tools/` — One Python script per API/function. All accept CLI args via argparse.
- `workflows/` — One Markdown SOP per pipeline phase.
- `.claude/agents/` — Claude subagent definitions.

## Test CVEs for Development

```
CVE-2021-44228   Log4Shell — KEV, EPSS ~0.97, exploits, ransomware, ATT&CK mapped
CVE-2024-3400    PAN-OS — KEV, CVSS 10.0, active exploitation
CVE-2022-30190   Follina — KEV, ransomware associated
CVE-2023-44487   HTTP/2 Rapid Reset — KEV, high EPSS
CVE-2020-1472    Zerologon — KEV, ransomware, critical
```

## When Things Break

1. **NVD API returns 403 or all 404s**: The API key may be invalid. Check `.env`.
2. **ExploitDB returns empty for all CVEs**: ExploitDB may have changed their HTML structure. Check `fetch_exploitdb.py`'s parser and adapt.
3. **ATT&CK bundle fails to download**: Use `--skip-attack` flag in `main.py`. The ATT&CK mapping is optional.
4. **EPSS scores all 0**: The FIRST.org API may be rate-limiting. Add a longer delay in `fetch_epss.py`.

Follow the self-improvement loop: identify what broke → fix the tool → verify the fix → update the workflow → move on with a stronger system.
