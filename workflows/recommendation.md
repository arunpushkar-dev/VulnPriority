# Workflow: Recommendation

## Objective
Generate CISO-grade, actionable remediation guidance for each scored CVE. Translate technical data into executive-readable summaries, numbered action items, and board-presentable language.

## Required Inputs
- `.tmp/scored/` — directory of `ScoredCVE` JSON files

## Tools Required
- `tools/generate_recommendations.py`

## Process

### Step 1: Generate recommendations
```bash
python tools/generate_recommendations.py --scored-dir .tmp/scored/ --output-dir .tmp/recommendations/
```

### Step 2: Review CISO summaries
Each recommendation includes a `ciso_summary` — 2–3 sentences written for a non-technical executive. Verify these summaries are:
- Jargon-free (no CVE scoring terminology without explanation)
- Specific (names the CVE, priority, and patch timeline)
- Action-oriented (implies what needs to happen)
- Board-presentable (a CISO could read this in a board meeting)

**Good example:** "CVE-2024-1234 has a priority score of 95/100 (Critical) and requires patching within 24 hours. This vulnerability is actively exploited by ransomware groups (CISA KEV catalog) with a 94.7% exploitation probability in the next 30 days. Affected components include Apache Tomcat 9.x; verify which servers in your DMZ are running this version before deprioritizing."

**Bad example:** "CVSS 9.8 RCE via network vector. KEV status positive. EPSS 0.947."

### Step 3: Validate immediate actions
Each CVE's `immediate_actions` list must be:
- Numbered in execution order
- Assigned to a team role: `[CISO]`, `[Security Ops]`, `[Engineering]`, `[Threat Intel]`, `[Blue Team]`
- Specific enough to act on without additional research

### Step 4: Attack surface derivation
The attack surface is derived from the CVSS `attackVector` field:
- `NETWORK` → "Internet-facing or network-accessible service"
- `ADJACENT` → "Systems on the same network segment"
- `LOCAL` → "Requires local system access"
- `PHYSICAL` → "Requires physical access"

### Step 5: CWE-based actions
The tool maps CWE IDs to specific technical actions. Key mappings:
- CWE-79 (XSS) → WAF rules + Content-Security-Policy
- CWE-89 (SQL Injection) → Parameterized query audit + WAF
- CWE-78 (OS Command Injection) → Emergency isolation
- CWE-287 (Authentication) → MFA enforcement + log audit

## Expected Outputs
- `.tmp/recommendations/CVE-XXXX.json` — `RecommendationOutput` per CVE

## Quality Checks
- [ ] Every scored CVE has a corresponding recommendation file
- [ ] `ciso_summary` is 2–3 sentences with no unexplained jargon
- [ ] `immediate_actions` list is non-empty and role-assigned
- [ ] `attack_surface` is populated (not "Unknown") when CVSS vector is available
- [ ] Critical-priority CVEs have at least 4 immediate action items
