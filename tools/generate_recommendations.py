#!/usr/bin/env python3
"""
generate_recommendations.py — Generate CISO-grade remediation guidance for scored CVEs.

Usage:
    python tools/generate_recommendations.py --scored-dir .tmp/scored/ --output-dir .tmp/recommendations/
"""

import argparse
import json
import sys
from pathlib import Path

# CVSS attack vector → attack surface description
ATTACK_VECTOR_MAP = {
    'NETWORK': 'Internet-facing or network-accessible service',
    'ADJACENT': 'Systems on the same network segment (intranet / VPN)',
    'LOCAL': 'Requires local system access (authenticated user or malware foothold)',
    'PHYSICAL': 'Requires physical access to the device',
}

# CWE ID → immediate action guidance
CWE_ACTIONS = {
    'CWE-79':  'Deploy WAF rules to filter reflected/stored XSS; add Content-Security-Policy headers; update to patched version.',
    'CWE-89':  'Audit for parameterized queries and prepared statements; deploy WAF SQLi rules; update application.',
    'CWE-78':  'EMERGENCY: Isolate affected systems from network if unpatched; apply vendor patch immediately.',
    'CWE-22':  'Restrict file-system permissions; apply input path validation; update to patched version.',
    'CWE-20':  'Apply vendor-supplied input validation patch; review all untrusted input paths.',
    'CWE-287': 'Force password resets; enable MFA; audit authentication logs for anomalies.',
    'CWE-306': 'Restrict unauthenticated access; require authentication for all sensitive endpoints.',
    'CWE-502': 'Block deserialization of untrusted data; apply patch; restrict network access to affected service.',
    'CWE-94':  'Apply vendor patch; restrict untrusted code execution paths; review injection points.',
    'CWE-416': 'Apply memory-safe patch; consider temporary service isolation for critical assets.',
    'CWE-125': 'Apply vendor patch; restrict access to affected service; monitor for exploitation attempts.',
    'CWE-787': 'Apply vendor patch; restrict network access; enable exploit mitigations (ASLR, DEP).',
    'CWE-190': 'Apply vendor patch; validate integer bounds in affected component.',
}

DEFAULT_ACTION = 'Apply the vendor-supplied patch; follow vendor advisory for temporary workarounds.'


def derive_attack_surface(enriched: dict) -> str:
    nvd = enriched.get('nvd') or {}
    cvss = nvd.get('cvss_v31') or nvd.get('cvss_v40') or {}
    av = cvss.get('attackVector', '').upper()
    # CWE-based fallback when CVSS vector is absent (common for very new CVEs)
    if not av:
        nvd = enriched.get('nvd') or {}
        cwes = nvd.get('cwe_ids', [])
        local_cwes = {'CWE-427', 'CWE-426', 'CWE-732', 'CWE-269', 'CWE-416'}
        if any(c in local_cwes for c in cwes):
            return 'Local — requires local access or user interaction'
        return 'Unknown (CVSS not yet assigned)'
    return ATTACK_VECTOR_MAP.get(av, 'Unknown')


def derive_immediate_actions(enriched: dict, priority: str) -> list[str]:
    actions = []
    nvd = enriched.get('nvd') or {}
    cwe_ids = nvd.get('cwe_ids', [])
    kev = enriched.get('kev') or {}

    # Priority-driven urgent actions
    if priority == 'Critical':
        actions.append('1. [CISO] Declare vulnerability as active incident; assign dedicated remediation owner.')
        actions.append('2. [Security Ops] Initiate emergency change process to bypass standard change windows.')

    if kev.get('in_kev'):
        actions.append(f'3. [Security Ops] This CVE is in the CISA KEV catalog (added {kev.get("date_added", "N/A")}). '
                       f'Required action: {kev.get("required_action", "See CISA advisory")}')

    # CWE-based technical actions
    action_added = False
    for cwe in cwe_ids:
        if cwe in CWE_ACTIONS:
            step = len(actions) + 1
            actions.append(f'{step}. [Engineering] {CWE_ACTIONS[cwe]}')
            action_added = True
            break

    if not action_added:
        step = len(actions) + 1
        actions.append(f'{step}. [Engineering] {DEFAULT_ACTION}')

    # Exploit-based actions
    exploit = enriched.get('exploit') or {}
    if exploit.get('has_public_exploit'):
        step = len(actions) + 1
        actions.append(f'{step}. [Threat Intel] Monitor SIEM for exploit signatures — public exploit code is available.')
    elif exploit.get('has_poc_only'):
        step = len(actions) + 1
        actions.append(f'{step}. [Threat Intel] Monitor threat feeds — PoC exists and active exploit development is likely.')

    # ATT&CK-based detection
    attack = enriched.get('attack') or {}
    if attack.get('techniques'):
        techniques = ', '.join(attack['techniques'][:3])
        step = len(actions) + 1
        actions.append(f'{step}. [Blue Team] Update detection rules for ATT&CK techniques: {techniques}.')

    return actions


def derive_workarounds(enriched: dict) -> list[str]:
    workarounds = []
    nvd = enriched.get('nvd') or {}
    kev = enriched.get('kev') or {}

    if kev.get('required_action'):
        workarounds.append(f'CISA guidance: {kev["required_action"]}')

    # Use curated patch_refs first (already filtered to trusted authoritative sources)
    patch_refs = nvd.get('patch_refs', [])
    if patch_refs:
        for url in patch_refs[:3]:
            workarounds.append(f'Vendor / official advisory: {url}')
    else:
        # Fallback: first reference in NVD refs list
        refs = nvd.get('references', [])
        if refs:
            workarounds.append(f'Reference: {refs[0]}')

    if not workarounds:
        workarounds.append('No workaround available — patching is the only remediation.')

    return workarounds


def build_ciso_summary(scored: dict) -> str:
    cve_id = scored['cve_id']
    priority = scored['priority_category']
    composite = scored['composite_score']
    enriched = scored.get('enriched', {})
    nvd = enriched.get('nvd') or {}
    kev = enriched.get('kev') or {}
    epss = enriched.get('epss') or {}
    exploit = enriched.get('exploit') or {}
    attack = enriched.get('attack') or {}
    threat = enriched.get('threat_context') or {}

    score_str = f'{composite:.0f}/100' if composite is not None else 'unscored'
    epss_score = epss.get('epss_score', 0) or 0.0
    epss_pct = f'{epss_score * 100:.1f}%'

    # Sentence 1: Priority and urgency
    if priority == 'Critical':
        urgency = 'requires immediate emergency patching within 24 hours'
    elif priority == 'High':
        urgency = 'must be remediated within 7 days'
    elif priority == 'Medium':
        urgency = 'should be addressed within 30 days'
    elif priority == 'Low':
        urgency = 'can be addressed within the next 90-day maintenance cycle'
    else:
        urgency = 'requires manual review — scoring data is pending'

    # Include system category in sentence 1 if non-standard
    sys_cat = nvd.get('system_category', 'IT')
    sys_note = f' ({sys_cat} environment)' if sys_cat not in ('IT', 'Unknown') else ''

    sentence1 = (
        f'{cve_id} scored {score_str} ({priority}){sys_note} and {urgency}. '
        f'Vulnerability status: {nvd.get("vuln_status", "Unknown")}.'
    )

    # Sentence 2: Threat intelligence indicators
    threat_parts = []

    if kev.get('in_kev') or threat.get('exploited_in_wild'):
        threat_parts.append('actively exploited in the wild (confirmed by CISA KEV)')
    if threat.get('ransomware_use') == 'Known' or kev.get('ransomware_use') == 'Known':
        threat_parts.append('weaponized by ransomware groups')
    if threat.get('botnet_use'):
        threat_parts.append('attributed to active botnet campaigns')

    maturity = exploit.get('exploit_maturity', 'None')
    if maturity == 'Weaponized' or exploit.get('is_weaponized'):
        threat_parts.append('weaponized exploit code is publicly available and ready to deploy')
    elif exploit.get('commercial_exploit'):
        threat_parts.append('exploit is available in commercial penetration testing frameworks (e.g., Metasploit)')
    elif maturity == 'Functional' or exploit.get('has_public_exploit'):
        threat_parts.append(f'{exploit.get("exploit_count", 1)} functional public exploit(s) are available')
    elif maturity == 'PoC' or exploit.get('has_poc_only'):
        threat_parts.append('proof-of-concept exploit code exists; functional exploit development is likely')

    if epss_score >= 0.7:
        threat_parts.append(f'EPSS exploitation probability is very high at {epss_pct} over the next 30 days')
    elif epss_score >= 0.3:
        threat_parts.append(f'EPSS exploitation probability is elevated at {epss_pct}')

    # CAPEC attack patterns
    capec_ids = nvd.get('capec_ids', [])
    if capec_ids:
        threat_parts.append(f'attack patterns classified as {", ".join(capec_ids[:2])}')

    if threat_parts:
        sentence2 = 'Threat intelligence: ' + '; '.join(threat_parts) + '.'
    else:
        sentence2 = (
            f'No confirmed active exploitation detected. '
            f'EPSS probability is {epss_pct} over the next 30 days. '
            f'Monitor threat feeds for emerging exploit activity.'
        )

    # Sentence 3: Affected systems and ATT&CK
    products = nvd.get('affected_products', [])
    cwe_ids = nvd.get('cwe_ids', [])
    techniques = attack.get('techniques', [])
    tactic_list = attack.get('tactics', [])

    if products:
        product_str = ', '.join(f'{p["vendor"]} {p["product"]}' for p in products[:3])
        sentence3 = f'Affected software: {product_str}.'
    else:
        sentence3 = 'Verify which systems in your environment are running the affected software version.'

    # Sentence 4: ATT&CK and CWE context
    tech_parts = []
    if cwe_ids:
        tech_parts.append(f'weakness type {", ".join(cwe_ids[:2])}')
    if techniques:
        tactic_str = f' ({", ".join(tactic_list[:2])})' if tactic_list else ''
        tech_parts.append(f'maps to ATT&CK {", ".join(techniques[:2])}{tactic_str}')

    sentence4 = ('Security classification: ' + '; '.join(tech_parts) + '.') if tech_parts else ''

    return ' '.join(filter(None, [sentence1, sentence2, sentence3, sentence4]))


def generate_recommendation(scored: dict) -> dict:
    cve_id = scored['cve_id']
    enriched = scored.get('enriched', {})
    nvd = enriched.get('nvd') or {}
    threat = enriched.get('threat_context') or {}
    exploit = enriched.get('exploit') or {}

    cvss = nvd.get('cvss_v31') or nvd.get('cvss_v40') or {}
    cvss_vector = cvss.get('vectorString')

    products = nvd.get('affected_products', [])
    affected_systems = [f'{p["vendor"]} {p["product"]}' for p in products[:10]]

    attack_surface = derive_attack_surface(enriched)
    immediate_actions = derive_immediate_actions(enriched, scored['priority_category'])
    workarounds = derive_workarounds(enriched)
    references = nvd.get('references', [])[:10]
    ciso_summary = build_ciso_summary(scored)

    return {
        'cve_id': cve_id,
        'priority_category': scored['priority_category'],
        'patch_timeline': scored['patch_timeline'],
        'composite_score': scored['composite_score'],
        'cvss_vector': cvss_vector,
        'affected_systems': affected_systems,
        'remediation_summary': nvd.get('description', '')[:500],
        'immediate_actions': immediate_actions,
        'workarounds': workarounds,
        'references': references,
        'attack_surface': attack_surface,
        'ciso_summary': ciso_summary,
        # New enrichment fields surfaced to UI
        'vuln_status': nvd.get('vuln_status', 'Unknown'),
        'system_category': nvd.get('system_category', 'IT'),
        'capec_ids': nvd.get('capec_ids', []),
        'cpe_list': nvd.get('cpe_list', []),
        'exploit_maturity': exploit.get('exploit_maturity', 'None'),
        'is_weaponized': exploit.get('is_weaponized', False),
        'commercial_exploit': exploit.get('commercial_exploit', False),
        'exploited_in_wild': threat.get('exploited_in_wild', False),
        'botnet_use': threat.get('botnet_use', False),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='Generate CISO-grade remediation recommendations')
    parser.add_argument('--scored-dir', default='.tmp/scored/', help='Directory of ScoredCVE JSON files')
    parser.add_argument('--output-dir', default='.tmp/recommendations/', help='Output directory')
    args = parser.parse_args()

    scored_dir = Path(args.scored_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(scored_dir.glob('CVE-*.json'))
    if not files:
        print(f'[Recommend] No scored CVE files found in {scored_dir}', file=sys.stderr)
        return 1

    for f in files:
        scored = json.loads(f.read_text(encoding='utf-8'))
        rec = generate_recommendation(scored)
        out_path = output_dir / f'{scored["cve_id"]}.json'
        out_path.write_text(json.dumps(rec, indent=2), encoding='utf-8')

    print(f'[Recommend] Generated recommendations for {len(files)} CVEs. Output: {output_dir}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
