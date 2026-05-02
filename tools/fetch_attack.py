#!/usr/bin/env python3
"""
fetch_attack.py — Map CVEs to MITRE ATT&CK techniques.

Mapping method:
  1. Primary: CWE ID → ATT&CK technique (CWE-to-CAPEC-to-ATT&CK community mapping)
  2. Secondary: CVSS attackVector + privileges → T1190 (Exploit Public-Facing Application)
     for unauthenticated network-exploitable CVEs

This approach is accurate because MITRE ATT&CK techniques don't store CVE IDs as
external references; the correct mapping path is CWE → CAPEC → ATT&CK.

Usage:
    python tools/fetch_attack.py --batch .tmp/validated_cves.json \
        --nvd-dir .tmp/nvd_raw/ --output-dir .tmp/attack_raw/
    python tools/fetch_attack.py --cve CVE-2024-1234 \
        --nvd-dir .tmp/nvd_raw/ --output .tmp/attack_raw/CVE-2024-1234.json
"""

import argparse
import json
import sys
from pathlib import Path

# CWE to ATT&CK technique mapping (curated from CWE-CAPEC-ATT&CK community mapping)
CWE_TO_ATTACK: dict[str, list[dict]] = {
    'CWE-78':  [{'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
                {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'}],
    'CWE-89':  [{'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'}],
    'CWE-79':  [{'id': 'T1059.007', 'name': 'Command and Scripting Interpreter: JavaScript', 'tactic': 'Execution'},
                {'id': 'T1185', 'name': 'Browser Session Hijacking', 'tactic': 'Collection'}],
    'CWE-94':  [{'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
                {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'}],
    'CWE-22':  [{'id': 'T1083', 'name': 'File and Directory Discovery', 'tactic': 'Discovery'},
                {'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'}],
    'CWE-287': [{'id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Defense Evasion'},
                {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'}],
    'CWE-306': [{'id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Initial Access'},
                {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'}],
    'CWE-502': [{'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
                {'id': 'T1203', 'name': 'Exploitation for Client Execution', 'tactic': 'Execution'}],
    'CWE-416': [{'id': 'T1203', 'name': 'Exploitation for Client Execution', 'tactic': 'Execution'},
                {'id': 'T1068', 'name': 'Exploitation for Privilege Escalation', 'tactic': 'Privilege Escalation'}],
    'CWE-125': [{'id': 'T1203', 'name': 'Exploitation for Client Execution', 'tactic': 'Execution'}],
    'CWE-787': [{'id': 'T1203', 'name': 'Exploitation for Client Execution', 'tactic': 'Execution'},
                {'id': 'T1068', 'name': 'Exploitation for Privilege Escalation', 'tactic': 'Privilege Escalation'}],
    'CWE-190': [{'id': 'T1499.004', 'name': 'Application or System Exploitation', 'tactic': 'Impact'}],
    'CWE-20':  [{'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'}],
    'CWE-269': [{'id': 'T1068', 'name': 'Exploitation for Privilege Escalation', 'tactic': 'Privilege Escalation'}],
    'CWE-732': [{'id': 'T1222', 'name': 'File and Directory Permissions Modification', 'tactic': 'Defense Evasion'}],
    'CWE-400': [{'id': 'T1499', 'name': 'Endpoint Denial of Service', 'tactic': 'Impact'}],
    'CWE-770': [{'id': 'T1499', 'name': 'Endpoint Denial of Service', 'tactic': 'Impact'}],
    'CWE-434': [{'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'},
                {'id': 'T1105', 'name': 'Ingress Tool Transfer', 'tactic': 'Command and Control'}],
    'CWE-611': [{'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'},
                {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'}],
    'CWE-918': [{'id': 'T1090', 'name': 'Proxy', 'tactic': 'Command and Control'},
                {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'}],
    'CWE-427': [{'id': 'T1574', 'name': 'Hijack Execution Flow', 'tactic': 'Privilege Escalation'},
                {'id': 'T1574.007', 'name': 'Path Interception by PATH Environment Variable', 'tactic': 'Defense Evasion'}],
    'CWE-426': [{'id': 'T1574', 'name': 'Hijack Execution Flow', 'tactic': 'Privilege Escalation'}],
    'CWE-276': [{'id': 'T1222', 'name': 'File and Directory Permissions Modification', 'tactic': 'Defense Evasion'}],
    'CWE-352': [{'id': 'T1185', 'name': 'Browser Session Hijacking', 'tactic': 'Collection'}],
    'CWE-601': [{'id': 'T1566', 'name': 'Phishing', 'tactic': 'Initial Access'}],
    'CWE-77':  [{'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'}],
    'CWE-119': [{'id': 'T1203', 'name': 'Exploitation for Client Execution', 'tactic': 'Execution'},
                {'id': 'T1068', 'name': 'Exploitation for Privilege Escalation', 'tactic': 'Privilege Escalation'}],
    'CWE-200': [{'id': 'T1005', 'name': 'Data from Local System', 'tactic': 'Collection'}],
    'CWE-312': [{'id': 'T1552', 'name': 'Unsecured Credentials', 'tactic': 'Credential Access'}],
    'CWE-798': [{'id': 'T1552.001', 'name': 'Credentials In Files', 'tactic': 'Credential Access'}],
    'CWE-862': [{'id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Defense Evasion'}],
    'CWE-863': [{'id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Defense Evasion'}],
}

# Network-exploitable, no-auth → T1190 as fallback
T1190 = {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'}


def map_cve_from_nvd(cve_id: str, nvd_path: Path) -> dict:
    """Map a CVE to ATT&CK techniques using its NVD enrichment data."""
    if not nvd_path.exists():
        return _empty(cve_id)

    nvd = json.loads(nvd_path.read_text(encoding='utf-8'))
    if nvd.get('error'):
        return _empty(cve_id)

    cwe_ids = nvd.get('cwe_ids', [])
    cvss = nvd.get('cvss_v31') or nvd.get('cvss_v40') or {}

    matched_techniques: list[dict] = []
    seen_ids: set[str] = set()

    # Map via CWE
    for cwe in cwe_ids:
        for tech in CWE_TO_ATTACK.get(cwe, []):
            if tech['id'] not in seen_ids:
                seen_ids.add(tech['id'])
                matched_techniques.append(tech)

    # Fallback: network-facing + no auth → T1190
    av = cvss.get('attackVector', '').upper()
    pr = cvss.get('privilegesRequired', '').upper()
    if av == 'NETWORK' and pr in ('NONE', 'LOW') and T1190['id'] not in seen_ids:
        matched_techniques.append(T1190)
        seen_ids.add(T1190['id'])

    if not matched_techniques:
        return _empty(cve_id)

    return {
        'cve_id': cve_id,
        'techniques': [t['id'] for t in matched_techniques],
        'technique_names': [t['name'] for t in matched_techniques],
        'tactics': list(dict.fromkeys(t['tactic'] for t in matched_techniques)),
    }


def _empty(cve_id: str) -> dict:
    return {
        'cve_id': cve_id,
        'techniques': [],
        'technique_names': [],
        'tactics': [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='Map CVEs to MITRE ATT&CK techniques via CWE mapping')
    parser.add_argument('--cve', help='Single CVE ID')
    parser.add_argument('--batch', help='Path to validated_cves.json')
    parser.add_argument('--nvd-dir', default='.tmp/nvd_raw/', help='Directory of NVD raw JSON files')
    parser.add_argument('--output', help='Output file (single mode)')
    parser.add_argument('--output-dir', default='.tmp/attack_raw/', help='Output directory (batch mode)')
    # Legacy --cache flag accepted but not used (STIX bundle approach was replaced)
    parser.add_argument('--cache', help='(deprecated) ATT&CK bundle cache path — not used')
    parser.add_argument('--refresh', action='store_true', help='(deprecated) not used')
    args = parser.parse_args()

    nvd_dir = Path(args.nvd_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.cve:
        cve_id = args.cve.upper()
        result = map_cve_from_nvd(cve_id, nvd_dir / f'{cve_id}.json')
        out_path = Path(args.output) if args.output else output_dir / f'{cve_id}.json'
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(json.dumps(result, indent=2))
        return 0

    if args.batch:
        data = json.loads(Path(args.batch).read_text(encoding='utf-8'))
        cves = data.get('valid_cves', [])
        mapped = 0
        for cve_id in cves:
            result = map_cve_from_nvd(cve_id, nvd_dir / f'{cve_id}.json')
            out_path = output_dir / f'{cve_id}.json'
            out_path.write_text(json.dumps(result, indent=2), encoding='utf-8')
            if result['techniques']:
                mapped += 1
                print(f'  {cve_id}: {", ".join(result["techniques"])} ({", ".join(result["tactics"])})')
        print(f'[ATT&CK] {mapped}/{len(cves)} CVEs mapped to ATT&CK techniques via CWE mapping.')
        return 0

    print('[ATT&CK] No action specified. Use --cve or --batch.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
