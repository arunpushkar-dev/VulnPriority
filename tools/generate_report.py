#!/usr/bin/env python3
"""
generate_report.py — Render the CISO HTML report from scored CVEs and recommendations.

Usage:
    python tools/generate_report.py --scored-dir .tmp/scored/ --recommendations-dir .tmp/recommendations/ \
      --output reports/vuln_report_20260424.html --title "Q2 2026 Vuln Assessment"
"""

import argparse
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def load_scored_cves(scored_dir: Path, recs_dir: Path) -> list[dict]:
    cves = []
    for f in sorted(scored_dir.glob('CVE-*.json')):
        scored = json.loads(f.read_text(encoding='utf-8'))
        rec_path = recs_dir / f.name
        rec = json.loads(rec_path.read_text(encoding='utf-8')) if rec_path.exists() else {}
        enriched = scored.get('enriched', {})
        nvd = enriched.get('nvd') or {}
        epss_data = enriched.get('epss') or {}
        kev_data = enriched.get('kev') or {}
        exploit_data = enriched.get('exploit') or {}
        attack_data = enriched.get('attack') or {}
        cvss = nvd.get('cvss_v31') or nvd.get('cvss_v40') or {}

        cves.append({
            'cve_id': scored['cve_id'],
            'composite_score': scored.get('composite_score'),
            'priority_category': scored.get('priority_category', 'Unscored'),
            'patch_timeline': scored.get('patch_timeline', 'N/A'),
            'cvss': cvss.get('baseScore'),
            'cvss_severity': cvss.get('baseSeverity', ''),
            'cvss_vector': cvss.get('vectorString'),
            'epss': epss_data.get('epss_score'),
            'epss_pct': epss_data.get('epss_percentile'),
            'in_kev': kev_data.get('in_kev', False),
            'kev_date_added': kev_data.get('date_added'),
            'kev_due_date': kev_data.get('due_date'),
            'kev_required_action': kev_data.get('required_action'),
            'ransomware': kev_data.get('ransomware_use') == 'Known',
            'has_exploit': exploit_data.get('has_public_exploit', False),
            'has_poc': exploit_data.get('has_poc_only', False),
            'exploit_count': exploit_data.get('exploit_count', 0),
            'exploit_links': exploit_data.get('exploit_links', []),
            'cwe_ids': nvd.get('cwe_ids', []),
            'techniques': attack_data.get('techniques', []),
            'technique_names': attack_data.get('technique_names', []),
            'tactics': attack_data.get('tactics', []),
            'affected_systems': rec.get('affected_systems', []),
            'attack_surface': rec.get('attack_surface', 'Unknown'),
            'ciso_summary': rec.get('ciso_summary', ''),
            'immediate_actions': rec.get('immediate_actions', []),
            'workarounds': rec.get('workarounds', []),
            'references': rec.get('references', []),
            'nvd_published': nvd.get('published_date', ''),
            'product': (rec.get('affected_systems') or ['Unknown'])[0] if rec.get('affected_systems') else 'Unknown',
        })

    # Sort by composite score descending
    cves.sort(key=lambda x: (x['composite_score'] or -1), reverse=True)
    return cves


def build_key_findings(cves: list[dict], stats: dict) -> list[str]:
    findings = []
    critical_count = stats['critical']
    kev_cves = [c for c in cves if c['in_kev']]
    ransomware_cves = [c for c in cves if c['ransomware']]
    exploit_cves = [c for c in cves if c['has_exploit']]

    if critical_count > 0:
        top = [c['cve_id'] for c in cves if c['priority_category'] == 'Critical'][:3]
        findings.append(
            f'{critical_count} vulnerabilit{"y" if critical_count == 1 else "ies"} require immediate patching '
            f'(within 24 hours): {", ".join(top)}.'
        )

    if kev_cves:
        findings.append(
            f'{len(kev_cves)} CVE{"s are" if len(kev_cves) > 1 else " is"} in the CISA Known Exploited '
            f'Vulnerabilities catalog, confirming active real-world exploitation.'
        )

    if ransomware_cves:
        names = [c['cve_id'] for c in ransomware_cves[:2]]
        findings.append(
            f'{len(ransomware_cves)} CVE{"s have" if len(ransomware_cves) > 1 else " has"} known ransomware '
            f'campaign use ({", ".join(names)}), significantly elevating business risk.'
        )

    if exploit_cves:
        findings.append(
            f'{len(exploit_cves)} CVE{"s have" if len(exploit_cves) > 1 else " has"} public exploit code '
            f'available, lowering the barrier to attack for adversaries.'
        )

    high_epss = [c for c in cves if c['epss'] and c['epss'] > 0.5]
    if high_epss:
        findings.append(
            f'{len(high_epss)} CVE{"s have" if len(high_epss) > 1 else " has"} an EPSS score above 50%, '
            f'indicating elevated near-term exploitation probability.'
        )

    if not findings:
        findings.append(f'Analyzed {stats["total"]} CVEs. No critical or high-priority vulnerabilities detected.')

    return findings


def build_data_sources(scored_dir: Path) -> list[dict]:
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    return [
        {'name': 'NIST NVD API v2', 'description': 'CVSS scores, CWE classification, affected products, references', 'fetched_at': now},
        {'name': 'CISA KEV Catalog', 'description': 'Known exploited vulnerability status, ransomware association, required actions', 'fetched_at': now},
        {'name': 'FIRST.org EPSS API', 'description': 'Exploit prediction score (probability of exploitation in 30 days)', 'fetched_at': now},
        {'name': 'Exploit-DB', 'description': 'Public exploit and PoC availability', 'fetched_at': now},
        {'name': 'OSV.dev', 'description': 'Package-level affected version ranges', 'fetched_at': now},
        {'name': 'MITRE ATT&CK', 'description': 'Technique and tactic mapping from enterprise STIX bundle', 'fetched_at': now},
    ]


def load_audit_entries(limit: int = 100) -> list[str]:
    audit_path = Path('.tmp/audit_log.jsonl')
    if not audit_path.exists():
        return []
    lines = audit_path.read_text(encoding='utf-8').strip().split('\n')
    return [l for l in lines if l.strip()][:limit]


def main() -> int:
    parser = argparse.ArgumentParser(description='Generate CISO HTML report')
    parser.add_argument('--scored-dir', default='.tmp/scored/', help='Directory of ScoredCVE JSON files')
    parser.add_argument('--recommendations-dir', default='.tmp/recommendations/', help='Recommendations directory')
    parser.add_argument('--output', required=True, help='Output HTML file path')
    parser.add_argument('--title', default=f'Vulnerability Prioritization Report {datetime.now().strftime("%Y-%m-%d")}')
    parser.add_argument('--logo', help='Path to organization logo PNG (embedded as base64)')
    args = parser.parse_args()

    scored_dir = Path(args.scored_dir)
    recs_dir = Path(args.recommendations_dir)

    if not scored_dir.exists():
        print(f'[Report] Scored directory not found: {scored_dir}', file=sys.stderr)
        return 1

    print('[Report] Loading scored CVEs...')
    cves = load_scored_cves(scored_dir, recs_dir)

    if not cves:
        print('[Report] No CVEs to report.', file=sys.stderr)
        return 1

    stats = {
        'total': len(cves),
        'critical': sum(1 for c in cves if c['priority_category'] == 'Critical'),
        'high': sum(1 for c in cves if c['priority_category'] == 'High'),
        'medium': sum(1 for c in cves if c['priority_category'] == 'Medium'),
        'low': sum(1 for c in cves if c['priority_category'] == 'Low'),
    }

    top5 = [c for c in cves if c['priority_category'] in ('Critical', 'High')][:5]
    key_findings = build_key_findings(cves, stats)
    data_sources = build_data_sources(scored_dir)
    audit_entries = load_audit_entries()

    # Optional logo
    logo_b64 = None
    if args.logo:
        logo_path = Path(args.logo)
        if logo_path.exists():
            logo_b64 = base64.b64encode(logo_path.read_bytes()).decode()

    # Jinja2 template
    template_dir = Path(__file__).parent.parent / 'templates'
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=False)
    env.globals['zip'] = zip

    template = env.get_template('report.html.j2')
    html = template.render(
        title=args.title,
        generated_at=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M'),
        freshness_note='NVD, CISA KEV, EPSS fetched during this run',
        stats=stats,
        top5=top5,
        all_cves=cves,
        key_findings=key_findings,
        data_sources=data_sources,
        audit_entries=audit_entries,
        logo_b64=logo_b64,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding='utf-8')

    print(f'[Report] HTML report written to: {output_path.resolve()}')
    print(f'[Report] {stats["total"]} CVEs - Critical: {stats["critical"]}, High: {stats["high"]}, '
          f'Medium: {stats["medium"]}, Low: {stats["low"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
