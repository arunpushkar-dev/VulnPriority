#!/usr/bin/env python3
"""
calculate_score.py — Apply the composite prioritization scoring formula to enriched CVEs.

Scoring formula:
  CVSS_COMPONENT   = (cvss_base / 10.0) × 30       [max 30 pts]
  EPSS_COMPONENT   = epss_score × 35                [max 35 pts]
  KEV_BONUS        = +20 if in CISA KEV
  EXPLOIT_BONUS    = +15 (full exploit) / +8 (PoC)
  RANSOMWARE_BONUS = +10 if KEV ransomware_use == "Known"
  COMPOSITE        = min(sum, 100)

Priority categories:
  Critical (≥80): 24 hours
  High (60-79):   7 days
  Medium (40-59): 30 days
  Low (<40):      90 days

Usage:
    python tools/calculate_score.py --enriched-dir .tmp/enriched/ --output-dir .tmp/scored/
    python tools/calculate_score.py --single .tmp/enriched/CVE-2024-1234.json --output .tmp/scored/CVE-2024-1234.json
"""

import argparse
import json
import sys
from pathlib import Path


def assign_priority(score: float) -> tuple[str, str]:
    if score >= 80:
        return ('Critical', 'Patch within 24 hours')
    elif score >= 60:
        return ('High', 'Patch within 7 days')
    elif score >= 40:
        return ('Medium', 'Patch within 30 days')
    else:
        return ('Low', 'Patch within 90 days')


def compute_score(enriched: dict) -> dict:
    cve_id = enriched['cve_id']
    flags = list(enriched.get('enrichment_errors', []))

    # CVSS component — prefer v4.0, fallback to v3.1
    cvss_raw = 0.0
    nvd = enriched.get('nvd') or {}
    cvss_v40 = nvd.get('cvss_v40')
    cvss_v31 = nvd.get('cvss_v31')

    if cvss_v40 and cvss_v40.get('baseScore'):
        cvss_raw = float(cvss_v40['baseScore'])
        flags.append('cvss_v40_used')
    elif cvss_v31 and cvss_v31.get('baseScore'):
        cvss_raw = float(cvss_v31['baseScore'])
    else:
        flags.append('cvss_missing')

    cvss_component = (cvss_raw / 10.0) * 30.0

    # EPSS component
    epss_raw = 0.0
    epss_data = enriched.get('epss') or {}
    if epss_data.get('epss_score') and not epss_data.get('epss_not_scored'):
        epss_raw = float(epss_data['epss_score'])
    else:
        flags.append('epss_missing')

    epss_component = epss_raw * 35.0

    # Insufficient data check
    if cvss_raw == 0.0 and epss_raw == 0.0:
        flags.append('insufficient_data')
        priority = 'Unscored'
        timeline = 'Manual review required'
        return {
            'cve_id': cve_id,
            'cvss_score_raw': cvss_raw,
            'epss_score_raw': epss_raw,
            'kev_bonus': 0.0,
            'exploit_bonus': 0.0,
            'ransomware_bonus': 0.0,
            'composite_score': None,
            'priority_category': priority,
            'patch_timeline': timeline,
            'enriched': enriched,
            'score_reasoning': 'Insufficient data: both CVSS and EPSS scores unavailable.',
            'data_flags': flags,
        }

    # KEV bonus
    kev_bonus = 0.0
    ransomware_bonus = 0.0
    kev = enriched.get('kev') or {}
    if kev.get('in_kev'):
        kev_bonus = 20.0
        if kev.get('ransomware_use') == 'Known':
            ransomware_bonus = 10.0

    # Exploit bonus — tiered by maturity level
    exploit_bonus = 0.0
    exploit = enriched.get('exploit') or {}
    maturity = exploit.get('exploit_maturity', 'None')
    exploit_label = ''
    if exploit.get('is_weaponized') or maturity == 'Weaponized':
        exploit_bonus = 15.0
        exploit_label = 'Weaponized exploit available'
    elif exploit.get('commercial_exploit') or maturity == 'Functional':
        exploit_bonus = 12.0
        exploit_label = 'Functional/commercial exploit available'
    elif exploit.get('has_public_exploit') or maturity == 'PoC':
        exploit_bonus = 8.0
        exploit_label = 'PoC exploit available'
    elif exploit.get('has_poc_only'):
        exploit_bonus = 5.0
        exploit_label = 'Proof-of-concept code available'

    # Exploited-in-wild bonus (from threat_context, derived in merge)
    threat = enriched.get('threat_context') or {}
    wild_bonus = 0.0
    if threat.get('exploited_in_wild') and not kev.get('in_kev'):
        # KEV already awards +20; only add wild bonus if NOT in KEV to avoid double-counting
        wild_bonus = 10.0

    raw_score = cvss_component + epss_component + kev_bonus + exploit_bonus + ransomware_bonus + wild_bonus
    composite = min(raw_score, 100.0)
    priority, timeline = assign_priority(composite)

    # Build human-readable reasoning
    parts = [
        f'CVSS {cvss_raw:.1f}/10 -> {cvss_component:.1f} pts',
        f'EPSS {epss_raw:.3f} ({epss_raw*100:.1f}% exploitation probability) -> {epss_component:.1f} pts',
    ]
    if kev_bonus:
        parts.append(f'CISA KEV member (active exploitation confirmed) -> +{kev_bonus:.0f} pts')
    if ransomware_bonus:
        parts.append(f'Ransomware group attribution -> +{ransomware_bonus:.0f} pts')
    if wild_bonus:
        parts.append(f'Exploited in the wild (high EPSS + exploit) -> +{wild_bonus:.0f} pts')
    if exploit_bonus:
        parts.append(f'{exploit_label} -> +{exploit_bonus:.0f} pts')
    if composite == 100.0 and raw_score > 100.0:
        parts.append(f'Score capped at 100 (raw: {raw_score:.1f})')

    reasoning = '; '.join(parts) + f'. Final score: {composite:.1f} -> {priority}.'

    return {
        'cve_id': cve_id,
        'cvss_score_raw': round(cvss_raw, 2),
        'epss_score_raw': round(epss_raw, 4),
        'kev_bonus': kev_bonus,
        'exploit_bonus': exploit_bonus,
        'ransomware_bonus': ransomware_bonus,
        'wild_bonus': wild_bonus,
        'exploit_maturity': maturity,
        'composite_score': round(composite, 2),
        'priority_category': priority,
        'patch_timeline': timeline,
        'enriched': enriched,
        'score_reasoning': reasoning,
        'data_flags': flags,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='Calculate composite prioritization scores')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--enriched-dir', help='Directory of EnrichedCVE JSON files')
    group.add_argument('--single', help='Single EnrichedCVE JSON file')
    parser.add_argument('--output-dir', default='.tmp/scored/', help='Output directory')
    parser.add_argument('--output', help='Output file (single mode)')
    args = parser.parse_args()

    if args.single:
        enriched = json.loads(Path(args.single).read_text(encoding='utf-8'))
        scored = compute_score(enriched)
        out_path = Path(args.output) if args.output else Path(args.output_dir) / f'{scored["cve_id"]}.json'
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(scored, indent=2), encoding='utf-8')
        print(f'{scored["cve_id"]}: {scored["composite_score"]} -> {scored["priority_category"]}')
        return 0

    enriched_dir = Path(args.enriched_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(enriched_dir.glob('CVE-*.json'))
    if not files:
        print(f'[Score] No enriched CVE files found in {enriched_dir}', file=sys.stderr)
        return 1

    scored_list = []
    for f in files:
        enriched = json.loads(f.read_text(encoding='utf-8'))
        scored = compute_score(enriched)
        out_path = output_dir / f'{scored["cve_id"]}.json'
        out_path.write_text(json.dumps(scored, indent=2), encoding='utf-8')
        scored_list.append({
            'cve_id': scored['cve_id'],
            'composite_score': scored['composite_score'],
            'priority_category': scored['priority_category'],
            'patch_timeline': scored['patch_timeline'],
        })

    # Write ranked summary
    scored_list.sort(key=lambda x: (x['composite_score'] or -1), reverse=True)
    summary_path = Path('.tmp/score_summary.json')
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(scored_list, indent=2), encoding='utf-8')

    # Print summary table
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Unscored': 0}
    for s in scored_list:
        counts[s['priority_category']] = counts.get(s['priority_category'], 0) + 1

    print(f'\n[Score] Results for {len(scored_list)} CVEs:')
    print(f'  Critical: {counts["Critical"]}  High: {counts["High"]}  '
          f'Medium: {counts["Medium"]}  Low: {counts["Low"]}  Unscored: {counts["Unscored"]}')

    if scored_list and scored_list[0]['composite_score']:
        top = scored_list[:5]
        print('\n  Top CVEs by priority score:')
        for s in top:
            score_str = f'{s["composite_score"]:.1f}' if s['composite_score'] else 'N/A'
            print(f'    {s["cve_id"]:20s}  {score_str:6s}  {s["priority_category"]}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
