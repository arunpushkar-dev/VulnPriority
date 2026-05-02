#!/usr/bin/env python3
"""
merge_enrichment.py — Merge all per-CVE raw source files into unified EnrichedCVE records.

Usage:
    python tools/merge_enrichment.py \
      --cves .tmp/validated_cves.json \
      --nvd-dir .tmp/nvd_raw/ \
      --osv-dir .tmp/osv_raw/ \
      --kev .tmp/kev_results.json \
      --epss-dir .tmp/epss_raw/ \
      --exploitdb-dir .tmp/exploitdb_raw/ \
      --attack-dir .tmp/attack_raw/ \
      --output-dir .tmp/enriched/
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_json_file(path: Path) -> dict | None:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            return None
    return None


def merge_cve(
    cve_id: str,
    nvd_dir: Path,
    osv_dir: Path,
    kev_data: dict,
    epss_dir: Path,
    exploitdb_dir: Path,
    attack_dir: Path,
) -> dict:
    errors = []

    # NVD
    nvd = load_json_file(nvd_dir / f'{cve_id}.json')
    if nvd is None:
        errors.append('nvd_missing')
    elif nvd.get('error'):
        errors.append(f'nvd_{nvd["error"]}')
        nvd = None

    # OSV
    osv = load_json_file(osv_dir / f'{cve_id}.json')
    if osv is None:
        errors.append('osv_missing')
    elif not osv.get('osv_id'):
        osv = None  # not in OSV, that's fine

    # KEV
    kev = kev_data.get(cve_id)
    if kev is None:
        kev = {
            'cve_id': cve_id,
            'in_kev': False,
            'vendor_project': None,
            'product': None,
            'vulnerability_name': None,
            'date_added': None,
            'required_action': None,
            'due_date': None,
            'ransomware_use': None,
        }

    # EPSS
    epss = load_json_file(epss_dir / f'{cve_id}.json')
    if epss is None:
        errors.append('epss_missing')
    elif epss.get('epss_not_scored'):
        errors.append('epss_not_scored')

    # ExploitDB
    exploit = load_json_file(exploitdb_dir / f'{cve_id}.json')
    if exploit is None:
        errors.append('exploitdb_missing')
    elif exploit.get('source_error'):
        errors.append(f'exploitdb_error: {exploit["source_error"]}')

    # ATT&CK
    attack = load_json_file(attack_dir / f'{cve_id}.json')
    if attack is None:
        errors.append('attack_missing')
    elif not attack.get('techniques'):
        attack = {'cve_id': cve_id, 'techniques': [], 'technique_names': [], 'tactics': []}

    # Derived threat context fields
    in_kev = kev.get('in_kev', False) if kev else False
    epss_score = (epss or {}).get('epss_score', 0.0) or 0.0
    has_exploit = (exploit or {}).get('has_public_exploit', False)
    is_weaponized = (exploit or {}).get('is_weaponized', False)

    # Exploited in the wild: confirmed by KEV (active exploitation) OR high EPSS + weaponized exploit
    exploited_in_wild = in_kev or (epss_score >= 0.7 and (has_exploit or is_weaponized))

    # Ransomware and botnet attribution from KEV
    ransomware_use = (kev or {}).get('ransomware_use')
    # Botnet attribution is not in KEV directly; reserved for future threat intel source
    botnet_use = False

    # Propagate exploited_in_wild into exploit record
    if exploit:
        exploit['exploited_in_wild'] = exploited_in_wild

    # Consolidate patch links from NVD (Patch/Vendor Advisory/Mitigation tagged refs)
    # and OSV (FIX-typed references)
    nvd_patch_refs = (nvd or {}).get('patch_refs', [])
    osv_fix_refs = (osv or {}).get('fix_refs', [])
    seen_patch: set[str] = set()
    patch_links: list[str] = []
    for url in nvd_patch_refs + osv_fix_refs:
        if url and url not in seen_patch:
            seen_patch.add(url)
            patch_links.append(url)

    return {
        'cve_id': cve_id,
        'nvd': nvd,
        'epss': epss,
        'kev': kev,
        'exploit': exploit,
        'osv': osv,
        'attack': attack,
        'threat_context': {
            'exploited_in_wild': exploited_in_wild,
            'ransomware_use': ransomware_use,
            'botnet_use': botnet_use,
            'exploit_maturity': (exploit or {}).get('exploit_maturity', 'None'),
            'is_weaponized': is_weaponized,
            'commercial_exploit': (exploit or {}).get('commercial_exploit', False),
        },
        'patch_links': patch_links,
        'fixed_versions': (osv or {}).get('fixed_versions', []),
        'enrichment_timestamp': datetime.now(timezone.utc).isoformat(),
        'enrichment_errors': errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='Merge all enrichment sources into EnrichedCVE records')
    parser.add_argument('--cves', required=True, help='Path to validated_cves.json')
    parser.add_argument('--nvd-dir', default='.tmp/nvd_raw/', help='NVD raw JSON directory')
    parser.add_argument('--osv-dir', default='.tmp/osv_raw/', help='OSV raw JSON directory')
    parser.add_argument('--kev', default='.tmp/kev_results.json', help='KEV batch results JSON')
    parser.add_argument('--epss-dir', default='.tmp/epss_raw/', help='EPSS raw JSON directory')
    parser.add_argument('--exploitdb-dir', default='.tmp/exploitdb_raw/', help='ExploitDB raw JSON directory')
    parser.add_argument('--attack-dir', default='.tmp/attack_raw/', help='ATT&CK mapping directory')
    parser.add_argument('--output-dir', default='.tmp/enriched/', help='Output directory')
    args = parser.parse_args()

    cves_data = json.loads(Path(args.cves).read_text(encoding='utf-8'))
    cves = cves_data.get('valid_cves', [])

    kev_path = Path(args.kev)
    kev_data = json.loads(kev_path.read_text(encoding='utf-8')) if kev_path.exists() else {}

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    complete, partial = 0, 0
    for i, cve_id in enumerate(cves):
        enriched = merge_cve(
            cve_id,
            nvd_dir=Path(args.nvd_dir),
            osv_dir=Path(args.osv_dir),
            kev_data=kev_data,
            epss_dir=Path(args.epss_dir),
            exploitdb_dir=Path(args.exploitdb_dir),
            attack_dir=Path(args.attack_dir),
        )
        out_path = output_dir / f'{cve_id}.json'
        out_path.write_text(json.dumps(enriched, indent=2), encoding='utf-8')

        sources = sum([
            enriched['nvd'] is not None,
            enriched['epss'] is not None,
            enriched['kev'] is not None,
            enriched['exploit'] is not None,
            enriched['osv'] is not None,
            enriched['attack'] is not None and bool(enriched['attack'].get('techniques')),
        ])
        if sources >= 3:
            complete += 1
        else:
            partial += 1
            if enriched['enrichment_errors']:
                print(f'  [Merge] {cve_id}: {sources}/6 sources — {", ".join(enriched["enrichment_errors"][:3])}')

    print(f'[Merge] Done. {complete} fully enriched, {partial} partial. Output: {output_dir}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
