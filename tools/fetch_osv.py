#!/usr/bin/env python3
"""
fetch_osv.py — Fetch package-level vulnerability data from OSV.dev.

Usage:
    python tools/fetch_osv.py --cve CVE-2024-1234 --output .tmp/osv_raw/CVE-2024-1234.json
    python tools/fetch_osv.py --batch .tmp/validated_cves.json --output-dir .tmp/osv_raw/
"""

import argparse
import json
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from patch_sources import is_trusted_patch_source

OSV_BASE_URL = 'https://api.osv.dev/v1/vulns'


def fetch_osv(cve_id: str) -> dict:
    url = f'{OSV_BASE_URL}/{cve_id}'
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return {'not_found': True}
        else:
            return {'error': f'http_{resp.status_code}'}
    except requests.RequestException as e:
        return {'error': str(e)}


def parse_osv_response(cve_id: str, data: dict) -> dict:
    if data.get('not_found') or data.get('error'):
        return {
            'cve_id': cve_id,
            'osv_id': None,
            'aliases': [],
            'summary': None,
            'affected_packages': [],
            'severity': [],
        }

    # FIX-typed references from OSV — filtered to authoritative sources only
    fix_refs: list[str] = []
    seen_fix: set[str] = set()
    for ref in data.get('references', []):
        if ref.get('type') == 'FIX':
            url = ref.get('url', '').strip()
            if url and url not in seen_fix and is_trusted_patch_source(url):
                seen_fix.add(url)
                fix_refs.append(url)

    # Fixed versions from ECOSYSTEM ranges
    fixed_versions: list[dict] = []
    affected = []
    for a in data.get('affected', []):
        pkg = a.get('package') or {}
        ecosystem = pkg.get('ecosystem', '')
        name = pkg.get('name', '')
        ranges = a.get('ranges', [])
        versions = a.get('versions', [])[:10]

        # Extract fixed versions from ECOSYSTEM ranges
        if ecosystem and name:
            for rng in ranges:
                if rng.get('type') == 'ECOSYSTEM':
                    for evt in rng.get('events', []):
                        fv = evt.get('fixed')
                        if fv:
                            entry = {'ecosystem': ecosystem, 'package': name, 'fixed_version': fv}
                            if entry not in fixed_versions:
                                fixed_versions.append(entry)

        affected.append({
            'ecosystem': ecosystem,
            'name': name,
            'ranges': ranges[:5],
            'versions': versions,
        })

    return {
        'cve_id': cve_id,
        'osv_id': data.get('id'),
        'aliases': data.get('aliases', []),
        'summary': data.get('summary') or data.get('details', '')[:300],
        'affected_packages': affected[:10],
        'severity': data.get('severity', []),
        'fix_refs': fix_refs[:10],
        'fixed_versions': fixed_versions[:10],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='Fetch CVE data from OSV.dev')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--cve', help='Single CVE ID')
    group.add_argument('--batch', help='Path to validated_cves.json')
    parser.add_argument('--output', help='Output file (single mode)')
    parser.add_argument('--output-dir', default='.tmp/osv_raw/', help='Output directory (batch mode)')
    parser.add_argument('--delay', type=float, default=0.5, help='Seconds between requests')
    args = parser.parse_args()

    if args.cve:
        cves = [args.cve.upper()]
        output_dir = Path(args.output).parent if args.output else Path('.tmp/osv_raw')
        single_output = Path(args.output) if args.output else output_dir / f'{args.cve.upper()}.json'
    else:
        data = json.loads(Path(args.batch).read_text(encoding='utf-8'))
        cves = data.get('valid_cves', [])
        output_dir = Path(args.output_dir)
        single_output = None

    output_dir.mkdir(parents=True, exist_ok=True)

    success, not_found, failed = 0, 0, 0
    for i, cve_id in enumerate(cves):
        out_path = single_output if single_output else output_dir / f'{cve_id}.json'

        if out_path.exists():
            success += 1
            continue

        print(f'  [{i+1}/{len(cves)}] Fetching OSV {cve_id}...')
        raw = fetch_osv(cve_id)
        parsed = parse_osv_response(cve_id, raw)
        out_path.write_text(json.dumps(parsed, indent=2), encoding='utf-8')

        if raw.get('not_found'):
            not_found += 1
        elif raw.get('error'):
            failed += 1
        else:
            success += 1

        if i < len(cves) - 1:
            time.sleep(args.delay)

    print(f'[OSV] Done. {success} found, {not_found} not in OSV, {failed} errors.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
