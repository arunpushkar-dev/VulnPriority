#!/usr/bin/env python3
"""
fetch_kev.py — Download and query the CISA Known Exploited Vulnerabilities (KEV) catalog.

Usage:
    python tools/fetch_kev.py --refresh --output .tmp/kev_cache.json
    python tools/fetch_kev.py --lookup CVE-2024-1234 --cache .tmp/kev_cache.json
    python tools/fetch_kev.py --batch .tmp/validated_cves.json --cache .tmp/kev_cache.json --output .tmp/kev_results.json
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import requests

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
CACHE_TTL_SECONDS = 86400  # 24 hours


def download_kev(output_path: Path) -> bool:
    print('[KEV] Downloading CISA KEV catalog...')
    try:
        resp = requests.get(KEV_URL, timeout=60)
        resp.raise_for_status()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(resp.content)
        catalog = resp.json()
        count = len(catalog.get('vulnerabilities', []))
        print(f'[KEV] Downloaded {count} known exploited vulnerabilities.')
        return True
    except requests.RequestException as e:
        print(f'[KEV] Download failed: {e}', file=sys.stderr)
        return False


def load_cache(cache_path: Path, auto_refresh: bool = True) -> dict | None:
    if not cache_path.exists():
        if auto_refresh:
            download_kev(cache_path)
        else:
            return None

    # Auto-refresh if stale
    age = time.time() - cache_path.stat().st_mtime
    if age > CACHE_TTL_SECONDS and auto_refresh:
        print(f'[KEV] Cache is {age/3600:.1f}h old. Refreshing...')
        download_kev(cache_path)

    return json.loads(cache_path.read_text(encoding='utf-8'))


def build_lookup(catalog: dict) -> dict[str, dict]:
    index = {}
    for v in catalog.get('vulnerabilities', []):
        cve_id = v.get('cveID', '').upper()
        if cve_id:
            index[cve_id] = {
                'cve_id': cve_id,
                'in_kev': True,
                'vendor_project': v.get('vendorProject'),
                'product': v.get('product'),
                'vulnerability_name': v.get('vulnerabilityName'),
                'date_added': v.get('dateAdded'),
                'required_action': v.get('requiredAction'),
                'due_date': v.get('dueDate'),
                'ransomware_use': v.get('knownRansomwareCampaignUse'),
            }
    return index


def lookup_cve(cve_id: str, index: dict) -> dict:
    cve_id = cve_id.upper()
    if cve_id in index:
        return index[cve_id]
    return {
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


def main() -> int:
    parser = argparse.ArgumentParser(description='CISA KEV catalog lookup')
    parser.add_argument('--refresh', action='store_true', help='Download fresh KEV catalog')
    parser.add_argument('--lookup', help='Single CVE ID to look up')
    parser.add_argument('--batch', help='Path to validated_cves.json')
    parser.add_argument('--cache', default='.tmp/kev_cache.json', help='Cache file path')
    parser.add_argument('--output', default='.tmp/kev_results.json', help='Batch output path')
    args = parser.parse_args()

    cache_path = Path(args.cache)

    if args.refresh:
        ok = download_kev(cache_path)
        if not args.lookup and not args.batch:
            return 0 if ok else 1

    catalog = load_cache(cache_path)
    if catalog is None:
        print('[KEV] Failed to load catalog.', file=sys.stderr)
        return 1

    index = build_lookup(catalog)
    print(f'[KEV] Catalog loaded: {len(index)} known exploited CVEs.')

    if args.lookup:
        result = lookup_cve(args.lookup, index)
        print(json.dumps(result, indent=2))
        return 0

    if args.batch:
        data = json.loads(Path(args.batch).read_text(encoding='utf-8'))
        cves = data.get('valid_cves', [])
        results = {cve_id: lookup_cve(cve_id, index) for cve_id in cves}

        kev_count = sum(1 for v in results.values() if v['in_kev'])
        ransomware_count = sum(1 for v in results.values() if v.get('ransomware_use') == 'Known')
        print(f'[KEV] {kev_count}/{len(cves)} CVEs in KEV catalog. {ransomware_count} with known ransomware use.')

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(results, indent=2), encoding='utf-8')
        print(f'[KEV] Results written to {output_path}')
        return 0

    print('[KEV] Nothing to do. Use --refresh, --lookup, or --batch.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
