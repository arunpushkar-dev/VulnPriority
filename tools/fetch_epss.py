#!/usr/bin/env python3
"""
fetch_epss.py — Fetch EPSS (Exploit Prediction Scoring System) scores from FIRST.org.

Batches up to 100 CVEs per API call for efficiency.

Usage:
    python tools/fetch_epss.py --cve CVE-2024-1234 --output .tmp/epss_raw/CVE-2024-1234.json
    python tools/fetch_epss.py --batch .tmp/validated_cves.json --output-dir .tmp/epss_raw/
"""

import argparse
import json
import sys
import time
from pathlib import Path

import requests

EPSS_BASE_URL = 'https://api.first.org/data/v1/epss'
BATCH_SIZE = 100


def fetch_epss_batch(cve_ids: list[str]) -> dict[str, dict]:
    url = EPSS_BASE_URL + '?cve=' + ','.join(cve_ids)
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code != 200:
            print(f'  [EPSS] HTTP {resp.status_code}', file=sys.stderr)
            return {}
        data = resp.json()
        results = {}
        for entry in data.get('data', []):
            cve_id = entry.get('cve', '').upper()
            if cve_id:
                results[cve_id] = {
                    'cve_id': cve_id,
                    'epss_score': float(entry.get('epss', 0)),
                    'epss_percentile': float(entry.get('percentile', 0)),
                    'model_version': data.get('version', ''),
                    'score_date': entry.get('date', ''),
                }
        return results
    except requests.RequestException as e:
        print(f'  [EPSS] Request error: {e}', file=sys.stderr)
        return {}


def empty_epss(cve_id: str) -> dict:
    return {
        'cve_id': cve_id,
        'epss_score': 0.0,
        'epss_percentile': 0.0,
        'model_version': '',
        'score_date': '',
        'epss_not_scored': True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='Fetch EPSS scores from FIRST.org')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--cve', help='Single CVE ID')
    group.add_argument('--batch', help='Path to validated_cves.json')
    parser.add_argument('--output', help='Output file (single mode)')
    parser.add_argument('--output-dir', default='.tmp/epss_raw/', help='Output directory (batch mode)')
    parser.add_argument('--delay', type=float, default=1.0, help='Seconds between batch chunk requests')
    args = parser.parse_args()

    if args.cve:
        cves = [args.cve.upper()]
        output_dir = Path(args.output).parent if args.output else Path('.tmp/epss_raw')
        single_output = Path(args.output) if args.output else output_dir / f'{args.cve.upper()}.json'
    else:
        data = json.loads(Path(args.batch).read_text(encoding='utf-8'))
        cves = data.get('valid_cves', [])
        output_dir = Path(args.output_dir)
        single_output = None

    output_dir.mkdir(parents=True, exist_ok=True)

    # Check which CVEs need fetching
    to_fetch = []
    for cve_id in cves:
        out_path = single_output if single_output else output_dir / f'{cve_id}.json'
        if not out_path.exists():
            to_fetch.append(cve_id)

    if not to_fetch:
        print(f'[EPSS] All {len(cves)} CVEs already cached.')
        return 0

    print(f'[EPSS] Fetching {len(to_fetch)} CVEs in batches of {BATCH_SIZE}...')

    fetched, not_scored = 0, 0
    for chunk_start in range(0, len(to_fetch), BATCH_SIZE):
        chunk = to_fetch[chunk_start:chunk_start + BATCH_SIZE]
        chunk_num = chunk_start // BATCH_SIZE + 1
        total_chunks = (len(to_fetch) + BATCH_SIZE - 1) // BATCH_SIZE
        print(f'  [EPSS] Batch {chunk_num}/{total_chunks} ({len(chunk)} CVEs)...')

        results = fetch_epss_batch(chunk)

        for cve_id in chunk:
            out_path = single_output if single_output else output_dir / f'{cve_id}.json'
            if cve_id in results:
                out_path.write_text(json.dumps(results[cve_id], indent=2), encoding='utf-8')
                fetched += 1
            else:
                out_path.write_text(json.dumps(empty_epss(cve_id), indent=2), encoding='utf-8')
                not_scored += 1

        if chunk_start + BATCH_SIZE < len(to_fetch):
            time.sleep(args.delay)

    print(f'[EPSS] Done. {fetched} scored, {not_scored} not in EPSS database.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
