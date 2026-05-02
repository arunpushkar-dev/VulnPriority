#!/usr/bin/env python3
"""
main.py — Vulnerability Prioritization Pipeline Orchestrator

Runs all 7 pipeline phases in sequence, from CVE intake through scored HTML report.

Usage:
    python main.py --input cves.txt --output html
    python main.py --input cves.txt --output both --title "Q2 2026 Vuln Assessment"
    python main.py --input cves.txt --output html --skip-exploitdb --nvd-api-key YOUR_KEY
    python main.py --input cves.txt --output html --skip-exploitdb --skip-attack  # fast mode

Pipeline phases:
    1. CVE Intake        → validate_cves.py
    2. NVD + OSV         → fetch_nvd.py, fetch_osv.py
    3. Threat Intel      → fetch_kev.py, fetch_epss.py, fetch_exploitdb.py
    4. Context Enrich    → fetch_attack.py, merge_enrichment.py
    5. Scoring           → calculate_score.py
    6. Recommendations   → generate_recommendations.py
    7. Report            → generate_report.py / export_to_sheets.py
"""

import argparse
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def run(cmd: list[str], step: str, verbose: bool = False) -> bool:
    """Run a subprocess tool. Returns True on success."""
    print(f'\n[{step}] Running: {" ".join(cmd)}')
    result = subprocess.run(cmd, capture_output=not verbose, text=True)
    if result.returncode != 0:
        print(f'[ERROR] {step} failed (exit {result.returncode})', file=sys.stderr)
        if not verbose and result.stderr:
            print(result.stderr, file=sys.stderr)
        return False
    if result.stdout:
        print(result.stdout.rstrip())
    print(f'[OK] {step}')
    return True


def ensure_dirs():
    dirs = [
        '.tmp/nvd_raw', '.tmp/epss_raw', '.tmp/osv_raw',
        '.tmp/exploitdb_raw', '.tmp/attack_raw', '.tmp/enriched',
        '.tmp/scored', '.tmp/recommendations',
    ]
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Vulnerability Prioritization Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--input', required=True, help='Path to CVE list file (one per line or comma-separated)')
    parser.add_argument('--output', required=True, choices=['html', 'sheets', 'both'], help='Report output format')
    parser.add_argument('--title', default=f'Vulnerability Prioritization Report {datetime.now().strftime("%Y-%m-%d")}',
                        help='Report title')
    parser.add_argument('--nvd-api-key', default=os.getenv('NVD_API_KEY', ''),
                        help='NVD API key (raises rate limit from 5 to 50 req/30s)')
    parser.add_argument('--skip-exploitdb', action='store_true', help='Skip ExploitDB scraping')
    parser.add_argument('--skip-attack', action='store_true', help='Skip MITRE ATT&CK mapping (saves ~30s for bundle download)')
    parser.add_argument('--report-dir', default='./reports', help='Output directory for HTML report')
    parser.add_argument('--no-cache', action='store_true', help='Force refresh of all cached data (KEV, ATT&CK)')
    parser.add_argument('--logo', help='Path to organization logo PNG (embedded in report)')
    parser.add_argument('--email', help='Share Google Sheets with this email (--output sheets/both only)')
    parser.add_argument('--verbose', action='store_true', help='Show full tool output')
    args = parser.parse_args()

    print('=' * 60)
    print('  VULNERABILITY PRIORITIZATION PIPELINE')
    print(f'  Input: {args.input}')
    print(f'  Output: {args.output}')
    print('=' * 60)

    ensure_dirs()

    # ── Phase 1: CVE Intake ──────────────────────────────────────
    ok = run(['python', 'tools/validate_cves.py',
              '--input', args.input,
              '--output', '.tmp/validated_cves.json'],
             'Phase 1: CVE Intake', args.verbose)
    if not ok:
        print('\n[ABORT] Cannot proceed without valid CVEs.', file=sys.stderr)
        return 1

    nvd_delay = '0.65' if args.nvd_api_key else '6.0'

    # ── Phase 2: Vulnerability Research (NVD + OSV) ──────────────
    nvd_cmd = ['python', 'tools/fetch_nvd.py',
               '--batch', '.tmp/validated_cves.json',
               '--output-dir', '.tmp/nvd_raw/',
               '--delay', nvd_delay]
    if args.nvd_api_key:
        nvd_cmd += ['--api-key', args.nvd_api_key]
    run(nvd_cmd, 'Phase 2a: NVD Fetch', args.verbose)

    run(['python', 'tools/fetch_osv.py',
         '--batch', '.tmp/validated_cves.json',
         '--output-dir', '.tmp/osv_raw/'],
        'Phase 2b: OSV Fetch', args.verbose)

    # ── Phase 3: Threat Intelligence ─────────────────────────────
    refresh_flag = ['--refresh'] if args.no_cache else []
    run(['python', 'tools/fetch_kev.py', '--refresh',
         '--output', '.tmp/kev_cache.json'] + ([] if not args.no_cache else []),
        'Phase 3a: KEV Refresh', args.verbose)

    run(['python', 'tools/fetch_kev.py',
         '--batch', '.tmp/validated_cves.json',
         '--cache', '.tmp/kev_cache.json',
         '--output', '.tmp/kev_results.json'],
        'Phase 3b: KEV Lookup', args.verbose)

    run(['python', 'tools/fetch_epss.py',
         '--batch', '.tmp/validated_cves.json',
         '--output-dir', '.tmp/epss_raw/'],
        'Phase 3c: EPSS Fetch', args.verbose)

    if not args.skip_exploitdb:
        run(['python', 'tools/fetch_exploitdb.py',
             '--batch', '.tmp/validated_cves.json',
             '--output-dir', '.tmp/exploitdb_raw/',
             '--delay', '2.0'],
            'Phase 3d: ExploitDB Scrape', args.verbose)

    # ── Phase 4: Context Enrichment ──────────────────────────────
    if not args.skip_attack:
        attack_refresh_cmd = ['python', 'tools/fetch_attack.py',
                               '--cache', '.tmp/attack_cache.json']
        if args.no_cache:
            attack_refresh_cmd.append('--refresh')
        run(attack_refresh_cmd + ['--batch', '.tmp/validated_cves.json',
                                   '--output-dir', '.tmp/attack_raw/'],
            'Phase 4a: ATT&CK Mapping', args.verbose)

    merge_cmd = ['python', 'tools/merge_enrichment.py',
                 '--cves', '.tmp/validated_cves.json',
                 '--nvd-dir', '.tmp/nvd_raw/',
                 '--osv-dir', '.tmp/osv_raw/',
                 '--kev', '.tmp/kev_results.json',
                 '--epss-dir', '.tmp/epss_raw/',
                 '--exploitdb-dir', '.tmp/exploitdb_raw/',
                 '--output-dir', '.tmp/enriched/']
    if not args.skip_attack:
        merge_cmd += ['--attack-dir', '.tmp/attack_raw/']
    run(merge_cmd, 'Phase 4b: Merge Enrichment', args.verbose)

    # ── Phase 5: Scoring ─────────────────────────────────────────
    ok = run(['python', 'tools/calculate_score.py',
              '--enriched-dir', '.tmp/enriched/',
              '--output-dir', '.tmp/scored/'],
             'Phase 5: Scoring', args.verbose)
    if not ok:
        print('\n[ABORT] Scoring failed.', file=sys.stderr)
        return 1

    # ── Phase 6: Recommendations ─────────────────────────────────
    run(['python', 'tools/generate_recommendations.py',
         '--scored-dir', '.tmp/scored/',
         '--output-dir', '.tmp/recommendations/'],
        'Phase 6: Recommendations', args.verbose)

    # ── Phase 7: Report Generation ───────────────────────────────
    report_path = f'{args.report_dir}/vuln_report_{datetime.now().strftime("%Y%m%d_%H%M")}.html'

    if args.output in ('html', 'both'):
        report_cmd = ['python', 'tools/generate_report.py',
                      '--scored-dir', '.tmp/scored/',
                      '--recommendations-dir', '.tmp/recommendations/',
                      '--output', report_path,
                      '--title', args.title]
        if args.logo:
            report_cmd += ['--logo', args.logo]
        ok = run(report_cmd, 'Phase 7a: HTML Report', args.verbose)
        if ok:
            print(f'\n  >>> HTML Report: {Path(report_path).resolve()}')

    if args.output in ('sheets', 'both'):
        sheets_cmd = ['python', 'tools/export_to_sheets.py',
                      '--scored-dir', '.tmp/scored/',
                      '--title', args.title]
        if args.email:
            sheets_cmd += ['--email', args.email]
        else:
            sheets_cmd.append('--share')
        run(sheets_cmd, 'Phase 7b: Google Sheets Export', args.verbose)

    print('\n' + '=' * 60)
    print('  PIPELINE COMPLETE')
    print('=' * 60)
    return 0


if __name__ == '__main__':
    sys.exit(main())
