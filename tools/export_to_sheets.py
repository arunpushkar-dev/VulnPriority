#!/usr/bin/env python3
"""
export_to_sheets.py — Export scored CVEs to a Google Sheets workbook.

Creates 4 tabs: Executive Summary, All Vulnerabilities, Score Breakdown, Audit Trail.

Usage:
    python tools/export_to_sheets.py --scored-dir .tmp/scored/ --title "Vuln Prioritization 2026-04-24" --share
    python tools/export_to_sheets.py --scored-dir .tmp/scored/ --title "..." --email user@company.com
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

SCOPES = [
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/drive',
]


def get_credentials(credentials_path: str):
    try:
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from google.auth.transport.requests import Request
    except ImportError:
        print('[Sheets] google-auth packages not installed. Run: pip install google-api-python-client google-auth-oauthlib', file=sys.stderr)
        return None

    token_path = Path('token.json')
    creds = None

    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            creds = flow.run_local_server(port=0)
        token_path.write_text(creds.to_json(), encoding='utf-8')

    return creds


def build_rows_all(cves: list[dict]) -> tuple[list, list[list]]:
    headers = [
        'CVE ID', 'Score', 'Priority', 'CVSS', 'EPSS%', 'In KEV', 'Exploit',
        'Ransomware', 'Patch Timeline', 'Affected Products', 'ATT&CK Techniques', 'CWE'
    ]
    rows = []
    for c in cves:
        enriched = c.get('enriched', {})
        nvd = enriched.get('nvd') or {}
        epss_data = enriched.get('epss') or {}
        kev_data = enriched.get('kev') or {}
        exploit_data = enriched.get('exploit') or {}
        attack_data = enriched.get('attack') or {}
        cvss = nvd.get('cvss_v31') or nvd.get('cvss_v40') or {}
        products = ', '.join(f'{p["vendor"]} {p["product"]}' for p in nvd.get('affected_products', [])[:3])
        techniques = ', '.join(attack_data.get('techniques', [])[:3])
        exploit_str = 'Full Exploit' if exploit_data.get('has_public_exploit') else ('PoC' if exploit_data.get('has_poc_only') else 'None')
        rows.append([
            c['cve_id'],
            c.get('composite_score'),
            c.get('priority_category', ''),
            cvss.get('baseScore', ''),
            round(epss_data.get('epss_score', 0) * 100, 2) if epss_data.get('epss_score') else '',
            'Yes' if kev_data.get('in_kev') else 'No',
            exploit_str,
            'Known' if kev_data.get('ransomware_use') == 'Known' else 'No',
            c.get('patch_timeline', ''),
            products,
            techniques,
            ', '.join(nvd.get('cwe_ids', [])[:3]),
        ])
    return headers, rows


def build_rows_score_breakdown(cves: list[dict]) -> tuple[list, list[list]]:
    headers = ['CVE ID', 'CVSS Raw', 'CVSS Component', 'EPSS Raw', 'EPSS Component',
               'KEV Bonus', 'Exploit Bonus', 'Ransomware Bonus', 'Raw Total', 'Final Score']
    rows = []
    for c in cves:
        cvss = c.get('cvss_score_raw', 0)
        epss = c.get('epss_score_raw', 0)
        kev = c.get('kev_bonus', 0)
        exp = c.get('exploit_bonus', 0)
        rans = c.get('ransomware_bonus', 0)
        cvss_comp = round(cvss / 10 * 30, 2)
        epss_comp = round(epss * 35, 2)
        raw = cvss_comp + epss_comp + kev + exp + rans
        rows.append([c['cve_id'], cvss, cvss_comp, epss, epss_comp, kev, exp, rans, round(raw, 2), c.get('composite_score', '')])
    return headers, rows


def load_cves(scored_dir: Path) -> list[dict]:
    cves = []
    for f in sorted(scored_dir.glob('CVE-*.json')):
        cves.append(json.loads(f.read_text(encoding='utf-8')))
    cves.sort(key=lambda x: (x.get('composite_score') or -1), reverse=True)
    return cves


def create_sheet(service, title: str) -> str:
    spreadsheet = service.spreadsheets().create(body={
        'properties': {'title': title},
        'sheets': [
            {'properties': {'title': 'Executive Summary', 'index': 0}},
            {'properties': {'title': 'All Vulnerabilities', 'index': 1}},
            {'properties': {'title': 'Score Breakdown', 'index': 2}},
            {'properties': {'title': 'Audit Trail', 'index': 3}},
        ]
    }).execute()
    return spreadsheet['spreadsheetId']


def write_range(service, spreadsheet_id: str, range_name: str, values: list[list]):
    service.spreadsheets().values().update(
        spreadsheetId=spreadsheet_id,
        range=range_name,
        valueInputOption='USER_ENTERED',
        body={'values': values},
    ).execute()


def format_header_row(service, spreadsheet_id: str, sheet_id: int):
    service.spreadsheets().batchUpdate(
        spreadsheetId=spreadsheet_id,
        body={'requests': [{
            'repeatCell': {
                'range': {'sheetId': sheet_id, 'startRowIndex': 0, 'endRowIndex': 1},
                'cell': {'userEnteredFormat': {
                    'backgroundColor': {'red': 0.1, 'green': 0.1, 'blue': 0.18},
                    'textFormat': {'foregroundColor': {'red': 1, 'green': 1, 'blue': 1}, 'bold': True},
                }},
                'fields': 'userEnteredFormat(backgroundColor,textFormat)',
            }
        }]}
    ).execute()


def main() -> int:
    parser = argparse.ArgumentParser(description='Export vulnerability data to Google Sheets')
    parser.add_argument('--scored-dir', default='.tmp/scored/', help='Directory of ScoredCVE JSON files')
    parser.add_argument('--title', default=f'Vuln Prioritization {datetime.now().strftime("%Y-%m-%d")}')
    parser.add_argument('--share', action='store_true', help='Make the spreadsheet link-shareable')
    parser.add_argument('--email', help='Share with a specific Google account')
    parser.add_argument('--credentials', default=os.getenv('GOOGLE_CREDENTIALS_PATH', './credentials.json'))
    args = parser.parse_args()

    creds = get_credentials(args.credentials)
    if creds is None:
        return 1

    try:
        from googleapiclient.discovery import build as google_build
    except ImportError:
        print('[Sheets] google-api-python-client not installed.', file=sys.stderr)
        return 1

    sheets_service = google_build('sheets', 'v4', credentials=creds)
    drive_service = google_build('drive', 'v3', credentials=creds)

    cves = load_cves(Path(args.scored_dir))
    if not cves:
        print('[Sheets] No scored CVEs found.', file=sys.stderr)
        return 1

    print(f'[Sheets] Creating spreadsheet: {args.title}')
    spreadsheet_id = create_sheet(sheets_service, args.title)
    sheet_url = f'https://docs.google.com/spreadsheets/d/{spreadsheet_id}'

    # Tab 1: Executive Summary
    critical = [c for c in cves if c.get('priority_category') == 'Critical']
    high = [c for c in cves if c.get('priority_category') == 'High']
    exec_data = [
        ['Vulnerability Prioritization Report', '', '', '', '', ''],
        ['Generated', datetime.now().strftime('%Y-%m-%d %H:%M'), '', '', '', ''],
        ['', '', '', '', '', ''],
        ['Summary Statistics', '', '', '', '', ''],
        ['Total CVEs', len(cves), '', '', '', ''],
        ['Critical', len(critical), '', '', '', ''],
        ['High', len(high), '', '', '', ''],
        ['Medium', sum(1 for c in cves if c.get('priority_category') == 'Medium'), '', '', '', ''],
        ['Low', sum(1 for c in cves if c.get('priority_category') == 'Low'), '', '', '', ''],
        ['', '', '', '', '', ''],
        ['Top Critical/High CVEs', '', '', '', '', ''],
        ['CVE ID', 'Score', 'Priority', 'CVSS', 'EPSS%', 'Patch Timeline'],
    ]
    for c in (critical + high)[:10]:
        enriched = c.get('enriched', {})
        epss_data = enriched.get('epss') or {}
        nvd = enriched.get('nvd') or {}
        cvss = nvd.get('cvss_v31') or nvd.get('cvss_v40') or {}
        exec_data.append([
            c['cve_id'],
            c.get('composite_score', ''),
            c.get('priority_category', ''),
            cvss.get('baseScore', ''),
            round(epss_data.get('epss_score', 0) * 100, 2) if epss_data.get('epss_score') else '',
            c.get('patch_timeline', ''),
        ])
    write_range(sheets_service, spreadsheet_id, 'Executive Summary!A1', exec_data)

    # Tab 2: All Vulnerabilities
    headers2, rows2 = build_rows_all(cves)
    write_range(sheets_service, spreadsheet_id, 'All Vulnerabilities!A1', [headers2] + rows2)

    # Tab 3: Score Breakdown
    headers3, rows3 = build_rows_score_breakdown(cves)
    write_range(sheets_service, spreadsheet_id, 'Score Breakdown!A1', [headers3] + rows3)

    # Tab 4: Audit Trail
    audit_path = Path('.tmp/audit_log.jsonl')
    audit_rows = [['Timestamp', 'CVE ID', 'Agent', 'Action', 'Success', 'Details']]
    if audit_path.exists():
        for line in audit_path.read_text(encoding='utf-8').strip().split('\n'):
            if line.strip():
                try:
                    entry = json.loads(line)
                    audit_rows.append([
                        entry.get('timestamp', ''),
                        entry.get('cve_id', ''),
                        entry.get('agent', ''),
                        entry.get('action', ''),
                        str(entry.get('success', '')),
                        entry.get('reasoning', ''),
                    ])
                except Exception:
                    pass
    write_range(sheets_service, spreadsheet_id, 'Audit Trail!A1', audit_rows[:1000])

    # Sharing
    if args.share:
        drive_service.permissions().create(
            fileId=spreadsheet_id,
            body={'type': 'anyone', 'role': 'reader'},
        ).execute()
        print(f'[Sheets] Spreadsheet is publicly link-shareable.')

    if args.email:
        drive_service.permissions().create(
            fileId=spreadsheet_id,
            body={'type': 'user', 'role': 'writer', 'emailAddress': args.email},
        ).execute()
        print(f'[Sheets] Shared with {args.email}')

    print(f'[Sheets] Done. Spreadsheet URL: {sheet_url}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
