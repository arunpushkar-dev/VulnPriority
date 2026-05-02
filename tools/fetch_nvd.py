#!/usr/bin/env python3
"""
fetch_nvd.py — Fetch CVE data from NVD API v2.

Rate limits:
  Without API key: 5 req/30s  → use --delay 6.0 (default)
  With API key:   50 req/30s  → use --delay 0.65

Usage:
    python tools/fetch_nvd.py --cve CVE-2024-1234 --output .tmp/nvd_raw/CVE-2024-1234.json
    python tools/fetch_nvd.py --batch .tmp/validated_cves.json --output-dir .tmp/nvd_raw/
    python tools/fetch_nvd.py --batch .tmp/validated_cves.json --output-dir .tmp/nvd_raw/ --api-key KEY --delay 0.65
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

# patch_sources lives in the same tools/ directory
sys.path.insert(0, str(Path(__file__).parent))
from patch_sources import is_trusted_patch_source

load_dotenv()

NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


def fetch_with_retry(url: str, headers: dict, max_retries: int = 3, base_delay: float = 6.0) -> dict | None:
    for attempt in range(max_retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return {'error': 'not_found', 'status': 404}
            elif resp.status_code == 429:
                wait = base_delay * (2 ** attempt)
                print(f'  [NVD] Rate limited. Waiting {wait:.0f}s (attempt {attempt+1}/{max_retries})...')
                time.sleep(wait)
            elif resp.status_code == 503:
                print(f'  [NVD] Service unavailable. Waiting 10s...')
                time.sleep(10)
            else:
                print(f'  [NVD] HTTP {resp.status_code} for {url}', file=sys.stderr)
                return None
        except requests.RequestException as e:
            print(f'  [NVD] Request error: {e}', file=sys.stderr)
            if attempt < max_retries:
                time.sleep(base_delay)
            else:
                return None
    return None


def parse_nvd_response(cve_id: str, data: dict) -> dict:
    """Extract relevant fields from NVD API v2 response into NVDEnrichment shape."""
    if data.get('error') == 'not_found':
        return {
            'cve_id': cve_id,
            'error': 'nvd_not_found',
            'description': '',
            'published_date': '',
            'last_modified': '',
            'cvss_v31': None,
            'cvss_v40': None,
            'cwe_ids': [],
            'affected_products': [],
            'references': [],
        }

    vulns = data.get('vulnerabilities', [])
    if not vulns:
        return {
            'cve_id': cve_id,
            'error': 'nvd_empty_response',
            'description': '',
            'published_date': '',
            'last_modified': '',
            'cvss_v31': None,
            'cvss_v40': None,
            'cwe_ids': [],
            'affected_products': [],
            'references': [],
        }

    cve = vulns[0]['cve']

    # Description (English)
    description = ''
    for d in cve.get('descriptions', []):
        if d.get('lang') == 'en':
            description = d.get('value', '')
            break

    # CVSS metrics
    metrics = cve.get('metrics', {})
    cvss_v31 = None
    cvss_v40 = None

    def _parse_cvss_metric(metrics_list, default_version):
        """Return parsed CVSS dict from a NVD metrics list, preferring Primary type."""
        primary = next((m for m in metrics_list if m.get('type') == 'Primary'), None)
        fallback = metrics_list[0] if metrics_list else None
        entry = primary or fallback
        if not entry:
            return None
        d = entry.get('cvssData', {})
        if not d.get('baseScore'):
            return None
        return {
            'version': d.get('version', default_version),
            'baseScore': d.get('baseScore'),
            'baseSeverity': d.get('baseSeverity', ''),
            'vectorString': d.get('vectorString', ''),
            'attackVector': d.get('attackVector', ''),
            'attackComplexity': d.get('attackComplexity', ''),
            'privilegesRequired': d.get('privilegesRequired', ''),
            'userInteraction': d.get('userInteraction', ''),
            'confidentialityImpact': d.get('confidentialityImpact', ''),
            'integrityImpact': d.get('integrityImpact', ''),
            'availabilityImpact': d.get('availabilityImpact', ''),
        }

    # v4.0 — direct
    cvss_v40 = _parse_cvss_metric(metrics.get('cvssMetricV40', []), '4.0')

    # v3.1 — try cvssMetricV31 first, fall back to cvssMetricV30
    cvss_v31 = _parse_cvss_metric(metrics.get('cvssMetricV31', []), '3.1')
    if cvss_v31 is None:
        cvss_v31 = _parse_cvss_metric(metrics.get('cvssMetricV30', []), '3.0')

    # CWE IDs
    cwe_ids = []
    for w in cve.get('weaknesses', []):
        for wd in w.get('description', []):
            val = wd.get('value', '')
            if val.startswith('CWE-') and val not in cwe_ids:
                cwe_ids.append(val)

    # Affected products (CPE-based, simplified)
    affected_products = []
    seen_products = set()
    for config in cve.get('configurations', []):
        for node in config.get('nodes', []):
            for cpe in node.get('cpeMatch', []):
                criteria = cpe.get('criteria', '')
                parts = criteria.split(':')
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    version = parts[5] if len(parts) > 5 else '*'
                    key = f'{vendor}:{product}'
                    if key not in seen_products:
                        seen_products.add(key)
                        affected_products.append({
                            'vendor': vendor,
                            'product': product,
                            'versions': [version],
                        })
                    else:
                        for ap in affected_products:
                            if ap['vendor'] == vendor and ap['product'] == product:
                                if version not in ap['versions']:
                                    ap['versions'].append(version)

    # CPE strings (raw, for system categorization)
    cpe_list = []
    for config in cve.get('configurations', []):
        for node in config.get('nodes', []):
            for cpe_match in node.get('cpeMatch', []):
                criteria = cpe_match.get('criteria', '')
                if criteria and criteria not in cpe_list:
                    cpe_list.append(criteria)

    # CAPEC IDs derived from CWE mapping
    capec_ids = _cwe_to_capec(cwe_ids)

    # System category: IT / ICS-OT / IoT / Cloud / Mobile
    system_category = _classify_system(cpe_list, cwe_ids)

    # References — extract all URLs plus patch/advisory links separately.
    # patch_refs only includes URLs from OEM / authoritative sources.
    #
    # Tag strategy (NVD API v2 tag vocabulary):
    #   Primary:  'Patch', 'Vendor Advisory', 'Mitigation' — any domain accepted
    #             if it passes is_trusted_patch_source.
    #   Extended: 'Third Party Advisory' — many vendor advisories for *upstream* CVEs
    #             are tagged this way (e.g. Red Hat advisory for an Apache CVE).
    #             Accepted only from trusted domains.
    #   Fallback: When no tagged refs survive, any reference from a trusted domain
    #             is surfaced so CISOs always have at least one actionable link.
    _PATCH_TAGS_PRIMARY  = {'Patch', 'Vendor Advisory', 'Mitigation'}
    _PATCH_TAGS_EXTENDED = {'Third Party Advisory'}
    all_refs = cve.get('references', [])
    seen_urls: set[str] = set()
    references: list[str] = []
    patch_refs: list[str] = []
    trusted_refs: list[str] = []     # fallback pool — trusted domain, any tag
    for ref in all_refs:
        url = ref.get('url', '').strip()
        if not url:
            continue
        tags = set(ref.get('tags', []))
        if url not in seen_urls:
            seen_urls.add(url)
            references.append(url)
        trusted = is_trusted_patch_source(url)
        if trusted and url not in trusted_refs:
            trusted_refs.append(url)
        is_primary  = bool(tags & _PATCH_TAGS_PRIMARY)
        is_extended = bool(tags & _PATCH_TAGS_EXTENDED) and trusted
        if (is_primary or is_extended) and url not in patch_refs and trusted:
            patch_refs.append(url)
    # Fallback: if tag-based extraction yielded nothing, surface all trusted-domain refs
    if not patch_refs:
        patch_refs = trusted_refs[:10]

    return {
        'cve_id': cve_id,
        'vuln_status': cve.get('vulnStatus', 'Unknown'),
        'description': description,
        'published_date': cve.get('published', ''),
        'last_modified': cve.get('lastModified', ''),
        'cvss_v31': cvss_v31,
        'cvss_v40': cvss_v40,
        'cwe_ids': cwe_ids,
        'capec_ids': capec_ids,
        'cpe_list': cpe_list[:30],
        'system_category': system_category,
        'affected_products': affected_products[:20],
        'references': references[:20],
        'patch_refs': patch_refs[:10],
    }


# CWE → CAPEC mapping (community standard)
_CWE_CAPEC: dict[str, list[str]] = {
    'CWE-79':  ['CAPEC-86', 'CAPEC-198'],
    'CWE-89':  ['CAPEC-66', 'CAPEC-7'],
    'CWE-78':  ['CAPEC-88', 'CAPEC-108'],
    'CWE-22':  ['CAPEC-126', 'CAPEC-64'],
    'CWE-94':  ['CAPEC-242', 'CAPEC-35'],
    'CWE-287': ['CAPEC-114', 'CAPEC-115'],
    'CWE-306': ['CAPEC-115', 'CAPEC-36'],
    'CWE-502': ['CAPEC-586'],
    'CWE-416': ['CAPEC-123'],
    'CWE-125': ['CAPEC-123', 'CAPEC-100'],
    'CWE-787': ['CAPEC-100', 'CAPEC-123'],
    'CWE-190': ['CAPEC-92'],
    'CWE-20':  ['CAPEC-88', 'CAPEC-153'],
    'CWE-269': ['CAPEC-122', 'CAPEC-1'],
    'CWE-732': ['CAPEC-1', 'CAPEC-60'],
    'CWE-400': ['CAPEC-469', 'CAPEC-130'],
    'CWE-770': ['CAPEC-130'],
    'CWE-434': ['CAPEC-1', 'CAPEC-17'],
    'CWE-611': ['CAPEC-221'],
    'CWE-918': ['CAPEC-664'],
    'CWE-427': ['CAPEC-38', 'CAPEC-471'],
    'CWE-426': ['CAPEC-38'],
    'CWE-276': ['CAPEC-1', 'CAPEC-60'],
    'CWE-352': ['CAPEC-62'],
    'CWE-601': ['CAPEC-194'],
    'CWE-77':  ['CAPEC-88'],
    'CWE-119': ['CAPEC-100', 'CAPEC-123'],
    'CWE-200': ['CAPEC-118', 'CAPEC-169'],
    'CWE-312': ['CAPEC-37'],
    'CWE-798': ['CAPEC-70', 'CAPEC-191'],
    'CWE-862': ['CAPEC-1', 'CAPEC-122'],
    'CWE-863': ['CAPEC-1', 'CAPEC-122'],
}


def _cwe_to_capec(cwe_ids: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for cwe in cwe_ids:
        for capec in _CWE_CAPEC.get(cwe, []):
            if capec not in seen:
                seen.add(capec)
                result.append(capec)
    return result


_ICS_OT_VENDORS = {
    'siemens', 'rockwell', 'schneider', 'honeywell', 'abb', 'ge',
    'yokogawa', 'emerson', 'moxa', 'advantech', 'omron', 'mitsubishi',
    'allen-bradley', 'beckhoff', 'phoenix_contact',
}
_IOT_VENDORS = {
    'd-link', 'netgear', 'tp-link', 'asus', 'zyxel', 'hikvision',
    'dahua', 'ubiquiti', 'mikrotik', 'qnap', 'synology', 'dlink',
}
_CLOUD_VENDORS = {
    'amazon', 'microsoft', 'google', 'hashicorp', 'kubernetes',
    'docker', 'vmware', 'redhat', 'canonical', 'openstack',
}
_MOBILE_PLATFORMS = {'android', 'ios', 'apple', 'iphone', 'ipad'}

_ICS_OT_CWES = {'CWE-1188', 'CWE-321', 'CWE-798', 'CWE-306'}


def _classify_system(cpe_list: list[str], cwe_ids: list[str]) -> str:
    vendors = set()
    products_lower = set()
    for cpe in cpe_list:
        parts = cpe.split(':')
        if len(parts) >= 5:
            vendors.add(parts[3].lower())
            products_lower.add(parts[4].lower())

    if vendors & _ICS_OT_VENDORS or any(
        kw in p for p in products_lower for kw in ('plc', 'scada', 'hmi', 'rtu', 'ics')
    ) or any(c in _ICS_OT_CWES for c in cwe_ids):
        return 'ICS/OT'
    if vendors & _IOT_VENDORS or any(
        kw in p for p in products_lower for kw in ('router', 'camera', 'firmware', 'nvr', 'dvr')
    ):
        return 'IoT'
    if vendors & _MOBILE_PLATFORMS or any(
        p in products_lower for p in ('android', 'ios')
    ):
        return 'Mobile'
    if vendors & _CLOUD_VENDORS or any(
        kw in p for p in products_lower for kw in ('cloud', 'container', 'kubernetes', 'docker')
    ):
        return 'Cloud/Virtualization'
    return 'IT'


def fetch_single(cve_id: str, api_key: str = '') -> dict | None:
    url = f'{NVD_BASE_URL}?cveId={cve_id}'
    headers = {'Accept': 'application/json'}
    if api_key:
        headers['apiKey'] = api_key
    return fetch_with_retry(url, headers)


def main() -> int:
    parser = argparse.ArgumentParser(description='Fetch CVE data from NVD API v2')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--cve', help='Single CVE ID')
    group.add_argument('--batch', help='Path to validated_cves.json')
    parser.add_argument('--output', help='Output file path (single mode)')
    parser.add_argument('--output-dir', default='.tmp/nvd_raw/', help='Output directory (batch mode)')
    parser.add_argument('--delay', type=float, default=6.0, help='Seconds between requests (default 6.0 for no-key)')
    parser.add_argument('--api-key', default=os.getenv('NVD_API_KEY', ''), help='NVD API key')
    parser.add_argument('--retry', type=int, default=3, help='Max retries per request')
    args = parser.parse_args()

    if args.cve:
        cves = [args.cve.upper()]
        output_dir = Path(args.output).parent if args.output else Path('.tmp/nvd_raw')
        single_output = Path(args.output) if args.output else output_dir / f'{args.cve.upper()}.json'
    else:
        data = json.loads(Path(args.batch).read_text(encoding='utf-8'))
        cves = data.get('valid_cves', [])
        output_dir = Path(args.output_dir)
        single_output = None

    output_dir.mkdir(parents=True, exist_ok=True)

    if args.api_key:
        print(f'[NVD] Using API key. Delay: {args.delay}s per request.')
    else:
        print(f'[NVD] No API key. Rate limit: 5 req/30s. Delay: {args.delay}s per request.')

    success, failed = 0, 0
    for i, cve_id in enumerate(cves):
        out_path = single_output if single_output else output_dir / f'{cve_id}.json'

        if out_path.exists():
            print(f'  [{i+1}/{len(cves)}] {cve_id} — cached, skipping')
            success += 1
            continue

        print(f'  [{i+1}/{len(cves)}] Fetching {cve_id}...')
        raw = fetch_single(cve_id, args.api_key)

        if raw is None:
            print(f'  [NVD] FAILED to fetch {cve_id}', file=sys.stderr)
            out_path.write_text(json.dumps({'cve_id': cve_id, 'error': 'fetch_failed'}, indent=2), encoding='utf-8')
            failed += 1
        else:
            parsed = parse_nvd_response(cve_id, raw)
            out_path.write_text(json.dumps(parsed, indent=2), encoding='utf-8')
            if parsed.get('error'):
                print(f'  [NVD] {cve_id} — {parsed["error"]}')
            success += 1

        if i < len(cves) - 1:
            time.sleep(args.delay)

    print(f'[NVD] Done. {success} fetched, {failed} failed. Output: {output_dir}')
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
