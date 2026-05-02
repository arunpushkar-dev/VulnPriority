#!/usr/bin/env python3
"""
validate_cves.py — CVE format validation and deduplication.

Usage:
    python tools/validate_cves.py --input cves.txt --output .tmp/validated_cves.json
"""

import argparse
import json
import re
import sys
from pathlib import Path

CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)


def parse_cve_input(raw: str) -> list[str]:
    """Split raw text into individual CVE candidates (newlines or commas)."""
    tokens = re.split(r'[\n,;]+', raw)
    return [t.strip() for t in tokens if t.strip()]


def validate(candidates: list[str]) -> tuple[list[str], list[str]]:
    seen = set()
    valid = []
    invalid = []
    for c in candidates:
        normalized = c.upper()
        if CVE_PATTERN.match(normalized):
            if normalized not in seen:
                seen.add(normalized)
                valid.append(normalized)
        else:
            invalid.append(c)
    # Sort by year desc, then by sequence number desc
    valid.sort(key=lambda x: (int(x.split('-')[1]), int(x.split('-')[2])), reverse=True)
    return valid, invalid


def main() -> int:
    parser = argparse.ArgumentParser(description='Validate and deduplicate CVE IDs')
    parser.add_argument('--input', required=True, help='Path to file containing CVE IDs')
    parser.add_argument('--output', default='.tmp/validated_cves.json', help='Output JSON path')
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f'[ERROR] Input file not found: {args.input}', file=sys.stderr)
        return 2

    raw = input_path.read_text(encoding='utf-8')
    candidates = parse_cve_input(raw)
    total_input = len(candidates)

    valid_cves, invalid_entries = validate(candidates)
    duplicate_count = total_input - len(valid_cves) - len(invalid_entries)

    result = {
        'valid_cves': valid_cves,
        'invalid_entries': invalid_entries,
        'duplicate_count': duplicate_count,
        'total_input': total_input,
        'total_valid': len(valid_cves),
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2), encoding='utf-8')

    print(f'[CVE Intake] {total_input} input -> {len(valid_cves)} valid, '
          f'{len(invalid_entries)} invalid, {duplicate_count} duplicates removed')

    if invalid_entries:
        print(f'[CVE Intake] Invalid entries: {", ".join(invalid_entries[:10])}')

    if len(valid_cves) == 0:
        print('[ERROR] No valid CVEs found. Pipeline cannot proceed.', file=sys.stderr)
        return 1

    print(f'[CVE Intake] Output: {output_path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
