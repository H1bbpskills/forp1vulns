#!/usr/bin/env python3
"""
JS File Analyzer for Bug Bounty Recon
Scans JavaScript files for:
- API paths/endpoints
- Hardcoded secrets (API keys, tokens, passwords)
- Internal URLs and domains
- Sensitive data patterns
- Cloud service references
- Debug/admin endpoints
"""

import re
import sys
import json
import os
from urllib.parse import urlparse
from collections import defaultdict

# Patterns to search for in JS files
PATTERNS = {
    # API Paths and Endpoints
    "api_paths": [
        r'["\x27/](api/v[0-9]+/[a-zA-Z0-9/_-]+)["\x27]',
        r'["\x27](\/api\/[a-zA-Z0-9/_-]+)["\x27]',
        r'["\x27](\/v[0-9]+\/[a-zA-Z0-9/_-]+)["\x27]',
        r'["\x27](\/graphql)["\x27]',
        r'["\x27](\/rest\/[a-zA-Z0-9/_-]+)["\x27]',
        r'["\x27](\/internal\/[a-zA-Z0-9/_-]+)["\x27]',
        r'["\x27](\/admin\/[a-zA-Z0-9/_-]+)["\x27]',
        r'["\x27](\/debug\/[a-zA-Z0-9/_-]+)["\x27]',
        r'["\x27](\/private\/[a-zA-Z0-9/_-]+)["\x27]',
        r'["\x27](\/hidden\/[a-zA-Z0-9/_-]+)["\x27]',
        r'["\x27](\/swagger[a-zA-Z0-9/_.-]*)["\x27]',
        r'["\x27](\/openapi[a-zA-Z0-9/_.-]*)["\x27]',
        r'["\x27](\/docs\/api[a-zA-Z0-9/_.-]*)["\x27]',
    ],

    # Hardcoded Secrets
    "secrets": [
        r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\x27]([a-zA-Z0-9_\-]{16,})["\x27]',
        r'(?i)(api[_-]?secret|apisecret)\s*[:=]\s*["\x27]([a-zA-Z0-9_\-]{16,})["\x27]',
        r'(?i)(access[_-]?token|accesstoken)\s*[:=]\s*["\x27]([a-zA-Z0-9_\-]{16,})["\x27]',
        r'(?i)(auth[_-]?token|authtoken)\s*[:=]\s*["\x27]([a-zA-Z0-9_\-]{16,})["\x27]',
        r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\x27]([a-zA-Z0-9_\-]{16,})["\x27]',
        r'(?i)(private[_-]?key|privatekey)\s*[:=]\s*["\x27]([a-zA-Z0-9_\-/+=]{16,})["\x27]',
        r'(?i)(password|passwd|pwd)\s*[:=]\s*["\x27]([^\x27"]{6,})["\x27]',
        r'(?i)(client[_-]?secret|clientsecret)\s*[:=]\s*["\x27]([a-zA-Z0-9_\-]{16,})["\x27]',
        r'(?i)(bearer)\s+([a-zA-Z0-9_\-\.]{20,})',
        r'(?i)(authorization)\s*[:=]\s*["\x27](Basic\s+[a-zA-Z0-9+/=]+)["\x27]',
    ],

    # AWS/Cloud Keys
    "cloud_keys": [
        r'(AKIA[0-9A-Z]{16})',  # AWS Access Key
        r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\x27]([a-zA-Z0-9/+=]{40})["\x27]',
        r'(?i)(aws[_-]?session[_-]?token)\s*[:=]\s*["\x27]([a-zA-Z0-9/+=]+)["\x27]',
        r's3\.amazonaws\.com/([a-zA-Z0-9._-]+)',  # S3 buckets
        r'([a-zA-Z0-9._-]+)\.s3\.amazonaws\.com',  # S3 buckets alt
        r'(?i)(azure[_-]?storage[_-]?key)\s*[:=]\s*["\x27]([a-zA-Z0-9+/=]+)["\x27]',
        r'(?i)(google[_-]?api[_-]?key|gcp[_-]?key)\s*[:=]\s*["\x27](AIza[a-zA-Z0-9_-]{35})["\x27]',
    ],

    # Internal/Hidden URLs
    "internal_urls": [
        r'https?://[a-zA-Z0-9.-]*(internal|staging|stg|dev|test|uat|preprod|sandbox|qa|lab|debug|admin|private|hidden|secret|beta|alpha)[a-zA-Z0-9.-]*\.[a-zA-Z]{2,}[a-zA-Z0-9/._-]*',
        r'https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/][^\s"\x27]*',
        r'https?://172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}[:/][^\s"\x27]*',
        r'https?://192\.168\.\d{1,3}\.\d{1,3}[:/][^\s"\x27]*',
        r'https?://localhost[:/][^\s"\x27]*',
        r'https?://127\.0\.0\.1[:/][^\s"\x27]*',
    ],

    # T-Mobile Specific
    "tmobile_specific": [
        r'https?://[a-zA-Z0-9.-]*\.t-mobile\.com[a-zA-Z0-9/._?&=-]*',
        r'https?://[a-zA-Z0-9.-]*\.sprint\.com[a-zA-Z0-9/._?&=-]*',
        r'https?://[a-zA-Z0-9.-]*api\.t-mobile\.com[a-zA-Z0-9/._?&=-]*',
        r'(?i)(msisdn|imsi|imei|iccid|mdn|esim)\s*[:=]\s*["\x27]([^"\x27]+)["\x27]',
        r'(?i)(digits|digit)[a-zA-Z0-9._/-]*api[a-zA-Z0-9._/-]*',
        r'(?i)(carrier|network)[_-]?auth[a-zA-Z0-9._/-]*',
        r'(?i)x-t-mobile-[a-zA-Z0-9-]+',
        r'(?i)x-mdn[:\s]',
        r'(?i)x-msisdn[:\s]',
        r'(?i)x-carrier[a-zA-Z0-9-]*[:\s]',
    ],

    # Sensitive Paths
    "sensitive_paths": [
        r'["\x27](/\.env)["\x27]',
        r'["\x27](/\.git[/"\x27])',
        r'["\x27](/config[./][a-zA-Z0-9._-]+)["\x27]',
        r'["\x27](/backup[/a-zA-Z0-9._-]*)["\x27]',
        r'["\x27](/dump[/a-zA-Z0-9._-]*)["\x27]',
        r'["\x27](/export[/a-zA-Z0-9._-]*)["\x27]',
        r'["\x27](/upload[/a-zA-Z0-9._-]*)["\x27]',
        r'["\x27](/download[/a-zA-Z0-9._-]*)["\x27]',
        r'["\x27](/temp[/a-zA-Z0-9._-]*)["\x27]',
        r'["\x27](/logs?[/a-zA-Z0-9._-]*)["\x27]',
        r'["\x27](/actuator[/a-zA-Z0-9._-]*)["\x27]',
        r'["\x27](/health[/a-zA-Z0-9._-]*)["\x27]',
        r'["\x27](/metrics[/a-zA-Z0-9._-]*)["\x27]',
        r'["\x27](/trace[/a-zA-Z0-9._-]*)["\x27]',
        r'["\x27](/info)["\x27]',
        r'["\x27](/status)["\x27]',
        r'["\x27](/console)["\x27]',
        r'["\x27](/phpinfo)["\x27]',
        r'["\x27](/server-status)["\x27]',
        r'["\x27](/server-info)["\x27]',
        r'["\x27](/wp-admin[/a-zA-Z0-9._-]*)["\x27]',
        r'["\x27](/wp-json[/a-zA-Z0-9._-]*)["\x27]',
    ],

    # Email addresses
    "emails": [
        r'[a-zA-Z0-9._%+-]+@t-mobile\.com',
        r'[a-zA-Z0-9._%+-]+@sprint\.com',
        r'[a-zA-Z0-9._%+-]+@(corp|internal|dev)\.[a-zA-Z0-9.-]+',
    ],

    # Interesting comments/debug
    "debug_info": [
        r'(?i)(todo|fixme|hack|bug|xxx|temp|debug)\s*[:]\s*(.{10,80})',
        r'(?i)(console\.(log|debug|info|warn|error))\s*\(\s*["\x27]([^"\x27]{10,})["\x27]',
    ],
}

# Severity classification
SEVERITY = {
    "secrets": "CRITICAL",
    "cloud_keys": "CRITICAL",
    "tmobile_specific": "HIGH",
    "internal_urls": "HIGH",
    "api_paths": "MEDIUM",
    "sensitive_paths": "MEDIUM",
    "emails": "LOW",
    "debug_info": "INFO",
}

def analyze_js_content(content, source_url):
    """Analyze JS content for interesting patterns"""
    findings = defaultdict(list)

    for category, patterns in PATTERNS.items():
        for pattern in patterns:
            try:
                matches = re.finditer(pattern, content)
                for match in matches:
                    finding = match.group(0).strip()
                    # Skip common false positives
                    if len(finding) < 8:
                        continue
                    if finding in ('undefined', 'null', 'false', 'true'):
                        continue
                    findings[category].append({
                        "match": finding[:200],
                        "source": source_url,
                        "severity": SEVERITY.get(category, "INFO"),
                    })
            except re.error:
                continue

    return findings

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_js.py <js_urls_file> [output_dir]")
        sys.exit(1)

    js_urls_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "."

    with open(js_urls_file) as f:
        js_urls = [line.strip() for line in f if line.strip()]

    print(f"[*] Analyzing {len(js_urls)} JS URLs...")

    all_findings = defaultdict(list)
    analyzed = 0
    errors = 0

    for url in js_urls:
        try:
            # Download JS file
            import subprocess
            result = subprocess.run(
                ['curl', '-sS', '-L', '--max-time', '15', '-k', url],
                capture_output=True, text=True, timeout=20
            )
            content = result.stdout

            if not content or len(content) < 50:
                continue

            # Analyze
            findings = analyze_js_content(content, url)
            for category, items in findings.items():
                all_findings[category].extend(items)

            analyzed += 1
            if analyzed % 50 == 0:
                print(f"[*] Analyzed {analyzed}/{len(js_urls)} files...")

        except Exception as e:
            errors += 1
            continue

    print(f"\n[*] Done: {analyzed} analyzed, {errors} errors")

    # Deduplicate findings
    for category in all_findings:
        seen = set()
        deduped = []
        for f in all_findings[category]:
            key = f["match"]
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        all_findings[category] = deduped

    # Output results
    total = sum(len(v) for v in all_findings.values())
    print(f"[*] Total unique findings: {total}")

    # Save JSON
    json_path = os.path.join(output_dir, "js_findings.json")
    with open(json_path, 'w') as f:
        json.dump(dict(all_findings), f, indent=2)

    # Save readable report
    report_path = os.path.join(output_dir, "js_findings_report.txt")
    with open(report_path, 'w') as f:
        f.write(f"JS Analysis Report\n{'='*60}\n")
        f.write(f"Files analyzed: {analyzed}\n")
        f.write(f"Total findings: {total}\n\n")

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            for category, items in sorted(all_findings.items()):
                if SEVERITY.get(category) != severity:
                    continue
                if not items:
                    continue
                f.write(f"\n{'='*60}\n")
                f.write(f"[{severity}] {category.upper()} ({len(items)} findings)\n")
                f.write(f"{'='*60}\n\n")
                for item in items[:100]:  # Cap at 100 per category
                    f.write(f"  Match: {item['match']}\n")
                    f.write(f"  Source: {item['source']}\n\n")

    # Print summary to stdout
    print(f"\n{'='*60}")
    print("FINDINGS SUMMARY")
    print(f"{'='*60}")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        for category, items in sorted(all_findings.items()):
            if SEVERITY.get(category) != severity and items:
                continue
            if items:
                print(f"  [{severity}] {category}: {len(items)} unique findings")

    print(f"\nReports saved to:")
    print(f"  {json_path}")
    print(f"  {report_path}")

if __name__ == "__main__":
    main()
