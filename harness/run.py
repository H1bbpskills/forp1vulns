#!/usr/bin/env python3
"""
Main runner for the focused bug bounty harness.

Usage:
    python -m harness.run --target https://api.example.com --phase blackbox
    python -m harness.run --target https://api.example.com --phase greybox \
        --attacker-token "eyJ..." --victim-token "eyJ..."
    python -m harness.run --target https://api.example.com --phase all \
        --attacker-token "eyJ..." --victim-token "eyJ..."
"""

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from harness.config import TargetConfig, Credentials
from harness.http_client import HttpClient
from harness.blackbox.endpoint_discovery import EndpointDiscovery
from harness.blackbox.info_disclosure import InfoDisclosureScanner
from harness.greybox.auth_manager import AuthManager
from harness.greybox.idor_scanner import IDORScanner
from harness.greybox.authz_tester import AuthzTester
from harness.reporting.reporter import Reporter


def run_blackbox(client: HttpClient, config: TargetConfig) -> list[dict]:
    print("\n" + "=" * 60)
    print("  PASS 1: BLACK-BOX (No Authentication)")
    print("=" * 60)

    findings = []

    print("\n[1/2] Endpoint Discovery — probing for unauth access...")
    discovery = EndpointDiscovery(client, config)
    ep_findings = discovery.run()
    findings.extend(ep_findings)
    print(f"      Found {len(ep_findings)} unauth-accessible endpoints")

    print("\n[2/2] Information Disclosure — checking headers, errors, leaks...")
    info_scanner = InfoDisclosureScanner(client, config)
    discovered = discovery.get_discovered_endpoints()
    info_findings = info_scanner.run(discovered)
    findings.extend(info_findings)
    print(f"      Found {len(info_findings)} info disclosure issues")

    return findings


def run_greybox(client: HttpClient, config: TargetConfig) -> list[dict]:
    print("\n" + "=" * 60)
    print("  PASS 2: GREY-BOX (Authenticated)")
    print("=" * 60)

    findings = []

    print("\n[1/3] Auth Setup — discovering user identities...")
    auth = AuthManager(client, config)
    identity_info = auth.setup()

    if identity_info.get("attacker"):
        print(f"      Attacker: ID={identity_info['attacker']['user_id']}, "
              f"Role={identity_info['attacker']['role']}")
    else:
        print("      WARNING: Could not discover attacker identity")

    if identity_info.get("victim"):
        print(f"      Victim:   ID={identity_info['victim']['user_id']}, "
              f"Role={identity_info['victim']['role']}")
    else:
        print("      WARNING: Could not discover victim identity (IDOR tests limited)")

    for err in identity_info.get("errors", []):
        print(f"      ERROR: {err}")

    print("\n[2/3] IDOR Scanner — testing object-level authorization...")
    idor = IDORScanner(client, config, auth)
    idor_findings = idor.run()
    real_findings = [f for f in idor_findings if "error" not in f]
    findings.extend(real_findings)
    print(f"      Found {len(real_findings)} IDOR vulnerabilities")

    print("\n[3/3] AuthZ Tester — testing privilege escalation...")
    authz = AuthzTester(client, config, auth)
    authz_findings = authz.run()
    real_authz = [f for f in authz_findings if "error" not in f]
    findings.extend(real_authz)
    print(f"      Found {len(real_authz)} authorization issues")

    return findings


def main():
    parser = argparse.ArgumentParser(description="Focused Bug Bounty Harness")
    parser.add_argument("--target", required=True, help="Base URL (e.g., https://api.example.com)")
    parser.add_argument("--phase", default="all", choices=["blackbox", "greybox", "all"])
    parser.add_argument("--attacker-token", default="", help="Attacker's auth token (User A)")
    parser.add_argument("--victim-token", default="", help="Victim's auth token (User B)")
    parser.add_argument("--rate-limit", type=float, default=0.5, help="Seconds between requests")
    parser.add_argument("--proxy", default=None, help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--output", default="./output", help="Output directory")
    parser.add_argument("--no-verify-ssl", action="store_true")
    args = parser.parse_args()

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    config = TargetConfig(
        base_url=args.target.rstrip("/"),
        credentials=Credentials(
            attacker_token=args.attacker_token,
            victim_token=args.victim_token,
        ),
        rate_limit=args.rate_limit,
        proxy=args.proxy,
        output_dir=Path(args.output),
        verify_ssl=not args.no_verify_ssl,
    )

    client = HttpClient(config)
    all_findings = []

    print(f"\n[*] Bug Bounty Harness — Run {run_id}")
    print(f"[*] Target: {config.base_url}")
    print(f"[*] Phase: {args.phase}")
    print(f"[*] Rate limit: {config.rate_limit}s between requests")

    if args.phase in ("blackbox", "all"):
        all_findings.extend(run_blackbox(client, config))

    if args.phase in ("greybox", "all"):
        if not args.attacker_token:
            print("\n[!] Grey-box phase requires --attacker-token")
            if args.phase == "greybox":
                sys.exit(1)
        else:
            all_findings.extend(run_greybox(client, config))

    # Deduplicate by (type, endpoint, method)
    seen = set()
    unique = []
    for f in all_findings:
        key = (f.get("type"), f.get("endpoint"), f.get("method", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Report
    print("\n" + "=" * 60)
    print("  RESULTS")
    print("=" * 60)

    reporter = Reporter(config)
    report_path = reporter.generate(unique, run_id)

    by_sev = {}
    for f in unique:
        sev = f.get("severity", "unknown")
        by_sev.setdefault(sev, []).append(f)

    for sev in ["critical", "high", "medium", "low"]:
        items = by_sev.get(sev, [])
        if items:
            print(f"\n  [{sev.upper()}] — {len(items)} finding(s)")
            for item in items:
                print(f"    • {item.get('cwe', '')} {item.get('type', '')} → {item.get('endpoint', '')}")

    print(f"\n[*] Total: {len(unique)} unique findings")
    print(f"[*] Report: {report_path}")

    # Save request log
    log_path = config.output_dir / f"requests_{run_id}.json"
    client.save_log(log_path)
    print(f"[*] Request log: {log_path}")


if __name__ == "__main__":
    main()
