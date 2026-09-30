#!/usr/bin/env python3
"""
Bug bounty harness controller.
Orchestrates the recon → analysis → exploitation → reporting pipeline.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from config import HarnessConfig, Target, Platform


class HarnessController:
    def __init__(self, config: HarnessConfig):
        self.config = config
        self.config.validate()
        self.findings: list[dict] = []
        self.run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    def run(self, phases: list[str] | None = None):
        phases = phases or ["recon", "analyze", "exploit", "report"]
        print(f"[*] Harness run {self.run_id} — target: {self.config.target.name}")
        print(f"[*] Phases: {', '.join(phases)}")
        print(f"[*] Scope: {self.config.target.scope_includes}")
        print()

        results = {}

        if "recon" in phases:
            results["recon"] = self._phase_recon()

        if "analyze" in phases:
            results["analysis"] = self._phase_analyze(results.get("recon", {}))

        if "exploit" in phases:
            results["exploit"] = self._phase_exploit(results.get("analysis", {}))

        if "report" in phases:
            results["report"] = self._phase_report()

        self._save_run(results)
        return results

    def _phase_recon(self) -> dict:
        print("[+] Phase: RECON")
        from recon.scope_parser import ScopeParser
        from recon.asset_enum import AssetEnumerator
        from recon.tech_detect import TechDetector

        scope = ScopeParser(self.config.target).parse()
        assets = AssetEnumerator(scope, self.config).enumerate()
        tech = TechDetector(assets).detect()

        print(f"    Parsed {len(scope.get('targets', []))} scope targets")
        print(f"    Enumerated {len(assets.get('endpoints', []))} assets")
        print(f"    Detected {len(tech.get('technologies', []))} technologies")
        return {"scope": scope, "assets": assets, "tech": tech}

    def _phase_analyze(self, recon: dict) -> dict:
        print("[+] Phase: ANALYZE")
        from analysis.static_review import StaticReviewer
        from analysis.dependency_audit import DependencyAuditor
        from analysis.config_review import ConfigReviewer

        static = StaticReviewer(self.config).review(recon.get("assets", {}))
        deps = DependencyAuditor(self.config).audit()
        configs = ConfigReviewer(self.config).review()

        candidates = static.get("findings", []) + deps.get("findings", []) + configs.get("findings", [])
        print(f"    Static review: {len(static.get('findings', []))} candidates")
        print(f"    Dependency audit: {len(deps.get('findings', []))} candidates")
        print(f"    Config review: {len(configs.get('findings', []))} candidates")
        return {"candidates": candidates}

    def _phase_exploit(self, analysis: dict) -> dict:
        print("[+] Phase: EXPLOIT")
        from exploit.poc_runner import PoCRunner
        from exploit.impact_verify import ImpactVerifier

        runner = PoCRunner(self.config)
        verifier = ImpactVerifier()
        verified = []

        for candidate in analysis.get("candidates", []):
            poc_result = runner.run(candidate)
            if poc_result.get("success"):
                impact = verifier.verify(candidate, poc_result)
                if impact.get("confirmed"):
                    candidate["impact"] = impact
                    candidate["poc"] = poc_result
                    verified.append(candidate)

        self.findings = verified
        print(f"    Verified {len(verified)} / {len(analysis.get('candidates', []))} candidates")
        return {"verified_findings": verified}

    def _phase_report(self) -> dict:
        print("[+] Phase: REPORT")
        from reporting.cvss_scorer import CVSSScorer
        from reporting.template_render import TemplateRenderer

        scorer = CVSSScorer()
        renderer = TemplateRenderer(self.config)

        for finding in self.findings:
            finding["cvss"] = scorer.score(finding)

        self.findings.sort(key=lambda f: f.get("cvss", {}).get("score", 0), reverse=True)

        report_path = renderer.render(self.findings, self.run_id)
        print(f"    Generated report: {report_path}")
        return {"report_path": str(report_path), "finding_count": len(self.findings)}

    def _save_run(self, results: dict):
        run_file = self.config.output_dir / f"run_{self.run_id}.json"
        run_data = {
            "run_id": self.run_id,
            "target": self.config.target.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "results": _serialize(results),
        }
        run_file.write_text(json.dumps(run_data, indent=2, default=str))
        print(f"\n[*] Run saved: {run_file}")

    def add_finding(self, finding: dict):
        self.findings.append(finding)


def _serialize(obj):
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(i) for i in obj]
    return obj


def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Harness Controller")
    parser.add_argument("--target", required=True, help="Target name from config")
    parser.add_argument("--phase", default="all", help="Phases to run: all, recon, analyze, exploit, report")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    phases = None if args.phase == "all" else [p.strip() for p in args.phase.split(",")]

    config = HarnessConfig(
        target=Target(
            name=args.target,
            scope_includes=["*"],
        ),
        verbose=args.verbose,
    )

    controller = HarnessController(config)
    controller.run(phases)


if __name__ == "__main__":
    main()
