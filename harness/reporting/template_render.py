"""
Render vulnerability findings into structured Markdown reports.
Supports per-finding and full-assessment templates.
"""

from datetime import datetime, timezone
from pathlib import Path


class TemplateRenderer:
    def __init__(self, config):
        self.config = config

    def render(self, findings: list[dict], run_id: str) -> Path:
        report = self._render_full_report(findings, run_id)
        output_path = self.config.output_dir / f"report_{run_id}.md"
        output_path.write_text(report)

        for i, finding in enumerate(findings, 1):
            finding_report = self._render_finding(finding, i)
            finding_path = self.config.output_dir / f"finding_{run_id}_{i}.md"
            finding_path.write_text(finding_report)

        return output_path

    def _render_full_report(self, findings: list[dict], run_id: str) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        target = self.config.target

        lines = [
            f"# Security Assessment Report — {target.name}",
            "",
            f"**Assessment Date:** {now}",
            f"**Target:** {target.repo_url or target.url or target.name}",
            f"**Scope:** {', '.join(target.scope_includes)}",
            f"**Platform:** {target.platform.value}",
            f"**Run ID:** {run_id}",
            "",
            "---",
            "",
            "## Summary",
            "",
            f"Total findings: **{len(findings)}**",
            "",
        ]

        by_severity = {}
        for f in findings:
            sev = f.get("cvss", {}).get("severity", "unknown")
            by_severity.setdefault(sev, []).append(f)

        for sev in ["critical", "high", "medium", "low", "informational"]:
            count = len(by_severity.get(sev, []))
            if count:
                lines.append(f"- **{sev.capitalize()}:** {count}")

        lines.extend(["", "---", ""])

        for i, finding in enumerate(findings, 1):
            lines.append(self._render_finding(finding, i))
            lines.append("")

        return "\n".join(lines)

    def _render_finding(self, finding: dict, index: int) -> str:
        cvss = finding.get("cvss", {})
        impact = finding.get("impact", {})
        poc = finding.get("poc", {}).get("evidence", {})

        lines = [
            f"## Finding {index} — {finding.get('cwe_name', 'Unknown')}",
            "",
            f"**Severity:** {cvss.get('severity', 'unknown').capitalize()} ({cvss.get('vector', 'N/A')} — {cvss.get('score', 'N/A')})",
            f"**Class:** {finding.get('cwe', 'N/A')} — {finding.get('cwe_name', 'N/A')}",
            f"**Target:** `{finding.get('file', 'N/A')}`{':' + str(finding.get('line', '')) if finding.get('line') else ''}",
            f"**Status:** {'Confirmed' if impact.get('confirmed') else 'Candidate'}",
            "",
            "### Summary",
            "",
            finding.get("description", "No description provided."),
            "",
            "### Steps to Reproduce",
            "",
            "1. Clone the target repository",
            f"2. Navigate to `{finding.get('file', 'N/A')}`, line {finding.get('line', 'N/A')}",
            f"3. Observe: {finding.get('description', '')}",
            "",
        ]

        if poc:
            lines.extend([
                "### Proof of Concept",
                "",
                "```",
                f"Exit code: {poc.get('exit_code', 'N/A')}",
                f"Duration: {poc.get('duration_ms', 'N/A')}ms",
                "",
                poc.get("stdout", "")[:2000],
                "```",
                "",
            ])

        lines.extend([
            "### Impact",
            "",
            impact.get("impact_statement", "Impact under investigation."),
            "",
            "### Remediation",
            "",
            self._remediation_for(finding.get("cwe", "")),
            "",
        ])

        return "\n".join(lines)

    def _remediation_for(self, cwe: str) -> str:
        remediations = {
            "CWE-78": "Avoid passing user input to system commands. Use parameterized APIs or allowlists.",
            "CWE-79": "Apply context-aware output encoding. Use framework auto-escaping. Set Content-Security-Policy headers.",
            "CWE-89": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
            "CWE-131": "Verify buffer size calculations use the correct variable's size. Add assertions for size invariants.",
            "CWE-190": "Use checked arithmetic operations. Validate inputs are within expected ranges before arithmetic.",
            "CWE-327": "Replace weak algorithms (MD5, SHA1, DES) with modern alternatives (SHA-256+, AES-256-GCM).",
            "CWE-347": "Always verify cryptographic signatures. Never allow 'none' algorithm. Validate certificate chains.",
            "CWE-502": "Avoid deserializing untrusted data. Use safe formats (JSON). If needed, use allowlists for types.",
            "CWE-798": "Move secrets to environment variables or a secrets manager. Never commit credentials.",
        }
        return remediations.get(cwe, "Review and apply defense-in-depth measures appropriate to this vulnerability class.")
