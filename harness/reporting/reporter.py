"""
Generate findings report in the user's preferred format.
Outputs per-finding Markdown matching the submission template.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


CVSS_DEFAULTS = {
    "CWE-639": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1, "High"),
    "CWE-306": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1, "Critical"),
    "CWE-269": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, "High"),
    "CWE-284": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1, "High"),
    "CWE-285": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1, "High"),
    "CWE-200": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "Medium"),
    "CWE-209": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "Medium"),
    "CWE-538": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"),
    "CWE-693": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 5.3, "Medium"),
    "CWE-489": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "Medium"),
}


class Reporter:
    def __init__(self, config):
        self.config = config

    def generate(self, findings: list[dict], run_id: str = "") -> Path:
        if not run_id:
            run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        output_dir = self.config.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "low"), 4))

        # Full report
        report = self._render_report(findings, run_id)
        report_path = output_dir / f"report_{run_id}.md"
        report_path.write_text(report)

        # Individual findings
        for i, finding in enumerate(findings, 1):
            finding_md = self._render_finding(finding, i)
            (output_dir / f"finding_{run_id}_{i}.md").write_text(finding_md)

        # JSON export
        json_path = output_dir / f"findings_{run_id}.json"
        json_path.write_text(json.dumps(findings, indent=2, default=str))

        return report_path

    def _render_report(self, findings: list[dict], run_id: str) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            f"# Security Assessment — {self.config.base_url}",
            "",
            f"**Date:** {now}",
            f"**Target:** {self.config.base_url}",
            f"**Run:** {run_id}",
            "",
            "---",
            "",
            "## Summary",
            "",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]

        counts = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            counts[sev] = counts.get(sev, 0) + 1
        for sev in ["critical", "high", "medium", "low"]:
            if sev in counts:
                lines.append(f"| {sev.capitalize()} | {counts[sev]} |")

        lines.extend(["", f"**Total:** {len(findings)}", "", "---", ""])

        for i, finding in enumerate(findings, 1):
            lines.append(self._render_finding(finding, i))
            lines.append("\n---\n")

        return "\n".join(lines)

    def _render_finding(self, finding: dict, index: int) -> str:
        cwe = finding.get("cwe", "")
        cvss_vec, cvss_score, cvss_sev = CVSS_DEFAULTS.get(
            cwe, ("N/A", 0.0, finding.get("severity", "medium").capitalize())
        )

        evidence = finding.get("evidence", "")
        if isinstance(evidence, dict):
            evidence = json.dumps(evidence, indent=2)

        lines = [
            f"## Finding {index} — {finding.get('cwe_name', 'Unknown')}",
            "",
            f"**Severity:** {cvss_sev} ({cvss_vec} — {cvss_score})",
            f"**Class:** {cwe} — {finding.get('cwe_name', '')}",
            f"**Target:** `{finding.get('endpoint', '')}`",
            f"**Status:** Confirmed",
            "",
            "### Summary",
            "",
            finding.get("description", ""),
            "",
            "### Steps to Reproduce",
            "",
        ]

        repro = finding.get("reproduction")
        if repro and isinstance(repro, dict):
            for i, (step_key, step_val) in enumerate(repro.items(), 1):
                lines.append(f"{i}. {step_val}")
        else:
            ev = finding.get("evidence", {})
            if isinstance(ev, dict) and "request" in ev:
                lines.append(f"1. Authenticate with test account")
                lines.append(f"2. Send: `{ev.get('request', '')}`")
                lines.append(f"3. Observe HTTP {ev.get('status', '')} response with victim data")
            else:
                lines.append(f"1. Navigate to `{finding.get('endpoint', '')}`")
                lines.append(f"2. Observe the response")

        lines.extend([
            "",
            "### Proof of Concept",
            "",
            "```",
            str(evidence)[:2000],
            "```",
            "",
            "### Impact",
            "",
            self._impact_for(finding),
            "",
            "### Remediation",
            "",
            self._remediation_for(cwe),
            "",
            "### References",
            "",
            f"- https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html",
        ])

        return "\n".join(lines)

    def _impact_for(self, finding: dict) -> str:
        impacts = {
            "idor_read": "Attacker can read any user's private data by manipulating resource IDs.",
            "idor_write": "Attacker can modify any user's data, leading to full account takeover.",
            "idor_param": "Attacker can access other users' data via parameter tampering.",
            "idor_enumeration": "Attacker can enumerate and access all users' resources via sequential IDs.",
            "vertical_privilege_escalation": "Regular user can access admin functionality, potentially taking over the application.",
            "privilege_escalation": "User can escalate their own privileges to admin level.",
            "horizontal_privilege_escalation": "Attacker can perform destructive actions on other users' accounts.",
            "method_bypass": "Authorization controls can be bypassed using alternative HTTP methods.",
            "missing_auth": "Endpoint exposes data without requiring authentication.",
            "unauth_access": "Sensitive endpoint accessible without any authentication.",
            "sensitive_data_exposure": "Sensitive data (tokens, keys, PII) exposed in responses.",
            "verbose_error": "Detailed error messages reveal internal application structure.",
            "version_disclosure": "Server version information aids targeted attack planning.",
            "missing_security_header": "Missing security headers reduce defense-in-depth.",
        }
        return impacts.get(finding.get("type", ""), "Security impact requires further assessment.")

    def _remediation_for(self, cwe: str) -> str:
        fixes = {
            "CWE-639": "Implement object-level authorization checks. Verify the authenticated user owns or has permission to access every requested resource. Never rely on client-supplied IDs alone.",
            "CWE-306": "Require authentication on all sensitive endpoints. Use middleware/decorators to enforce auth before handler logic runs.",
            "CWE-269": "Implement role-based access control (RBAC). Check user role server-side before allowing admin actions. Never trust client-supplied role claims.",
            "CWE-284": "Enforce authorization checks on every state-changing operation. Verify the requesting user has permission to act on the target resource.",
            "CWE-285": "Apply function-level access control. Each endpoint should verify the caller's role/permissions independently.",
            "CWE-200": "Remove sensitive data from responses. Sanitize error messages. Strip internal identifiers from API responses.",
            "CWE-209": "Return generic error messages to clients. Log detailed errors server-side only.",
            "CWE-538": "Remove sensitive files from web-accessible directories. Block access to dotfiles, backups, and config files.",
            "CWE-693": "Add security headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options.",
        }
        return fixes.get(cwe, "Apply defense-in-depth appropriate to this vulnerability class.")
