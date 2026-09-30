"""
Format findings for submission to bug bounty platforms.
Each platform has different field requirements and conventions.
"""

from pathlib import Path


class PlatformFormatter:
    def format_for_hackerone(self, finding: dict) -> dict:
        cvss = finding.get("cvss", {})
        impact = finding.get("impact", {})

        return {
            "title": f"[{finding.get('cwe', '')}] {finding.get('cwe_name', '')} in {finding.get('file', '')}",
            "vulnerability_information": self._build_description(finding),
            "severity_rating": self._h1_severity(cvss.get("severity", "medium")),
            "weakness_id": self._cwe_to_h1_id(finding.get("cwe", "")),
            "impact": impact.get("impact_statement", ""),
            "structured_scope": finding.get("file", ""),
        }

    def format_for_bugcrowd(self, finding: dict) -> dict:
        cvss = finding.get("cvss", {})

        return {
            "title": f"{finding.get('cwe_name', '')} — {finding.get('file', '')}",
            "description": self._build_description(finding),
            "severity": self._bc_severity(cvss.get("score", 0)),
            "vrt": self._cwe_to_vrt(finding.get("cwe", "")),
            "proof_of_concept": self._build_poc_section(finding),
        }

    def _build_description(self, finding: dict) -> str:
        parts = [
            f"## Summary\n\n{finding.get('description', '')}",
            f"\n\n## Vulnerability Details\n\n"
            f"- **CWE:** {finding.get('cwe', '')} — {finding.get('cwe_name', '')}\n"
            f"- **File:** `{finding.get('file', '')}`\n"
            f"- **Line:** {finding.get('line', 'N/A')}\n"
            f"- **CVSS:** {finding.get('cvss', {}).get('vector', 'N/A')} ({finding.get('cvss', {}).get('score', 'N/A')})",
        ]

        poc = finding.get("poc", {}).get("evidence", {})
        if poc:
            parts.append(
                f"\n\n## Steps to Reproduce\n\n"
                f"1. Clone the repository\n"
                f"2. Navigate to `{finding.get('file', '')}`, line {finding.get('line', 'N/A')}\n"
                f"3. Run the PoC script\n\n"
                f"### Output\n```\n{poc.get('stdout', '')[:1000]}\n```"
            )

        impact = finding.get("impact", {})
        if impact:
            parts.append(f"\n\n## Impact\n\n{impact.get('impact_statement', '')}")

        return "".join(parts)

    def _build_poc_section(self, finding: dict) -> str:
        poc = finding.get("poc", {}).get("evidence", {})
        if not poc:
            return "PoC available upon request."
        return f"```\n{poc.get('stdout', '')[:2000]}\n```"

    def _h1_severity(self, severity: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        return mapping.get(severity, "medium")

    def _bc_severity(self, score: float) -> int:
        if score >= 9.0:
            return 5  # P1
        if score >= 7.0:
            return 4  # P2
        if score >= 4.0:
            return 3  # P3
        if score >= 0.1:
            return 2  # P4
        return 1  # P5

    def _cwe_to_h1_id(self, cwe: str) -> str:
        return cwe.replace("CWE-", "")

    def _cwe_to_vrt(self, cwe: str) -> str:
        mapping = {
            "CWE-78": "server_side_injection.command_injection",
            "CWE-79": "cross_site_scripting_xss",
            "CWE-89": "server_side_injection.sql_injection",
            "CWE-131": "memory_corruption.buffer_overflow",
            "CWE-327": "broken_cryptography",
            "CWE-502": "server_side_injection.deserialization",
        }
        return mapping.get(cwe, "other")
