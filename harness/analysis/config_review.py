"""
Review configuration files for security misconfigurations.
"""

import json
import re
from pathlib import Path


MISCONFIG_CHECKS = [
    {
        "file_patterns": ["*.env", ".env*", "docker-compose*.yml"],
        "check": "hardcoded_secrets",
        "description": "Hardcoded secrets in configuration",
        "cwe": "CWE-798",
        "severity": "high",
    },
    {
        "file_patterns": ["Dockerfile", "docker-compose*.yml"],
        "check": "privileged_container",
        "description": "Container running as root or with privileged mode",
        "cwe": "CWE-250",
        "severity": "medium",
    },
    {
        "file_patterns": ["*.conf", "nginx.conf", "httpd.conf"],
        "check": "server_misconfig",
        "description": "Server misconfiguration",
        "cwe": "CWE-16",
        "severity": "medium",
    },
    {
        "file_patterns": ["cors*", "*.json", "*.yml"],
        "check": "cors_wildcard",
        "description": "Overly permissive CORS",
        "cwe": "CWE-942",
        "severity": "medium",
    },
]

SECRET_PATTERNS = [
    r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
    r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"(?:secret|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=\s*\S+",
    r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
]


class ConfigReviewer:
    def __init__(self, config):
        self.config = config

    def review(self) -> dict:
        repo_path = self.config.output_dir / "repo"
        if not repo_path.exists():
            return {"findings": []}

        findings = []
        findings.extend(self._check_secrets(repo_path))
        findings.extend(self._check_docker(repo_path))
        findings.extend(self._check_cors(repo_path))
        return {"findings": findings}

    def _check_secrets(self, root: Path) -> list[dict]:
        findings = []
        for fpath in root.rglob("*"):
            if not fpath.is_file() or fpath.stat().st_size > 1_000_000:
                continue
            if ".git" in fpath.parts:
                continue
            try:
                content = fpath.read_text(errors="replace")
            except Exception:
                continue
            for pattern in SECRET_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    findings.append({
                        "cwe": "CWE-798",
                        "cwe_name": "Hardcoded Credentials",
                        "file": str(fpath.relative_to(root)),
                        "line": content[:match.start()].count("\n") + 1,
                        "description": f"Potential hardcoded secret: {match.group()[:40]}...",
                        "severity": "high",
                        "status": "candidate",
                    })
        return findings

    def _check_docker(self, root: Path) -> list[dict]:
        findings = []
        for dockerfile in root.rglob("Dockerfile"):
            content = dockerfile.read_text(errors="replace")
            if re.search(r"USER\s+root", content) or not re.search(r"USER\s+\w+", content):
                findings.append({
                    "cwe": "CWE-250",
                    "cwe_name": "Execution with Unnecessary Privileges",
                    "file": str(dockerfile.relative_to(root)),
                    "description": "Container may run as root",
                    "severity": "medium",
                    "status": "candidate",
                })
        return findings

    def _check_cors(self, root: Path) -> list[dict]:
        findings = []
        for fpath in root.rglob("*"):
            if not fpath.is_file() or fpath.suffix not in (".json", ".yml", ".yaml", ".js", ".ts", ".py"):
                continue
            if ".git" in fpath.parts:
                continue
            try:
                content = fpath.read_text(errors="replace")
            except Exception:
                continue
            if re.search(r"(?:Access-Control-Allow-Origin|cors).*\*", content, re.IGNORECASE):
                findings.append({
                    "cwe": "CWE-942",
                    "cwe_name": "Overly Permissive CORS",
                    "file": str(fpath.relative_to(root)),
                    "description": "Wildcard CORS origin detected",
                    "severity": "medium",
                    "status": "candidate",
                })
        return findings
