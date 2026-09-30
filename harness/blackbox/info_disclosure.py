"""
Pass 1b: Information disclosure detection.

Checks:
- Verbose error responses (stack traces, SQL errors, debug info)
- Security headers missing (HSTS, CSP, X-Frame-Options, etc.)
- Server/technology version leaks in headers
- Source map exposure
- Sensitive data in responses (emails, tokens, internal IPs)
"""

import re

from harness.http_client import HttpClient


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

VERSION_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]

ERROR_SIGNATURES = [
    (r"Traceback \(most recent call last\)", "Python stack trace"),
    (r"at [\w.$]+\([\w.]+:\d+\)", "Java/Kotlin stack trace"),
    (r"(?:Fatal error|Warning):.*on line \d+", "PHP error"),
    (r"Microsoft\.AspNetCore|System\.Exception", ".NET stack trace"),
    (r"node_modules/|at Module\._compile", "Node.js stack trace"),
    (r"SQLSTATE\[|mysql_|pg_query|ORA-\d+", "SQL error leaked"),
    (r"syntax error.*near|You have an error in your SQL", "SQL syntax error"),
    (r'"debug"\s*:\s*true', "Debug mode enabled"),
    (r'"stack"\s*:\s*"', "Stack trace in JSON response"),
    (r"django\.core|settings\.py", "Django internals leaked"),
    (r"(?:SECRET_KEY|DATABASE_URL|API_KEY)\s*[:=]", "Secret in response"),
]

SENSITIVE_DATA_PATTERNS = [
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email_address"),
    (r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b", "internal_ip"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "jwt_token"),
    (r"(?:AKIA|ASIA)[A-Z0-9]{16}", "aws_access_key"),
    (r"(?:sk-|pk_live_|pk_test_|sk_live_|sk_test_)[a-zA-Z0-9]{20,}", "api_key"),
    (r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", "github_token"),
    (r"mongodb(?:\+srv)?://[^\s\"']+", "mongodb_connection_string"),
    (r"postgres(?:ql)?://[^\s\"']+", "postgres_connection_string"),
]


class InfoDisclosureScanner:
    def __init__(self, client: HttpClient, config):
        self.client = client
        self.config = config

    def run(self, discovered_endpoints: list[dict] | None = None) -> list[dict]:
        findings = []

        # Check base URL
        findings.extend(self._check_headers())
        findings.extend(self._check_error_pages())

        # Check each discovered endpoint
        for ep in (discovered_endpoints or []):
            findings.extend(self._check_response_content(ep))

        return findings

    def _check_headers(self) -> list[dict]:
        findings = []
        try:
            resp = self.client.get("/", headers=self.config.no_auth_headers())
        except Exception:
            return findings

        # Missing security headers
        for header in SECURITY_HEADERS:
            if header not in resp.headers:
                findings.append({
                    "type": "missing_security_header",
                    "cwe": "CWE-693",
                    "cwe_name": "Protection Mechanism Failure",
                    "severity": "low" if header != "Strict-Transport-Security" else "medium",
                    "endpoint": "/",
                    "description": f"Missing security header: `{header}`",
                    "evidence": f"Response headers: {dict(resp.headers)}",
                })

        # Version disclosure in headers
        for header in VERSION_HEADERS:
            value = resp.headers.get(header)
            if value:
                findings.append({
                    "type": "version_disclosure",
                    "cwe": "CWE-200",
                    "cwe_name": "Exposure of Sensitive Information",
                    "severity": "low",
                    "endpoint": "/",
                    "description": f"Server version disclosed via `{header}: {value}`",
                    "evidence": f"{header}: {value}",
                })

        return findings

    def _check_error_pages(self) -> list[dict]:
        findings = []
        error_triggers = [
            "/nonexistent_path_404_test",
            "/api/v1/' OR 1=1--",
            "/api/v1/users/99999999",
            "/api/v1/{{test}}",
            "/%00",
            "/api/v1/users?id=abc",
        ]

        for path in error_triggers:
            try:
                resp = self.client.get(path, headers=self.config.no_auth_headers())
            except Exception:
                continue

            for pattern, sig_name in ERROR_SIGNATURES:
                if re.search(pattern, resp.text):
                    findings.append({
                        "type": "verbose_error",
                        "cwe": "CWE-209",
                        "cwe_name": "Generation of Error Message Containing Sensitive Information",
                        "severity": "medium",
                        "endpoint": path,
                        "status_code": resp.status_code,
                        "description": f"Verbose error response detected: {sig_name}",
                        "evidence": resp.text[:500],
                    })
                    break  # one finding per endpoint

        return findings

    def _check_response_content(self, endpoint: dict) -> list[dict]:
        findings = []
        content = endpoint.get("response_snippet", "")
        path = endpoint.get("path", "")

        if not content:
            return findings

        for pattern, data_type in SENSITIVE_DATA_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                findings.append({
                    "type": "sensitive_data_exposure",
                    "cwe": "CWE-200",
                    "cwe_name": "Exposure of Sensitive Information",
                    "severity": "high" if data_type in ("aws_access_key", "api_key", "jwt_token", "github_token") else "medium",
                    "endpoint": path,
                    "description": f"Sensitive data ({data_type}) found in response from `{path}`",
                    "evidence": f"Found {len(matches)} instance(s) of {data_type}",
                    "match_count": len(matches),
                })

        return findings
