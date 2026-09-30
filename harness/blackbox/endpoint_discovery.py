"""
Pass 1a: Discover endpoints accessible without authentication.

Checks:
- Common path brute-force (admin panels, API docs, debug endpoints)
- Sitemap/robots.txt parsing
- Response code analysis (200 vs 401/403 = unprotected vs protected)
- OPTIONS method to find allowed methods
"""

import re
from urllib.parse import urljoin

from harness.http_client import HttpClient


COMMON_PATHS = [
    # API docs / specs
    "/swagger.json", "/swagger-ui.html", "/api-docs", "/openapi.json",
    "/docs", "/redoc", "/graphql", "/graphiql", "/playground",
    "/api/v1", "/api/v2", "/api/v3",
    "/.well-known/openid-configuration",

    # Admin / debug
    "/admin", "/admin/", "/dashboard", "/debug", "/debug/vars",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/actuator/configprops", "/actuator/mappings", "/actuator/metrics",
    "/_debug", "/_status", "/_health", "/health", "/healthz", "/status",
    "/server-status", "/server-info",
    "/elmah.axd", "/trace.axd",
    "/phpinfo.php", "/info.php",
    "/__debug__", "/debug/pprof",

    # Sensitive files
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.svn/entries", "/.svn/wc.db",
    "/.DS_Store", "/Thumbs.db",
    "/wp-config.php.bak", "/config.php.bak",
    "/.htaccess", "/.htpasswd",
    "/web.config", "/crossdomain.xml",
    "/sitemap.xml", "/robots.txt",
    "/composer.json", "/package.json", "/Gemfile",

    # Source maps
    "/main.js.map", "/app.js.map", "/bundle.js.map",
    "/static/js/main.chunk.js.map",

    # Backup / dump
    "/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
    "/backup.zip", "/backup.tar.gz",

    # Auth endpoints (check if accessible without auth)
    "/api/users", "/api/user", "/api/accounts", "/api/account",
    "/api/me", "/api/profile", "/api/settings",
    "/api/admin/users", "/api/internal",
    "/users", "/members", "/profiles",
]


class EndpointDiscovery:
    def __init__(self, client: HttpClient, config):
        self.client = client
        self.config = config

    def run(self) -> list[dict]:
        findings = []
        discovered = []

        # Phase 1: robots.txt and sitemap
        robot_paths = self._parse_robots()
        sitemap_paths = self._parse_sitemap()

        all_paths = list(set(COMMON_PATHS + robot_paths + sitemap_paths))

        # Phase 2: Probe each path without auth
        for path in all_paths:
            result = self._probe_path(path)
            if result:
                discovered.append(result)
                if result["accessible_no_auth"]:
                    findings.append(self._make_finding(result))

        # Phase 3: Check OPTIONS on discovered endpoints
        for ep in discovered:
            methods = self._check_methods(ep["path"])
            ep["allowed_methods"] = methods

        return findings

    def get_discovered_endpoints(self) -> list[dict]:
        """Return all discovered endpoints for grey-box phase."""
        endpoints = []
        for path in COMMON_PATHS:
            result = self._probe_path(path)
            if result and result["status"] not in (0, 404):
                endpoints.append(result)
        return endpoints

    def _probe_path(self, path: str) -> dict | None:
        try:
            resp = self.client.get(path, headers=self.config.no_auth_headers())
        except Exception:
            return None

        if resp.status_code == 404:
            return None

        interesting = resp.status_code in (200, 201, 204, 301, 302, 403, 405, 500)
        if not interesting:
            return None

        return {
            "path": path,
            "status": resp.status_code,
            "accessible_no_auth": resp.status_code in (200, 201, 204),
            "content_type": resp.headers.get("Content-Type", ""),
            "content_length": len(resp.content),
            "response_snippet": resp.text[:500] if resp.status_code == 200 else "",
        }

    def _check_methods(self, path: str) -> list[str]:
        try:
            resp = self.client._request("OPTIONS", path, headers=self.config.no_auth_headers())
            allow = resp.headers.get("Allow", "")
            if allow:
                return [m.strip() for m in allow.split(",")]
        except Exception:
            pass
        return []

    def _parse_robots(self) -> list[str]:
        paths = []
        try:
            resp = self.client.get("/robots.txt", headers=self.config.no_auth_headers())
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:")):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            paths.append(path)
        except Exception:
            pass
        return paths

    def _parse_sitemap(self) -> list[str]:
        paths = []
        try:
            resp = self.client.get("/sitemap.xml", headers=self.config.no_auth_headers())
            if resp.status_code == 200:
                for match in re.finditer(r"<loc>(.*?)</loc>", resp.text):
                    url = match.group(1)
                    if self.config.base_url in url:
                        path = url.replace(self.config.base_url, "")
                        paths.append(path)
        except Exception:
            pass
        return paths

    def _make_finding(self, result: dict) -> dict:
        sensitive_paths = {
            "/.env", "/.git/config", "/.git/HEAD", "/debug",
            "/actuator/env", "/actuator/configprops",
            "/backup.sql", "/dump.sql", "/.htpasswd",
            "/swagger.json", "/openapi.json", "/graphql",
        }
        path = result["path"]

        if path in sensitive_paths:
            severity = "high"
            cwe = "CWE-538"
            cwe_name = "Insertion of Sensitive Information into Externally-Accessible File"
        elif "/admin" in path or "/internal" in path:
            severity = "high"
            cwe = "CWE-306"
            cwe_name = "Missing Authentication for Critical Function"
        elif "/api/" in path:
            severity = "medium"
            cwe = "CWE-306"
            cwe_name = "Missing Authentication for Critical Function"
        else:
            severity = "low"
            cwe = "CWE-200"
            cwe_name = "Exposure of Sensitive Information"

        return {
            "type": "unauth_access",
            "cwe": cwe,
            "cwe_name": cwe_name,
            "severity": severity,
            "endpoint": path,
            "status_code": result["status"],
            "content_type": result["content_type"],
            "description": (
                f"Endpoint `{path}` returns HTTP {result['status']} without authentication. "
                f"Content-Type: {result['content_type']}, Size: {result['content_length']} bytes."
            ),
            "evidence": result["response_snippet"][:200],
        }
