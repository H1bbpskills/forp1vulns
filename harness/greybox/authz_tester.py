"""
Pass 2b: Authorization / Privilege Escalation Tester.

Tests:
- Horizontal privilege escalation (same role, different user's actions)
- Vertical privilege escalation (low-priv user accessing admin endpoints)
- Missing function-level access control
- Role-based access bypass
"""

from harness.http_client import HttpClient
from harness.greybox.auth_manager import AuthManager


ADMIN_ENDPOINTS = [
    ("GET", "/api/admin/users"),
    ("GET", "/api/v1/admin/users"),
    ("GET", "/api/admin/settings"),
    ("GET", "/api/admin/config"),
    ("GET", "/api/admin/logs"),
    ("GET", "/api/admin/audit"),
    ("GET", "/api/admin/dashboard"),
    ("GET", "/api/internal/users"),
    ("GET", "/api/internal/config"),
    ("GET", "/api/internal/metrics"),
    ("POST", "/api/admin/users"),
    ("PUT", "/api/admin/settings"),
    ("DELETE", "/api/admin/users/1"),
    ("GET", "/admin/api/users"),
    ("GET", "/management/users"),
    ("GET", "/api/v1/admin"),
    ("GET", "/api/roles"),
    ("GET", "/api/permissions"),
]

PRIVILEGE_ACTIONS = [
    ("POST", "/api/users", {"role": "admin"}, "Self-promote to admin via user creation"),
    ("PATCH", "/api/users/{attacker_id}", {"role": "admin"}, "Self-promote via profile update"),
    ("PUT", "/api/users/{attacker_id}", {"is_admin": True}, "Set admin flag on own profile"),
    ("POST", "/api/roles", {"user_id": "{attacker_id}", "role": "admin"}, "Assign admin role"),
    ("PATCH", "/api/account", {"type": "premium"}, "Upgrade account type"),
    ("POST", "/api/invites", {"role": "admin"}, "Create admin invite"),
    ("PUT", "/api/settings", {"maintenance_mode": True}, "Modify global settings"),
]

SENSITIVE_ACTIONS_AS_VICTIM = [
    ("DELETE", "/api/users/{victim_id}", "Delete victim's account"),
    ("POST", "/api/users/{victim_id}/password-reset", "Reset victim's password"),
    ("PUT", "/api/users/{victim_id}/email", {"email": "attacker@test.com"}, "Change victim's email"),
    ("POST", "/api/users/{victim_id}/disable", "Disable victim's account"),
    ("POST", "/api/users/{victim_id}/transfer", {"to": "{attacker_id}"}, "Transfer victim's assets"),
]


class AuthzTester:
    def __init__(self, client: HttpClient, config, auth: AuthManager):
        self.client = client
        self.config = config
        self.auth = auth

    def run(self) -> list[dict]:
        findings = []

        if not self.auth.attacker:
            return [{"error": "Need attacker credentials for authz testing"}]

        # Test 1: Access admin endpoints with regular user token
        findings.extend(self._test_vertical_escalation())

        # Test 2: Privilege escalation actions
        findings.extend(self._test_privilege_actions())

        # Test 3: Sensitive cross-user actions
        if self.auth.victim:
            findings.extend(self._test_horizontal_actions())

        # Test 4: Method-based bypass (GET→POST, etc.)
        findings.extend(self._test_method_bypass())

        # Test 5: Token manipulation
        findings.extend(self._test_token_manipulation())

        return findings

    def _test_vertical_escalation(self) -> list[dict]:
        findings = []
        attacker_headers = self.config.attacker_headers()

        for method, path in ADMIN_ENDPOINTS:
            try:
                resp = self.client._request(method, path, headers=attacker_headers)
            except Exception:
                continue

            if resp.status_code in (200, 201, 204):
                try:
                    has_data = len(resp.text) > 10
                except Exception:
                    has_data = False

                if has_data:
                    findings.append({
                        "type": "vertical_privilege_escalation",
                        "cwe": "CWE-269",
                        "cwe_name": "Improper Privilege Management",
                        "severity": "critical",
                        "endpoint": path,
                        "method": method,
                        "description": (
                            f"Admin endpoint `{method} {path}` accessible with regular user token. "
                            f"Returned HTTP {resp.status_code} with {len(resp.text)} bytes of data."
                        ),
                        "evidence": {
                            "request": f"{method} {path}",
                            "status": resp.status_code,
                            "response_snippet": resp.text[:500],
                        },
                    })

        return findings

    def _test_privilege_actions(self) -> list[dict]:
        findings = []
        attacker_headers = self.config.attacker_headers()
        attacker_id = self.auth.attacker.user_id if self.auth.attacker else ""

        for entry in PRIVILEGE_ACTIONS:
            method, path_template, payload_template, desc = entry[0], entry[1], entry[2], entry[3]
            path = path_template.replace("{attacker_id}", attacker_id)

            payload = {}
            for k, v in payload_template.items():
                if isinstance(v, str):
                    payload[k] = v.replace("{attacker_id}", attacker_id)
                else:
                    payload[k] = v

            try:
                resp = self.client._request(method, path, headers=attacker_headers, json=payload)
            except Exception:
                continue

            if resp.status_code in (200, 201, 204):
                findings.append({
                    "type": "privilege_escalation",
                    "cwe": "CWE-269",
                    "cwe_name": "Improper Privilege Management",
                    "severity": "critical",
                    "endpoint": path,
                    "method": method,
                    "description": f"Privilege escalation: {desc}. Server returned {resp.status_code}.",
                    "evidence": {
                        "request": f"{method} {path}",
                        "payload": payload,
                        "status": resp.status_code,
                        "response_snippet": resp.text[:500],
                    },
                })

        return findings

    def _test_horizontal_actions(self) -> list[dict]:
        findings = []
        attacker_headers = self.config.attacker_headers()
        attacker_id = self.auth.attacker.user_id if self.auth.attacker else ""
        victim_id = self.auth.victim.user_id if self.auth.victim else ""

        for entry in SENSITIVE_ACTIONS_AS_VICTIM:
            if len(entry) == 3:
                method, path_template, desc = entry
                payload = None
            else:
                method, path_template, payload_template, desc = entry
                payload = {}
                for k, v in payload_template.items():
                    if isinstance(v, str):
                        payload[k] = v.replace("{attacker_id}", attacker_id).replace("{victim_id}", victim_id)
                    else:
                        payload[k] = v

            path = path_template.replace("{victim_id}", victim_id).replace("{attacker_id}", attacker_id)

            try:
                kwargs = {"headers": attacker_headers}
                if payload:
                    kwargs["json"] = payload
                resp = self.client._request(method, path, **kwargs)
            except Exception:
                continue

            if resp.status_code in (200, 201, 204):
                findings.append({
                    "type": "horizontal_privilege_escalation",
                    "cwe": "CWE-284",
                    "cwe_name": "Improper Access Control",
                    "severity": "critical",
                    "endpoint": path,
                    "method": method,
                    "description": (
                        f"Horizontal privilege escalation: {desc}. "
                        f"Attacker performed action on victim (ID: {victim_id}) with own token."
                    ),
                    "evidence": {
                        "request": f"{method} {path}",
                        "payload": payload,
                        "status": resp.status_code,
                        "response_snippet": resp.text[:500],
                    },
                })

        return findings

    def _test_method_bypass(self) -> list[dict]:
        findings = []
        attacker_headers = self.config.attacker_headers()

        # Find endpoints that return 403/405 with GET, then try other methods
        test_paths = ["/api/admin/users", "/api/admin/settings", "/api/internal"]

        for path in test_paths:
            try:
                get_resp = self.client.get(path, headers=attacker_headers)
            except Exception:
                continue

            if get_resp.status_code in (403, 405):
                for alt_method in ["POST", "PUT", "PATCH", "DELETE", "HEAD"]:
                    try:
                        alt_resp = self.client._request(alt_method, path, headers=attacker_headers)
                    except Exception:
                        continue

                    if alt_resp.status_code in (200, 201, 204):
                        findings.append({
                            "type": "method_bypass",
                            "cwe": "CWE-285",
                            "cwe_name": "Improper Authorization",
                            "severity": "high",
                            "endpoint": path,
                            "method": alt_method,
                            "description": (
                                f"Method bypass: `GET {path}` returns {get_resp.status_code} "
                                f"but `{alt_method} {path}` returns {alt_resp.status_code}."
                            ),
                            "evidence": {
                                "blocked_method": f"GET → {get_resp.status_code}",
                                "bypassed_method": f"{alt_method} → {alt_resp.status_code}",
                                "response_snippet": alt_resp.text[:500],
                            },
                        })

        return findings

    def _test_token_manipulation(self) -> list[dict]:
        findings = []
        attacker_headers = self.config.attacker_headers()

        # Test: remove auth header entirely on endpoints that should require it
        protected_paths = ["/api/me", "/api/users", "/api/profile", "/api/account",
                           "/api/v1/me", "/api/v1/users"]

        for path in protected_paths:
            try:
                auth_resp = self.client.get(path, headers=attacker_headers)
            except Exception:
                continue

            if auth_resp.status_code != 200:
                continue

            # Same endpoint, no auth
            try:
                noauth_resp = self.client.get(path, headers=self.config.no_auth_headers())
            except Exception:
                continue

            if noauth_resp.status_code == 200 and len(noauth_resp.text) > 10:
                findings.append({
                    "type": "missing_auth",
                    "cwe": "CWE-306",
                    "cwe_name": "Missing Authentication for Critical Function",
                    "severity": "high",
                    "endpoint": path,
                    "method": "GET",
                    "description": (
                        f"Endpoint `{path}` returns data both with and without authentication. "
                        f"Authentication may not be enforced."
                    ),
                    "evidence": {
                        "with_auth": f"HTTP {auth_resp.status_code}, {len(auth_resp.text)} bytes",
                        "without_auth": f"HTTP {noauth_resp.status_code}, {len(noauth_resp.text)} bytes",
                        "response_snippet": noauth_resp.text[:300],
                    },
                })

        return findings
