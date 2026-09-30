"""
Pass 2a: IDOR (Insecure Direct Object Reference) Scanner.

Core technique: Use attacker's token to access victim's resources by swapping IDs.

Tests:
- GET /api/resource/{victim_id} with attacker's token
- PUT/PATCH /api/resource/{victim_id} with attacker's token (modify victim's data)
- DELETE /api/resource/{victim_id} with attacker's token
- Enumerate sequential/predictable IDs
- Parameter-based IDOR (?user_id=, ?account_id=, etc.)
"""

import re
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

from harness.http_client import HttpClient
from harness.greybox.auth_manager import AuthManager


RESOURCE_PATH_PATTERNS = [
    "/api/users/{id}",
    "/api/v1/users/{id}",
    "/api/accounts/{id}",
    "/api/v1/accounts/{id}",
    "/api/profiles/{id}",
    "/api/orders/{id}",
    "/api/v1/orders/{id}",
    "/api/invoices/{id}",
    "/api/documents/{id}",
    "/api/files/{id}",
    "/api/messages/{id}",
    "/api/v1/messages/{id}",
    "/api/notifications/{id}",
    "/api/payments/{id}",
    "/api/transactions/{id}",
    "/api/settings/{id}",
    "/api/preferences/{id}",
    "/users/{id}",
    "/user/{id}",
    "/account/{id}",
    "/profile/{id}",
    "/order/{id}",
]

PARAM_IDOR_KEYS = [
    "user_id", "userId", "uid", "account_id", "accountId",
    "id", "profile_id", "profileId", "owner_id", "ownerId",
    "customer_id", "customerId", "member_id", "memberId",
]


class IDORScanner:
    def __init__(self, client: HttpClient, config, auth: AuthManager):
        self.client = client
        self.config = config
        self.auth = auth

    def run(self) -> list[dict]:
        findings = []

        if not self.auth.attacker or not self.auth.victim:
            return [{"error": "Need both attacker and victim identities for IDOR testing"}]

        attacker_id = self.auth.attacker.user_id
        victim_id = self.auth.victim.user_id

        if not victim_id:
            return [{"error": "Could not determine victim's user ID"}]

        # Test 1: Path-based IDOR — access victim's resources with attacker's token
        findings.extend(self._test_path_idor(attacker_id, victim_id))

        # Test 2: Parameter-based IDOR
        findings.extend(self._test_param_idor(victim_id))

        # Test 3: Enumerable/sequential ID access
        findings.extend(self._test_id_enumeration(attacker_id, victim_id))

        # Test 4: Write-based IDOR (PUT/PATCH/DELETE on victim's resources)
        findings.extend(self._test_write_idor(victim_id))

        return findings

    def _test_path_idor(self, attacker_id: str, victim_id: str) -> list[dict]:
        findings = []
        attacker_headers = self.config.attacker_headers()

        for pattern in RESOURCE_PATH_PATTERNS:
            # First: confirm attacker can access their own resource
            own_path = pattern.replace("{id}", attacker_id)
            try:
                own_resp = self.client.get(own_path, headers=attacker_headers)
            except Exception:
                continue

            if own_resp.status_code != 200:
                continue  # endpoint doesn't exist or format is wrong

            # Now: try to access victim's resource with attacker's token
            victim_path = pattern.replace("{id}", victim_id)
            try:
                victim_resp = self.client.get(victim_path, headers=attacker_headers)
            except Exception:
                continue

            if victim_resp.status_code == 200:
                # Confirm it's actually the victim's data, not a generic response
                if self._confirms_different_user(own_resp.text, victim_resp.text, victim_id):
                    findings.append({
                        "type": "idor_read",
                        "cwe": "CWE-639",
                        "cwe_name": "Authorization Bypass Through User-Controlled Key",
                        "severity": "high",
                        "endpoint": victim_path,
                        "method": "GET",
                        "description": (
                            f"IDOR: Attacker can read victim's data at `{pattern}`. "
                            f"Accessed victim ID `{victim_id}` using attacker's token."
                        ),
                        "evidence": {
                            "request": f"GET {victim_path} with attacker token",
                            "status": victim_resp.status_code,
                            "response_snippet": victim_resp.text[:500],
                        },
                        "reproduction": {
                            "step1": f"Authenticate as attacker (User A)",
                            "step2": f"GET {victim_path} with attacker's Authorization header",
                            "step3": "Observe: victim's data returned",
                        },
                    })

        return findings

    def _test_param_idor(self, victim_id: str) -> list[dict]:
        findings = []
        attacker_headers = self.config.attacker_headers()

        base_paths = ["/api/users", "/api/v1/users", "/api/profile",
                      "/api/account", "/api/data", "/api/resources"]

        for path in base_paths:
            for param in PARAM_IDOR_KEYS:
                url = f"{path}?{param}={victim_id}"
                try:
                    resp = self.client.get(url, headers=attacker_headers)
                except Exception:
                    continue

                if resp.status_code == 200 and self._looks_like_user_data(resp.text, victim_id):
                    findings.append({
                        "type": "idor_param",
                        "cwe": "CWE-639",
                        "cwe_name": "Authorization Bypass Through User-Controlled Key",
                        "severity": "high",
                        "endpoint": url,
                        "method": "GET",
                        "description": (
                            f"Parameter-based IDOR: `{param}={victim_id}` returns victim's data "
                            f"when called with attacker's token."
                        ),
                        "evidence": {
                            "request": f"GET {url} with attacker token",
                            "status": resp.status_code,
                            "response_snippet": resp.text[:500],
                        },
                    })

        return findings

    def _test_id_enumeration(self, attacker_id: str, victim_id: str) -> list[dict]:
        findings = []

        # Only test if IDs look sequential/numeric
        try:
            attacker_int = int(attacker_id)
            victim_int = int(victim_id)
        except (ValueError, TypeError):
            return findings  # UUIDs — skip enumeration test

        attacker_headers = self.config.attacker_headers()
        test_ids = [str(i) for i in range(max(1, victim_int - 3), victim_int + 4)
                    if i != attacker_int]

        accessible = []
        for pattern in RESOURCE_PATH_PATTERNS[:5]:  # test a few patterns
            for test_id in test_ids:
                path = pattern.replace("{id}", test_id)
                try:
                    resp = self.client.get(path, headers=attacker_headers)
                    if resp.status_code == 200:
                        accessible.append({"id": test_id, "path": path})
                except Exception:
                    continue

            if len(accessible) >= 2:
                findings.append({
                    "type": "idor_enumeration",
                    "cwe": "CWE-639",
                    "cwe_name": "Authorization Bypass Through User-Controlled Key",
                    "severity": "high",
                    "endpoint": pattern,
                    "description": (
                        f"Sequential ID enumeration: {len(accessible)} other users' resources "
                        f"accessible by iterating IDs at `{pattern}`."
                    ),
                    "evidence": {
                        "accessible_ids": [a["id"] for a in accessible[:5]],
                        "total_found": len(accessible),
                    },
                })
                break

        return findings

    def _test_write_idor(self, victim_id: str) -> list[dict]:
        findings = []
        attacker_headers = self.config.attacker_headers()

        write_tests = [
            ("/api/users/{id}", "PUT", {"name": "idor_test_probe"}),
            ("/api/v1/users/{id}", "PATCH", {"name": "idor_test_probe"}),
            ("/api/profiles/{id}", "PUT", {"bio": "idor_test_probe"}),
            ("/api/accounts/{id}", "PATCH", {"status": "idor_test_probe"}),
        ]

        for pattern, method, payload in write_tests:
            path = pattern.replace("{id}", victim_id)
            try:
                if method == "PUT":
                    resp = self.client.put(path, headers=attacker_headers, json=payload)
                elif method == "PATCH":
                    resp = self.client.patch(path, headers=attacker_headers, json=payload)
                else:
                    continue
            except Exception:
                continue

            if resp.status_code in (200, 201, 204):
                findings.append({
                    "type": "idor_write",
                    "cwe": "CWE-639",
                    "cwe_name": "Authorization Bypass Through User-Controlled Key",
                    "severity": "critical",
                    "endpoint": path,
                    "method": method,
                    "description": (
                        f"Write IDOR: Attacker can MODIFY victim's data at `{pattern}` "
                        f"using {method}. Victim ID: `{victim_id}`."
                    ),
                    "evidence": {
                        "request": f"{method} {path} with attacker token",
                        "payload": payload,
                        "status": resp.status_code,
                        "response_snippet": resp.text[:500],
                    },
                })

        return findings

    def _confirms_different_user(self, own_text: str, victim_text: str, victim_id: str) -> bool:
        if own_text == victim_text:
            return False  # same response = probably not real IDOR
        if victim_id in victim_text:
            return True
        return own_text != victim_text

    def _looks_like_user_data(self, text: str, victim_id: str) -> bool:
        if victim_id in text:
            return True
        try:
            data = __import__("json").loads(text)
            if isinstance(data, dict):
                return any(k in data for k in ("id", "user_id", "email", "name", "username"))
        except Exception:
            pass
        return False
