"""
Authentication manager for grey-box testing.

Manages two identities:
- Attacker: our test account (User A)
- Victim: second test account (User B) whose resources we try to access as User A

This is the core of IDOR and privilege escalation testing.
"""

import json
from dataclasses import dataclass

from harness.http_client import HttpClient


@dataclass
class UserIdentity:
    label: str
    token: str
    user_id: str = ""
    role: str = ""
    email: str = ""
    raw_profile: dict | None = None


class AuthManager:
    def __init__(self, client: HttpClient, config):
        self.client = client
        self.config = config
        self.attacker: UserIdentity | None = None
        self.victim: UserIdentity | None = None

    def setup(self) -> dict:
        """Discover both users' identities by calling /me or /profile endpoints."""
        results = {"attacker": None, "victim": None, "errors": []}

        me_endpoints = ["/api/me", "/api/v1/me", "/api/user", "/api/profile",
                        "/me", "/user", "/profile", "/api/v1/user", "/api/v1/profile",
                        "/api/users/me", "/api/v1/users/me", "/api/account"]

        # Discover attacker identity
        if self.config.credentials.attacker_token:
            self.attacker = self._discover_identity(
                "attacker", self.config.credentials.attacker_token, me_endpoints
            )
            if self.attacker:
                results["attacker"] = {
                    "user_id": self.attacker.user_id,
                    "role": self.attacker.role,
                    "email": self.attacker.email,
                }
            else:
                results["errors"].append("Could not discover attacker identity")

        # Discover victim identity
        if self.config.credentials.victim_token:
            self.victim = self._discover_identity(
                "victim", self.config.credentials.victim_token, me_endpoints
            )
            if self.victim:
                results["victim"] = {
                    "user_id": self.victim.user_id,
                    "role": self.victim.role,
                    "email": self.victim.email,
                }
            else:
                results["errors"].append("Could not discover victim identity")

        return results

    def _discover_identity(self, label: str, token: str, endpoints: list[str]) -> UserIdentity | None:
        headers = self.config.headers(token)

        for endpoint in endpoints:
            try:
                resp = self.client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return UserIdentity(
                        label=label,
                        token=token,
                        user_id=self._extract_id(data),
                        role=self._extract_role(data),
                        email=self._extract_field(data, ["email", "mail", "emailAddress"]),
                        raw_profile=data,
                    )
            except Exception:
                continue

        return None

    def _extract_id(self, data: dict) -> str:
        for key in ["id", "user_id", "userId", "_id", "uid", "sub", "account_id"]:
            val = data.get(key) or (data.get("data", {}) or {}).get(key) or (data.get("user", {}) or {}).get(key)
            if val is not None:
                return str(val)
        return ""

    def _extract_role(self, data: dict) -> str:
        for key in ["role", "roles", "type", "user_type", "permissions", "scope"]:
            val = data.get(key) or (data.get("data", {}) or {}).get(key) or (data.get("user", {}) or {}).get(key)
            if val is not None:
                if isinstance(val, list):
                    return ",".join(str(v) for v in val)
                return str(val)
        return ""

    def _extract_field(self, data: dict, keys: list[str]) -> str:
        for key in keys:
            val = data.get(key) or (data.get("data", {}) or {}).get(key) or (data.get("user", {}) or {}).get(key)
            if val is not None:
                return str(val)
        return ""
