"""
Target configuration for the focused bug bounty harness.
"""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Credentials:
    """Two sets of creds: attacker (our account) and victim (second account for IDOR)."""
    attacker_token: str = ""
    victim_token: str = ""
    attacker_cookie: str = ""
    victim_cookie: str = ""
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer"


@dataclass
class TargetConfig:
    base_url: str
    scope_includes: list[str] = field(default_factory=list)
    scope_excludes: list[str] = field(default_factory=list)
    credentials: Credentials = field(default_factory=Credentials)
    rate_limit: float = 0.5  # seconds between requests
    timeout: int = 15
    user_agent: str = "BugBountyHarness/1.0 (Authorized Security Testing)"
    verify_ssl: bool = True
    proxy: str | None = None
    output_dir: Path = Path("./output")
    wordlist_dir: Path = Path("./wordlists")

    def headers(self, token: str = "") -> dict:
        h = {"User-Agent": self.user_agent}
        if token:
            h[self.credentials.auth_header] = f"{self.credentials.auth_prefix} {token}"
        return h

    def attacker_headers(self) -> dict:
        return self.headers(self.credentials.attacker_token)

    def victim_headers(self) -> dict:
        return self.headers(self.credentials.victim_token)

    def no_auth_headers(self) -> dict:
        return self.headers()

    @property
    def request_kwargs(self) -> dict:
        kwargs: dict = {"timeout": self.timeout, "verify": self.verify_ssl}
        if self.proxy:
            kwargs["proxies"] = {"http": self.proxy, "https": self.proxy}
        return kwargs
