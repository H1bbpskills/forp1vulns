"""
Bug bounty harness configuration.
Define authorized targets, scope boundaries, and harness settings.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Platform(Enum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    CUSTOM = "custom"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


@dataclass
class Target:
    name: str
    url: Optional[str] = None
    repo_url: Optional[str] = None
    scope_includes: list[str] = field(default_factory=list)
    scope_excludes: list[str] = field(default_factory=list)
    platform: Platform = Platform.BUGCROWD
    program_url: Optional[str] = None


@dataclass
class HarnessConfig:
    target: Target
    output_dir: Path = Path("./output")
    poc_dir: Path = Path("./poc")
    max_requests_per_second: int = 10
    timeout_seconds: int = 30
    user_agent: str = "SecurityResearch/1.0 (Authorized Bug Bounty)"
    verify_ssl: bool = True
    proxy: Optional[str] = None
    verbose: bool = False

    def validate(self):
        if not self.target.scope_includes:
            raise ValueError("scope_includes must not be empty — define authorized targets")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.poc_dir.mkdir(parents=True, exist_ok=True)


# Example: configure for a source-code audit target
EXAMPLE_CONFIG = HarnessConfig(
    target=Target(
        name="example-mpc-lib",
        repo_url="https://github.com/example/mpc-lib",
        scope_includes=["src/common/cosigner/*", "src/common/crypto/*"],
        scope_excludes=["test/*", "docs/*"],
        platform=Platform.BUGCROWD,
        program_url="https://bugcrowd.com/example-program",
    ),
    output_dir=Path("./output"),
    poc_dir=Path("./poc"),
)
