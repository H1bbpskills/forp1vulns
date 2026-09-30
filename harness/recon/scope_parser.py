"""
Parse bug bounty program scope into structured target definitions.
Handles in-scope/out-of-scope rules, wildcard domains, repo paths.
"""

import fnmatch
import re
from dataclasses import dataclass, field


@dataclass
class ScopeEntry:
    pattern: str
    entry_type: str  # "web", "api", "repo", "mobile", "hardware"
    notes: str = ""


@dataclass
class ParsedScope:
    includes: list[ScopeEntry] = field(default_factory=list)
    excludes: list[ScopeEntry] = field(default_factory=list)


class ScopeParser:
    def __init__(self, target):
        self.target = target

    def parse(self) -> dict:
        scope = ParsedScope()

        for pattern in self.target.scope_includes:
            entry_type = self._classify_pattern(pattern)
            scope.includes.append(ScopeEntry(pattern=pattern, entry_type=entry_type))

        for pattern in self.target.scope_excludes:
            entry_type = self._classify_pattern(pattern)
            scope.excludes.append(ScopeEntry(pattern=pattern, entry_type=entry_type))

        targets = []
        for entry in scope.includes:
            targets.append({
                "pattern": entry.pattern,
                "type": entry.entry_type,
                "excluded_by": [
                    e.pattern for e in scope.excludes
                    if self._overlaps(entry.pattern, e.pattern)
                ],
            })

        return {
            "targets": targets,
            "include_count": len(scope.includes),
            "exclude_count": len(scope.excludes),
        }

    def is_in_scope(self, path: str) -> bool:
        in_scope = any(
            fnmatch.fnmatch(path, p) for p in self.target.scope_includes
        )
        excluded = any(
            fnmatch.fnmatch(path, p) for p in self.target.scope_excludes
        )
        return in_scope and not excluded

    def _classify_pattern(self, pattern: str) -> str:
        if pattern.startswith("http"):
            if "/api/" in pattern or "api." in pattern:
                return "api"
            return "web"
        if pattern.startswith("*.") or re.match(r"^[\w.-]+\.\w+", pattern):
            return "web"
        if "/" in pattern or pattern.endswith(("*.py", "*.js", "*.cpp", "*.go")):
            return "repo"
        return "repo"

    def _overlaps(self, include: str, exclude: str) -> bool:
        return fnmatch.fnmatch(include, exclude) or fnmatch.fnmatch(exclude, include)
