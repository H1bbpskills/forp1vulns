"""
Audit project dependencies for known vulnerabilities.
Parses lockfiles and checks against known CVE databases.
"""

import json
import re
from pathlib import Path


LOCKFILE_PARSERS = {
    "package-lock.json": "_parse_npm",
    "yarn.lock": "_parse_yarn",
    "Pipfile.lock": "_parse_pipfile",
    "requirements.txt": "_parse_requirements",
    "Cargo.lock": "_parse_cargo",
    "go.sum": "_parse_gosum",
    "conan.lock": "_parse_conan",
}


class DependencyAuditor:
    def __init__(self, config):
        self.config = config

    def audit(self) -> dict:
        findings = []
        repo_path = self.config.output_dir / "repo"

        if not repo_path.exists():
            return {"findings": [], "dependencies": []}

        deps = self._collect_dependencies(repo_path)
        for dep in deps:
            vulns = self._check_known_vulns(dep)
            findings.extend(vulns)

        return {"findings": findings, "dependencies": deps}

    def _collect_dependencies(self, repo_path: Path) -> list[dict]:
        deps = []
        for lockfile, parser_name in LOCKFILE_PARSERS.items():
            lockpath = repo_path / lockfile
            if lockpath.exists():
                parser = getattr(self, parser_name)
                deps.extend(parser(lockpath))
        return deps

    def _parse_npm(self, path: Path) -> list[dict]:
        try:
            data = json.loads(path.read_text())
        except Exception:
            return []
        deps = []
        for name, info in data.get("dependencies", {}).items():
            version = info.get("version", "unknown") if isinstance(info, dict) else str(info)
            deps.append({"name": name, "version": version, "ecosystem": "npm"})
        return deps

    def _parse_yarn(self, path: Path) -> list[dict]:
        deps = []
        for match in re.finditer(r'^"?(@?[\w./-]+)@', path.read_text(), re.MULTILINE):
            deps.append({"name": match.group(1), "version": "unknown", "ecosystem": "npm"})
        return deps

    def _parse_pipfile(self, path: Path) -> list[dict]:
        try:
            data = json.loads(path.read_text())
        except Exception:
            return []
        deps = []
        for section in ("default", "develop"):
            for name, info in data.get(section, {}).items():
                version = info.get("version", "unknown") if isinstance(info, dict) else "unknown"
                deps.append({"name": name, "version": version, "ecosystem": "pypi"})
        return deps

    def _parse_requirements(self, path: Path) -> list[dict]:
        deps = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                match = re.match(r"([\w.-]+)\s*(?:==|>=|<=|~=|!=)?\s*([\d.]*)", line)
                if match:
                    deps.append({"name": match.group(1), "version": match.group(2) or "unknown", "ecosystem": "pypi"})
        return deps

    def _parse_cargo(self, path: Path) -> list[dict]:
        deps = []
        for match in re.finditer(r'^name = "(.+)".*\nversion = "(.+)"', path.read_text(), re.MULTILINE):
            deps.append({"name": match.group(1), "version": match.group(2), "ecosystem": "cargo"})
        return deps

    def _parse_gosum(self, path: Path) -> list[dict]:
        deps = []
        seen = set()
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                if name not in seen:
                    seen.add(name)
                    deps.append({"name": name, "version": parts[1], "ecosystem": "go"})
        return deps

    def _parse_conan(self, path: Path) -> list[dict]:
        try:
            data = json.loads(path.read_text())
        except Exception:
            return []
        deps = []
        for node in data.get("graph_lock", {}).get("nodes", {}).values():
            ref = node.get("ref", "")
            if "/" in ref:
                name, version = ref.split("/", 1)
                version = version.split("@")[0]
                deps.append({"name": name, "version": version, "ecosystem": "conan"})
        return deps

    def _check_known_vulns(self, dep: dict) -> list[dict]:
        # Placeholder: in production, query OSV, NVD, or Snyk APIs
        return []
