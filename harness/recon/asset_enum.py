"""
Enumerate assets within authorized scope.
For source-code targets: walk file trees, extract function signatures, map data flows.
For web targets: discover endpoints, parameters, authentication flows.
"""

import os
import re
from pathlib import Path


class AssetEnumerator:
    def __init__(self, scope: dict, config):
        self.scope = scope
        self.config = config

    def enumerate(self) -> dict:
        assets = {"endpoints": [], "files": [], "functions": [], "dependencies": []}

        for target in self.scope.get("targets", []):
            if target["type"] == "repo":
                self._enumerate_repo(target, assets)
            elif target["type"] in ("web", "api"):
                self._enumerate_web(target, assets)

        return assets

    def _enumerate_repo(self, target: dict, assets: dict):
        repo_path = self.config.target.repo_url
        if not repo_path:
            return

        local_path = self.config.output_dir / "repo"
        if local_path.exists():
            self._walk_source(local_path, target["pattern"], assets)

    def _walk_source(self, root: Path, pattern: str, assets: dict):
        import fnmatch
        for dirpath, _, filenames in os.walk(root):
            for fname in filenames:
                fpath = Path(dirpath) / fname
                rel = str(fpath.relative_to(root))
                if fnmatch.fnmatch(rel, pattern):
                    assets["files"].append(rel)
                    self._extract_functions(fpath, assets)

    def _extract_functions(self, fpath: Path, assets: dict):
        try:
            content = fpath.read_text(errors="replace")
        except Exception:
            return

        suffix = fpath.suffix
        patterns = {
            ".py": r"def\s+(\w+)\s*\(",
            ".js": r"(?:function\s+(\w+)|(\w+)\s*[:=]\s*(?:async\s+)?function)",
            ".ts": r"(?:function\s+(\w+)|(\w+)\s*[:=]\s*(?:async\s+)?function)",
            ".cpp": r"(?:\w+[\s*&]+)(\w+)\s*\([^)]*\)\s*\{",
            ".c": r"(?:\w+[\s*&]+)(\w+)\s*\([^)]*\)\s*\{",
            ".go": r"func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(",
            ".rs": r"fn\s+(\w+)\s*[<(]",
        }

        regex = patterns.get(suffix)
        if regex:
            for match in re.finditer(regex, content):
                name = next((g for g in match.groups() if g), None)
                if name:
                    assets["functions"].append({
                        "name": name,
                        "file": str(fpath),
                        "line": content[:match.start()].count("\n") + 1,
                    })

    def _enumerate_web(self, target: dict, assets: dict):
        assets["endpoints"].append({
            "url": target["pattern"],
            "type": target["type"],
            "methods": ["GET"],
        })
