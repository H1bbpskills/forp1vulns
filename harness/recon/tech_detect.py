"""
Detect technologies, frameworks, and libraries in the target.
Maps findings to known vulnerability classes per technology.
"""


TECH_SIGNATURES = {
    "openssl": {
        "files": ["**/openssl/**", "**/libssl*"],
        "imports": ["#include <openssl/"],
        "vuln_classes": ["CWE-326", "CWE-295", "CWE-327"],
    },
    "paillier": {
        "files": ["**/paillier*"],
        "imports": ["paillier"],
        "vuln_classes": ["CWE-327", "CWE-131", "CWE-190"],
    },
    "mpc": {
        "files": ["**/mpc*", "**/threshold*", "**/cosigner*"],
        "imports": ["threshold", "cosigner", "mpc"],
        "vuln_classes": ["CWE-327", "CWE-347", "CWE-20"],
    },
    "express": {
        "files": ["**/node_modules/express/**"],
        "imports": ["require('express')", "from 'express'"],
        "vuln_classes": ["CWE-79", "CWE-89", "CWE-352"],
    },
    "django": {
        "files": ["**/django/**", "manage.py"],
        "imports": ["from django", "import django"],
        "vuln_classes": ["CWE-89", "CWE-79", "CWE-352"],
    },
    "react": {
        "files": ["**/react/**", "**/react-dom/**"],
        "imports": ["from 'react'", "require('react')"],
        "vuln_classes": ["CWE-79"],
    },
}


class TechDetector:
    def __init__(self, assets: dict):
        self.assets = assets

    def detect(self) -> dict:
        detected = []
        files = self.assets.get("files", [])
        functions = self.assets.get("functions", [])

        for tech_name, sig in TECH_SIGNATURES.items():
            if self._matches(files, functions, sig):
                detected.append({
                    "name": tech_name,
                    "vuln_classes": sig["vuln_classes"],
                    "confidence": "high" if len(self._match_count(files, sig)) > 2 else "medium",
                })

        return {"technologies": detected}

    def _matches(self, files: list, functions: list, sig: dict) -> bool:
        import fnmatch
        for f in files:
            for pattern in sig.get("files", []):
                if fnmatch.fnmatch(f, pattern):
                    return True
        return False

    def _match_count(self, files: list, sig: dict) -> list:
        import fnmatch
        matches = []
        for f in files:
            for pattern in sig.get("files", []):
                if fnmatch.fnmatch(f, pattern):
                    matches.append(f)
        return matches
