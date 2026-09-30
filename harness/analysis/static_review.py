"""
Pattern-based static source code review.
Scans for known vulnerability patterns organized by CWE class.
"""

import re
from pathlib import Path


VULN_PATTERNS = {
    "CWE-78": {
        "name": "OS Command Injection",
        "patterns": [
            (r"system\s*\(", "system() call — check for user input in args"),
            (r"popen\s*\(", "popen() call — check for user input in command"),
            (r"exec\s*\(", "exec() call — potential command injection"),
            (r"subprocess\.call\(.*shell\s*=\s*True", "subprocess with shell=True"),
            (r"os\.system\s*\(", "os.system() — always dangerous with user input"),
        ],
    },
    "CWE-79": {
        "name": "Cross-Site Scripting",
        "patterns": [
            (r"innerHTML\s*=", "innerHTML assignment — check for sanitization"),
            (r"document\.write\s*\(", "document.write — XSS sink"),
            (r"\.html\s*\(", "jQuery .html() — XSS sink"),
            (r"\{\{.*\|.*safe\s*\}\}", "Django safe filter — bypasses escaping"),
            (r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML"),
        ],
    },
    "CWE-89": {
        "name": "SQL Injection",
        "patterns": [
            (r"f['\"].*SELECT.*\{", "f-string in SQL query"),
            (r"\".*SELECT.*\"\s*%\s*", "%-formatting in SQL query"),
            (r"\.format\(.*SELECT", ".format() in SQL query"),
            (r"execute\s*\(\s*['\"].*\+", "String concatenation in execute()"),
            (r"raw\s*\(\s*f['\"]", "Django raw() with f-string"),
        ],
    },
    "CWE-131": {
        "name": "Incorrect Buffer Size Calculation",
        "patterns": [
            (r"malloc\s*\(.*sizeof.*\*", "malloc with arithmetic — check for overflow"),
            (r"memcpy\s*\([^,]+,\s*[^,]+,\s*sizeof\s*\((?!\s*\*)", "memcpy size mismatch risk"),
            (r"\.size\(\)\s*[^;]*\.data\(\)", "size/data from different objects"),
        ],
    },
    "CWE-190": {
        "name": "Integer Overflow",
        "patterns": [
            (r"\w+\s*\*\s*\w+.*malloc", "Multiplication before allocation"),
            (r"(?:uint|int|size_t)\s+\w+\s*=\s*\w+\s*[+*]\s*\w+", "Arithmetic without overflow check"),
        ],
    },
    "CWE-327": {
        "name": "Broken Crypto Algorithm",
        "patterns": [
            (r"MD5|md5", "MD5 usage — weak hash"),
            (r"SHA1(?!_)|sha1(?!_)", "SHA1 usage — weak hash"),
            (r"DES(?!3)|des(?!3)", "DES usage — weak cipher"),
            (r"ECB", "ECB mode — no semantic security"),
            (r"rand\(\)|srand\(|Math\.random", "Weak PRNG in security context"),
        ],
    },
    "CWE-347": {
        "name": "Improper Verification of Cryptographic Signature",
        "patterns": [
            (r"verify.*=\s*false", "Signature verification disabled"),
            (r"VERIFY_NONE|SSL_VERIFY_NONE", "TLS verification disabled"),
            (r"algorithms\s*=\s*\[.*none", "JWT 'none' algorithm allowed"),
        ],
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "patterns": [
            (r"pickle\.loads?\s*\(", "pickle.load — arbitrary code execution"),
            (r"yaml\.load\s*\([^,]*\)(?!.*Loader)", "yaml.load without safe Loader"),
            (r"unserialize\s*\(", "PHP unserialize — object injection"),
            (r"JSON\.parse\s*\(.*\beval\b", "eval in JSON parse context"),
        ],
    },
}


class StaticReviewer:
    def __init__(self, config):
        self.config = config

    def review(self, assets: dict) -> dict:
        findings = []

        for file_path in assets.get("files", []):
            full_path = self.config.output_dir / "repo" / file_path
            if full_path.exists():
                file_findings = self._scan_file(full_path, file_path)
                findings.extend(file_findings)

        return {"findings": findings}

    def scan_content(self, content: str, filename: str) -> list[dict]:
        findings = []
        lines = content.split("\n")

        for cwe, info in VULN_PATTERNS.items():
            for pattern, description in info["patterns"]:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        findings.append({
                            "cwe": cwe,
                            "cwe_name": info["name"],
                            "file": filename,
                            "line": line_num,
                            "code": line.strip(),
                            "description": description,
                            "severity": self._cwe_severity(cwe),
                            "status": "candidate",
                        })

        return findings

    def _scan_file(self, full_path: Path, rel_path: str) -> list:
        try:
            content = full_path.read_text(errors="replace")
        except Exception:
            return []
        return self.scan_content(content, rel_path)

    def _cwe_severity(self, cwe: str) -> str:
        critical = {"CWE-78", "CWE-89", "CWE-502"}
        high = {"CWE-79", "CWE-347", "CWE-327"}
        medium = {"CWE-131", "CWE-190"}
        if cwe in critical:
            return "critical"
        if cwe in high:
            return "high"
        if cwe in medium:
            return "medium"
        return "low"
