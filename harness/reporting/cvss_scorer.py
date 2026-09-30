"""
CVSS 3.1 vector calculator.
Computes base score from attack characteristics.
"""

from dataclasses import dataclass


@dataclass
class CVSSVector:
    attack_vector: str = "N"       # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str = "L"   # L=Low, H=High
    privileges_required: str = "N" # N=None, L=Low, H=High
    user_interaction: str = "N"    # N=None, R=Required
    scope: str = "U"              # U=Unchanged, C=Changed
    confidentiality: str = "N"    # N=None, L=Low, H=High
    integrity: str = "N"          # N=None, L=Low, H=High
    availability: str = "N"       # N=None, L=Low, H=High


AV_SCORES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_SCORES = {"L": 0.77, "H": 0.44}
PR_SCORES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_SCORES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_SCORES = {"N": 0.85, "R": 0.62}
CIA_SCORES = {"H": 0.56, "L": 0.22, "N": 0.0}


class CVSSScorer:
    def score(self, finding: dict) -> dict:
        vector = self._finding_to_vector(finding)
        base_score = self._calculate(vector)
        severity = self._severity_label(base_score)
        vector_string = self._vector_string(vector)

        return {
            "score": base_score,
            "severity": severity,
            "vector": vector_string,
        }

    def score_from_vector(self, vector: CVSSVector) -> dict:
        base_score = self._calculate(vector)
        return {
            "score": base_score,
            "severity": self._severity_label(base_score),
            "vector": self._vector_string(vector),
        }

    def _calculate(self, v: CVSSVector) -> float:
        iss = 1.0 - (
            (1.0 - CIA_SCORES[v.confidentiality])
            * (1.0 - CIA_SCORES[v.integrity])
            * (1.0 - CIA_SCORES[v.availability])
        )

        if v.scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

        pr_scores = PR_SCORES_CHANGED if v.scope == "C" else PR_SCORES_UNCHANGED
        exploitability = (
            8.22
            * AV_SCORES[v.attack_vector]
            * AC_SCORES[v.attack_complexity]
            * pr_scores[v.privileges_required]
            * UI_SCORES[v.user_interaction]
        )

        if impact <= 0:
            return 0.0

        if v.scope == "U":
            raw = min(impact + exploitability, 10.0)
        else:
            raw = min(1.08 * (impact + exploitability), 10.0)

        return self._roundup(raw)

    def _roundup(self, value: float) -> float:
        import math
        return math.ceil(value * 10) / 10

    def _severity_label(self, score: float) -> str:
        if score == 0.0:
            return "none"
        if score <= 3.9:
            return "low"
        if score <= 6.9:
            return "medium"
        if score <= 8.9:
            return "high"
        return "critical"

    def _vector_string(self, v: CVSSVector) -> str:
        return (
            f"CVSS:3.1/AV:{v.attack_vector}/AC:{v.attack_complexity}"
            f"/PR:{v.privileges_required}/UI:{v.user_interaction}"
            f"/S:{v.scope}/C:{v.confidentiality}/I:{v.integrity}/A:{v.availability}"
        )

    def _finding_to_vector(self, finding: dict) -> CVSSVector:
        cwe = finding.get("cwe", "")
        cwe_defaults = {
            "CWE-78":  CVSSVector("N", "L", "L", "N", "U", "H", "H", "H"),
            "CWE-79":  CVSSVector("N", "L", "N", "R", "C", "L", "L", "N"),
            "CWE-89":  CVSSVector("N", "L", "N", "N", "U", "H", "H", "H"),
            "CWE-131": CVSSVector("N", "H", "L", "N", "U", "H", "H", "N"),
            "CWE-190": CVSSVector("N", "H", "N", "N", "U", "H", "H", "H"),
            "CWE-327": CVSSVector("N", "H", "N", "N", "U", "H", "H", "N"),
            "CWE-347": CVSSVector("N", "L", "N", "N", "U", "H", "H", "N"),
            "CWE-502": CVSSVector("N", "L", "N", "N", "U", "H", "H", "H"),
        }
        return cwe_defaults.get(cwe, CVSSVector())
