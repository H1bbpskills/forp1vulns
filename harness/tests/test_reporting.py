"""Tests for reporting modules."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from reporting.cvss_scorer import CVSSScorer, CVSSVector


def test_cvss_critical():
    scorer = CVSSScorer()
    vector = CVSSVector("N", "L", "N", "N", "U", "H", "H", "H")
    result = scorer.score_from_vector(vector)
    assert result["score"] >= 9.0
    assert result["severity"] == "critical"


def test_cvss_medium():
    scorer = CVSSScorer()
    vector = CVSSVector("N", "H", "L", "R", "U", "L", "L", "N")
    result = scorer.score_from_vector(vector)
    assert 3.0 <= result["score"] <= 6.9
    assert result["severity"] in ("low", "medium")


def test_cvss_none():
    scorer = CVSSScorer()
    vector = CVSSVector("N", "L", "N", "N", "U", "N", "N", "N")
    result = scorer.score_from_vector(vector)
    assert result["score"] == 0.0
    assert result["severity"] == "none"


def test_cvss_vector_string():
    scorer = CVSSScorer()
    vector = CVSSVector("N", "L", "N", "N", "C", "H", "H", "N")
    result = scorer.score_from_vector(vector)
    assert result["vector"].startswith("CVSS:3.1/")
    assert "AV:N" in result["vector"]


if __name__ == "__main__":
    test_cvss_critical()
    test_cvss_medium()
    test_cvss_none()
    test_cvss_vector_string()
    print("All reporting tests passed.")
