"""Tests for analysis modules."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.static_review import StaticReviewer


class FakeConfig:
    class output_dir:
        pass


def test_static_review_detects_sqli():
    reviewer = StaticReviewer(FakeConfig())
    code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    findings = reviewer.scan_content(code, "app.py")
    cwes = [f["cwe"] for f in findings]
    assert "CWE-89" in cwes


def test_static_review_detects_xss():
    reviewer = StaticReviewer(FakeConfig())
    code = 'element.innerHTML = userInput;'
    findings = reviewer.scan_content(code, "app.js")
    cwes = [f["cwe"] for f in findings]
    assert "CWE-79" in cwes


def test_static_review_detects_cmdi():
    reviewer = StaticReviewer(FakeConfig())
    code = 'os.system(f"ping {host}")'
    findings = reviewer.scan_content(code, "util.py")
    cwes = [f["cwe"] for f in findings]
    assert "CWE-78" in cwes


def test_static_review_detects_weak_crypto():
    reviewer = StaticReviewer(FakeConfig())
    code = 'hash = MD5(data);'
    findings = reviewer.scan_content(code, "crypto.cpp")
    cwes = [f["cwe"] for f in findings]
    assert "CWE-327" in cwes


if __name__ == "__main__":
    test_static_review_detects_sqli()
    test_static_review_detects_xss()
    test_static_review_detects_cmdi()
    test_static_review_detects_weak_crypto()
    print("All analysis tests passed.")
