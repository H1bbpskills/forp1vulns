"""Tests for the focused bug bounty harness."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from harness.config import TargetConfig, Credentials
from harness.reporting.reporter import Reporter, CVSS_DEFAULTS


def test_reporter_renders_finding():
    config = TargetConfig(base_url="https://test.example.com", output_dir=Path("/tmp/test_output"))
    reporter = Reporter(config)

    finding = {
        "type": "idor_read",
        "cwe": "CWE-639",
        "cwe_name": "Authorization Bypass Through User-Controlled Key",
        "severity": "high",
        "endpoint": "/api/users/42",
        "method": "GET",
        "description": "IDOR: Attacker can read victim's data.",
        "evidence": {"request": "GET /api/users/42", "status": 200},
    }

    md = reporter._render_finding(finding, 1)
    assert "CWE-639" in md
    assert "IDOR" in md
    assert "/api/users/42" in md
    assert "### Remediation" in md


def test_cvss_defaults_cover_key_cwes():
    expected = ["CWE-639", "CWE-306", "CWE-269", "CWE-284", "CWE-200"]
    for cwe in expected:
        assert cwe in CVSS_DEFAULTS, f"Missing CVSS default for {cwe}"
        vec, score, sev = CVSS_DEFAULTS[cwe]
        assert score > 0
        assert vec.startswith("CVSS:3.1/")


def test_severity_ordering():
    findings = [
        {"severity": "low", "type": "version_disclosure", "cwe": "CWE-200"},
        {"severity": "critical", "type": "idor_write", "cwe": "CWE-639"},
        {"severity": "medium", "type": "verbose_error", "cwe": "CWE-209"},
        {"severity": "high", "type": "idor_read", "cwe": "CWE-639"},
    ]
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 4))

    assert findings[0]["severity"] == "critical"
    assert findings[1]["severity"] == "high"
    assert findings[-1]["severity"] == "low"


def test_config_headers():
    config = TargetConfig(
        base_url="https://test.example.com",
        credentials=Credentials(attacker_token="atk_token", victim_token="vic_token"),
    )
    atk = config.attacker_headers()
    assert "Bearer atk_token" in atk["Authorization"]

    vic = config.victim_headers()
    assert "Bearer vic_token" in vic["Authorization"]

    noauth = config.no_auth_headers()
    assert "Authorization" not in noauth


if __name__ == "__main__":
    test_reporter_renders_finding()
    test_cvss_defaults_cover_key_cwes()
    test_severity_ordering()
    test_config_headers()
    print("All harness tests passed.")
