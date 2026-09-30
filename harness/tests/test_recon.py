"""Tests for recon modules."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import Target
from recon.scope_parser import ScopeParser


def test_scope_parser_in_scope():
    target = Target(
        name="test",
        scope_includes=["src/common/*"],
        scope_excludes=["src/common/test/*"],
    )
    parser = ScopeParser(target)
    assert parser.is_in_scope("src/common/crypto.cpp")
    assert not parser.is_in_scope("src/common/test/test_crypto.cpp")
    assert not parser.is_in_scope("docs/readme.md")


def test_scope_parser_parse():
    target = Target(
        name="test",
        scope_includes=["src/*", "lib/*"],
        scope_excludes=["test/*"],
    )
    parser = ScopeParser(target)
    result = parser.parse()
    assert result["include_count"] == 2
    assert result["exclude_count"] == 1
    assert len(result["targets"]) == 2


if __name__ == "__main__":
    test_scope_parser_in_scope()
    test_scope_parser_parse()
    print("All recon tests passed.")
