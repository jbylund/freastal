"""freastal.__version__ must be the version pyproject.toml declares."""

import re
from pathlib import Path

import freastal


def test_version_matches_pyproject():
    text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    declared = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M).group(1)
    assert freastal.__version__ == declared
