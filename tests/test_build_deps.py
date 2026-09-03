"""setup.py must let setuptools see header edits.

`sources` alone hides headers from setuptools' staleness check, so a
header-only edit leaves the stale .so in place and still reports success.
These tests pin the `depends` list that makes the timestamp check correct.
"""

import importlib.util
import os

import pytest

# setup.py imports its build backend, which a bare 3.12+ environment does not
# have: pip builds in an isolated env and no longer preinstalls setuptools.
pytest.importorskip("setuptools", reason="setup.py needs setuptools to import")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETUP_PY = os.path.join(ROOT, "setup.py")


@pytest.fixture(scope="module")
def setup_py():
    """setup.py imported as a module (its setup() call is __main__-guarded)."""
    if not os.path.exists(SETUP_PY):
        pytest.skip("no setup.py – running against an installed distribution")
    spec = importlib.util.spec_from_file_location("freastal_setup", SETUP_PY)
    module = importlib.util.module_from_spec(spec)
    cwd = os.getcwd()
    os.chdir(ROOT)  # setup.py names its sources relative to the project root
    try:
        spec.loader.exec_module(module)
    finally:
        os.chdir(cwd)
    return module


def _repo_headers():
    found = []
    for base in ("freastal/src", "vendor/picohttpparser", "vendor/picotls"):
        for dirpath, _, filenames in os.walk(os.path.join(ROOT, base)):
            found += [
                os.path.relpath(os.path.join(dirpath, name), ROOT)
                for name in filenames
                if name.endswith(".h")
            ]
    return found


def test_every_header_is_a_declared_dependency(setup_py):
    declared = {os.path.normpath(p) for p in setup_py.ext.depends}
    missing = sorted(set(_repo_headers()) - declared)
    assert not missing, f"headers invisible to the rebuild check: {missing}"


def test_declared_dependencies_all_exist(setup_py):
    # newer_group() raises on a missing dependency, so a stale glob would
    # break the build rather than just skipping the check.
    assert setup_py.ext.depends
    for path in setup_py.ext.depends:
        assert os.path.exists(os.path.join(ROOT, path)), path


def test_vendor_inputs_cover_what_the_archive_replaces(setup_py):
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        inputs = {os.path.normpath(p) for p in setup_py.vendor_inputs()}
    finally:
        os.chdir(cwd)
    for path in (
        "vendor/picohttpparser/picohttpparser.c",
        "vendor/picohttpparser/picohttpparser.h",
        "vendor/picotls/lib/picotls.c",
        "vendor/picotls/lib/openssl.c",
        "vendor/picotls/include/picotls.h",
    ):
        assert os.path.normpath(path) in inputs, path


def test_newer_than_selects_only_later_files(setup_py, tmp_path):
    reference = tmp_path / "vendor.a"
    older = tmp_path / "older.c"
    newer = tmp_path / "newer.c"
    for path in (older, reference, newer):
        path.write_text("x")
    os.utime(older, (1, 1))
    os.utime(reference, (2, 2))
    os.utime(newer, (3, 3))

    assert setup_py.newer_than([str(older), str(newer)], str(reference)) == [str(newer)]
    assert setup_py.newer_than([str(older)], str(reference)) == []
