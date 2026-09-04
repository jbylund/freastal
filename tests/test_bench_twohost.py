"""The two-host runner's orchestration, tested without a second host.

The measurement needs two machines; none of the machinery does. Transport is a
seam precisely so this can run in CI, because the orchestration is where the
bugs are -- a resume that loses a cell, a policy that sweeps a server which
cannot pipeline, a saturation guard that lets a client-bound row through.
"""

import json
import os
import sys

import pytest

BENCH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bench", "compare"
)
sys.path.insert(0, BENCH)

twohost = pytest.importorskip("twohost")
runner = pytest.importorskip("runner")


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------


def test_local_runner_runs_and_reports():
    r = runner.LocalRunner()
    out = r.run(["echo", "hello"])
    assert out.returncode == 0
    assert out.stdout.strip() == "hello"


def test_local_runner_walks_the_whole_process_tree():
    """Not pgrep -P: under spawn a worker's cmdline is the multiprocessing
    bootstrap, so counting direct children can satisfy a >= workers check while
    missing real workers -- which reads as 0% CPU rather than as an error."""
    r = runner.LocalRunner()
    import subprocess

    # Three levels, because two would pass with a plain `pgrep -P`. The
    # grandchild is the one a direct-children scan misses, and under spawn a
    # real worker sits exactly there.
    grandchild = "import time; time.sleep(8)"
    child = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}]); "
        "time.sleep(8)"
    )
    parent = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}]); "
        "time.sleep(8)"
    )
    p = subprocess.Popen(
        [sys.executable, "-c", parent],
        start_new_session=True,
    )
    try:
        import time

        time.sleep(2.5)
        pids = r.descendants({"kind": "local", "pid": p.pid, "proc": p})
        assert p.pid in pids
        assert len(pids) >= 3, f"expected parent+child+grandchild, got {pids}"

        # and the grandchild is precisely what a direct-children scan misses
        direct = [int(x) for x in r.run(["pgrep", "-P", str(p.pid)]).stdout.split()]
        assert len(direct) < len(pids), (
            "pgrep -P found as much as the tree walk, so this fixture is not"
            " exercising the case the walk exists for"
        )
    finally:
        try:
            os.killpg(p.pid, 9)
        except ProcessLookupError:
            p.kill()
        p.wait(timeout=10)


def test_ssh_runner_builds_a_batch_mode_command():
    """BatchMode matters: without it a missing key turns a benchmark into a
    password prompt that blocks until the run is killed."""
    s = runner.SshRunner("example.invalid")
    cmd = s._ssh("true")
    assert "BatchMode=yes" in cmd
    assert "example.invalid" in cmd


# ---------------------------------------------------------------------------
# the pipelining policy
# ---------------------------------------------------------------------------


def test_a_server_that_cannot_pipeline_is_never_swept():
    """bjoern measured 9,823 rps at depth 1 and 21 at depth 4 -- it reads one
    request per read and the rest of the batch waits for a timeout. Sweeping it
    would spend the run measuring that timeout."""
    assert twohost.depths_for("bjoern", [1, 8, 64]) == [1]
    assert twohost.depths_for("freastal-wsgi", [1, 8, 64]) == [1, 8, 64]


def test_the_comparison_is_pinned_to_one_depth():
    """Every server compared at the same depth, or the table ranks pipelining
    support rather than throughput: freastal gains ~16%, uvicorn is flat, and
    bjoern collapses."""
    assert twohost.COMPARE_DEPTH == 1


def test_everything_that_can_pipeline_is_swept():
    """Including uvicorn. "Measured flat once" is not "swept", and the claim
    that only freastal gains deserves the same evidence as the claim that it
    does. bjoern is the only exclusion, because it cannot parse a batch."""
    assert "gunicorn-uvicorn" in twohost.DIAGNOSTIC_KINDS
    assert "freastal-wsgi" in twohost.DIAGNOSTIC_KINDS
    assert "freastal-asgi" in twohost.DIAGNOSTIC_KINDS
    assert "bjoern" not in twohost.DIAGNOSTIC_KINDS
    assert twohost.NO_PIPELINING == {"bjoern"}


# ---------------------------------------------------------------------------
# results: append-only and resumable
# ---------------------------------------------------------------------------


def test_results_are_durable_and_resumable(tmp_path):
    path = str(tmp_path / "r.ndjson")
    res = twohost.Results(path)
    cfg = {"kind": "freastal-wsgi", "workers": 1, "body": 500, "port": 9000}
    res.add("cell-a", cfg, "sweep", {"rps": 123.0})
    assert res.has("cell-a")

    # a second reader sees it without the first having closed: the file is
    # flushed and fsynced per measurement, because a two-hour run that dies at
    # ninety minutes should cost ninety minutes of nothing.
    again = twohost.Results(path)
    assert again.has("cell-a")
    assert again.get("cell-a")["rps"] == 123.0
    assert not again.has("cell-b")


def test_every_record_carries_its_config(tmp_path):
    """A row that cannot say which server and shape produced it is not a
    result, and the ndjson is the only durable artefact."""
    path = str(tmp_path / "r.ndjson")
    res = twohost.Results(path)
    cfg = {"kind": "bjoern", "workers": 1, "body": 500, "port": 9001}
    res.add(
        "c", cfg, "final", {"rps": 1.0, "threads": 4, "connections": 64, "depth": 1}
    )
    with open(path) as fh:
        row = json.loads(fh.read().splitlines()[0])
    for key in (
        "kind",
        "workers",
        "body",
        "port",
        "phase",
        "threads",
        "connections",
        "depth",
        "rps",
        "ts",
    ):
        assert key in row, f"{key} missing from the recorded row"


def test_cell_ids_separate_phases_and_trials():
    """Resume keys on the cell id, so a sweep and a final at the same shape
    must not collide -- that would silently skip the measurement that matters."""
    cfg = {"kind": "freastal-wsgi", "workers": 4, "body": 500, "port": 9000}
    sweep = twohost.cell_id(cfg, "sweep", (4, 64, 1))
    final0 = twohost.cell_id(cfg, "final", (4, 64, 1), trial=0)
    final1 = twohost.cell_id(cfg, "final", (4, 64, 1), trial=1)
    assert len({sweep, final0, final1}) == 3


def test_bjoern_gets_no_multi_worker_config():
    """bjoern is single-process here; asking for workers=4 would silently
    measure one process against four of everything else."""
    cfgs = twohost.configs([500], [1, 4])
    kinds = {(c["kind"], c["workers"]) for c in cfgs}
    assert ("bjoern", 1) in kinds
    assert ("bjoern", 4) not in kinds


def test_every_config_gets_its_own_port():
    cfgs = twohost.configs([500, 12000], [1, 4])
    ports = [c["port"] for c in cfgs]
    assert len(ports) == len(set(ports))
