"""The two-host runner's orchestration, tested without a second host.

The measurement needs two machines; none of the machinery does. Transport is a
seam precisely so this can run in CI, because the orchestration is where the
bugs are -- a resume that loses a cell, a policy that sweeps a server which
cannot pipeline, a saturation guard that lets a client-bound row through.
"""

import json
import os
import sys
from types import SimpleNamespace

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
    """bjoern reads one request per read, so depth would measure a timeout."""
    assert twohost.depths_for("bjoern", [1, 8, 64]) == [1]
    assert twohost.depths_for("freastal-wsgi", [1, 8, 64]) == [1, 8, 64]


def test_the_comparison_is_pinned_to_one_depth():
    """Different depths would rank pipelining support, not just throughput."""
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


def test_saturation_uses_workers_not_process_tree_size():
    """Masters and multiprocessing helpers are not extra worker capacity."""
    assert twohost.server_saturation_pct(4.02, workers=4) == pytest.approx(100.5)


def test_wrk_sample_records_tail_latency_when_clean():
    out = SimpleNamespace(
        returncode=0,
        stderr="",
        stdout="""
Latency Distribution
   50%    1.10ms
   75%    1.40ms
   90%    2.00ms
   99%    4.20ms
Requests/sec:  12345.67
""",
    )
    metrics, error = twohost.parse_wrk_output(out)
    assert error is None
    assert metrics["rps"] == pytest.approx(12345.67)
    assert metrics["latency"]["99"] == "4.20ms"


@pytest.mark.parametrize(
    "line",
    [
        "Socket errors: connect 0, read 2, write 0, timeout 0",
        "Non-2xx or 3xx responses: 3",
    ],
)
def test_wrk_sample_with_transport_or_http_errors_is_rejected(line):
    out = SimpleNamespace(
        returncode=0,
        stderr="",
        stdout=f"Requests/sec: 123.0\n{line}\n",
    )
    metrics, error = twohost.parse_wrk_output(out)
    assert metrics is None
    assert "errors" in error


def test_endpoint_check_rejects_the_wrong_body_size():
    class Client:
        def run(self, argv, timeout):
            return SimpleNamespace(returncode=0, stdout="200 499", stderr="")

    assert "expected '200 500'" in twohost.check_response(Client(), "http://host/", 500)


def test_file_descriptor_preflight_rejects_an_oversized_shape():
    class Host:
        label = "client"

        def run(self, argv, timeout):
            return SimpleNamespace(returncode=0, stdout="1024\n", stderr="")

    with pytest.raises(RuntimeError, match="RLIMIT_NOFILE is 1024"):
        twohost.check_nofile(Host(), required=4352)


def test_pipeline_script_is_copied_to_the_client():
    class Client:
        name = "ssh"
        label = "client"

        def __init__(self):
            self.copy = None

        def put_file(self, source, destination):
            self.copy = (source, destination)

        def run(self, argv, timeout):
            return SimpleNamespace(returncode=0, stdout="", stderr="")

    client = Client()
    destination = twohost.prepare_pipeline_script(client, "/tmp/pipeline.lua")
    assert destination == "/tmp/pipeline.lua"
    assert client.copy[0].endswith("/bench/compare/pipeline.lua")
    assert client.copy[1] == destination


# ---------------------------------------------------------------------------
# results: append-only and resumable
# ---------------------------------------------------------------------------


def test_results_are_durable_and_resumable(tmp_path):
    path = str(tmp_path / "r.ndjson")
    res = twohost.Results(path, "run-a", "source-a")
    cfg = {"kind": "freastal-wsgi", "workers": 1, "body": 500, "port": 9000}
    res.add("cell-a", cfg, "sweep", {"rps": 123.0})
    assert res.has("cell-a")

    # a second reader sees it without the first having closed: the file is
    # flushed and fsynced per measurement, because a two-hour run that dies at
    # ninety minutes should cost ninety minutes of nothing.
    again = twohost.Results(path, "run-a", "source-a")
    assert again.has("cell-a")
    assert again.get("cell-a")["rps"] == 123.0
    assert not again.has("cell-b")


def test_failed_and_stale_results_are_retried(tmp_path):
    path = str(tmp_path / "r.ndjson")
    cfg = {"kind": "freastal-wsgi", "workers": 1, "body": 500, "port": 9000}
    first = twohost.Results(path, "run-a", "source-a")
    first.add("failed", cfg, "diagnostic", None)
    first.add("success", cfg, "sweep", {"rps": 123.0})
    assert not first.has("failed")

    resumed = twohost.Results(path, "run-a", "source-a")
    assert not resumed.has("failed")
    assert resumed.has("success")

    changed_run = twohost.Results(path, "run-b", "source-b")
    assert not changed_run.has("success")


def test_every_record_carries_its_config(tmp_path):
    """A row that cannot say which server and shape produced it is not a
    result, and the ndjson is the only durable artefact."""
    path = str(tmp_path / "r.ndjson")
    res = twohost.Results(path, "run-a", "source-a")
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
        "run_id",
        "source_id",
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
