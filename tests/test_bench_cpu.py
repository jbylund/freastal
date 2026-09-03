"""The benchmark's CPU instrument, checked against processes we control.

`bench/compare/cpusample.py` decides whether a published rps number describes a
saturated server or a saturated client, so it is worth more than a comment
saying it looks right. Two layers here:

- the accounting maths, against hand-written samples and a fake /proc, which
  runs everywhere; and
- the whole sampler against real busy loops burning a *known* number of cores
  for a known time, which needs /proc and so runs only on Linux (the container
  the comparison harness actually runs in).
"""

import importlib.util
import os
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPARE = os.path.join(ROOT, "bench", "compare")


def _load(name):
    path = os.path.join(COMPARE, f"{name}.py")
    if not os.path.exists(path):
        pytest.skip(f"{path} not present - running against an installed dist")
    spec = importlib.util.spec_from_file_location(f"_bench_{name}", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def cs():
    return _load("cpusample")


@pytest.fixture(scope="module")
def harness(cs):
    # harness.py does a bare `import cpusample`, the way it is run in the
    # container with bench/compare on PYTHONPATH.
    sys.modules.setdefault("cpusample", cs)
    return _load("harness")


linux_only = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="/proc is Linux-only"
)


# ---------------------------------------------------------------------------
# parsing /proc/<pid>/stat
# ---------------------------------------------------------------------------


def test_stat_fields_survives_a_comm_full_of_parens_and_spaces(cs):
    """A process named ") x (" must not shift every later field by one.

    This is not hypothetical padding: `comm` is 15 arbitrary bytes, and getting
    it wrong reads the wrong column as utime, which would silently produce
    confident nonsense rather than an error.
    """
    # comm here is ") x ( )" - parens and spaces, exactly what breaks split().
    fields = cs.stat_fields("42 () x ( )) S 1 7 7 0 -1 0 1 2 3 4 100 250 0 0\n")
    assert fields[cs._F_PGRP - 3] == "7"
    assert fields[cs._F_UTIME - 3] == "100"
    assert fields[cs._F_STIME - 3] == "250"


def test_read_pid_and_scan_pgid_against_a_fake_proc(cs, tmp_path):
    def write(pid, pgrp, utime, stime):
        d = tmp_path / str(pid)
        d.mkdir()
        (d / "stat").write_text(
            f"{pid} (srv) S 1 {pgrp} {pgrp} 0 -1 0 1 2 3 4 {utime} {stime} 0 0\n"
        )

    write(100, 100, 30, 20)  # group leader
    write(101, 100, 10, 5)  # worker in the group
    write(200, 200, 99, 99)  # someone else entirely
    (tmp_path / "self").mkdir()  # a non-numeric entry must be ignored

    assert cs.read_pid(101, str(tmp_path)) == (100, 15)
    assert cs.read_pid(999, str(tmp_path)) is None
    assert cs.scan_pgid(100, str(tmp_path)) == {100: 50, 101: 15}


# ---------------------------------------------------------------------------
# the accounting, on samples whose answer is known by construction
# ---------------------------------------------------------------------------


def _samples(cs, per_pid_cores, seconds, interval=0.5, client_cores=0.0):
    """Synthesise samples for processes burning exactly `per_pid_cores`."""
    out = []
    n = int(seconds / interval) + 1
    for i in range(n):
        t = i * interval
        server = {
            1000 + j: round(c * t * cs.CLK_TCK) for j, c in enumerate(per_pid_cores)
        }
        out.append((t, server, round(client_cores * t * cs.CLK_TCK)))
    return out


def test_summarize_reports_the_cores_that_were_burned(cs):
    s = cs.summarize(
        _samples(cs, [1.0, 1.0, 0.5], 30.0, client_cores=2.0),
        workers=3,
        ncpu=8,
        client_threads=4,
    )
    assert s["server_cores"] == pytest.approx(2.5, abs=0.02)
    assert s["server_sat_pct"] == pytest.approx(83.3, abs=0.5)
    assert s["client_cores"] == pytest.approx(2.0, abs=0.02)
    assert s["client_sat_pct"] == pytest.approx(50.0, abs=0.5)
    assert s["worker_cores"] == pytest.approx([1.0, 1.0, 0.5], abs=0.02)
    assert s["window_s"] == pytest.approx(30.0, abs=0.01)


def test_one_hot_worker_is_visible_where_the_sum_hides_it(cs):
    """1.0 + 0.2 + 0.2 + 0.2 sums to the same 1.6 as four workers at 0.4.

    That is the load-distribution bug the #48/#50 investigation could not see,
    so the two cases must not produce the same record.
    """
    hot = cs.summarize(
        _samples(cs, [1.0, 0.2, 0.2, 0.2], 20.0), workers=4, ncpu=8, client_threads=4
    )
    even = cs.summarize(
        _samples(cs, [0.4, 0.4, 0.4, 0.4], 20.0), workers=4, ncpu=8, client_threads=4
    )
    assert hot["server_cores"] == pytest.approx(even["server_cores"], abs=0.05)
    assert hot["worker_imbalance_pct"] == pytest.approx(80.0, abs=2.0)
    assert even["worker_imbalance_pct"] == pytest.approx(0.0, abs=2.0)


def test_a_worker_that_dies_mid_run_shows_up_as_an_idle_rank(cs):
    good = _samples(cs, [1.0, 1.0], 20.0)
    dead = []
    for t, server, client in good:
        server = dict(server)
        if t > 5.0:  # pid 1001 disappears from /proc after 5s
            server.pop(1001)
        dead.append((t, server, client))
    s = cs.summarize(dead, workers=2, ncpu=8, client_threads=4)
    # It keeps the 5s of work it did, spread over the 20s window.
    assert s["worker_cores"] == pytest.approx([1.0, 0.25], abs=0.03)
    assert s["worker_imbalance_pct"] == pytest.approx(75.0, abs=3.0)


def test_a_ramp_is_distinguishable_from_a_flat_run(cs):
    """The mean is the same either way; ramp_s and the peak are not."""
    interval, cs_ticks = 0.5, cs.CLK_TCK
    flat, ramp = [], []
    acc_f = acc_r = 0.0
    for i in range(41):  # 20s
        t = i * interval
        flat.append((t, {1000: round(acc_f * cs_ticks)}, 0))
        ramp.append((t, {1000: round(acc_r * cs_ticks)}, 0))
        acc_f += 0.5 * interval  # 0.5 cores throughout
        acc_r += (0.0 if t < 10 else 1.0) * interval  # idle 10s, then 1 core

    f = cs.summarize(flat, workers=1, ncpu=8, client_threads=4)
    r = cs.summarize(ramp, workers=1, ncpu=8, client_threads=4)
    assert f["server_cores"] == pytest.approx(r["server_cores"], abs=0.05)
    assert f["server_peak_cores"] == pytest.approx(0.5, abs=0.05)
    assert r["server_peak_cores"] == pytest.approx(1.0, abs=0.05)
    assert f["ramp_s"] == pytest.approx(0.5, abs=0.6)
    assert r["ramp_s"] == pytest.approx(10.0, abs=0.6)


def test_a_short_trailing_sample_cannot_invent_a_peak(cs):
    """The flush sample lands milliseconds after a periodic one.

    One 100 Hz tick over a 5 ms gap is 2.0 cores if you divide naively, which
    would put a fictional peak in every single row.
    """
    s = _samples(cs, [0.5], 10.0)
    last_t, last_server, last_client = s[-1]
    s.append((last_t + 0.005, {k: v + 1 for k, v in last_server.items()}, last_client))
    out = cs.summarize(s, workers=1, ncpu=8, client_threads=4)
    assert out["server_peak_cores"] == pytest.approx(0.5, abs=0.05)


@pytest.mark.parametrize(
    ("srv", "cli", "machine", "want"),
    [
        (95.0, 20.0, 40.0, "server-limited"),
        (30.0, 95.0, 40.0, "client-limited"),
        (30.0, 30.0, 40.0, "neither"),
        # Both sides on their own budget with the box two thirds idle is not a
        # machine limit; only the box actually being full is.
        (95.0, 95.0, 50.0, "both-saturated"),
        (50.0, 50.0, 95.0, "machine-limited"),
        (50.0, float("nan"), float("nan"), "unknown"),
    ],
)
def test_verdicts(cs, srv, cli, machine, want):
    assert cs.verdict(srv, cli, machine) == want


def test_summarize_refuses_to_guess_from_one_sample(cs):
    assert cs.summarize([], 1, 8, 4) is None
    assert cs.summarize([(0.0, {1: 0}, 0)], 1, 8, 4) is None


# ---------------------------------------------------------------------------
# per-config reduction in harness.py
# ---------------------------------------------------------------------------


def test_median_cpu_takes_workers_rank_by_rank(harness):
    rounds = [
        {
            "server_cores": 2.0,
            "server_sat_pct": 50.0,
            "server_peak_cores": 3.0,
            "client_cores": 1.0,
            "client_sat_pct": 25.0,
            "machine_sat_pct": 37.5,
            "worker_imbalance_pct": 80.0,
            "ramp_s": 0.5,
            "sampler_cpu_pct_of_core": 0.01,
            "worker_cores": [1.4, 0.2, 0.2, 0.2],
        },
        {
            "server_cores": 2.2,
            "server_sat_pct": 55.0,
            "server_peak_cores": 3.2,
            "client_cores": 3.6,
            "client_sat_pct": 90.0,
            "machine_sat_pct": 72.5,
            "worker_imbalance_pct": 84.0,
            "ramp_s": None,
            "sampler_cpu_pct_of_core": 0.02,
            "worker_cores": [1.8, 0.2, 0.1, 0.1],
        },
        {
            "server_cores": 2.1,
            "server_sat_pct": 52.5,
            "server_peak_cores": 3.1,
            "client_cores": 3.8,
            "client_sat_pct": 95.0,
            "machine_sat_pct": 73.9,
            "worker_imbalance_pct": 82.0,
            "ramp_s": 0.5,
            "sampler_cpu_pct_of_core": 0.015,
            "worker_cores": [1.6, 0.2, 0.15, 0.15],
        },
    ]
    m = harness.median_cpu(rounds)
    assert m["server_sat_pct"] == 52.5
    assert m["client_sat_pct"] == 90.0
    assert m["worker_cores"] == [1.6, 0.2, 0.15, 0.15]
    assert m["ramp_s"] == 0.5  # the None round is dropped, not treated as zero
    assert m["n"] == 3
    # Recomputed from the medians printed beside it, never voted on.
    assert m["verdict"] == "client-limited"


def test_median_cpu_is_none_when_nothing_was_sampled(harness):
    assert harness.median_cpu([None, None]) is None
    assert harness.median_cpu([]) is None


def test_effective_cpus_prefers_a_cgroup_quota(harness, monkeypatch, tmp_path):
    """A `--cpus=4` container must not divide by the host's 18 cores."""
    monkeypatch.setattr(harness.os, "cpu_count", lambda: 18)
    quota = tmp_path / "cpu.max"

    real_open = open

    def fake_open(path, *a, **kw):
        if path == "/sys/fs/cgroup/cpu.max":
            return real_open(quota, *a, **kw)
        return real_open(path, *a, **kw)

    monkeypatch.setattr("builtins.open", fake_open)

    quota.write_text("400000 100000\n")
    assert harness.effective_cpus() == (4, "4 (cgroup limit of 18)")
    quota.write_text("max 100000\n")
    assert harness.effective_cpus() == (18, "18")
    quota.unlink()
    assert harness.effective_cpus() == (18, "18")


def test_fmt_pct_never_prints_nan_in_the_table(harness):
    assert harness.fmt_pct(None) == "n/a"
    assert harness.fmt_pct(float("nan")) == "n/a"
    assert harness.fmt_pct(83.4) == "83%"


# ---------------------------------------------------------------------------
# the real oracle: processes burning a known number of cores
# ---------------------------------------------------------------------------

# Busy-loop with a duty cycle, so the oracle covers fractional cores too.
_BURN = """
import os, sys, time
duty, secs, n = float(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3])
for _ in range(n - 1):
    if os.fork() == 0:
        break
end = time.monotonic() + secs
while time.monotonic() < end:
    t = time.monotonic() + 0.02 * duty
    while time.monotonic() < t:
        pass
    if duty < 1.0:
        time.sleep(0.02 * (1.0 - duty))
"""


def _burn(duty, secs, n):
    return subprocess.Popen(
        [sys.executable, "-c", _BURN, str(duty), str(secs), str(n)],
        start_new_session=True,
    )


@linux_only
@pytest.mark.parametrize(("duty", "procs"), [(1.0, 2), (0.5, 1)])
def test_sampler_measures_a_known_burn(cs, duty, procs):
    if (os.cpu_count() or 1) < procs + 1:
        pytest.skip("not enough cores to burn a known number of them")
    seconds = 4.0
    server = _burn(duty, seconds, procs)
    client = _burn(1.0, seconds, 1)
    try:
        time.sleep(0.4)  # let the forks land before the first sample
        s = cs.Sampler(server.pid, client.pid, interval=0.2)
        s.start()
        time.sleep(seconds - 1.0)
        s.stop()
        out = cs.summarize(
            s.samples,
            workers=procs,
            ncpu=os.cpu_count(),
            client_threads=1,
            thread_cpu_s=s.thread_cpu_s,
        )
    finally:
        for p in (server, client):
            p.kill()
            p.wait()

    assert s.error is None
    assert out["pids"] == procs
    # 15% either way: the burner is a Python loop, not a calibrated oracle, and
    # the box is shared. The failure this guards against is off-by-a-factor -
    # wrong /proc field, ticks read as seconds, per-pid double counting.
    assert out["server_cores"] == pytest.approx(duty * procs, rel=0.15)
    assert out["client_cores"] == pytest.approx(1.0, rel=0.15)
    assert out["worker_cores"] == pytest.approx([duty] * procs, rel=0.2)


@linux_only
def test_the_sampler_costs_almost_nothing(cs):
    """The instrument competes for the cores it is measuring, so bound it.

    Sampled here at 20 Hz - ten times the harness's 0.5s period - and still
    required to stay under 5% of one core. In the bench container at 0.5s it
    lands around 0.05%; the margin is for a busy shared CI box.
    """
    victim = _burn(1.0, 3.0, 1)
    try:
        time.sleep(0.2)
        s = cs.Sampler(victim.pid, victim.pid, interval=0.05)
        s.start()
        time.sleep(2.0)
        s.stop()
    finally:
        victim.kill()
        victim.wait()
    out = cs.summarize(
        s.samples,
        workers=1,
        ncpu=os.cpu_count(),
        client_threads=1,
        thread_cpu_s=s.thread_cpu_s,
    )
    assert len(s.samples) > 20
    assert out["sampler_cpu_pct_of_core"] < 5.0
