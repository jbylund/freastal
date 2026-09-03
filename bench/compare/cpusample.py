"""CPU accounting for a benchmark run: was the server working, or the client?

`results.json` used to record only what the client observed - `rps`, `p50`,
`p99`, scatter. None of that says whether the *server* was busy, so a
client-bound measurement and a capacity measurement look identical. That
ambiguity produced three wrong conclusions in #48/#50.

This module samples ``utime + stime`` for the server's whole process group and
for the ``wrk`` process, on the same schedule, across the measured run only.

Why sample rather than read the boundaries twice
------------------------------------------------
Two reads give a mean over the run, and a mean cannot distinguish a server
pinned at 90% for 30s from one that ramped for 10s and then sat at 100%. Nor
can it show a worker that died at second 3, or one worker at 100% while three
idle - which is the exact shape that confused #50. Sampling costs one
``read()`` per process per tick and turns those into `peak`, `ramp_s` and
`worker_cores`.

Why a thread, not a separate process
------------------------------------
The harness's main thread is blocked in ``Popen.communicate()`` for the whole
measured run with the GIL released, so a sampling thread runs unimpeded. A
separate process would cost an extra interpreter (~10 MB RSS, ~30 ms of
startup) plus IPC and would still burn the same CPU on the same cores - it adds
contention rather than avoiding it. The cost is not asserted: the sampler
measures its own thread CPU with ``time.thread_time()`` and publishes it as
``sampler_cpu_pct_of_core`` in every round, so a reader can check that the
instrument is cheap on their machine rather than take this comment's word.

Linux only - it reads ``/proc``. Everything here degrades to ``None`` elsewhere,
which is how the harness reports ``n/a`` when run natively on macOS.
"""

import itertools
import math
import os
import statistics
import threading
import time

# Fields of /proc/<pid>/stat, 1-indexed as in proc(5). Everything from field 3
# on is parsed relative to the end of `comm`, because comm is an arbitrary
# 15-byte string that can contain spaces and parentheses.
_F_PGRP = 5
_F_UTIME = 14
_F_STIME = 15

try:
    CLK_TCK = os.sysconf("SC_CLK_TCK")
except (ValueError, AttributeError, OSError):  # pragma: no cover - not POSIX
    CLK_TCK = 100

# A side that is using at least this fraction of the cores it could use is
# "saturated" for the purpose of the verdict. 0.8 rather than 0.95 because a
# real server never reaches 100% of its worker budget - it also blocks on the
# socket - and because the reading is a mean over the run.
SATURATED = 80.0
# Above this, the *box* is full: server and client are taking each other's
# cores and neither number describes the software. Checked before the 2x2,
# since co-resident wrk is exactly this benchmark's known weakness. It is a
# separate test from the two above, not "both of them at once": at `-w4 -t4` on
# an 18-core host both sides can sit on their own budget with two thirds of the
# machine idle, and calling that machine-limited would be plainly false.
MACHINE_FULL = 90.0


def stat_fields(raw):
    """Split /proc/<pid>/stat into fields 3..N, so `field n` is `out[n - 3]`.

    ``comm`` is an arbitrary 15-byte string in parentheses and may itself
    contain ``)`` and spaces, so a plain ``split()`` mis-indexes every later
    field for a process named ``(sad) proc``. Every field after ``comm`` is a
    number or a single letter, so the *last* ``)`` on the line is always its
    closing paren - which makes ``rpartition`` exact where ``split`` is not.
    """
    _, sep, rest = raw.rpartition(")")
    if not sep:
        return None
    return rest.split()


def read_pid(pid, proc_root="/proc"):
    """Return ``(pgrp, ticks)`` for one pid, or ``None`` if it is gone.

    ``ticks`` is ``utime + stime`` - CPU burned by the process itself, summed
    over all its threads. Children are deliberately excluded: every server here
    forks its workers into the same process group, so they are counted as
    separate pids and can be reported individually.
    """
    try:
        with open(f"{proc_root}/{pid}/stat") as f:
            raw = f.read()
    except (OSError, ValueError):
        return None
    fields = stat_fields(raw)
    if fields is None or len(fields) < _F_STIME - 2:
        return None
    try:
        return (
            int(fields[_F_PGRP - 3]),
            int(fields[_F_UTIME - 3]) + int(fields[_F_STIME - 3]),
        )
    except ValueError:  # pragma: no cover - truncated read
        return None


def scan_pgid(pgid, proc_root="/proc"):
    """``{pid: ticks}`` for every live process in `pgid`.

    The whole group is rescanned every tick rather than resolved once, so a
    worker that dies mid-run stops contributing and one that is respawned
    starts. That costs one read per process on the box; in the bench container
    that is a dozen reads, which the published `sampler_cpu_pct_of_core` shows
    is free. There is no cheaper kernel interface for "pids in a process
    group": the pgrp is only readable per-process.
    """
    out = {}
    try:
        entries = os.listdir(proc_root)
    except OSError:  # pragma: no cover - no /proc
        return out
    for name in entries:
        if not name.isdigit():
            continue
        got = read_pid(name, proc_root)
        if got is not None and got[0] == pgid:
            out[int(name)] = got[1]
    return out


def available():
    """True if this platform can be sampled at all."""
    return os.path.isdir("/proc/self")


class Sampler:
    """Sample a server process group and one client pid on a fixed period.

    Start it immediately after spawning `wrk` and stop it when `wrk` exits: the
    window is then exactly the measured run, with the warmup excluded because
    it happened before the first sample.
    """

    def __init__(self, pgid, client_pid, interval=0.5, proc_root="/proc"):
        self.pgid = pgid
        self.client_pid = client_pid
        self.interval = interval
        self.proc_root = proc_root
        self.samples = []  # (monotonic_t, {pid: ticks}, client_ticks|None)
        self.thread_cpu_s = 0.0
        self.error = None
        self._stop = threading.Event()
        self._thread = None

    def _sample(self):
        server = scan_pgid(self.pgid, self.proc_root)
        client = read_pid(self.client_pid, self.proc_root)
        return (time.monotonic(), server, None if client is None else client[1])

    def _run(self):
        t0 = time.thread_time()
        try:
            # Absolute deadlines, so a slow sample does not make the period
            # drift longer and longer over a 30s run.
            n = 0
            base = time.monotonic()
            while True:
                self.samples.append(self._sample())
                n += 1
                delay = base + n * self.interval - time.monotonic()
                if self._stop.wait(max(delay, 0.0)):
                    break
            self.samples.append(self._sample())
        except Exception as exc:  # noqa: BLE001 - instrument must never kill a run
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            self.thread_cpu_s = time.thread_time() - t0

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10.0)


def _cores(dticks, dt):
    if dt <= 0:
        return float("nan")
    return dticks / CLK_TCK / dt


def summarize(samples, workers, ncpu, client_threads, thread_cpu_s=0.0):
    """Reduce raw samples to the numbers a reader would act on.

    Returns ``None`` if there is not enough to say anything. Everything is in
    cores (1.0 = one core fully busy for the window) or in percent of the cores
    that side could have used.
    """
    if len(samples) < 2:
        return None
    t_first, t_last = samples[0][0], samples[-1][0]
    window = t_last - t_first
    if window <= 0:
        return None

    # Per-pid first/last seen, not a single pair of boundary reads. A pid that
    # appears late is counted from its first sighting rather than having its
    # whole history charged to this window; a pid that died at second 3 keeps
    # the 3 seconds of work it did, divided by the full window, so it reads as
    # a near-idle worker instead of vanishing from the accounting.
    first, last = {}, {}
    for _t, server, _c in samples:
        for pid, ticks in server.items():
            first.setdefault(pid, ticks)
            last[pid] = ticks
    per_pid = sorted(
        (_cores(last[pid] - first[pid], window) for pid in first), reverse=True
    )
    server_cores = sum(per_pid)

    # Peak over one sample interval. This is what separates "pinned the whole
    # run" from "ramped, then pinned"; the mean cannot. Intervals much shorter
    # than the sampling period - the final flush sample lands right after the
    # periodic one - are dropped: at 100 Hz accounting a single stray tick over
    # a 5 ms gap reads as two whole cores.
    deltas = [
        (tb - ta, sa, sb) for (ta, sa, _), (tb, sb, _) in itertools.pairwise(samples)
    ]
    nominal = statistics.median(dt for dt, _, _ in deltas)
    interval_cores = []
    t = t_first
    for dt, sa, sb in deltas:
        t += dt
        if dt < 0.5 * nominal:
            continue
        d = sum(ticks - sa[pid] for pid, ticks in sb.items() if pid in sa)
        interval_cores.append((t - t_first, _cores(d, dt)))
    peak = max((c for _t, c in interval_cores), default=float("nan"))
    # Time until the server first reached 90% of its own run mean. Non-zero
    # means the 5s warmup did not finish warming it up and the mean below
    # understates the server - not that the server is slow.
    ramp_s = float("nan")
    for t_rel, c in interval_cores:
        if c >= 0.9 * server_cores:
            ramp_s = t_rel
            break

    # The top `workers` pids by CPU are the workers; anything below them is a
    # supervisor. gunicorn has a master, freastal has a parent that only joins,
    # bjoern has neither - ranking by CPU gets all three right without the
    # harness having to know each server's process shape. If fewer than
    # `workers` pids exist, the list is short-padded with zeros, which is the
    # signal that a worker died.
    worker_cores = (per_pid + [0.0] * workers)[:workers]
    if workers > 1 and worker_cores[0] > 0:
        imbalance = (worker_cores[0] - worker_cores[-1]) / worker_cores[0] * 100.0
    else:
        imbalance = 0.0

    client_first = client_last = None
    for _t, _s, c in samples:
        if c is not None:
            if client_first is None:
                client_first = c
            client_last = c
    client_cores = (
        _cores(client_last - client_first, window)
        if client_first is not None
        else float("nan")
    )

    server_sat = server_cores / max(workers, 1) * 100.0
    # wrk cannot use more cores than it has threads, nor more than the box has.
    client_sat = client_cores / max(min(client_threads, ncpu), 1) * 100.0
    machine_sat = (server_cores + client_cores) / max(ncpu, 1) * 100.0

    return {
        "server_cores": round(server_cores, 3),
        "server_sat_pct": round(server_sat, 1),
        "server_peak_cores": None if math.isnan(peak) else round(peak, 3),
        "client_cores": round(client_cores, 3),
        "client_sat_pct": round(client_sat, 1),
        "machine_sat_pct": round(machine_sat, 1),
        "worker_cores": [round(c, 3) for c in worker_cores],
        "worker_imbalance_pct": round(imbalance, 1),
        "ramp_s": None if math.isnan(ramp_s) else round(ramp_s, 2),
        "verdict": verdict(server_sat, client_sat, machine_sat),
        "pids": len(first),
        "window_s": round(window, 2),
        "samples": len(samples),
        # The instrument's own cost, measured rather than claimed.
        "sampler_cpu_pct_of_core": round(thread_cpu_s / window * 100.0, 3),
    }


def verdict(server_sat, client_sat, machine_sat):
    """One of five readings. See bench/compare/README.md for what to do next.

    A label is a threshold on a continuous quantity, so a row sitting on the
    line should be read from `srv` and `cli` themselves rather than from this
    word. It exists so that an obviously client-bound row cannot be published
    as a capacity number without someone noticing.
    """
    if math.isnan(machine_sat):  # the client pid was never readable
        return "unknown"
    if machine_sat >= MACHINE_FULL:
        return "machine-limited"
    srv, cli = server_sat >= SATURATED, client_sat >= SATURATED
    if srv and cli:
        # The server used its whole worker budget, so the row is a real number
        # for *this* config - but the client used its whole thread budget too,
        # so a larger config cannot be measured without more `-t`.
        return "both-saturated"
    if srv:
        return "server-limited"
    if cli:
        return "client-limited"
    return "neither"
