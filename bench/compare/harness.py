#!/usr/bin/env python3
"""Cross-server comparison benchmark. Runs inside the container; see run.sh.

Produces the table in README.md, plus a JSON record of everything needed to
defend or reproduce it.

Method
------
Servers are **interleaved**: every round measures every server once, and the
reported figure is the per-server median across rounds.  Running each server
to completion in turn instead would let thermal drift or a noisy neighbour
land entirely on one row, which is exactly how a benchmark table ends up
asserting something about the machine rather than the software.

Every server is verified before load - the harness asserts it answers 200 with
a body of the expected length - because a stale process on a reused port
produces plausible-looking numbers for the wrong binary.
"""

import argparse
import json
import math
import os
import platform
import re
import signal
import socket
import statistics
import subprocess
import sys
import time

import cpusample

HERE = os.path.dirname(os.path.abspath(__file__))

# (label, protocol, tls, how to launch). "gunicorn" is its own CLI.
#
# freastal covers the full {WSGI,ASGI} x {plaintext,TLS} matrix; the comparison
# servers appear plaintext-only, which is how they are normally deployed (TLS
# terminated upstream). Every row is measured at each --worker-counts value.
SERVERS = [
    ("gunicorn+uvicorn", "ASGI", False, "gunicorn"),
    ("bjoern", "WSGI", False, "bjoern"),
    ("freastal", "WSGI", False, "freastal-wsgi"),
    ("freastal", "ASGI", False, "freastal-asgi"),
    ("freastal", "WSGI", True, "freastal-wsgi-tls"),
    ("freastal", "ASGI", True, "freastal-asgi-tls"),
]

REQ_RE = re.compile(r"^Requests/sec:\s+([\d.]+)", re.MULTILINE)
COUNT_RE = re.compile(r"^\s*(\d+) requests in ", re.MULTILINE)
LAT_RE = re.compile(r"^\s+(\d+)%\s+([\d.]+)(us|ms|s)\s*$")
ERR_RE = re.compile(r"Non-2xx or 3xx responses:\s+(\d+)")
SOCKERR_RE = re.compile(r"Socket errors:.*")
# "    Req/Sec    31.57k     4.10k   41.61k    62.75%" -> mean, stdev
RPS_STDEV_RE = re.compile(
    r"^\s+Req/Sec\s+([\d.]+)([kKmM]?)\s+([\d.]+)([kKmM]?)", re.MULTILINE
)


def sh(*cmd):
    return subprocess.run(
        cmd, capture_output=True, text=True, check=False
    ).stdout.strip()


def _uvicorn_impl(preferred, fallback):
    """Report which optional accelerator uvicorn will actually use."""
    try:
        __import__(preferred)
        return preferred
    except ImportError:
        return f"{fallback} (MISCONFIGURED: {preferred} not installed)"


def provenance(args):
    """Everything a reader needs to know what the numbers describe."""
    # A linuxkit VM on aarch64 exposes no "model name", so run.sh passes the
    # host's CPU string in; the container is running on that silicon either way.
    cpu = os.environ.get("BENCH_HOST_CPU", "")
    if not cpu:
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.startswith(("model name", "Model")):
                        cpu = line.split(":", 1)[1].strip()
                        break
        except OSError:
            pass
    return {
        "arch": platform.machine(),
        "os": f"{platform.system()} {platform.release()}",
        "distro": sh("bash", "-c", ". /etc/os-release 2>/dev/null && echo $PRETTY_NAME")
        or "unknown",
        "cpu": cpu or "unknown",
        "cpus_available": effective_cpus()[1],
        "python": platform.python_version(),
        "libuv": os.environ.get(
            "BENCH_LIBUV_VERSION", sh("pkg-config", "--modversion", "libuv")
        ),
        "gunicorn": os.environ.get("BENCH_GUNICORN_VERSION", ""),
        "uvicorn": os.environ.get("BENCH_UVICORN_VERSION", ""),
        "bjoern": os.environ.get("BENCH_BJOERN_VERSION", ""),
        "wrk": (sh("wrk", "--version") or "").splitlines()[0]
        if sh("wrk", "--version")
        else "",
        "uvicorn_worker": os.environ.get("BENCH_UVICORN_WORKER_VERSION", ""),
        # Which loop and HTTP parser uvicorn actually resolved. Bare uvicorn
        # silently falls back to asyncio + h11, which is ~2.5x slower than the
        # uvloop + httptools install its own docs recommend - so if this says
        # anything but uvloop/httptools, the baseline is misconfigured and the
        # table is not a fair comparison.
        "uvicorn_loop": _uvicorn_impl("uvloop", "asyncio"),
        "uvicorn_http": _uvicorn_impl("httptools", "h11"),
        "freastal_commit": os.environ.get("BENCH_FREASTAL_COMMIT", "unknown"),
        "worker_counts": args.worker_counts,
        "duration_s": args.duration,
        "wrk_threads": args.threads,
        "wrk_connections": args.connections,
        "rounds": args.rounds,
        "loopback": True,
        "cpu_sample_interval_s": args.cpu_interval,
        "cpu_saturated_pct": cpusample.SATURATED,
        "cpu_machine_full_pct": cpusample.MACHINE_FULL,
    }


def effective_cpus():
    """`(usable cores, how to describe them)`.

    A cgroup quota is the real limit, not the host's core count, so a
    `--cpus=4` run must not divide by 18 and report itself as idle. Used both
    for the recorded provenance and as the denominator of `machine_sat_pct`.

    The count itself comes from `cpusample.available_cpus()` so that the
    harness and the instrument can never disagree about how many cores are in
    play; this adds only the human-readable half.
    """
    host = os.cpu_count() or 1
    n = cpusample.available_cpus()
    return n, (str(n) if n == host else f"{n} (cgroup limit of {host})")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def launch(kind, port, body, workers, args):
    env = dict(
        os.environ,
        BENCH_SERVER=kind,
        BENCH_PORT=str(port),
        BENCH_BODY=str(body),
        BENCH_WORKERS=str(workers),
        BENCH_CERT=args.cert,
        BENCH_KEY=args.key,
        # Prepend, never replace: the inherited PYTHONPATH is what puts the
        # freshly built freastal extension on the path. Overwriting it here
        # makes `import freastal` fail and every freastal row read "n/a".
        PYTHONPATH=os.pathsep.join(
            p for p in (HERE, os.environ.get("PYTHONPATH", "")) if p
        ),
    )
    if kind == "gunicorn":
        # uvicorn_worker is the maintained worker class; the one bundled in
        # uvicorn is deprecated. Fall back if the package is absent.
        try:
            import uvicorn_worker  # noqa: F401

            worker = "uvicorn_worker.UvicornWorker"
        except ImportError:
            worker = "uvicorn.workers.UvicornWorker"
        cmd = [
            "gunicorn",
            "apps:asgi_app",
            "-k",
            worker,
            "-w",
            str(workers),
            "-b",
            f"0.0.0.0:{port}",
            "--log-level",
            "error",
        ]
    else:
        cmd = [sys.executable, os.path.join(HERE, "servers.py")]
    # Deliberately not a context manager: Popen writes to this for the life
    # of the server and kill() closes it.
    log = open(f"/tmp/bench-{kind}-{port}.log", "wb")  # noqa: SIM115
    proc = subprocess.Popen(
        cmd,
        env=env,
        cwd=HERE,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    # start_new_session makes proc a session leader, so its pgid is its pid.
    # Record it now: once the leader exits, os.getpgid() raises and the worker
    # children - which are still in that group - would never be signalled.
    return proc, log, proc.pid


def verify(port, body, tls, timeout=40.0):
    """Confirm the right server is up AND serving the expected body length."""
    scheme = "https" if tls else "http"
    url = f"{scheme}://127.0.0.1:{port}/"
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        r = subprocess.run(
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code} %{size_download}",
                "-k",
                "--max-time",
                "2",
                url,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        last = r.stdout.strip()
        parts = last.split()
        if len(parts) == 2 and parts[0] == "200" and int(parts[1]) == body:
            return True
        time.sleep(0.25)
    print(
        f"    !! verify failed for {url}: got {last!r}, wanted '200 {body}'",
        file=sys.stderr,
    )
    return False


def kill(proc, log, pgid):
    """Kill the whole process group, not just the leader.

    Every server here forks workers - freastal via multiprocessing, gunicorn
    via its master, bjoern by hand - and those children survive a SIGKILL of
    the parent. Signalling the recorded pgid reaches them; looking the pgid up
    at teardown does not, because by then the leader may already be gone, which
    made os.getpgid() raise and silently skipped the group kill.
    """
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        pass
    log.close()
    # Reap whatever the group kill collected, so zombies cannot accumulate
    # across a long matrix run.
    try:
        while os.waitpid(-1, os.WNOHANG)[0]:
            pass
    except (ChildProcessError, OSError):
        pass


def parse_wrk(out):
    m, c = REQ_RE.search(out), COUNT_RE.search(out)
    if not m or not c or int(c.group(1)) == 0:
        return None
    res = {"rps": float(m.group(1)), "requests": int(c.group(1)), "lat": {}}
    for line in out.splitlines():
        lm = LAT_RE.match(line)
        if lm:
            mult = {"us": 1.0, "ms": 1e3, "s": 1e6}[lm.group(3)]
            res["lat"][lm.group(1)] = float(lm.group(2)) * mult
    # Within-run stability, straight from wrk: the coefficient of variation of
    # per-thread throughput across its sampling interval.
    res["rps_cv_pct"] = float("nan")
    sm = RPS_STDEV_RE.search(out)
    if sm:
        scale = {"": 1.0, "k": 1e3, "K": 1e3, "m": 1e6, "M": 1e6}
        mean = float(sm.group(1)) * scale[sm.group(2)]
        stdev = float(sm.group(3)) * scale[sm.group(4)]
        if mean > 0:
            res["rps_cv_pct"] = stdev / mean * 100.0

    em = ERR_RE.search(out)
    res["non2xx"] = int(em.group(1)) if em else 0
    se = SOCKERR_RE.search(out)
    res["sockerr"] = se.group(0) if se else ""
    return res


def measured_wrk(scheme, port, pgid, workers, args):
    """Run the measured `wrk` and sample both sides' CPU for its lifetime.

    Popen rather than run(), because the sampler needs `wrk`'s pid. The main
    thread then spends the whole measured run blocked in `communicate()` with
    the GIL released, which is what lets an in-process sampling thread be cheap
    enough to be honest about. Sampling starts here and not around the warmup,
    so the warmup is excluded by construction rather than subtracted later.
    """
    wrk = subprocess.Popen(
        [
            "wrk",
            f"-t{args.threads}",
            f"-c{args.connections}",
            f"-d{args.duration}s",
            "--latency",
            f"{scheme}://127.0.0.1:{port}/",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    sampler = None
    if args.cpu_interval > 0 and cpusample.available():
        sampler = cpusample.Sampler(pgid, wrk.pid, interval=args.cpu_interval)
        sampler.start()
    try:
        out, _ = wrk.communicate()
    finally:
        # Unconditional: a sampler left running after a failed round would poll
        # a dead pgid for the rest of the matrix, one leaked thread per failure.
        if sampler is not None:
            sampler.stop()
    if sampler is None:
        return out, None
    cpu = cpusample.summarize(
        sampler.samples,
        workers=workers,
        ncpu=effective_cpus()[0],
        client_threads=args.threads,
        thread_cpu_s=sampler.thread_cpu_s,
    )
    if cpu is not None and sampler.error:
        cpu["error"] = sampler.error
    return out, cpu


def measure_one(kind, body, tls, workers, args):
    port = free_port()
    proc, log, pgid = launch(kind, port, body, workers, args)
    try:
        if not verify(port, body, tls):
            with open(f"/tmp/bench-{kind}-{port}.log", errors="replace") as lf:
                tail = lf.read()[-1500:]
            raise RuntimeError(f"{kind} did not come up correctly:\n{tail}")
        scheme = "https" if tls else "http"
        subprocess.run(
            [
                "wrk",
                "-t2",
                "-c20",
                f"-d{args.warmup}s",
                f"{scheme}://127.0.0.1:{port}/",
            ],
            capture_output=True,
            check=False,
        )
        out, cpu = measured_wrk(scheme, port, pgid, workers, args)
        r = parse_wrk(out)
        if r is None:
            raise RuntimeError(f"{kind}: unusable wrk output:\n{out}")
        r["cpu"] = cpu
        return r
    finally:
        kill(proc, log, pgid)


def _med(vals):
    """Median of the usable values, or nan. None and nan are dropped, because
    one round where the sampler could not see a pid must not poison the rest."""
    clean = [v for v in vals if v is not None and not math.isnan(v)]
    return statistics.median(clean) if clean else float("nan")


def median_cpu(cpus):
    """Per-config CPU figures: the median of each field across rounds.

    The numbers are medians; the verdict is not. Classifying the median
    saturation after the fact would launder a round that was client-bound in
    among two that were not - the median is a number, and a verdict is a claim.
    So each round is classified on its own figures and the config keeps a
    verdict only when every round agrees, reporting "mixed" otherwise. "mixed"
    is a finding, and points at cpu_all in results.json.
    """
    got = [c for c in cpus if c]
    if not got:
        return None
    out = {
        k: round(_med([c.get(k) for c in got]), 3)
        for k in (
            "server_cores",
            "server_sat_pct",
            "server_peak_cores",
            "client_cores",
            "client_sat_pct",
            "machine_sat_pct",
            "worker_imbalance_pct",
            "ramp_s",
            "sampler_cpu_pct_of_core",
        )
    }
    # Per-worker cores, taken rank by rank: the median of the busiest worker
    # across rounds, then of the second busiest, and so on. One worker at 100%
    # and three at 20% is a load-distribution bug that server_cores hides.
    ranks = max(len(c.get("worker_cores") or ()) for c in got)
    out["worker_cores"] = [
        round(_med([(c.get("worker_cores") or [None] * ranks)[i] for c in got]), 3)
        for i in range(ranks)
    ]
    out["verdict"] = cpusample.reduce_verdicts(
        [
            cpusample.verdict(
                c.get("server_sat_pct"),
                c.get("client_sat_pct"),
                c.get("machine_sat_pct"),
            )
            for c in got
        ]
    )
    out["n"] = len(got)
    return out


def fmt_k(rps):
    return f"~{rps / 1000:.0f}k"


def fmt_pct(v):
    return "n/a" if v is None or math.isnan(v) else f"{v:.0f}%"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--duration", type=int, default=30)
    p.add_argument("--warmup", type=int, default=5)
    p.add_argument(
        "--worker-counts",
        dest="worker_counts",
        default="1,4",
        help="comma-separated worker counts to measure",
    )
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--connections", type=int, default=40)
    p.add_argument("--bodies", default="500,12000")
    p.add_argument(
        "--cpu-interval",
        dest="cpu_interval",
        type=float,
        default=0.5,
        help="seconds between CPU samples during the measured run; 0 disables",
    )
    p.add_argument("--cert", default="/tmp/bench-cert.pem")
    p.add_argument("--key", default="/tmp/bench-key.pem")
    p.add_argument("--json", default="/out/results.json")
    p.add_argument("--markdown", default="/out/table.md")
    args = p.parse_args()

    bodies = [int(b) for b in args.bodies.split(",")]
    prov = provenance(args)
    print("=== provenance ===")
    for k, v in prov.items():
        print(f"  {k:18} {v}")

    worker_counts = [int(w) for w in args.worker_counts.split(",")]

    # samples[(body, workers, label, proto, tls)] -> per-round results
    samples = {}
    for rnd in range(args.rounds):
        for body in bodies:
            for workers in worker_counts:
                for label, proto, tls, kind in SERVERS:
                    key = (body, workers, label, proto, tls)
                    tag = f"{label} {proto}{' TLS' if tls else ''}"
                    print(
                        f"[round {rnd + 1}/{args.rounds}] body={body} w={workers} "
                        f"{tag} ...",
                        end="",
                        flush=True,
                    )
                    try:
                        r = measure_one(kind, body, tls, workers, args)
                    except Exception as exc:  # noqa: BLE001 - one bad config must not kill the run
                        print(f" FAILED: {exc}".replace("\n", " ")[:180])
                        samples.setdefault(key, [])
                        continue
                    samples.setdefault(key, []).append(r)
                    flag = "  !! errors" if (r["non2xx"] or r["sockerr"]) else ""
                    print(
                        f" {r['rps']:>9.0f} rps  p50={r['lat'].get('50', 0):.0f}us{flag}"
                    )

    # ---- reduce ----
    rows = {}
    for key, rs in samples.items():
        clean = [r for r in rs if not r["non2xx"] and not r["sockerr"]]
        used = clean or rs
        if not used:
            continue
        rows[key] = {
            "rps": statistics.median(r["rps"] for r in used),
            "p50": statistics.median(r["lat"].get("50", float("nan")) for r in used),
            "p99": statistics.median(r["lat"].get("99", float("nan")) for r in used),
            "n": len(used),
            "dropped": len(rs) - len(clean),
            "rps_all": [r["rps"] for r in rs],
            # (max-min)/median across rounds. A median over widely scattered
            # samples looks authoritative and is not, so publish the scatter.
            # Median of wrk's own within-run CV: high here means the server
            # itself is jittery; low here with a high spread_pct means the
            # machine drifted between rounds.
            "within_cv_pct": statistics.median(
                r.get("rps_cv_pct", float("nan")) for r in used
            ),
            "spread_pct": (
                (max(r["rps"] for r in used) - min(r["rps"] for r in used))
                / statistics.median(r["rps"] for r in used)
                * 100.0
                if len(used) > 1
                else float("nan")
            ),
            # Every round's raw CPU record, so a surprising median can be
            # traced back to the round that produced it.
            "cpu_all": [r.get("cpu") for r in rs],
            "cpu": median_cpu([r.get("cpu") for r in used]),
        }

    # ---- markdown ----
    out = []
    out.append(
        "Benchmarked against gunicorn+uvicorn (the most common production "
        "Python stack) as baseline, at the same worker count.\n"
    )
    out.append(
        "| | |\n|---|---|\n"
        f"| Platform | {prov['arch']}, {prov['distro']} "
        f"(kernel {prov['os'].split()[-1]}) |\n"
        f"| CPU | {prov['cpu']}, {prov['cpus_available']} available |\n"
        f"| Python | {prov['python']} |\n"
        f"| libuv | {prov['libuv']} |\n"
        f"| Load | `wrk -t{prov['wrk_threads']} -c{prov['wrk_connections']}`, "
        f"{prov['duration_s']}s x {prov['rounds']} rounds (median), loopback |\n"
        f"| Versions | gunicorn {prov['gunicorn']}, uvicorn {prov['uvicorn']} "
        f"({prov['uvicorn_loop']} + {prov['uvicorn_http']}), "
        f"bjoern {prov['bjoern']} |\n"
        f"| freastal | {prov['freastal_commit']} |\n"
    )

    for body in bodies:
        label = f"{body}B" if body < 1000 else f"{body // 1000}KB"
        out.append(f"\n### {label} response\n")
        out.append(
            "| Server | Protocol | TLS | Workers | Req/s | p50 | p99 "
            "| vs baseline | between | within | srv | cli |"
        )
        out.append(
            "|--------|----------|:---:|--------:|------:|----:|----:"
            "|------------:|--------:|-------:|----:|----:|"
        )
        for workers in worker_counts:
            base = rows.get((body, workers, "gunicorn+uvicorn", "ASGI", False))
            for slabel, proto, tls, _kind in SERVERS:
                r = rows.get((body, workers, slabel, proto, tls))
                tls_cell = "yes" if tls else "no"
                if r is None:
                    out.append(
                        f"| {slabel} | {proto} | {tls_cell} | {workers} "
                        f"| n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |"
                    )
                    continue
                ratio = "n/a"
                if base:
                    ratio = f"{r['rps'] / base['rps']:.2f}x"
                bold = slabel == "gunicorn+uvicorn"
                w = (lambda t: f"**{t}**") if bold else (lambda t: t)
                cpu = r.get("cpu") or {}
                cells = [
                    w(slabel),
                    w(proto),
                    w(tls_cell),
                    w(str(workers)),
                    w(fmt_k(r["rps"])),
                    w(f"{r['p50']:.0f}us"),
                    w(f"{r['p99']:.0f}us"),
                    w(ratio),
                    w("n/a" if r["n"] < 2 else f"{r['spread_pct']:.0f}%"),
                    w(f"{r['within_cv_pct']:.0f}%"),
                    w(fmt_pct(cpu.get("server_sat_pct"))),
                    w(fmt_pct(cpu.get("client_sat_pct"))),
                ]
                out.append("| " + " | ".join(cells) + " |")
    out.append(
        "\n`srv` is the server's CPU over the measured run as a percentage of "
        "its worker count; `cli` is `wrk`'s own CPU as a percentage of the "
        "cores it could use. High `srv` with low `cli` is a capacity number. "
        "Low `srv` with high `cli` is a property of the harness, not the "
        "server. Both low means the load shape, not either side, was the "
        "limit; both high means this config is measurable but a larger one is "
        "not, without more client threads. See bench/compare/README.md."
    )
    md = "\n".join(out) + "\n"

    print("\n" + md)
    os.makedirs(os.path.dirname(args.json), exist_ok=True)
    with open(args.json, "w") as f:
        json.dump(
            {
                "provenance": prov,
                "rows": {
                    f"body={b}|workers={w}|{lb}|{pr}|tls={t}": v
                    for (b, w, lb, pr, t), v in rows.items()
                },
            },
            f,
            indent=2,
        )
    with open(args.markdown, "w") as f:
        f.write(md)
    print(f"wrote {args.json} and {args.markdown}")


if __name__ == "__main__":
    main()
