"""Two-host benchmark: find each server's best client shape, then measure it.

Complements harness.py rather than replacing it. harness.py runs everything on
one machine and owns the published table -- provenance, interleaving, the
scatter columns, the markdown. This runs the server and the load generator on
*different* hosts, which is the only way to exercise a real NIC, a real MTU and
real segmentation (see the two-host issue). The two should converge once this
has been used in anger; until then the seam is deliberate, so a change here
cannot break the table that ships.

Phase 1 sweeps shapes per config and keeps the argmax. Phase 2 measures only
those argmaxes, interleaved across configs so drift lands on every row rather
than on whichever was running -- the reason harness.py interleaves, and the
difference between a table about the software and one about the machine.

Every measurement is appended to the results file as it completes. A two-hour
run that dies at ninety minutes should cost ninety minutes of nothing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from runner import LocalRunner, SshRunner

CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

# The bar for "this row is a capacity number". Shared with cpusample so the two
# tools cannot drift into disagreeing about what saturated means.
try:
    from cpusample import HIGH_PCT as SATURATED_PCT
except ImportError:  # pragma: no cover - standalone use
    SATURATED_PCT = 80.0


# --------------------------------------------------------------------------
# what gets measured
# --------------------------------------------------------------------------

# The comparison runs every server at the same depth, and that depth is 1.
#
# Pipelining is not a throughput knob that each server happens to tune
# differently -- it is a protocol capability. Letting each server run at its
# own best depth would rank that capability and print it in the shape of a
# throughput number.
#
# So depth is fixed for the comparison, and the depth sweep survives as a
# separate diagnostic over everything that can pipeline, reported apart from
# the table and never mixed into it.
COMPARE_DEPTH = 1

# Who gets the shape x depth cross product.
#
# Everything that can accept pipelined requests, which is everything except
# bjoern. uvicorn is included even though a quick check suggested it gains
# nothing from depth: "measured flat once" is not the same as "swept", and the
# claim that only freastal benefits is worth holding to the same standard as
# the claim that freastal does. bjoern is excluded because it cannot parse a
# pipelined batch at all, so a sweep would measure its read timeout.
DIAGNOSTIC_KINDS = {"freastal-wsgi", "freastal-asgi", "gunicorn-uvicorn"}


# Servers that cannot be asked for pipelined requests.
#
# bjoern reads one request per socket read, so the rest of a pipelined batch
# waits for another read event. Sweeping depth for it would measure that
# limitation rather than throughput.
NO_PIPELINING = {"bjoern"}


def depths_for(kind, requested):
    """Depths to sweep for one server, honouring what it can actually do."""
    if kind in NO_PIPELINING:
        return [1]
    return requested


def configs(bodies, worker_counts, only=None):
    """The server configurations, one port each."""
    out, port = [], 9200
    for kind in ("freastal-wsgi", "freastal-asgi", "gunicorn-uvicorn", "bjoern"):
        for workers in worker_counts:
            for body in bodies:
                if kind == "bjoern" and workers > 1:
                    continue  # bjoern is single-process here
                out.append(
                    {"kind": kind, "workers": workers, "body": body, "port": port}
                )
                port += 1
    if only:
        out = [c for c in out if c["kind"] in only]
    return out


def cell_id(cfg, phase, shape=None, trial=None):
    s = f"-t{shape[0]}c{shape[1]}d{shape[2]}" if shape else ""
    t = f"-r{trial}" if trial is not None else ""
    return f"{cfg['kind']}-w{cfg['workers']}-b{cfg['body']}-{phase}{s}{t}"


def source_id():
    """Identify the source tree whose server is expected on the remote host."""
    override = os.environ.get("BENCH_SOURCE_ID")
    if override:
        return override
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    commit = subprocess.run(
        ["git", "-C", root, "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    diff = subprocess.run(
        ["git", "-C", root, "diff", "--binary", "--", "bench/compare", "freastal"],
        capture_output=True,
        check=False,
    ).stdout
    if diff:
        return f"{commit or 'unknown'}-dirty-{hashlib.sha256(diff).hexdigest()[:12]}"
    return commit or "unknown"


def run_fingerprint(args, source):
    """Stable identity for every input that can change a resumed result."""
    fields = (
        "server_host",
        "client_host",
        "server_addr",
        "server_python",
        "server_script",
        "remote_lua",
        "bodies",
        "workers",
        "only",
        "shapes",
        "depths",
        "sweep_warmup",
        "sweep_duration",
        "final_warmup",
        "final_duration",
        "trials",
        "diagnostic",
    )
    payload = {"source_id": source, **{name: getattr(args, name) for name in fields}}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:20]


# --------------------------------------------------------------------------
# server lifecycle on the server host
# --------------------------------------------------------------------------


def cpu_seconds(host, pids):
    """Total CPU across pids. Linux reads /proc in one shot; macOS uses ps."""
    if not pids:
        return 0.0
    if host.name == "ssh" or sys.platform.startswith("linux"):
        expr = " ".join(f"/proc/{p}/stat" for p in pids)
        out = host.run(f"cat {expr} 2>/dev/null", timeout=30).stdout
        tot = 0
        for line in out.splitlines():
            # A pid that vanished between listing and reading is normal (a
            # worker exiting); a malformed line is not, but neither is worth
            # ending a run over -- the caller checks the total is non-zero.
            try:
                f = line.rsplit(")", 1)[1].split()
                tot += int(f[11]) + int(f[12])
            except (IndexError, ValueError):
                continue
        return tot / CLK_TCK
    tot = 0.0
    for p in pids:
        out = host.run(["ps", "-p", str(p), "-o", "time="]).stdout.strip()
        if out:
            parts = out.split(":")
            s = float(parts[-1])
            if len(parts) > 1:
                s += int(parts[-2]) * 60
            if len(parts) > 2:
                s += int(parts[-3]) * 3600
            tot += s
    return tot


def start_server(host, cfg, args):
    env = {
        "BENCH_PORT": str(cfg["port"]),
        "BENCH_WORKERS": str(cfg["workers"]),
        "BENCH_BODY": str(cfg["body"]),
    }
    argv = [args.server_python, args.server_script, cfg["kind"]]
    handle = host.start(argv, env=env)
    url = f"http://{args.server_addr}:{cfg['port']}/"
    for _ in range(int(args.start_timeout / 0.25)):
        r = host.run(
            [
                "curl",
                "-sf",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                f"http://127.0.0.1:{cfg['port']}/",
            ],
            timeout=15,
        )
        if r.stdout.strip() == "200":
            return handle, url
        time.sleep(0.25)
    host.stop(handle)
    raise RuntimeError(f"{cfg['kind']} w{cfg['workers']} b{cfg['body']} never answered")


# --------------------------------------------------------------------------
# one measurement
# --------------------------------------------------------------------------


def server_saturation_pct(cores, workers):
    """Server CPU as a percentage of the configured worker budget.

    Process trees also contain masters, resource trackers and fork servers.
    Counting those pids as possible worker cores understates saturation for
    exactly the multi-worker configurations this metric exists to validate.
    """
    return round(cores / max(1, workers) * 100, 1)


def parse_wrk_output(out):
    """Return usable wrk metrics, or an error that disqualifies the sample."""
    raw = "\n".join(part for part in (out.stdout, out.stderr) if part).strip()
    if out.returncode:
        return None, f"wrk exited {out.returncode}: {raw[-1000:]}"

    socket_errors = 0
    match = re.search(
        r"Socket errors:\s*connect\s+(\d+),\s*read\s+(\d+),"
        r"\s*write\s+(\d+),\s*timeout\s+(\d+)",
        raw,
    )
    if match:
        socket_errors = sum(int(value) for value in match.groups())
    http_match = re.search(r"Non-2xx or 3xx responses:\s*(\d+)", raw)
    http_errors = int(http_match.group(1)) if http_match else 0
    if socket_errors or http_errors:
        return (
            None,
            f"wrk reported {socket_errors} socket errors and {http_errors} HTTP errors",
        )

    rps_match = re.search(r"Requests/sec:\s+([\d.]+)", raw)
    if not rps_match:
        return None, f"wrk output has no Requests/sec: {raw[-1000:]}"
    latency = {
        percentile: value
        for percentile, value in re.findall(
            r"^\s*(50|75|90|99)%\s+(\S+)\s*$", raw, flags=re.MULTILINE
        )
    }
    return {
        "rps": float(rps_match.group(1)),
        "socket_errors": socket_errors,
        "http_errors": http_errors,
        "latency": latency,
    }, None


def check_response(client, url, expected_body):
    out = client.run(
        [
            "curl",
            "-sf",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code} %{size_download}",
            url,
        ],
        timeout=15,
    )
    expected = f"200 {expected_body}"
    if out.returncode or out.stdout.strip() != expected:
        detail = (out.stderr or out.stdout or "no curl output").strip()
        return f"endpoint expected {expected!r}, got {out.stdout.strip()!r}: {detail}"
    return None


def check_nofile(host, required):
    """Refuse shapes the host's per-process descriptor limit cannot sustain."""
    out = host.run(["sh", "-c", "ulimit -n"], timeout=15)
    value = out.stdout.strip()
    if out.returncode or not value:
        detail = (out.stderr or out.stdout or "no output").strip()
        raise RuntimeError(f"cannot read {host.label} RLIMIT_NOFILE: {detail}")
    if value == "unlimited":
        return
    try:
        limit = int(value)
    except ValueError as exc:
        raise RuntimeError(
            f"cannot parse {host.label} RLIMIT_NOFILE value {value!r}"
        ) from exc
    if limit < required:
        raise RuntimeError(
            f"{host.label} RLIMIT_NOFILE is {limit}, but the largest client shape "
            f"needs at least {required}; raise `ulimit -n` before benchmarking"
        )


def prepare_pipeline_script(client, remote_path):
    """Install the versioned wrk script used by depth diagnostics."""
    local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pipeline.lua")
    destination = local_path if client.name == "local" else remote_path
    client.put_file(local_path, destination)
    out = client.run(["test", "-r", destination], timeout=15)
    if out.returncode:
        raise RuntimeError(
            f"pipelining diagnostic script is not readable on {client.label}: "
            f"{destination}"
        )
    return destination


def measure(
    client,
    server,
    handle,
    url,
    shape,
    warmup,
    duration,
    workers,
    expected_body,
    args,
):
    threads, conns, depth = shape
    tail = [str(depth)] if depth > 1 else []
    base = ["wrk", "--latency", "-t", str(threads), "-c", str(conns)]
    sample = {
        "threads": threads,
        "connections": conns,
        "depth": depth,
        "warmup_s": warmup,
        "duration_s": duration,
    }
    response_error = check_response(client, url, expected_body)
    if response_error:
        return {**sample, "error": response_error}
    if warmup:
        warmup_out = client.run(
            base
            + ["-d", f"{warmup}s"]
            + (["-s", args.remote_lua] if depth > 1 else [])
            + [url]
            + (["--"] + tail if depth > 1 else []),
            timeout=warmup + 90,
        )
        _, warmup_error = parse_wrk_output(warmup_out)
        if warmup_error:
            return {**sample, "error": f"warmup failed: {warmup_error}"}
    pids = server.descendants(handle)
    c0 = cpu_seconds(server, pids)
    out = client.run(
        base
        + ["-d", f"{duration}s"]
        + (["-s", args.remote_lua] if depth > 1 else [])
        + [url]
        + (["--"] + tail if depth > 1 else []),
        timeout=duration + 120,
    )
    c1 = cpu_seconds(server, pids)
    metrics, error = parse_wrk_output(out)
    if error:
        return {**sample, "error": error}
    cores = (c1 - c0) / duration
    return {
        **sample,
        **metrics,
        "server_cores": round(cores, 3),
        "server_sat_pct": server_saturation_pct(cores, workers),
    }


# --------------------------------------------------------------------------


class Results:
    """Append-only, flushed per measurement, and resumable."""

    def __init__(self, path, run_id, source):
        self.path = path
        self.run_id = run_id
        self.source_id = source
        self.done = {}
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    # A partial last line means the previous run was killed
                    # mid-write. Everything before it is still good, which is
                    # the point of append-only.
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if (
                        rec.get("run_id") == run_id
                        and rec.get("cell")
                        and rec.get("rps")
                    ):
                        self.done[rec["cell"]] = rec
            print(f"  resuming: {len(self.done)} measurements already recorded")
        # Deliberately long-lived and not a context manager: it is written
        # and fsynced once per measurement across the whole run, so that a
        # run killed at any point keeps everything already measured.
        self.fh = open(path, "a")  # noqa: SIM115

    def has(self, cell):
        return cell in self.done

    def get(self, cell):
        return self.done.get(cell)

    def add(self, cell, cfg, phase, rec):
        row = {
            "cell": cell,
            "run_id": self.run_id,
            "source_id": self.source_id,
            "phase": phase,
            "ts": time.time(),
            **cfg,
            **(rec or {}),
        }
        if row.get("rps"):
            self.done[cell] = row
        self.fh.write(json.dumps(row) + "\n")
        self.fh.flush()
        os.fsync(self.fh.fileno())
        return row


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server-host", default="local")
    p.add_argument("--client-host", default="local")
    p.add_argument("--server-addr", default="127.0.0.1")
    p.add_argument("--server-python", default=sys.executable)
    p.add_argument("--server-script", required=True)
    p.add_argument("--remote-lua", default="/tmp/pipeline.lua")
    p.add_argument("--bodies", default="500")
    p.add_argument("--workers", default="1")
    p.add_argument("--only", default="")
    p.add_argument("--shapes", default="2x32,4x64,4x128")
    p.add_argument("--depths", default="1")
    p.add_argument("--sweep-warmup", type=int, default=2)
    p.add_argument("--sweep-duration", type=int, default=5)
    p.add_argument("--final-warmup", type=int, default=5)
    p.add_argument("--final-duration", type=int, default=30)
    p.add_argument("--trials", type=int, default=3)
    p.add_argument("--start-timeout", type=float, default=60)
    p.add_argument(
        "--diagnostic",
        action="store_true",
        help="also sweep pipelining depth for freastal, reported "
        "under its own phase and never mixed into the table",
    )
    p.add_argument("--out", default="results.ndjson")
    args = p.parse_args()

    def host(spec, label):
        return LocalRunner(label) if spec == "local" else SshRunner(spec, label)

    server = host(args.server_host, "server")
    client = host(args.client_host, "client")
    source = source_id()
    run_id = run_fingerprint(args, source)
    print(f"  run: {run_id}  source: {source}")
    res = Results(args.out, run_id, source)

    cfgs = configs(
        [int(b) for b in args.bodies.split(",")],
        [int(w) for w in args.workers.split(",")],
        [s for s in args.only.split(",") if s] or None,
    )
    base_shapes = [tuple(int(x) for x in s.split("x")) for s in args.shapes.split(",")]
    all_depths = [int(d) for d in args.depths.split(",")]
    if args.diagnostic and any(depth > 1 for depth in all_depths):
        args.remote_lua = prepare_pipeline_script(client, args.remote_lua)
    required_nofile = max(connections for _, connections in base_shapes) + 256
    check_nofile(client, required_nofile)
    check_nofile(server, required_nofile)

    # The comparison sweeps SHAPE only, at a fixed depth, for every server.
    def shapes_for(cfg):
        return [(t, c, COMPARE_DEPTH) for (t, c) in base_shapes]

    diag_cfgs = (
        [
            c
            for c in cfgs
            if c["kind"] in DIAGNOSTIC_KINDS and c["kind"] not in NO_PIPELINING
        ]
        if args.diagnostic
        else []
    )
    total = sum(len(shapes_for(c)) for c in cfgs)
    print(
        f"  comparison: every server at depth {COMPARE_DEPTH} "
        f"({len(cfgs)} configs, {total} shape measurements, {args.trials} trials)"
    )
    if diag_cfgs:
        print(
            f"  diagnostic: depth sweep {all_depths} for "
            f"{len(diag_cfgs)} freastal configs, reported separately"
        )

    # ---- phase 1: per-config shape sweep -------------------------------
    best = {}
    for cfg in cfgs:
        handle = url = None
        try:
            handle, url = start_server(server, cfg, args)
            for shape in shapes_for(cfg):
                cell = cell_id(cfg, "sweep", shape)
                if res.has(cell):
                    rec = res.get(cell)
                else:
                    rec = measure(
                        client,
                        server,
                        handle,
                        url,
                        shape,
                        args.sweep_warmup,
                        args.sweep_duration,
                        cfg["workers"],
                        cfg["body"],
                        args,
                    )
                    rec = res.add(cell, cfg, "sweep", rec)
                if rec.get("rps") and (
                    cfg["port"] not in best or rec["rps"] > best[cfg["port"]][0]
                ):
                    best[cfg["port"]] = (rec["rps"], shape)
        except Exception as exc:  # noqa: BLE001 - one config must not end the run
            print(f"  !! {cfg['kind']} w{cfg['workers']}: {exc}")
        finally:
            if handle:
                server.stop(handle)
        if cfg["port"] in best:
            r, sh = best[cfg["port"]]
            print(
                f"  sweep {cfg['kind']:<17} w{cfg['workers']} b{cfg['body']:<6} "
                f"-> -t{sh[0]} -c{sh[1]} d{sh[2]}  {r:>10,.0f} rps"
            )

    # ---- phase 2: interleaved trials at each argmax ---------------------
    for trial in range(args.trials):
        for cfg in cfgs:
            if cfg["port"] not in best:
                continue
            shape = best[cfg["port"]][1]
            cell = cell_id(cfg, "final", shape, trial)
            if res.has(cell):
                continue
            handle = None
            try:
                handle, url = start_server(server, cfg, args)
                rec = measure(
                    client,
                    server,
                    handle,
                    url,
                    shape,
                    args.final_warmup,
                    args.final_duration,
                    cfg["workers"],
                    cfg["body"],
                    args,
                )
                row = res.add(cell, cfg, "final", rec)
                print(
                    f"  trial {trial} {cfg['kind']:<17} w{cfg['workers']} "
                    f"{row.get('rps', 0):>10,.0f} rps  sat {row.get('server_sat_pct', 0):>5.1f}%"
                )
            except Exception as exc:  # noqa: BLE001
                print(f"  !! trial {trial} {cfg['kind']}: {exc}")
            finally:
                if handle:
                    server.stop(handle)

    # ---- phase 3: pipelining diagnostic, freastal only -------------------
    #
    # Deliberately after the comparison and recorded under its own phase, so
    # nothing here can end up in a row next to a server measured at depth 1.
    #
    # Shape and depth are swept together rather than fixing shape at the
    # comparison's argmax. They interact: the concurrency that suits depth 1
    # is not the one that suits depth 64, because pipelining moves the
    # bottleneck off the round trip. This is diagnostic-only, so the cross
    # product is affordable here in a way it is not for the comparison.
    for cfg in diag_cfgs:
        handle = None
        try:
            handle, url = start_server(server, cfg, args)
            for t, c in base_shapes:
                for d in all_depths:
                    dshape = (t, c, d)
                    cell = cell_id(cfg, "diagnostic", dshape)
                    if res.has(cell):
                        continue
                    rec = measure(
                        client,
                        server,
                        handle,
                        url,
                        dshape,
                        args.sweep_warmup,
                        args.sweep_duration,
                        cfg["workers"],
                        cfg["body"],
                        args,
                    )
                    row = res.add(cell, cfg, "diagnostic", rec)
                    print(
                        f"  diag  {cfg['kind']:<17} w{cfg['workers']} "
                        f"-t{t} -c{c} d{d:<3} {row.get('rps', 0):>10,.0f} rps"
                    )
        except Exception as exc:  # noqa: BLE001
            print(f"  !! diagnostic {cfg['kind']}: {exc}")
        finally:
            if handle:
                server.stop(handle)

    # ---- summary --------------------------------------------------------
    if diag_cfgs:
        print(
            "\n  pipelining diagnostic (NOT comparable to the table above:"
            " each server at its own best shape AND depth):"
        )
        for cfg in diag_cfgs:
            rows = [
                r
                for r in res.done.values()
                if r.get("phase") == "diagnostic"
                and r.get("port") == cfg["port"]
                and r.get("rps")
            ]
            if not rows:
                continue
            top = max(rows, key=lambda r: r["rps"])
            base = min(
                (r for r in rows if r["depth"] == 1),
                key=lambda r: -r["rps"],
                default=None,
            )
            gain = f"  ({top['rps'] / base['rps']:.2f}x depth 1)" if base else ""
            print(
                f"    {cfg['kind']:<17} w{cfg['workers']} best "
                f"-t{top['threads']} -c{top['connections']} d{top['depth']} "
                f"{top['rps']:>10,.0f} rps{gain}"
            )

    print(f"\n  comparison (all servers at depth {COMPARE_DEPTH}):")
    for cfg in cfgs:
        rows = [
            r
            for r in res.done.values()
            if r.get("phase") == "final"
            and r.get("port") == cfg["port"]
            and r.get("rps")
        ]
        if not rows:
            continue
        rps = [r["rps"] for r in rows]
        med = statistics.median(rps)
        spread = (max(rps) - min(rps)) / med * 100 if len(rps) > 1 else 0.0
        sat = statistics.median(r["server_sat_pct"] for r in rows)
        flag = (
            ""
            if sat >= SATURATED_PCT
            else "   <- server not saturated, not a capacity number"
        )
        print(
            f"    {cfg['kind']:<17} w{cfg['workers']} b{cfg['body']:<6} "
            f"{med:>10,.0f} rps  spread {spread:>4.1f}%  sat {sat:>5.1f}%{flag}"
        )


if __name__ == "__main__":
    main()
