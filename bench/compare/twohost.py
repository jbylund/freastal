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
import json
import os
import re
import statistics
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
# differently -- it is a capability they either have or do not, measured here:
# freastal gains ~16%, gunicorn+uvicorn is flat across depths 1-16, and bjoern
# collapses 470x because it reads one request per read. Letting each server run
# at its own best depth would therefore rank pipelining support and print it in
# the shape of a throughput number.
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
# Measured, not assumed: bjoern serves 9,823 rps at depth 1 and 21 rps at depth
# 4 -- a 470x collapse, because it reads one request per read and the rest of
# the batch sits until a timeout. Sweeping depth for it would spend most of the
# run measuring that timeout, and any depth>1 row would report "bjoern does not
# implement pipelining" in the shape of a throughput number.
#
# For the record, the other two are not worth sweeping for the same reason in
# reverse: gunicorn+uvicorn measured flat across depths 1-16, and only freastal
# gains from it (+16%). Which is why a pipelined row belongs in a diagnostic
# rather than in a comparison table.
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


def measure(client, server, handle, url, shape, warmup, duration, args):
    threads, conns, depth = shape
    tail = [str(depth)] if depth > 1 else []
    base = ["wrk", "-t", str(threads), "-c", str(conns)]
    if warmup:
        client.run(
            base
            + ["-d", f"{warmup}s"]
            + (["-s", args.remote_lua] if depth > 1 else [])
            + [url]
            + (["--"] + tail if depth > 1 else []),
            timeout=warmup + 90,
        )
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
    m = re.search(r"Requests/sec:\s+([\d.]+)", out.stdout)
    if not m:
        return None
    cores = (c1 - c0) / duration
    return {
        "rps": float(m.group(1)),
        "server_cores": round(cores, 3),
        "server_sat_pct": round(cores / max(1, len(pids) - 1) * 100, 1)
        if len(pids) > 1
        else round(cores * 100, 1),
        "threads": threads,
        "connections": conns,
        "depth": depth,
        "warmup_s": warmup,
        "duration_s": duration,
    }


# --------------------------------------------------------------------------


class Results:
    """Append-only, flushed per measurement, and resumable."""

    def __init__(self, path):
        self.path = path
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
                    if "cell" in rec:
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
        row = {"cell": cell, "phase": phase, "ts": time.time(), **cfg, **(rec or {})}
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
    res = Results(args.out)

    cfgs = configs(
        [int(b) for b in args.bodies.split(",")],
        [int(w) for w in args.workers.split(",")],
        [s for s in args.only.split(",") if s] or None,
    )
    base_shapes = [tuple(int(x) for x in s.split("x")) for s in args.shapes.split(",")]
    all_depths = [int(d) for d in args.depths.split(",")]

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
    # bottleneck off the round trip. Measured over WiFi, -c512 d1 gave 55,904
    # rps while -c512 d64 gave 145,390 -- and a diagnostic pinned to the depth-1
    # shape would have reported whichever depth happened to suit it. This is
    # freastal-only, so the cross product is affordable here in a way it is not
    # for the comparison.
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
