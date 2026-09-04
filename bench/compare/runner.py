"""Where a command runs, so the orchestration can be tested without a network.

The two-host benchmark is mostly orchestration -- bring a server up over there,
drive it from over here, tear it down, do not lose the results if something
dies halfway. That machinery is where the bugs are, and none of it needs two
hosts to exercise. So the transport is a seam: LocalRunner for developing and
verifying, SshRunner for the real run, same code path either way.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess


class LocalRunner:
    name = "local"

    def __init__(self, label="local"):
        self.label = label

    def run(self, argv, timeout=60, check=False):
        return subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=check
        )

    def start(self, argv, env=None):
        """Start a long-lived process; returns a handle usable with stop()."""
        e = dict(os.environ, **(env or {}))
        p = subprocess.Popen(
            argv,
            env=e,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return {"kind": "local", "pid": p.pid, "proc": p}

    def stop(self, handle):
        """TERM the group, then KILL what is left.

        The group, not the process: under spawn a worker's cmdline is the
        multiprocessing bootstrap, so killing by pid or by name leaves the
        workers alive holding the port -- which then poisons the next
        measurement with a stale server on a reused port.

        ProcessLookupError means it exited on its own, which is the outcome
        being asked for; anything else is a real failure and should surface.
        """
        p = handle["proc"]
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            p.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Nothing further to try; say so rather than returning as if the
            # process were gone, because the caller is about to reuse the port.
            raise RuntimeError(
                f"server pid {p.pid} survived SIGKILL; the next measurement "
                f"would run against a stale process on a reused port"
            ) from None

    def descendants(self, handle):
        """Every pid under the handle, so CPU covers workers not just the parent."""
        seen, frontier = [handle["pid"]], [handle["pid"]]
        while frontier:
            nxt = []
            for p in frontier:
                out = self.run(["pgrep", "-P", str(p)]).stdout.split()
                for c in out:
                    c = int(c)
                    if c not in seen:
                        seen.append(c)
                        nxt.append(c)
            frontier = nxt
        return seen


class SshRunner:
    """The same interface, over ssh. Deliberately thin: no persistent shell, so
    a dropped connection fails one command rather than corrupting a run."""

    name = "ssh"

    def __init__(self, host, label=None, python="python3"):
        self.host = host
        self.label = label or host
        self.python = python

    def _ssh(self, remote_cmd):
        return [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            self.host,
            remote_cmd,
        ]

    def run(self, argv, timeout=60, check=False):
        cmd = argv if isinstance(argv, str) else shlex.join(argv)
        return subprocess.run(
            self._ssh(cmd), capture_output=True, text=True, timeout=timeout, check=check
        )

    def start(self, argv, env=None):
        """Start detached on the remote and return its pid.

        setsid so the whole worker tree is one process group -- the same reason
        harness.py records a pgid: killing by name cannot see multiprocessing's
        spawned children, whose cmdline is the bootstrap rather than the script.
        """
        envs = " ".join(f"{k}={shlex.quote(str(v))}" for k, v in (env or {}).items())
        cmd = shlex.join(argv) if not isinstance(argv, str) else argv
        remote = f"{envs} setsid nohup {cmd} >/dev/null 2>&1 & echo $!"
        out = self.run(remote, timeout=30)
        pid = out.stdout.strip().splitlines()[-1] if out.stdout.strip() else ""
        if not pid.isdigit():
            raise RuntimeError(f"could not start on {self.host}: {out.stderr[-400:]}")
        return {"kind": "ssh", "pid": int(pid)}

    def stop(self, handle):
        pid = handle["pid"]
        self.run(
            f"kill -TERM -{pid} 2>/dev/null; sleep 1; kill -KILL -{pid} 2>/dev/null; true",
            timeout=30,
        )

    def descendants(self, handle):
        pid = handle["pid"]
        script = (
            f"p={pid}; all=$p; frontier=$p; "
            'while [ -n "$frontier" ]; do '
            "  next=$(pgrep -P $(echo $frontier | tr ' ' ',') 2>/dev/null | tr '\\n' ' '); "
            "  new=''; for c in $next; do "
            '    case " $all " in *" $c "*) ;; *) all="$all $c"; new="$new $c";; esac; '
            "  done; frontier=$new; done; echo $all"
        )
        out = self.run(script, timeout=30)
        return [int(x) for x in out.stdout.split() if x.isdigit()]
