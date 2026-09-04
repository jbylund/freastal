#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "server.h"
#include "wsgi.h"
#include "asgi.h"
#include "tls.h"
#include <unistd.h>

/*
 * server_init() plus the one piece of descriptor bookkeeping both entry points
 * share.
 *
 * ticket_ring_fd is consumed here on every path, success or failure.  A worker
 * keeps only the mapping tls_server_init() made: the mapping is what holds the
 * shared region open, so a retained descriptor would buy nothing except one
 * more handle on key material -- and would keep the region alive after a
 * worker had deliberately dropped it (tls_ticket_ring_detach in tls.c).
 */
static int serve_init(PyObject *app, const char *host, int port, int reuse_port,
                      const char *certfile, const char *keyfile, int fd,
                      int ticket_ring_fd) {
    int rc = server_init(app, host, port, (bool)reuse_port, certfile, keyfile,
                         fd, ticket_ring_fd);
    if (ticket_ring_fd >= 0)
        close(ticket_ring_fd);
    if (rc < 0 && !PyErr_Occurred())
        PyErr_SetString(PyExc_RuntimeError, "freastal: server_init failed");
    return rc;
}

/* ---- freastal.serve(app, host='0.0.0.0', port=8000, reuse_port=False) ---- */

static PyObject *py_serve(PyObject *self, PyObject *args, PyObject *kwargs) {
    (void)self;
    static const char *kwlist[] = {
        "app", "host", "port", "reuse_port", "certfile", "keyfile", "fd",
        "ticket_ring_fd", NULL
    };
    PyObject   *app      = NULL;
    const char *host     = "0.0.0.0";
    int         port     = 8000;
    int         reuse_p  = 0;
    const char *certfile = NULL;
    const char *keyfile  = NULL;
    int         fd       = -1;
    int         ring_fd  = -1;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|sipzzii",
            (char **)kwlist, &app, &host, &port, &reuse_p, &certfile, &keyfile,
            &fd, &ring_fd))
        return NULL;

    if (!PyCallable_Check(app)) {
        PyErr_SetString(PyExc_TypeError, "app must be callable");
        return NULL;
    }

    if (serve_init(app, host, port, reuse_p, certfile, keyfile, fd, ring_fd) < 0)
        return NULL;

    server_run();

    Py_RETURN_NONE;
}

/* ---- freastal.serve_asgi(app, loop, host, port, reuse_port) ---- */

static PyObject *py_serve_asgi(PyObject *self, PyObject *args, PyObject *kwargs) {
    (void)self;
    static const char *kwlist[] = {
        "app", "loop", "host", "port", "reuse_port", "certfile", "keyfile",
        "fd", "ticket_ring_fd", NULL
    };
    PyObject   *app      = NULL;
    PyObject   *loop     = NULL;
    const char *host     = "0.0.0.0";
    int         port     = 8000;
    int         reuse_p  = 0;
    const char *certfile = NULL;
    const char *keyfile  = NULL;
    int         fd       = -1;
    int         ring_fd  = -1;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|sipzzii",
            (char **)kwlist, &app, &loop, &host, &port, &reuse_p,
            &certfile, &keyfile, &fd, &ring_fd))
        return NULL;

    if (!PyCallable_Check(app)) {
        PyErr_SetString(PyExc_TypeError, "app must be callable");
        return NULL;
    }

    if (serve_init(app, host, port, reuse_p, certfile, keyfile, fd, ring_fd) < 0)
        return NULL;

    if (asgi_server_init(loop) < 0) {
        if (!PyErr_Occurred())
            PyErr_SetString(PyExc_RuntimeError, "freastal: asgi_server_init failed");
        return NULL;
    }

    server_run();
    Py_RETURN_NONE;
}

/* ---- freastal.tls_buffer_stats() ---- */

/*
 * The TLS write path's two invariants -- every encryption buffer is released
 * exactly once, and a steady stream of same-size responses allocates nothing
 * -- are invisible from the wire and would not show up in a short test run.
 * Exposing the counters lets the test suite assert them directly instead.
 *
 * The read path's invariant is invisible in the same way and is here for the
 * same reason: a request within read_zerocopy_max is decrypted straight into
 * read_buf, so read_grows must not move.  A response is identical either way,
 * which is exactly why the counter is the only thing that can tell them apart.
 *
 * Must be called from the loop thread (i.e. from inside the app callback),
 * which is the only thread that touches these.
 */
static PyObject *py_tls_buffer_stats(PyObject *self, PyObject *args) {
    (void)self; (void)args;
#ifdef FREASTAL_TLS
    return Py_BuildValue(
        "{s:k,s:k,s:k,s:i,s:k,s:k,s:i}",
        "blocks_live",       g_server.tls_wbuf_live,
        "bigbufs_live",      g_server.tls_bigbuf_live,
        "mallocs",           g_server.tls_wbuf_mallocs,
        "pool_free",         g_server.tls_wbuf_pool_n,
        "read_grows",        g_server.tls_read_grows,
        "read_spills",       g_server.tls_read_spills,
        "read_zerocopy_max", (int)TLS_READ_ZEROCOPY_MAX
    );
#else
    Py_RETURN_NONE;
#endif
}


/* ---- freastal.reuse_port_supported() ---- */

static PyObject *py_reuse_port_supported(PyObject *self, PyObject *args) {
    (void)self; (void)args;
    return PyBool_FromLong(server_reuseport_supported());
}

#ifdef FREASTAL_TLS
/* ---- freastal._rotate_ticket_key() ---- */

static PyObject *py_rotate_ticket_key(PyObject *self, PyObject *args) {
    (void)self; (void)args;
    /* Deliberately no g_server.tls_enabled check up front any more: the
     * process that owns a shared ring is the one that called serve(), and it
     * never runs server_init() at all, so it has no g_server to be enabled.
     * tls_ticket_rotate_hook() applies the check on the path where it still
     * means something. */
    if (tls_ticket_rotate_hook() < 0)
        return NULL;
    Py_RETURN_NONE;
}

/* ---- freastal._ticket_ring_create() / _rotate() / _destroy() ---- */

static PyObject *py_ticket_ring_create(PyObject *self, PyObject *args) {
    (void)self; (void)args;
    int ro_fd = -1;
    if (tls_ticket_ring_create(&ro_fd) < 0)
        return NULL;
    return PyLong_FromLong(ro_fd);
}

static PyObject *py_ticket_ring_rotate(PyObject *self, PyObject *args) {
    (void)self; (void)args;
    if (tls_ticket_ring_rotate_owned() < 0)
        return NULL;
    Py_RETURN_NONE;
}

static PyObject *py_ticket_ring_destroy(PyObject *self, PyObject *args) {
    (void)self; (void)args;
    tls_ticket_ring_destroy();
    Py_RETURN_NONE;
}
#endif

static PyMethodDef freastal_methods[] = {
#ifdef FREASTAL_TLS
    {
        "_ticket_ring_create",
        py_ticket_ring_create,
        METH_NOARGS,
        "_ticket_ring_create() -> int\n\n"
        "Internal: create the shared session-ticket key ring and return a\n"
        "READ-ONLY descriptor for it, to hand to each worker as serve()'s\n"
        "ticket_ring_fd. Called in the process that owns the ring -- the one\n"
        "that calls serve() with workers > 1 -- which is also the only process\n"
        "that may write to it. The caller owns the returned descriptor.",
    },
    {
        "_ticket_ring_rotate",
        py_ticket_ring_rotate,
        METH_NOARGS,
        "_ticket_ring_rotate()\n\n"
        "Internal: advance the shared ring this process owns by one step, and\n"
        "publish it to every worker. Raises if this process owns no ring.",
    },
    {
        "_ticket_ring_destroy",
        py_ticket_ring_destroy,
        METH_NOARGS,
        "_ticket_ring_destroy()\n\n"
        "Internal: zeroize, unmap and close the shared ring this process owns.\n"
        "The zeroize writes through to the single physical page every worker\n"
        "has mapped, so the keys are destroyed in all of them at once.\n"
        "Idempotent, and a no-op when this process owns no ring.",
    },
    {
        "_rotate_ticket_key",
        py_rotate_ticket_key,
        METH_NOARGS,
        "_rotate_ticket_key()\n\n"
        "Advance the ticket key ring THIS process is using one step, as the\n"
        "hourly timer would, and do not return until this process can see the\n"
        "result. Test hook: the ring's contract -- a retired key still opens\n"
        "tickets until the lifetime constraint says it cannot -- is not\n"
        "otherwise reachable without an hour of wall clock. Rotating early is\n"
        "always safe, so this is harmless if called in anger.\n\n"
        "With workers > 1 the ring is shared and owned by the process that\n"
        "called serve(), so a worker cannot rotate it: this asks that process\n"
        "to (SIGUSR1) and waits for the new key to appear through the shared\n"
        "mapping. So it still means one rotation of the ring the next\n"
        "connection is sealed under -- and it now goes through the real\n"
        "lockstep path rather than around it.",
    },
#endif
    {
        "reuse_port_supported",
        py_reuse_port_supported,
        METH_NOARGS,
        "reuse_port_supported()\n\n"
        "True if libuv on THIS machine will honour UV_TCP_REUSEPORT, probed by\n"
        "attempting the bind rather than inferred from the platform name or\n"
        "from what setup.py saw at build time.",
    },
    {
        "tls_buffer_stats",
        py_tls_buffer_stats,
        METH_NOARGS,
        "tls_buffer_stats()\n\n"
        "Internal: counters for the TLS buffer paths.  Returns a dict with\n"
        "blocks_live, bigbufs_live, mallocs and pool_free for the write side,\n"
        "read_grows, read_spills and read_zerocopy_max for the read side, or\n"
        "None if the extension was built without TLS.  Call from inside the\n"
        "app callback."
    },
    {
        "serve",
        (PyCFunction)(void(*)(void))py_serve,
        METH_VARARGS | METH_KEYWORDS,
        "serve(app, host='0.0.0.0', port=8000, reuse_port=False, certfile=None,\n"
        "      keyfile=None, fd=-1)\n\n"
        "Run a WSGI app under the freastal server.\n"
        "fd, if >= 0, is an already-bound listening socket to serve on instead\n"
        "of binding host:port; host and port are still used for the environ.\n"
        "Pass certfile and keyfile (PEM paths) to enable TLS 1.3 (requires picotls).\n"
        "Blocks until the event loop exits (e.g. SIGINT)."
    },
    {
        "serve_asgi",
        (PyCFunction)(void(*)(void))py_serve_asgi,
        METH_VARARGS | METH_KEYWORDS,
        "serve_asgi(app, loop, host='0.0.0.0', port=8000, reuse_port=False,\n"
        "           certfile=None, keyfile=None, fd=-1)\n\n"
        "Run an ASGI app under the freastal server.\n"
        "fd, if >= 0, is an already-bound listening socket to serve on instead\n"
        "of binding host:port; host and port are still used for the environ.\n"
        "Pass certfile and keyfile (PEM paths) to enable TLS 1.3 (requires picotls).\n"
        "loop must be a running asyncio event loop.\n"
        "Blocks until the event loop exits."
    },
    {
        "asgi_send_response",
        asgi_send_response_c,
        METH_VARARGS,
        "asgi_send_response(capsule, status, headers, body)\n\n"
        "Internal: called from _asgi_protocol.py to send the HTTP response."
    },
    {
        "asgi_coro_step",
        (PyCFunction)(void(*)(void))asgi_coro_step_c,
        METH_FASTCALL,
        "asgi_coro_step(coro[, context])\n\n"
        "Internal: send(None) into an ASGI app's coroutine, running the step\n"
        "inside `context` if one is given.  Returns what the coroutine yielded,\n"
        "or ASGI_CORO_DONE if it returned instead of suspending."
    },
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef freastal_module = {
    PyModuleDef_HEAD_INIT,
    "_freastal",
    "freastal C extension – libuv + picohttpparser WSGI server",
    -1,
    freastal_methods,
    NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit__freastal(void) {
    PyObject *m = PyModule_Create(&freastal_module);
    if (!m) return NULL;

    if (wsgi_init(m) < 0 || asgi_init(m) < 0) {
        Py_DECREF(m);
        return NULL;
    }

    /* Whether this build can pass UV_TCP_REUSEPORT to uv_tcp_bind at all.
     * Without it the C layer used to drop a reuse_port=True request on the
     * floor; exporting the flag lets serve() refuse instead of pretending. */
    /* Which libuv this is actually linked against. UV_TCP_REUSEPORT arrived in
     * 1.49.0, and whether it is present changes how workers>1 binds -- so when
     * someone reports "multi-worker is slow", this is the first thing to ask
     * for, and a build log is usually long gone by then. */
    PyModule_AddStringConstant(m, "libuv_version", uv_version_string());

#ifdef FREASTAL_REUSEPORT
    /* Retained only to say whether the *flag exists* in the uv.h this was
     * compiled against. Whether it will be honoured is a runtime question and
     * is answered by reuse_port_supported(); a wheel built on one machine runs
     * on another, and macOS compiles the enum then fails every REUSEPORT bind
     * with ENOTSUP. Callers want the function, not this. */
    PyModule_AddIntConstant(m, "HAS_REUSE_PORT", 1);
#else
    PyModule_AddIntConstant(m, "HAS_REUSE_PORT", 0);
#endif

    PyModule_AddStringConstant(m, "__version__", "0.0.1");

#ifdef FREASTAL_TLS
    /* The ring's three numbers, so freastal/__init__.py can time the owner's
     * rotation thread off the same constant the C code rotates on rather than
     * a second copy that could drift from it, and so a test can assert the
     * constraint in server.h instead of re-deriving it. */
    PyModule_AddIntConstant(m, "TICKET_ROTATE_MS", (long)TLS_TICKET_ROTATE_MS);
    PyModule_AddIntConstant(m, "TICKET_LIFETIME_S", (long)TLS_TICKET_LIFETIME_S);
    PyModule_AddIntConstant(m, "TICKET_RING_SLOTS", (long)TLS_TICKET_RING);
#endif

    /* Whether picotls was compiled in.  This is a build-time fact, but it has
     * to be readable at runtime: without it a caller cannot tell a TLS build
     * from one that would quietly serve their certfile's port in plaintext,
     * and neither can a test. */
#ifdef FREASTAL_TLS
    if (PyModule_AddIntConstant(m, "has_tls", 1) < 0) { Py_DECREF(m); return NULL; }
#else
    if (PyModule_AddIntConstant(m, "has_tls", 0) < 0) { Py_DECREF(m); return NULL; }
#endif
    return m;
}
