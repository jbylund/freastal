#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "server.h"
#include "wsgi.h"
#include "asgi.h"

/* ---- freastal.serve(app, host='0.0.0.0', port=8000, reuse_port=False) ---- */

static PyObject *py_serve(PyObject *self, PyObject *args, PyObject *kwargs) {
    (void)self;
    static const char *kwlist[] = {
        "app", "host", "port", "reuse_port", "certfile", "keyfile", "fd", NULL
    };
    PyObject   *app      = NULL;
    const char *host     = "0.0.0.0";
    int         port     = 8000;
    int         reuse_p  = 0;
    const char *certfile = NULL;
    const char *keyfile  = NULL;
    int         fd       = -1;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|sipzzi",
            (char **)kwlist, &app, &host, &port, &reuse_p, &certfile, &keyfile, &fd))
        return NULL;

    if (!PyCallable_Check(app)) {
        PyErr_SetString(PyExc_TypeError, "app must be callable");
        return NULL;
    }

    if (server_init(app, host, port, (bool)reuse_p, certfile, keyfile, fd) < 0) {
        if (!PyErr_Occurred())
            PyErr_SetString(PyExc_RuntimeError, "freastal: server_init failed");
        return NULL;
    }

    server_run();

    Py_RETURN_NONE;
}

/* ---- freastal.serve_asgi(app, loop, host, port, reuse_port) ---- */

static PyObject *py_serve_asgi(PyObject *self, PyObject *args, PyObject *kwargs) {
    (void)self;
    static const char *kwlist[] = {
        "app", "loop", "host", "port", "reuse_port", "certfile", "keyfile",
        "fd", NULL
    };
    PyObject   *app      = NULL;
    PyObject   *loop     = NULL;
    const char *host     = "0.0.0.0";
    int         port     = 8000;
    int         reuse_p  = 0;
    const char *certfile = NULL;
    const char *keyfile  = NULL;
    int         fd       = -1;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|sipzzi",
            (char **)kwlist, &app, &loop, &host, &port, &reuse_p,
            &certfile, &keyfile, &fd))
        return NULL;

    if (!PyCallable_Check(app)) {
        PyErr_SetString(PyExc_TypeError, "app must be callable");
        return NULL;
    }

    if (server_init(app, host, port, (bool)reuse_p, certfile, keyfile, fd) < 0) {
        if (!PyErr_Occurred())
            PyErr_SetString(PyExc_RuntimeError, "freastal: server_init failed");
        return NULL;
    }

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

static PyMethodDef freastal_methods[] = {
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
#ifdef FREASTAL_REUSEPORT
    PyModule_AddIntConstant(m, "HAS_REUSE_PORT", 1);
#else
    PyModule_AddIntConstant(m, "HAS_REUSE_PORT", 0);
#endif

    PyModule_AddStringConstant(m, "__version__", "0.0.1");

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
