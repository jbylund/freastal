#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "server.h"
#include "wsgi.h"
#include "asgi.h"

/* ---- freastal.serve(app, host='0.0.0.0', port=8000, reuse_port=True) ---- */

static PyObject *py_serve(PyObject *self, PyObject *args, PyObject *kwargs) {
    (void)self;
    static const char *kwlist[] = {
        "app", "host", "port", "reuse_port", "certfile", "keyfile", NULL
    };
    PyObject   *app      = NULL;
    const char *host     = "0.0.0.0";
    int         port     = 8000;
    int         reuse_p  = 1;
    const char *certfile = NULL;
    const char *keyfile  = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|sipzz",
            (char **)kwlist, &app, &host, &port, &reuse_p, &certfile, &keyfile))
        return NULL;

    if (!PyCallable_Check(app)) {
        PyErr_SetString(PyExc_TypeError, "app must be callable");
        return NULL;
    }

    if (server_init(app, host, port, (bool)reuse_p, certfile, keyfile) < 0) {
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
        "app", "loop", "host", "port", "reuse_port", NULL
    };
    PyObject   *app     = NULL;
    PyObject   *loop    = NULL;
    const char *host    = "0.0.0.0";
    int         port    = 8000;
    int         reuse_p = 1;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|sip",
            (char **)kwlist, &app, &loop, &host, &port, &reuse_p))
        return NULL;

    if (!PyCallable_Check(app)) {
        PyErr_SetString(PyExc_TypeError, "app must be callable");
        return NULL;
    }

    if (server_init(app, host, port, (bool)reuse_p, NULL, NULL) < 0) {
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

static PyMethodDef freastal_methods[] = {
    {
        "serve",
        (PyCFunction)(void(*)(void))py_serve,
        METH_VARARGS | METH_KEYWORDS,
        "serve(app, host='0.0.0.0', port=8000, reuse_port=True, certfile=None, keyfile=None)\n\n"
        "Run a WSGI app under the freastal server.\n"
        "Pass certfile and keyfile (PEM paths) to enable TLS 1.3 (requires picotls).\n"
        "Blocks until the event loop exits (e.g. SIGINT)."
    },
    {
        "serve_asgi",
        (PyCFunction)(void(*)(void))py_serve_asgi,
        METH_VARARGS | METH_KEYWORDS,
        "serve_asgi(app, loop, host='0.0.0.0', port=8000, reuse_port=True)\n\n"
        "Run an ASGI app under the freastal server.\n"
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

    if (wsgi_init(m) < 0) {
        Py_DECREF(m);
        return NULL;
    }

    PyModule_AddStringConstant(m, "__version__", "0.0.1");
    return m;
}
