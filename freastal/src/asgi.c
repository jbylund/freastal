#include "server.h"
#include "asgi.h"
#include <arpa/inet.h>
#include <string.h>

/* ---- libuv callbacks ---- */

/*
 * asgi_check_cb – fires after each libuv I/O poll.
 *
 * Only steps asyncio when it has work to do (loop._ready non-empty).
 * This guarantees loop._run_once() always uses timeout=0 internally,
 * never blocking the libuv thread.
 */
/* Bracket _run_once() with asyncio._set_running_loop() so Python 3.14's
 * context.run() finds the expected running-loop thread-local while stepping tasks. */
static inline void set_running_loop(PyObject *loop) {
    if (g_server.asyncio_set_running_loop) {
        PyObject *r = PyObject_CallOneArg(g_server.asyncio_set_running_loop, loop);
        Py_XDECREF(r);
        if (PyErr_Occurred()) PyErr_Clear();
    }
}

static void asgi_check_cb(uv_check_t *handle) {
    (void)handle;
    GIL_LOCK();
    PyObject *ready = PyObject_GetAttrString(g_server.asgi_loop, "_ready");
    bool has_work = (ready != NULL && PyObject_IsTrue(ready) > 0);
    Py_XDECREF(ready);
    if (has_work) {
        set_running_loop(g_server.asgi_loop);
        PyObject *ret = PyObject_CallNoArgs(g_server.asgi_run_once);
        Py_XDECREF(ret);
        if (PyErr_Occurred()) PyErr_Clear();
        set_running_loop(Py_None);
    }
    GIL_UNLOCK();
}

/*
 * asgi_poll_cb – fires when asyncio's selector fd is readable.
 *
 * This happens when external async I/O completes (e.g. an awaited DB query
 * or outbound HTTP response arrives).  Calling _run_once() here processes
 * those I/O events and resumes waiting coroutines.  epoll_wait inside
 * _run_once() returns immediately because the fd is readable, so no blocking.
 */
static void asgi_poll_cb(uv_poll_t *handle, int status, int events) {
    (void)handle; (void)events;
    if (status < 0) return;
    GIL_LOCK();
    set_running_loop(g_server.asgi_loop);
    PyObject *ret = PyObject_CallNoArgs(g_server.asgi_run_once);
    Py_XDECREF(ret);
    if (PyErr_Occurred()) PyErr_Clear();
    set_running_loop(Py_None);
    GIL_UNLOCK();
}

/* ---- ASGI scope builder ---- */

static PyObject *build_asgi_scope(client_t *c) {
    PyObject *scope = PyDict_New();
    if (!scope) return NULL;

#define SS(k, v) do { \
    if (PyDict_SetItemString(scope, k, (v)) < 0) { Py_DECREF(scope); return NULL; } \
} while (0)

#define SSN(k, expr) do { \
    PyObject *_v = (expr); \
    if (!_v || PyDict_SetItemString(scope, k, _v) < 0) \
        { Py_XDECREF(_v); Py_DECREF(scope); return NULL; } \
    Py_DECREF(_v); \
} while (0)

    SS("type",         g_server.asgi_type_http);
    SS("asgi",         g_server.asgi_version_dict);
    SS("root_path",    g_server.asgi_empty_str);
    SS("scheme",       g_server.asgi_scheme_http);
    SS("server",       g_server.asgi_server_tuple);
    SS("http_version", c->minor_version == 1 ? g_server.asgi_http_11
                                              : g_server.asgi_http_10);

    SSN("method", PyUnicode_FromStringAndSize(c->method, (Py_ssize_t)c->method_len));

    /* path / raw_path / query_string */
    {
        const char *qmark = (const char *)memchr(c->path, '?', c->path_len);
        if (qmark) {
            Py_ssize_t plen = (Py_ssize_t)(qmark - c->path);
            Py_ssize_t qlen = (Py_ssize_t)(c->path_len - (size_t)(qmark + 1 - c->path));
            SSN("path",         PyUnicode_FromStringAndSize(c->path, plen));
            SSN("raw_path",     PyBytes_FromStringAndSize(c->path, plen));
            SSN("query_string", PyBytes_FromStringAndSize(qmark + 1, qlen));
        } else {
            SSN("path",     PyUnicode_FromStringAndSize(c->path, (Py_ssize_t)c->path_len));
            SSN("raw_path", PyBytes_FromStringAndSize(c->path, (Py_ssize_t)c->path_len));
            SS("query_string", g_server.asgi_empty_bytes);
        }
    }

    /* client: (peer_ip, peer_port) */
    {
        PyObject *ip   = PyUnicode_FromString(c->peer_addr);
        PyObject *port = PyLong_FromLong((long)c->peer_port);
        PyObject *tup  = (ip && port) ? PyTuple_Pack(2, ip, port) : NULL;
        Py_XDECREF(ip); Py_XDECREF(port);
        if (!tup) { Py_DECREF(scope); return NULL; }
        int rc = PyDict_SetItemString(scope, "client", tup);
        Py_DECREF(tup);
        if (rc < 0) { Py_DECREF(scope); return NULL; }
    }

    /* headers: list of (name_bytes_lower, value_bytes) */
    {
        PyObject *hlist = PyList_New((Py_ssize_t)c->num_headers);
        if (!hlist) { Py_DECREF(scope); return NULL; }
        for (size_t i = 0; i < c->num_headers; i++) {
            const char *hn  = c->headers[i].name;
            size_t      hnl = c->headers[i].name_len;
            const char *hv  = c->headers[i].value;
            size_t      hvl = c->headers[i].value_len;

            /* lowercase name in a stack buffer */
            char lower[256];
            size_t cpy = hnl < sizeof(lower) ? hnl : sizeof(lower) - 1;
            for (size_t j = 0; j < cpy; j++) {
                unsigned char ch = (unsigned char)hn[j];
                lower[j] = (char)(ch >= 'A' && ch <= 'Z' ? ch + 32 : ch);
            }

            PyObject *nb = PyBytes_FromStringAndSize(lower, (Py_ssize_t)cpy);
            PyObject *vb = PyBytes_FromStringAndSize(hv,    (Py_ssize_t)hvl);
            PyObject *pr = (nb && vb) ? PyTuple_Pack(2, nb, vb) : NULL;
            Py_XDECREF(nb); Py_XDECREF(vb);
            if (!pr) { Py_DECREF(hlist); Py_DECREF(scope); return NULL; }
            PyList_SET_ITEM(hlist, (Py_ssize_t)i, pr); /* steals ref */
        }
        int rc = PyDict_SetItemString(scope, "headers", hlist);
        Py_DECREF(hlist);
        if (rc < 0) { Py_DECREF(scope); return NULL; }
    }

#undef SS
#undef SSN
    return scope;
}

/* ---- Response formatting ---- */

static const char *status_reason(int s) {
    switch (s) {
        case 100: return "Continue";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 204: return "No Content";
        case 206: return "Partial Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 422: return "Unprocessable Entity";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default:  return "Unknown";
    }
}

static int format_response_asgi(client_t *c, int status,
                                  PyObject *headers, PyObject *body) {
    char *hdr = c->resp_hdr;
    int   max = RESP_HDR_SIZE;
    int   len = 0, n;
    bool  have_cl = false, have_conn = false;

    n = snprintf(hdr, (size_t)max, "HTTP/1.1 %d %s\r\n", status, status_reason(status));
    if (n < 0 || n >= max) return -1;
    len += n;

    Py_ssize_t nhdrs = PyList_GET_SIZE(headers);
    for (Py_ssize_t i = 0; i < nhdrs; i++) {
        PyObject   *pair = PyList_GET_ITEM(headers, i);
        PyObject   *no   = PySequence_GetItem(pair, 0);
        PyObject   *vo   = PySequence_GetItem(pair, 1);
        if (!no || !vo || !PyBytes_Check(no) || !PyBytes_Check(vo)) {
            Py_XDECREF(no); Py_XDECREF(vo); return -1;
        }
        const char *name = PyBytes_AS_STRING(no);
        Py_ssize_t  nl   = PyBytes_GET_SIZE(no);
        const char *val  = PyBytes_AS_STRING(vo);
        Py_ssize_t  vl   = PyBytes_GET_SIZE(vo);

        if (nl == 14 && strncasecmp(name, "content-length", 14) == 0) have_cl   = true;
        if (nl == 10 && strncasecmp(name, "connection",     10) == 0) have_conn = true;

        n = snprintf(hdr + len, (size_t)(max - len), "%.*s: %.*s\r\n",
                     (int)nl, name, (int)vl, val);
        Py_DECREF(no); Py_DECREF(vo);
        if (n < 0 || n >= max - len) return -1;
        len += n;
    }

    if (!have_cl) {
        Py_ssize_t blen = (body && PyBytes_Check(body)) ? PyBytes_GET_SIZE(body) : 0;
        n = snprintf(hdr + len, (size_t)(max - len), "Content-Length: %zd\r\n", blen);
        if (n < 0 || n >= max - len) return -1;
        len += n;
    }
    if (!have_conn) {
        n = snprintf(hdr + len, (size_t)(max - len), "Connection: %s\r\n",
                     c->keep_alive ? "keep-alive" : "close");
        if (n < 0 || n >= max - len) return -1;
        len += n;
    }

    if (len + 2 >= max) return -1;
    hdr[len++] = '\r'; hdr[len++] = '\n';
    c->resp_hdr_len = len;
    return 0;
}

/* ---- Python-callable response sender ---- */

/*
 * _freastal.asgi_send_response(capsule, status: int, headers: list, body: bytes)
 *
 * Called from Python inside the asyncio task (via _asgi_protocol.send()).
 * GIL is held (we're inside loop._run_once()).
 * write_response() → uv_write() is safe to call from within libuv callbacks.
 */
PyObject *asgi_send_response_c(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *capsule, *headers, *body;
    int status;

    if (!PyArg_ParseTuple(args, "OiOO", &capsule, &status, &headers, &body))
        return NULL;

    client_t *c = (client_t *)PyCapsule_GetPointer(capsule, "freastal.client");
    if (!c) return NULL;

    if (!PyList_Check(headers)) {
        PyErr_SetString(PyExc_TypeError, "asgi headers must be a list");
        return NULL;
    }

    if (format_response_asgi(c, status, headers, body) < 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "freastal asgi: response header buffer overflow");
        return NULL;
    }

    if (body && PyBytes_Check(body) && PyBytes_GET_SIZE(body) > 0) {
        Py_INCREF(body);
        c->resp_body = body;
    }

    write_response(c);
    Py_RETURN_NONE;
}

/* ---- Dispatch ---- */

static void send_500_asgi(client_t *c) {
    static const char resp[] =
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Content-Length: 0\r\nConnection: close\r\n\r\n";
    c->keep_alive = false;
    memcpy(c->resp_hdr, resp, sizeof(resp) - 1);
    c->resp_hdr_len = sizeof(resp) - 1;
    c->resp_body = NULL;
    write_response(c);
}

void asgi_dispatch(client_t *c) {
    /* GIL must be held by caller (http_dispatch locks it). */
    PyObject *scope = build_asgi_scope(c);
    if (!scope) { PyErr_Clear(); send_500_asgi(c); return; }

    /* Request body bytes */
    const char *bp   = c->read_buf + c->headers_end;
    Py_ssize_t  blen = (Py_ssize_t)c->read_len - c->headers_end;
    if (blen < 0) blen = 0;
    if ((size_t)blen > c->content_length) blen = (Py_ssize_t)c->content_length;
    PyObject *body = PyBytes_FromStringAndSize(bp, blen);
    if (!body) { Py_DECREF(scope); PyErr_Clear(); send_500_asgi(c); return; }

    /* Capsule carrying the client pointer into Python */
    PyObject *cap = PyCapsule_New(c, "freastal.client", NULL);
    if (!cap) {
        Py_DECREF(scope); Py_DECREF(body); PyErr_Clear(); send_500_asgi(c); return;
    }

    /* run_asgi_request(loop, app, scope, body, capsule) → asyncio.Task */
    PyObject *task = PyObject_CallFunctionObjArgs(
        g_server.asgi_run_request,
        g_server.asgi_loop, g_server.app,
        scope, body, cap, NULL
    );
    Py_DECREF(scope); Py_DECREF(body); Py_DECREF(cap);

    if (!task) { PyErr_Print(); send_500_asgi(c); return; }
    c->asgi_task = task; /* ref held until on_write clears it */
}

/* ---- Server init ---- */

int asgi_server_init(PyObject *loop) {
    Py_INCREF(loop);
    g_server.asgi_loop = loop;

    g_server.asgi_run_once = PyObject_GetAttrString(loop, "_run_once");
    if (!g_server.asgi_run_once) return -1;

    /* Cache asyncio._set_running_loop for Python 3.14+ running-loop validation */
    {
        PyObject *amod = PyImport_ImportModule("asyncio");
        if (amod) {
            g_server.asyncio_set_running_loop =
                PyObject_GetAttrString(amod, "_set_running_loop");
            Py_DECREF(amod);
            if (!g_server.asyncio_set_running_loop) PyErr_Clear();
        } else {
            PyErr_Clear();
        }
    }

    /* Import Python bridge */
    PyObject *mod = PyImport_ImportModule("freastal._asgi_protocol");
    if (!mod) return -1;
    g_server.asgi_run_request = PyObject_GetAttrString(mod, "run_asgi_request");
    Py_DECREF(mod);
    if (!g_server.asgi_run_request) return -1;

    /* Pre-build constant scope objects */
    g_server.asgi_type_http    = PyUnicode_InternFromString("http");
    g_server.asgi_http_11      = PyUnicode_InternFromString("1.1");
    g_server.asgi_http_10      = PyUnicode_InternFromString("1.0");
    g_server.asgi_scheme_http  = PyUnicode_InternFromString("http");
    g_server.asgi_empty_str    = PyUnicode_InternFromString("");
    g_server.asgi_empty_bytes  = PyBytes_FromStringAndSize("", 0);

    g_server.asgi_version_dict = PyDict_New();
    if (g_server.asgi_version_dict) {
        PyObject *v30 = PyUnicode_FromString("3.0");
        if (v30) { PyDict_SetItemString(g_server.asgi_version_dict, "version", v30); }
        Py_XDECREF(v30);
    }

    PyObject *hstr  = PyUnicode_FromString(g_server.host);
    PyObject *pint  = PyLong_FromLong((long)g_server.port);
    g_server.asgi_server_tuple = (hstr && pint) ? PyTuple_Pack(2, hstr, pint) : NULL;
    Py_XDECREF(hstr); Py_XDECREF(pint);

    if (!g_server.asgi_type_http   || !g_server.asgi_http_11      ||
        !g_server.asgi_http_10     || !g_server.asgi_scheme_http   ||
        !g_server.asgi_empty_str   || !g_server.asgi_empty_bytes   ||
        !g_server.asgi_version_dict|| !g_server.asgi_server_tuple)
        return -1;

    /* uv_check_t: step asyncio after each libuv I/O poll */
    uv_check_init(g_server.loop, &g_server.asgi_check);
    uv_check_start(&g_server.asgi_check, asgi_check_cb);
    uv_unref((uv_handle_t *)&g_server.asgi_check);

    /*
     * uv_poll_t on asyncio's selector fd: fires when external async I/O
     * completes (e.g. awaited DB query, aiohttp response).
     * Uses Linux epoll chaining: asyncio's epoll fd sits inside libuv's epoll;
     * when the inner epoll is readable, libuv wakes up and we call _run_once().
     * Gracefully skipped if _selector.fileno() is unavailable (uvloop, Windows).
     */
    PyObject *sel = PyObject_GetAttrString(loop, "_selector");
    if (sel) {
        PyObject *fd_obj = PyObject_CallMethod(sel, "fileno", NULL);
        Py_DECREF(sel);
        if (fd_obj) {
            int afd = (int)PyLong_AsLong(fd_obj);
            Py_DECREF(fd_obj);
            if (afd >= 0 && !PyErr_Occurred()) {
                if (uv_poll_init(g_server.loop, &g_server.asgi_poll, afd) == 0) {
                    uv_poll_start(&g_server.asgi_poll, UV_READABLE, asgi_poll_cb);
                    uv_unref((uv_handle_t *)&g_server.asgi_poll);
                    g_server.asgi_poll_active = true;
                }
            }
        }
        if (PyErr_Occurred()) PyErr_Clear();
    } else {
        PyErr_Clear();
    }

    g_server.asgi_mode = true;
    fprintf(stderr, "[freastal] ASGI mode enabled (asyncio%s)\n",
            g_server.asgi_poll_active ? " + async I/O bridge" : "");
    return 0;
}
