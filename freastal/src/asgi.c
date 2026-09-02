#include "server.h"
#include "asgi.h"
#include "hdrcache.h"
#include "hdrvalid.h"
#include <arpa/inet.h>
#include <string.h>

/* Interned attribute names used to drive the loop's callback queue.  Private
 * to the driver below rather than in g_server, which holds server state. */
static PyObject *s_popleft   = NULL;  /* deque.popleft */
static PyObject *s_run       = NULL;  /* Handle._run */
static PyObject *s_cancelled = NULL;  /* Handle._cancelled */
static PyObject *s_when      = NULL;  /* TimerHandle._when */

/* Returned to Python in place of a yielded value when the app's coroutine has
 * returned; see asgi_coro_step_c(). */
static PyObject *asgi_coro_done = NULL;

/* ---- libuv callbacks ---- */

/* len(obj) for the loop's callback queues; 0 rather than an error, since a
 * failure here must not be allowed to wedge the event loop.  _scheduled is a
 * plain list, so its length is a struct field read rather than a trip through
 * the sequence protocol -- this is asked on every libuv iteration. */
static inline Py_ssize_t asgi_pending(PyObject *obj) {
    if (unlikely(!obj)) return 0;
    if (likely(PyList_CheckExact(obj))) return PyList_GET_SIZE(obj);
    Py_ssize_t n = PyObject_Size(obj);
    if (unlikely(n < 0)) { PyErr_Clear(); return 0; }
    return n;
}

/* One non-blocking step of the asyncio loop.  Callers must hold the GIL and
 * must only call this when the loop has work that is due now, so that
 * _run_once() computes a zero select() timeout and never blocks libuv. */
static void asgi_run_once(void) {
    PyObject *ret = PyObject_CallNoArgs(g_server.asgi_run_once);
    Py_XDECREF(ret);
    if (unlikely(PyErr_Occurred())) PyErr_Clear();
}

/*
 * asgi_drain_ready - loop._run_once()'s tail, without the poll at its head.
 *
 * _run_once() calls self._selector.select(timeout) unconditionally, even when
 * _ready is full and no I/O can possibly be pending.  On this path that
 * syscall buys nothing: freastal watches the selector fd itself with a
 * uv_poll_t, and asgi_poll_cb runs the real _run_once() whenever it fires, so
 * completed async I/O is picked up there.  Running the queue from C instead
 * costs one epoll_wait (or, on macOS, one far more expensive kqueue call) less
 * per loop turn, and there are one or more turns per suspending request.
 * uvloop drains its own queue from a uv_idle_t for the same reason.
 *
 * ntodo is snapshotted before the loop, exactly as _run_once() does, so a
 * callback that schedules another callback has it run on the next turn rather
 * than extending this one.  Handle._run() routes the callback's own exceptions
 * into loop.call_exception_handler(), so the only failures that reach here are
 * the ones _run_once() would also have let escape (SystemExit and friends);
 * like _run_once() we end the turn and leave the rest of the queue for the
 * next one, which asgi_arm_wakeups() has already guaranteed will happen.
 *
 * What is not reproduced is _run_once()'s debug-mode instrumentation
 * (loop._current_handle and the slow-callback warning).  That is deliberate:
 * the eager path already runs most requests without entering _run_once() at
 * all, so a debug loop never saw them either, and paying for a loop._debug
 * read per turn would buy fidelity the bridge does not have in the first
 * place.
 */
static void asgi_drain_ready(Py_ssize_t ntodo) {
    PyObject *ready = g_server.asgi_ready;

    for (Py_ssize_t i = 0; i < ntodo; i++) {
        PyObject *h = PyObject_CallMethodNoArgs(ready, s_popleft);
        if (unlikely(!h)) break;

        PyObject *canc = PyObject_GetAttr(h, s_cancelled);
        if (unlikely(!canc)) { Py_DECREF(h); break; }
        /* asyncio only ever stores a bool here; PyObject_IsTrue is the
         * fallback so that a handle which does not is still read the way
         * _run_once()'s `if handle._cancelled` would read it. */
        int cancelled = Py_IsFalse(canc) ? 0
                      : Py_IsTrue(canc)  ? 1
                      : PyObject_IsTrue(canc);
        Py_DECREF(canc);
        if (unlikely(cancelled != 0)) {
            Py_DECREF(h);
            if (unlikely(cancelled < 0)) break;
            continue;
        }

        PyObject *r = PyObject_CallMethodNoArgs(h, s_run);
        Py_XDECREF(r);
        Py_DECREF(h);
        if (unlikely(!r)) break;
    }

    if (unlikely(PyErr_Occurred())) PyErr_Clear();
}

/*
 * asgi_idle_cb – deliberately empty.
 *
 * The handle exists for its side effect: while an idle handle is active libuv
 * performs a zero-timeout poll instead of blocking for I/O, which is what
 * guarantees another loop iteration (and so another asgi_check_cb) while
 * asyncio still has callbacks to run.
 */
static void asgi_idle_cb(uv_idle_t *handle) { (void)handle; }

static void asgi_timer_cb(uv_timer_t *handle);

static void asgi_arm_wakeups_n(Py_ssize_t nready);

/*
 * Line libuv's next poll up with asyncio's outstanding work.
 *
 * Without this, libuv blocks in its poll phase as soon as no socket is
 * readable.  uv_check_t only fires once per iteration, so the loop would stop
 * stepping asyncio entirely and any suspended ASGI task would hang until
 * unrelated traffic happened to wake the loop.
 *
 * Callbacks due now are covered by the idle handle (zero-timeout poll, so the
 * next iteration is immediate); scheduled callbacks get a uv_timer_t armed for
 * asyncio's earliest deadline.  Both are dropped as soon as the loop drains,
 * so an idle server still blocks in poll rather than spinning.
 */
void asgi_arm_wakeups(void) {
    asgi_arm_wakeups_n(asgi_pending(g_server.asgi_ready));
}

/* As asgi_arm_wakeups(), for callers that have just measured len(_ready). */
static void asgi_arm_wakeups_n(Py_ssize_t nready) {
    bool has_ready = nready > 0;
    if (has_ready != g_server.asgi_idle_active) {
        if (has_ready) uv_idle_start(&g_server.asgi_idle, asgi_idle_cb);
        else           uv_idle_stop(&g_server.asgi_idle);
        g_server.asgi_idle_active = has_ready;
    }

    if (asgi_pending(g_server.asgi_scheduled) == 0) {
        if (g_server.asgi_timer_active) {
            uv_timer_stop(&g_server.asgi_timer);
            g_server.asgi_timer_active = false;
        }
        return;
    }

    /* _scheduled is a heap of TimerHandle, so [0] is the earliest deadline. */
    uint64_t ms = 0;
    PyObject *h = PyList_Check(g_server.asgi_scheduled)
                ? PyList_GetItem(g_server.asgi_scheduled, 0) : NULL;  /* borrowed */
    PyObject *when_o = h ? PyObject_GetAttr(h, s_when) : NULL;
    PyObject *now_o  = when_o ? PyObject_CallNoArgs(g_server.asgi_loop_time) : NULL;
    if (now_o) {
        double delay = PyFloat_AsDouble(when_o) - PyFloat_AsDouble(now_o);
        /* Round up: waking early would leave the deadline in the future, and
         * _run_once() would then pass a positive timeout to select(). */
        if (delay > 0) ms = (uint64_t)(delay * 1000.0) + 1;
    }
    Py_XDECREF(when_o);
    Py_XDECREF(now_o);
    if (PyErr_Occurred()) PyErr_Clear();

    uv_timer_start(&g_server.asgi_timer, asgi_timer_cb, ms, 0);
    g_server.asgi_timer_active = true;
}

static void asgi_timer_cb(uv_timer_t *handle) {
    (void)handle;
    GIL_LOCK();
    g_server.asgi_timer_active = false;
    /* _run_once() rather than the C drain: only it moves the TimerHandles
     * whose deadline has come off _scheduled and onto _ready.  The deadline
     * has passed, so it clamps its own select() timeout to zero. */
    asgi_run_once();
    asgi_arm_wakeups();
    GIL_UNLOCK();
}

/*
 * asgi_check_cb – fires after each libuv I/O poll.
 *
 * Only steps asyncio when it has work to do (loop._ready non-empty), so that
 * an idle server does no Python work per libuv iteration.
 */
static void asgi_check_cb(uv_check_t *handle) {
    (void)handle;
    GIL_LOCK();
    Py_ssize_t nready = asgi_pending(g_server.asgi_ready);
    if (nready > 0) {
        /* Without the uv_poll_t on the selector fd, _run_once()'s select() is
         * the only thing that can notice completed async I/O, so keep paying
         * for it there -- correctness first on platforms and event loops where
         * the selector cannot be watched. */
        if (likely(g_server.asgi_poll_active)) asgi_drain_ready(nready);
        else                                   asgi_run_once();
        nready = asgi_pending(g_server.asgi_ready);
    }
    asgi_arm_wakeups_n(nready);
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
    asgi_run_once();
    asgi_arm_wakeups();
    GIL_UNLOCK();
}

/* ---- Driving the app's coroutine ---- */

/*
 * asgi_coro_step(coro) / asgi_coro_step(coro, ctx)
 *
 * One send(None) into the app's coroutine, returning what it yielded or the
 * ASGI_CORO_DONE sentinel if it returned instead.  With `ctx`, the step runs
 * inside that context, as _asgi_protocol needs for the eager first step.
 *
 * This replaces `ctx.run(coro.send, None)` wrapped in `except StopIteration`.
 * Both halves of that cost more than the step itself: `coro.send` binds a
 * fresh method object per call, and StopIteration is raised, unwound and
 * caught on every request that completes inline -- which is nearly all of
 * them.  PyIter_Send() reports the return with PYGEN_RETURN and never touches
 * the exception machinery, and PyContext_Enter/Exit is exactly what
 * context.run() does around the call.
 */
PyObject *asgi_coro_step_c(PyObject *self, PyObject *const *args,
                            Py_ssize_t nargs) {
    (void)self;
    if (unlikely(nargs < 1 || nargs > 2)) {
        PyErr_SetString(PyExc_TypeError,
                        "asgi_coro_step() takes a coroutine and an optional context");
        return NULL;
    }

    PyObject *ctx = (nargs == 2) ? args[1] : NULL;
    if (ctx && unlikely(PyContext_Enter(ctx) < 0)) return NULL;

    /* PYGEN_NEXT leaves the yielded value in `out`; PYGEN_ERROR leaves it NULL
     * with the app's exception set, which is what this function returns. */
    PyObject *out = NULL;
    if (PyIter_Send(args[0], Py_None, &out) == PYGEN_RETURN) {
        Py_XDECREF(out);  /* an ASGI app returns None, but do not assume it */
        out = Py_NewRef(asgi_coro_done);
    }

    /* Exit even when the step raised: the exception belongs to the app, and
     * this can only fail if the context was never entered.  Doing it after
     * PyIter_Send matches ctx.run(), which also restores the caller's context
     * before letting the exception out. */
    if (ctx && unlikely(PyContext_Exit(ctx) < 0)) Py_CLEAR(out);
    return out;
}

/* ---- ASGI scope builder ---- */

/*
 * Build the per-request ASGI scope.
 *
 * The scope is a copy of a template dict built once at startup.  PyDict_Copy()
 * of a combined dict clones the whole key table with one memcpy and increfs the
 * entries, so none of the twelve scope keys is allocated, hashed or interned
 * here -- the previous PyDict_SetItemString() form did all three, twelve times
 * per request.  What remains is one dict allocation plus an in-place value
 * store for each entry that actually varies.
 *
 * The copy is a genuine, independent dict, which it has to be: Starlette adds
 * app/router/state/endpoint/route/path_params to the scope it is handed and
 * Litestar rewrites scope["path"], so a shared or recycled dict would bleed one
 * request's state into the next.
 */
static PyObject *build_asgi_scope(client_t *c) {
    const asgi_keys_t *k = &g_server.asgi_keys;

    PyObject *scope = PyDict_Copy(g_server.asgi_scope_template);
    if (unlikely(!scope)) return NULL;

#define SS(key, v) do { \
    if (unlikely(PyDict_SetItem(scope, k->key, (v)) < 0)) \
        { Py_DECREF(scope); return NULL; } \
} while (0)

#define SSN(key, expr) do { \
    PyObject *_v = (expr); \
    if (unlikely(!_v) || unlikely(PyDict_SetItem(scope, k->key, _v) < 0)) \
        { Py_XDECREF(_v); Py_DECREF(scope); return NULL; } \
    Py_DECREF(_v); \
} while (0)

    /* type / asgi / root_path / scheme / server come from the template.
     *
     * So do the defaults for the two entries below: the template is immutable,
     * so "1.1" and b"" are constants of this build, never a value left behind
     * by an earlier request. */
    if (unlikely(c->minor_version != 1))
        SS(http_version, g_server.asgi_http_10);

    SSN(method, PyUnicode_FromStringAndSize(c->method, (Py_ssize_t)c->method_len));

    /* path / raw_path / query_string */
    {
        const char *qmark = (const char *)memchr(c->path, '?', c->path_len);
        Py_ssize_t  plen  = qmark ? (Py_ssize_t)(qmark - c->path)
                                  : (Py_ssize_t)c->path_len;
        SSN(path,     PyUnicode_FromStringAndSize(c->path, plen));
        SSN(raw_path, PyBytes_FromStringAndSize(c->path, plen));
        if (qmark) {
            Py_ssize_t qlen = (Py_ssize_t)(c->path_len - (size_t)(qmark + 1 - c->path));
            SSN(query_string, PyBytes_FromStringAndSize(qmark + 1, qlen));
        }
    }

    /* client: (peer_ip, peer_port).  Fixed for the life of the connection, so
     * build it once and reuse it across keep-alive requests -- the same reason
     * the WSGI path caches peer_addr_obj for REMOTE_ADDR. */
    if (!c->asgi_client_obj) {
        PyObject *ip   = PyUnicode_FromString(c->peer_addr);
        PyObject *port = PyLong_FromLong((long)c->peer_port);
        c->asgi_client_obj = (ip && port) ? PyTuple_Pack(2, ip, port) : NULL;
        Py_XDECREF(ip); Py_XDECREF(port);
        if (unlikely(!c->asgi_client_obj)) { Py_DECREF(scope); return NULL; }
    }
    SS(client, c->asgi_client_obj);

    /* headers: list of (name_bytes_lower, value_bytes) */
    {
        PyObject *hlist = PyList_New((Py_ssize_t)c->num_headers);
        if (!hlist) { Py_DECREF(scope); return NULL; }
        for (size_t i = 0; i < c->num_headers; i++) {
            const char *hn  = c->headers[i].name;
            size_t      hnl = c->headers[i].name_len;
            const char *hv  = c->headers[i].value;
            size_t      hvl = c->headers[i].value_len;

            /* Name: a pre-built object for the names that recur on every
             * request, otherwise lowercased straight into a fresh bytes
             * object -- no intermediate C buffer, and no length cap. */
            const hdr_cache_entry *e = hdr_cache_lookup(hn, hnl);
            PyObject *nb;
            if (likely(e != NULL)) {
                nb = e->asgi_name;
                Py_INCREF(nb);
            } else {
                nb = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)hnl);
                if (nb) {
                    char *dst = PyBytes_AS_STRING(nb);
                    for (size_t j = 0; j < hnl; j++) {
                        unsigned char ch = (unsigned char)hn[j];
                        dst[j] = (char)(ch >= 'A' && ch <= 'Z' ? ch + 32 : ch);
                    }
                }
            }
            PyObject *vb = PyBytes_FromStringAndSize(hv, (Py_ssize_t)hvl);
            PyObject *pr = (nb && vb) ? PyTuple_Pack(2, nb, vb) : NULL;
            Py_XDECREF(nb); Py_XDECREF(vb);
            if (!pr) { Py_DECREF(hlist); Py_DECREF(scope); return NULL; }
            PyList_SET_ITEM(hlist, (Py_ssize_t)i, pr); /* steals ref */
        }
        int rc = PyDict_SetItem(scope, k->headers, hlist);
        Py_DECREF(hlist);
        if (rc < 0) { Py_DECREF(scope); return NULL; }
    }

#undef SS
#undef SSN
    return scope;
}

/* ---- Response formatting ---- */

/*
 * Complete status lines rather than bare reason phrases: the version prefix,
 * the code and the CRLF are constant together, so the common case is one
 * memcpy of a literal whose length sizeof() already knows (nginx keeps
 * ngx_http_status_lines[] the same way).  NULL for codes not in the table.
 */
static const char *status_line(int s, int *len) {
#define SL(lit) do { *len = (int)sizeof(lit) - 1; return (lit); } while (0)
    switch (s) {
        case 100: SL("HTTP/1.1 100 Continue\r\n");
        case 200: SL("HTTP/1.1 200 OK\r\n");
        case 201: SL("HTTP/1.1 201 Created\r\n");
        case 202: SL("HTTP/1.1 202 Accepted\r\n");
        case 204: SL("HTTP/1.1 204 No Content\r\n");
        case 206: SL("HTTP/1.1 206 Partial Content\r\n");
        case 301: SL("HTTP/1.1 301 Moved Permanently\r\n");
        case 302: SL("HTTP/1.1 302 Found\r\n");
        case 304: SL("HTTP/1.1 304 Not Modified\r\n");
        case 307: SL("HTTP/1.1 307 Temporary Redirect\r\n");
        case 308: SL("HTTP/1.1 308 Permanent Redirect\r\n");
        case 400: SL("HTTP/1.1 400 Bad Request\r\n");
        case 401: SL("HTTP/1.1 401 Unauthorized\r\n");
        case 403: SL("HTTP/1.1 403 Forbidden\r\n");
        case 404: SL("HTTP/1.1 404 Not Found\r\n");
        case 405: SL("HTTP/1.1 405 Method Not Allowed\r\n");
        case 409: SL("HTTP/1.1 409 Conflict\r\n");
        case 410: SL("HTTP/1.1 410 Gone\r\n");
        case 422: SL("HTTP/1.1 422 Unprocessable Entity\r\n");
        case 429: SL("HTTP/1.1 429 Too Many Requests\r\n");
        case 500: SL("HTTP/1.1 500 Internal Server Error\r\n");
        case 502: SL("HTTP/1.1 502 Bad Gateway\r\n");
        case 503: SL("HTTP/1.1 503 Service Unavailable\r\n");
        case 504: SL("HTTP/1.1 504 Gateway Timeout\r\n");
        default:  return NULL;
    }
#undef SL
}

/* Set by append_asgi_header() when the app supplied the header itself. */
#define ASGI_HAS_CL   0x1u
#define ASGI_HAS_CONN 0x2u

/*
 * Append one "name: value\r\n" from an ASGI (name, value) pair.  Returns the
 * bytes written, or -1 if the pair is not the two bytes objects the spec
 * requires or the line does not fit in `remaining`.
 *
 * Apps hand us lists or tuples, so both are read through the borrowed-reference
 * macros: PySequence_GetItem costs generic protocol dispatch plus a new
 * reference (and its later decref) for each of the two fields of every header.
 * Any other sequence still works through the fallback, whose new references are
 * released on every path -- the header bytes are only read while they are held.
 */
static int append_asgi_header(char *dst, int remaining, PyObject *pair,
                              unsigned *flags) {
    PyObject *owned_n = NULL, *owned_v = NULL;
    PyObject *no, *vo;

    if (likely(PyList_CheckExact(pair) && PyList_GET_SIZE(pair) == 2)) {
        no = PyList_GET_ITEM(pair, 0);
        vo = PyList_GET_ITEM(pair, 1);
    } else if (PyTuple_CheckExact(pair) && PyTuple_GET_SIZE(pair) == 2) {
        no = PyTuple_GET_ITEM(pair, 0);
        vo = PyTuple_GET_ITEM(pair, 1);
    } else {
        no = owned_n = PySequence_GetItem(pair, 0);
        vo = owned_v = PySequence_GetItem(pair, 1);
    }

    int written = -1;
    if (likely(no && vo && PyBytes_Check(no) && PyBytes_Check(vo))) {
        const char *name = PyBytes_AS_STRING(no);
        Py_ssize_t  nl   = PyBytes_GET_SIZE(no);
        const char *val  = PyBytes_AS_STRING(vo);
        Py_ssize_t  vl   = PyBytes_GET_SIZE(vo);
        Py_ssize_t  need = nl + vl + 4;          /* ": " and CRLF */

        /* Length pre-check avoids scanning headers that can't possibly match */
        if (nl == 14 && strncasecmp(name, "content-length", 14) == 0)
            *flags |= ASGI_HAS_CL;
        else if (nl == 10 && strncasecmp(name, "connection", 10) == 0)
            *flags |= ASGI_HAS_CONN;

        if (likely(need <= (Py_ssize_t)remaining)) {
            /* One bounds check covers the whole line.  memcpy also copies the
             * value verbatim, where "%.*s" would stop at an embedded NUL. */
            memcpy(dst, name, (size_t)nl);
            dst[nl]     = ':';
            dst[nl + 1] = ' ';
            memcpy(dst + nl + 2, val, (size_t)vl);
            dst[nl + vl + 2] = '\r';
            dst[nl + vl + 3] = '\n';
            written = (int)need;
        }
    }

    Py_XDECREF(owned_n);
    Py_XDECREF(owned_v);
    return written;
}

/*
 * Write the response header block into c->resp_hdr[].  Returns 0, or -1 if the
 * buffer is too small -- the caller raises on -1, so a block that does not fit
 * is rejected rather than truncated.
 *
 * memcpy of sized literals instead of snprintf, for the same reason as
 * format_response_headers() in wsgi.c: no format-string parsing and no
 * implicit strlen on each argument.
 */
static int format_response_asgi(client_t *c, int status,
                                  PyObject *headers, PyObject *body) {
    char    *hdr   = c->resp_hdr;
    int      max   = RESP_HDR_SIZE;
    int      len   = 0;
    unsigned flags = 0;

/* Bounds-checked memcpy into the header buffer. */
#define HDR_APPEND(src, srclen) \
    do { \
        int _sl = (int)(srclen); \
        if (_sl > max - len) return -1; \
        memcpy(hdr + len, (src), (size_t)_sl); \
        len += _sl; \
    } while (0)

    /* Status line */
    int         slen;
    const char *sline = status_line(status, &slen);
    if (likely(sline != NULL)) {
        HDR_APPEND(sline, slen);
    } else {
        /* Codes outside the table are rare enough not to be worth a fast path,
         * and one bounds-checked snprintf reproduces the previous bytes for
         * anything an app might pass, negative values included. */
        int n = snprintf(hdr, (size_t)max, "HTTP/1.1 %d Unknown\r\n", status);
        if (n < 0 || n >= max) return -1;
        len = n;
    }

    /* Response headers from the app */
    Py_ssize_t nhdrs = PyList_GET_SIZE(headers);
    for (Py_ssize_t i = 0; i < nhdrs; i++) {
        int n = append_asgi_header(hdr + len, max - len,
                                   PyList_GET_ITEM(headers, i), &flags);
        if (unlikely(n < 0)) return -1;
        len += n;
    }

    /* Auto Content-Length */
    if (!(flags & ASGI_HAS_CL)) {
        Py_ssize_t blen = (body && PyBytes_Check(body)) ? PyBytes_GET_SIZE(body) : 0;
        HDR_APPEND("Content-Length: ", 16);
        int n = write_uint(hdr + len, max - len, blen);
        if (n < 0) return -1;
        len += n;
        HDR_APPEND("\r\n", 2);
    }

    /* Auto Connection */
    if (!(flags & ASGI_HAS_CONN)) {
        if (c->keep_alive)
            HDR_APPEND("Connection: keep-alive\r\n", 24);
        else
            HDR_APPEND("Connection: close\r\n", 19);
    }

    HDR_APPEND("\r\n", 2);

#undef HDR_APPEND

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

    /*
     * Reject CR, LF and NUL before anything is copied into the response
     * buffer.  format_response_asgi() writes application names and values
     * verbatim, so an app reflecting unvalidated input into a header could
     * otherwise inject headers or split the response.  The status is an int
     * here, so unlike the WSGI path it needs no checking.
     */
    {
        Py_ssize_t nhdrs = PyList_GET_SIZE(headers);
        for (Py_ssize_t i = 0; i < nhdrs; i++) {
            PyObject *pair = PyList_GET_ITEM(headers, i);
            PyObject *no, *vo;
            if (PyTuple_CheckExact(pair) && PyTuple_GET_SIZE(pair) == 2) {
                no = PyTuple_GET_ITEM(pair, 0);
                vo = PyTuple_GET_ITEM(pair, 1);
            } else if (PyList_CheckExact(pair) && PyList_GET_SIZE(pair) == 2) {
                no = PyList_GET_ITEM(pair, 0);
                vo = PyList_GET_ITEM(pair, 1);
            } else {
                /* Leave other shapes to the formatter, which handles the
                 * general sequence case and reports its own error. */
                continue;
            }
            if (!PyBytes_Check(no) || !PyBytes_Check(vo)) continue;

            if (!freastal_hdr_name_ok(PyBytes_AS_STRING(no),
                                      PyBytes_GET_SIZE(no))) {
                PyErr_Format(PyExc_ValueError,
                    "freastal asgi: invalid header name %R", no);
                return NULL;
            }
            if (!freastal_hdr_value_ok(PyBytes_AS_STRING(vo),
                                       PyBytes_GET_SIZE(vo))) {
                PyErr_Format(PyExc_ValueError,
                    "freastal asgi: header %R has a value containing a "
                    "control character", no);
                return NULL;
            }
        }
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

    /* Capsule carrying the client pointer into Python.  The pointer is stable
     * for the life of the connection, so the capsule is built once and reused;
     * a suspended task that outlives the request keeps it alive by refcount. */
    if (!c->asgi_capsule) {
        c->asgi_capsule = PyCapsule_New(c, "freastal.client", NULL);
        if (!c->asgi_capsule) {
            Py_DECREF(scope); Py_DECREF(body); PyErr_Clear(); send_500_asgi(c); return;
        }
    }

    /*
     * run_asgi_request(loop, app, scope, body, capsule) runs the app eagerly
     * and returns None if it finished inline (the common case: the response
     * is already written by then) or an asyncio.Task if it suspended.
     *
     * The app runs on this stack rather than inside _run_once(), but the loop
     * is already the running loop for this thread -- asgi_server_init() made
     * it so once and for good -- so asyncio.get_running_loop() works here as
     * it does inside a task.
     */
    PyObject *task = PyObject_CallFunctionObjArgs(
        g_server.asgi_run_request,
        g_server.asgi_loop, g_server.app,
        scope, body, c->asgi_capsule, NULL
    );
    Py_DECREF(scope); Py_DECREF(body);

    if (!task) {
        PyErr_Print();
        /* If the app raised after sending, the response is already on the
         * wire and a second one would corrupt the stream. */
        if (c->resp_hdr_len == 0) send_500_asgi(c);
        return;
    }

    if (task == Py_None) {
        Py_DECREF(task);
        /* Finished inline. A well-behaved app has already called send(); one
         * that returned without sending would leave the connection hanging,
         * so answer it rather than waiting for the peer to time out. */
        if (c->resp_hdr_len == 0) send_500_asgi(c);
        return;
    }

    c->asgi_task = task; /* suspended; ref held until on_write clears it */

    /* The task sits on loop._ready, but this is not necessarily the I/O phase:
     * a pipelined request is dispatched from a write completion, which libuv
     * runs *before* it computes the poll timeout.  Re-arm so the loop cannot
     * block before asgi_check_cb gets to step the task.  Apps that finish
     * inline need no arming -- their uv_write already puts the stream on
     * libuv's pending queue, which forces the same zero timeout. */
    asgi_arm_wakeups();
}

/* ---- Server init ---- */

int asgi_server_init(PyObject *loop) {
    Py_INCREF(loop);
    g_server.asgi_loop = loop;

    g_server.asgi_run_once = PyObject_GetAttrString(loop, "_run_once");
    if (!g_server.asgi_run_once) return -1;

    /* Cached once: asyncio mutates these in place and never rebinds them. */
    g_server.asgi_ready = PyObject_GetAttrString(loop, "_ready");
    if (!g_server.asgi_ready) return -1;
    g_server.asgi_scheduled = PyObject_GetAttrString(loop, "_scheduled");
    if (!g_server.asgi_scheduled) return -1;
    g_server.asgi_loop_time = PyObject_GetAttrString(loop, "time");
    if (!g_server.asgi_loop_time) return -1;

    /* Attribute names for the callback-queue driver, interned once. */
    s_popleft   = PyUnicode_InternFromString("popleft");
    s_run       = PyUnicode_InternFromString("_run");
    s_cancelled = PyUnicode_InternFromString("_cancelled");
    s_when      = PyUnicode_InternFromString("_when");
    if (!s_popleft || !s_run || !s_cancelled || !s_when) return -1;

    /*
     * Make `loop` the running loop for this thread, once, permanently.
     *
     * This thread is about to enter uv_run() and drive that loop until the
     * process exits, which is exactly what run_forever() would be doing, so
     * the thread-local should say so for the whole of it.  Apps reach it
     * through asyncio.get_running_loop(); Python 3.14 also validates it in
     * context.run() while stepping tasks.  Setting it here rather than around
     * every dispatch and every loop turn removes two Python calls per request
     * and two more per turn.  server_run() releases the GIL with
     * Py_BEGIN_ALLOW_THREADS, which keeps this thread's PyThreadState alive,
     * so the value survives into the libuv callbacks' PyGILState_Ensure().
     */
    {
        PyObject *amod = PyImport_ImportModule("asyncio");
        PyObject *setter = amod ? PyObject_GetAttrString(amod, "_set_running_loop")
                                : NULL;
        Py_XDECREF(amod);
        if (setter) {
            PyObject *r = PyObject_CallOneArg(setter, loop);
            Py_XDECREF(r);
            Py_DECREF(setter);
        }
        if (PyErr_Occurred()) PyErr_Clear();
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

    /*
     * Scope template.  Every key the scope can carry is inserted here, in the
     * order the scope has always had them, so that the per-request copy needs
     * no insert at all -- only value stores into slots that already exist.
     *
     * Py_None marks an entry the request path always overwrites; the other
     * values are the ones a request inherits when it does not.  Twelve entries
     * leave the copy nine free slots before CPython resizes it, which covers
     * the six keys Starlette and FastAPI add.
     */
    {
        PyObject *t = PyDict_New();
        if (!t) return -1;
        g_server.asgi_scope_template = t;

        int rc = 0;
        rc |= PyDict_SetItemString(t, "type",         g_server.asgi_type_http);
        rc |= PyDict_SetItemString(t, "asgi",         g_server.asgi_version_dict);
        rc |= PyDict_SetItemString(t, "root_path",    g_server.asgi_empty_str);
        rc |= PyDict_SetItemString(t, "scheme",       g_server.asgi_scheme_http);
        rc |= PyDict_SetItemString(t, "server",       g_server.asgi_server_tuple);
        rc |= PyDict_SetItemString(t, "http_version", g_server.asgi_http_11);
        rc |= PyDict_SetItemString(t, "method",       Py_None);
        rc |= PyDict_SetItemString(t, "path",         Py_None);
        rc |= PyDict_SetItemString(t, "raw_path",     Py_None);
        rc |= PyDict_SetItemString(t, "query_string", g_server.asgi_empty_bytes);
        rc |= PyDict_SetItemString(t, "client",       Py_None);
        rc |= PyDict_SetItemString(t, "headers",      Py_None);
        if (rc < 0) return -1;

        /* PyDict_SetItemString interns its key, so interning the same text
         * here hands back the very objects in the template's key table: the
         * per-request lookups hit the pointer-equality fast path. */
        asgi_keys_t *k = &g_server.asgi_keys;
        k->http_version = PyUnicode_InternFromString("http_version");
        k->method       = PyUnicode_InternFromString("method");
        k->path         = PyUnicode_InternFromString("path");
        k->raw_path     = PyUnicode_InternFromString("raw_path");
        k->query_string = PyUnicode_InternFromString("query_string");
        k->client       = PyUnicode_InternFromString("client");
        k->headers      = PyUnicode_InternFromString("headers");
        if (!k->http_version || !k->method || !k->path || !k->raw_path ||
            !k->query_string || !k->client || !k->headers)
            return -1;
    }

    /* uv_check_t: step asyncio after each libuv I/O poll */
    uv_check_init(g_server.loop, &g_server.asgi_check);
    uv_check_start(&g_server.asgi_check, asgi_check_cb);
    uv_unref((uv_handle_t *)&g_server.asgi_check);

    /* Started and stopped on demand by asgi_arm_wakeups(); unref'd so neither
     * keeps the loop alive on its own. */
    uv_idle_init(g_server.loop, &g_server.asgi_idle);
    uv_unref((uv_handle_t *)&g_server.asgi_idle);
    uv_timer_init(g_server.loop, &g_server.asgi_timer);
    uv_unref((uv_handle_t *)&g_server.asgi_timer);

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

/* ---- Module init ---- */

/*
 * Called from PyInit__freastal, not from asgi_server_init: _asgi_protocol
 * imports these at module import time, which the unit tests do without ever
 * starting a server.
 */
int asgi_init(PyObject *m) {
    /* A plain object(), so that no value an app could yield can be mistaken
     * for "the coroutine returned". */
    asgi_coro_done = PyObject_CallNoArgs((PyObject *)&PyBaseObject_Type);
    if (!asgi_coro_done) return -1;
    if (PyModule_AddObject(m, "ASGI_CORO_DONE", Py_NewRef(asgi_coro_done)) < 0) {
        Py_DECREF(asgi_coro_done);  /* the reference AddObject did not steal */
        return -1;
    }
    return 0;
}
