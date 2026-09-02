#include "wsgi.h"
#include <string.h>

/* ---- StartResponse Python type ---- */

typedef struct {
    PyObject_HEAD
    client_t *client;
} StartResponse;

/*
 * Legacy wsgi write() callable.  PEP 3333 requires start_response to return
 * a write callable; modern apps never call it, so this is a no-op.
 */
static PyObject *wsgi_write_noop(PyObject *self, PyObject *args) {
    (void)self; (void)args;
    Py_RETURN_NONE;
}

static PyMethodDef _noop_write_method = {
    "wsgi_write", wsgi_write_noop, METH_VARARGS, NULL
};

static PyObject *g_noop_write = NULL;

static PyObject *StartResponse_call(StartResponse *self, PyObject *args, PyObject *kwargs) {
    (void)kwargs;
    PyObject *status, *headers;
    PyObject *exc_info = Py_None;

    if (!PyArg_ParseTuple(args, "UO|O:start_response", &status, &headers, &exc_info))
        return NULL;

    if (exc_info != Py_None && exc_info != NULL) {
        /* Re-raise previous exception if headers have already been sent */
        if (self->client->resp_status) {
            PyErr_SetString(PyExc_RuntimeError,
                "start_response called again with exc_info after headers sent");
            return NULL;
        }
    }

    if (!PyList_Check(headers)) {
        PyErr_SetString(PyExc_TypeError, "response_headers must be a list");
        return NULL;
    }

    client_t *c = self->client;
    Py_INCREF(status);
    Py_XDECREF(c->resp_status);
    c->resp_status = status;

    Py_INCREF(headers);
    Py_XDECREF(c->resp_pyheaders);
    c->resp_pyheaders = headers;

    Py_INCREF(g_noop_write);
    return g_noop_write;
}

static void StartResponse_dealloc(StartResponse *self) {
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyTypeObject StartResponse_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name      = "freastal.StartResponse",
    .tp_basicsize = sizeof(StartResponse),
    .tp_dealloc   = (destructor)StartResponse_dealloc,
    .tp_call      = (ternaryfunc)StartResponse_call,
    .tp_flags     = Py_TPFLAGS_DEFAULT,
};

/* ---- Body collection ---- */

/*
 * Iterate the WSGI response iterable and return a single bytes object.
 * Optimised for the common case of a single-element iterable.
 */
static PyObject *collect_body(PyObject *iterable) {
    PyObject *iter = PyObject_GetIter(iterable);
    if (!iter) return NULL;

    /* Get first chunk */
    PyObject *first = PyIter_Next(iter);
    if (!first) {
        Py_DECREF(iter);
        if (PyErr_Occurred()) return NULL;
        return PyBytes_FromStringAndSize("", 0);
    }

    /* Check for second chunk (avoids list alloc in the 99% single-chunk case) */
    PyObject *second = PyIter_Next(iter);
    if (!second && !PyErr_Occurred()) {
        Py_DECREF(iter);
        if (!PyBytes_Check(first)) {
            PyErr_SetString(PyExc_TypeError, "WSGI response body chunks must be bytes");
            Py_DECREF(first);
            return NULL;
        }
        return first; /* fast path: no copy */
    }

    /* Multiple chunks – accumulate into a list, then join */
    PyObject *list = PyList_New(0);
    if (!list) {
        Py_DECREF(iter); Py_DECREF(first); Py_XDECREF(second);
        return NULL;
    }
    PyList_Append(list, first); Py_DECREF(first);
    if (second) { PyList_Append(list, second); Py_DECREF(second); }

    PyObject *item;
    while ((item = PyIter_Next(iter)) != NULL) {
        PyList_Append(list, item);
        Py_DECREF(item);
    }
    Py_DECREF(iter);

    if (PyErr_Occurred()) { Py_DECREF(list); return NULL; }

    /* Compute total length, then build a single bytes object without sep */
    Py_ssize_t total = 0;
    Py_ssize_t n = PyList_GET_SIZE(list);
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *chunk = PyList_GET_ITEM(list, i);
        if (!PyBytes_Check(chunk)) {
            PyErr_SetString(PyExc_TypeError, "WSGI response body chunks must be bytes");
            Py_DECREF(list);
            return NULL;
        }
        total += PyBytes_GET_SIZE(chunk);
    }

    PyObject *result = PyBytes_FromStringAndSize(NULL, total);
    if (!result) { Py_DECREF(list); return NULL; }

    char *dst = PyBytes_AS_STRING(result);
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *chunk = PyList_GET_ITEM(list, i);
        Py_ssize_t len  = PyBytes_GET_SIZE(chunk);
        memcpy(dst, PyBytes_AS_STRING(chunk), (size_t)len);
        dst += len;
    }
    Py_DECREF(list);
    return result;
}

/* ---- Response formatting ---- */

/* Write a non-negative integer as decimal ASCII. Returns bytes written, -1 on overflow. */
static int write_uint(char *dst, int remaining, Py_ssize_t n) {
    char tmp[20];
    int  i = 0;
    if (n == 0) {
        tmp[i++] = '0';
    } else {
        size_t u = (size_t)n;
        while (u > 0) { tmp[i++] = (char)('0' + u % 10); u /= 10; }
        for (int lo = 0, hi = i - 1; lo < hi; lo++, hi--) {
            char t = tmp[lo]; tmp[lo] = tmp[hi]; tmp[hi] = t;
        }
    }
    if (i > remaining) return -1;
    memcpy(dst, tmp, (size_t)i);
    return i;
}

/*
 * Write "HTTP/1.1 <status>\r\n<headers>\r\nContent-Length: N\r\nConnection: ...\r\n\r\n"
 * into c->resp_hdr[].  Returns 0 on success, -1 if the buffer is too small.
 *
 * Uses PyUnicode_AsUTF8AndSize + memcpy instead of snprintf to avoid implicit
 * strlen on each string argument and format-string parsing overhead.
 */
static int format_response_headers(client_t *c, Py_ssize_t body_len) {
    char *hdr = c->resp_hdr;
    int   max = RESP_HDR_SIZE;
    int   len = 0;
    bool  have_content_length = false;
    bool  have_connection     = false;

/* Bounds-checked memcpy into the header buffer. */
#define HDR_APPEND(src, srclen) \
    do { \
        int _sl = (int)(srclen); \
        if (_sl > max - len) return -1; \
        memcpy(hdr + len, (src), (size_t)_sl); \
        len += _sl; \
    } while (0)

    /* Status line */
    Py_ssize_t  status_len;
    const char *status_str = PyUnicode_AsUTF8AndSize(c->resp_status, &status_len);
    if (!status_str) return -1;
    HDR_APPEND("HTTP/1.1 ", 9);
    HDR_APPEND(status_str, status_len);
    HDR_APPEND("\r\n", 2);

    /* Response headers from the app */
    Py_ssize_t nhdrs = PyList_GET_SIZE(c->resp_pyheaders);
    for (Py_ssize_t i = 0; i < nhdrs; i++) {
        PyObject   *pair = PyList_GET_ITEM(c->resp_pyheaders, i);
        Py_ssize_t  name_len, value_len;
        const char *name  = PyUnicode_AsUTF8AndSize(PyTuple_GET_ITEM(pair, 0), &name_len);
        const char *value = PyUnicode_AsUTF8AndSize(PyTuple_GET_ITEM(pair, 1), &value_len);
        if (!name || !value) return -1;

        /* Length pre-check avoids scanning headers that can't possibly match */
        if (name_len == 14 && strncasecmp(name, "content-length", 14) == 0)
            have_content_length = true;
        else if (name_len == 10 && strncasecmp(name, "connection", 10) == 0)
            have_connection = true;

        HDR_APPEND(name, name_len);
        HDR_APPEND(": ", 2);
        HDR_APPEND(value, value_len);
        HDR_APPEND("\r\n", 2);
    }

    /* Auto Content-Length */
    if (!have_content_length) {
        HDR_APPEND("Content-Length: ", 16);
        int n = write_uint(hdr + len, max - len, body_len);
        if (n < 0) return -1;
        len += n;
        HDR_APPEND("\r\n", 2);
    }

    /* Auto Connection */
    if (!have_connection) {
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

/* ---- WSGI environ builder ---- */

/*
 * Pre-built environ template
 * ==========================
 *
 * environ has a nearly fixed key set, so instead of growing a fresh dict from
 * scratch on every request (PyDict_New() starts with the shared empty keys
 * object and needs three key-table allocations plus two rebuilds to reach ~20
 * entries) we build one template dict at startup and PyDict_Copy() it per
 * request.
 *
 * PyDict_Copy() of a combined, mostly-compact, exact dict takes CPython's
 * clone_combined_dict() path: one PyObject_Malloc plus a memcpy of the whole
 * PyDictKeysObject, then an incref per live key/value.  That gives us, per
 * request, a key table that is already populated, already indexed and already
 * over-allocated -- no hashing, no per-key insert, and no dictresize.
 *
 * The template holds:
 *   - the 9-10 entries whose *values* are also constant (wsgi.version,
 *     wsgi.url_scheme, wsgi.multithread/multiprocess/run_once, SERVER_NAME,
 *     SERVER_PORT, SERVER_SOFTWARE, SCRIPT_NAME, wsgi.errors); and
 *   - the 6 per-request core keys (REQUEST_METHOD, PATH_INFO, QUERY_STRING,
 *     SERVER_PROTOCOL, REMOTE_ADDR, wsgi.input) with a Py_None placeholder.
 *     build_environ() overwrites all six unconditionally, so a placeholder can
 *     never reach the application; overwriting an existing key is also cheaper
 *     than inserting a new one (no index write, no dk_usable bookkeeping).
 *
 * Keys are inserted in exactly the order main's build_environ() used, so the
 * environ handed to the application has an identical iteration order.
 *
 * Head-room
 * ---------
 * A clone inherits the template's spare capacity, so the template must be over-
 * allocated or the header inserts would resize after all.  There is no public
 * API that presizes a dict: _PyDict_NewPresized() is private (and on 3.11+ it
 * builds a *general* key table, which would silently downgrade environ from the
 * compact unicode-key layout a naturally grown string-keyed dict gets).  So we
 * over-allocate the way the interpreter itself does -- by inserting and
 * immediately removing padding keys until CPython grows the key table, which it
 * sizes from ma_used (not from the entry count) and which compacts the padding
 * away in the process.  The loop stops as soon as sys.getsizeof() reports the
 * table grew; sys.getsizeof() is only used to decide how much head-room to buy,
 * never for correctness.
 *
 * Measured on CPython 3.10.12 / 3.11.13 / 3.12.9 / 3.13.7 this yields a 64-slot
 * table holding 16 live entries with 25 spare slots -- 41 entries before the
 * first resize, i.e. ~25 request headers.  Beyond that the dict resizes exactly
 * as it always did.
 *
 * Everything here is public C API (PyDict_New/SetItem/DelItem/Copy/GET_SIZE);
 * no dict internals are assumed, so a future CPython that changes its growth
 * policy can only cost head-room, never correctness.  The self-check below
 * discards the padding if PyDict_Copy() turns out not to clone the table.
 *
 * Why not a genuinely shared key table?
 * -------------------------------------
 * CPython's split tables (ma_values != NULL) let many dicts share one
 * PyDictKeysObject, which would remove even the memcpy.  They are not reachable
 * here, for two independent reasons:
 *
 *   1. No exported function builds a dict around a caller-supplied
 *      PyDictKeysObject.  new_dict() is static; the only split-dict producer is
 *      the instance-__dict__ machinery behind _PyObjectDict_SetItem(), which
 *      needs a heap type's ht_cached_keys, moved to internal-only headers in
 *      3.12 and given a different signature in 3.13.  Doing it by hand means
 *      redeclaring struct _dictkeysobject, whose layout changed in 3.11
 *      (dk_kind, dk_log2_size, separate unicode entries), 3.12 (PyDictValues
 *      with an embedded insertion-order array) and 3.13 (dk_refcnt semantics,
 *      free-threading).  That is exactly the kind of layout assumption this
 *      code must not make.
 *
 *   2. Even if one could be minted, it would not survive a request.  A split
 *      table only stays split while values are filled in slot order for keys
 *      that are already in the shared table; inserting an unknown key, filling
 *      out of order, or deleting anything makes insertdict() call
 *      insertion_resize() and convert to a combined table.  environ's tail is
 *      the request's HTTP_* headers, whose names and order vary per request, so
 *      the first header insert would convert every environ back to combined --
 *      paying for a values array *and* a full dictresize, i.e. strictly worse
 *      than what this file does now.
 */

#define ENVIRON_TEMPLATE_MAX_PAD 64

static PyObject *g_environ_template = NULL;        /* wsgi.url_scheme = "http"  */
#ifdef FREASTAL_TLS
static PyObject *g_environ_template_https = NULL;  /* wsgi.url_scheme = "https" */
#endif

/* sys.getsizeof(d), or -1 (with the error swallowed) if it is unavailable. */
static Py_ssize_t dict_alloc_size(PyObject *getsizeof, PyObject *d) {
    PyObject *r = PyObject_CallFunctionObjArgs(getsizeof, d, NULL);
    if (!r) { PyErr_Clear(); return -1; }
    Py_ssize_t n = PyLong_AsSsize_t(r);
    Py_DECREF(r);
    if (n < 0) PyErr_Clear();
    return n;
}

/* Build the template.  getsizeof == NULL skips the over-allocation step. */
static PyObject *environ_template_new(PyObject *url_scheme_val, PyObject *getsizeof);

static PyObject *environ_template_new(PyObject *url_scheme_val, PyObject *getsizeof) {
    wsgi_keys_t *k = &g_server.keys;

    PyObject *t = PyDict_New();
    if (!t) return NULL;

#define TSET(key, val) \
    do { if (PyDict_SetItem(t, k->key, (val)) < 0) { Py_DECREF(t); return NULL; } } while (0)

    /* Constant values, in main's insertion order. */
    TSET(wsgi_version,      k->wsgi_version_val);
    TSET(wsgi_url_scheme,   url_scheme_val);
    TSET(wsgi_multithread,  Py_False);
    TSET(wsgi_multiprocess, Py_True);
    TSET(wsgi_run_once,     Py_False);
    TSET(SERVER_NAME,       k->server_name_val);
    TSET(SERVER_PORT,       k->server_port_val);
    TSET(SERVER_SOFTWARE,   k->server_software_val);
    TSET(SCRIPT_NAME,       k->empty_str);
    if (g_server.sys_stderr)
        TSET(wsgi_errors, g_server.sys_stderr);

    /* Per-request slots.  build_environ() overwrites every one of these on
     * every request; the placeholder is never observable. */
    TSET(REQUEST_METHOD,  Py_None);
    TSET(PATH_INFO,       Py_None);
    TSET(QUERY_STRING,    Py_None);
    TSET(SERVER_PROTOCOL, Py_None);
    TSET(REMOTE_ADDR,     Py_None);
    TSET(wsgi_input,      Py_None);

#undef TSET

    if (!getsizeof) return t;

    Py_ssize_t nreal = PyDict_GET_SIZE(t);
    Py_ssize_t base  = dict_alloc_size(getsizeof, t);
    if (base < 0) return t;

    for (int i = 0; i < ENVIRON_TEMPLATE_MAX_PAD; i++) {
        char name[40];
        int  n = snprintf(name, sizeof(name), "__freastal_pad_%d__", i);
        PyObject *pad = PyUnicode_FromStringAndSize(name, (Py_ssize_t)n);
        if (!pad) { PyErr_Clear(); break; }
        int rc = PyDict_SetItem(t, pad, Py_None);
        if (rc == 0) rc = PyDict_DelItem(t, pad);
        Py_DECREF(pad);
        if (rc < 0) { PyErr_Clear(); break; }

        Py_ssize_t now = dict_alloc_size(getsizeof, t);
        if (now < 0 || now > base) break;   /* key table grew -- done */
    }

    /* A padding key must never survive into environ.  It cannot in practice
     * (PyDict_DelItem of a key inserted one line earlier), but the cost of
     * being sure is one comparison at startup. */
    if (PyDict_GET_SIZE(t) != nreal) {
        Py_DECREF(t);
        return environ_template_new(url_scheme_val, NULL);
    }

    return t;
}

static PyObject *environ_template_build(PyObject *url_scheme_val, PyObject *getsizeof) {
    PyObject *t = environ_template_new(url_scheme_val, getsizeof);
    if (!t || !getsizeof) return t;

    /* Self-check: confirm PyDict_Copy() really clones the over-allocated key
     * table.  If it does not (a CPython that dropped clone_combined_dict, or
     * one whose compaction rule rejects our template), the padding is pure
     * dead weight -- rebuild without it. */
    PyObject *probe = PyDict_Copy(t);
    if (!probe) { PyErr_Clear(); return t; }
    Py_ssize_t a = dict_alloc_size(getsizeof, t);
    Py_ssize_t b = dict_alloc_size(getsizeof, probe);
    Py_DECREF(probe);
    if (a > 0 && b > 0 && b < a) {
        Py_DECREF(t);
        t = environ_template_new(url_scheme_val, NULL);
    }
    return t;
}

/*
 * Called from server_init() once the interned keys, sys.stderr and the
 * BytesIO singleton are in place.  Returns 0 on success, -1 on failure.
 */
int wsgi_init_environ_template(void) {
    wsgi_keys_t *k = &g_server.keys;

    /* Only used to size the template, so a failure here is not fatal --
     * we simply skip the over-allocation step. */
    PyObject *sys_mod = PyImport_ImportModule("sys");
    PyObject *getsizeof = NULL;
    if (sys_mod) {
        getsizeof = PyObject_GetAttrString(sys_mod, "getsizeof");
        Py_DECREF(sys_mod);
    }
    if (!getsizeof) PyErr_Clear();

    Py_XDECREF(g_environ_template);
    g_environ_template = environ_template_build(k->wsgi_url_scheme_val, getsizeof);
#ifdef FREASTAL_TLS
    Py_XDECREF(g_environ_template_https);
    g_environ_template_https =
        environ_template_build(k->wsgi_url_scheme_https_val, getsizeof);
#endif

    Py_XDECREF(getsizeof);

    if (!g_environ_template) return -1;
#ifdef FREASTAL_TLS
    if (!g_environ_template_https) return -1;
#endif
    return 0;
}

static PyObject *build_environ(client_t *c) {
    wsgi_keys_t *k = &g_server.keys;

#ifdef FREASTAL_TLS
    PyObject *tmpl = c->tls ? g_environ_template_https : g_environ_template;
#else
    PyObject *tmpl = g_environ_template;
#endif
    if (unlikely(!tmpl)) {
        PyErr_SetString(PyExc_RuntimeError, "freastal: environ template not initialised");
        return NULL;
    }

    /* Clones the pre-built, pre-indexed, over-allocated key table.  The 9-10
     * constant entries arrive already set; the 6 per-request slots arrive as
     * Py_None placeholders and are overwritten unconditionally below. */
    PyObject *env = PyDict_Copy(tmpl);
    if (!env) return NULL;

#define SET(key, val) \
    do { if (PyDict_SetItem(env, k->key, (val)) < 0) \
         { Py_DECREF(env); return NULL; } } while (0)

#define SET_NEW(key, expr) \
    do { PyObject *_v = (expr); \
         if (!_v || PyDict_SetItem(env, k->key, _v) < 0) \
         { Py_XDECREF(_v); Py_DECREF(env); return NULL; } \
         Py_DECREF(_v); } while (0)

    /* Per-request: REQUEST_METHOD */
    SET_NEW(REQUEST_METHOD,
            PyUnicode_FromStringAndSize(c->method, (Py_ssize_t)c->method_len));

    /* Per-request: PATH_INFO and QUERY_STRING (split on '?') */
    {
        const char *qmark = memchr(c->path, '?', c->path_len);
        if (qmark) {
            SET_NEW(PATH_INFO,
                    PyUnicode_FromStringAndSize(c->path, (Py_ssize_t)(qmark - c->path)));
            SET_NEW(QUERY_STRING,
                    PyUnicode_FromStringAndSize(qmark + 1,
                        (Py_ssize_t)(c->path + c->path_len - qmark - 1)));
        } else {
            SET_NEW(PATH_INFO,
                    PyUnicode_FromStringAndSize(c->path, (Py_ssize_t)c->path_len));
            SET(QUERY_STRING, k->empty_str);
        }
    }

    /* SERVER_PROTOCOL */
    SET(SERVER_PROTOCOL, c->minor_version == 1 ? k->http_1_1 : k->http_1_0);

    /* REMOTE_ADDR — cached per-connection; IP doesn't change across keep-alive requests */
    if (!c->peer_addr_obj) {
        c->peer_addr_obj = PyUnicode_FromString(c->peer_addr);
        if (!c->peer_addr_obj) { Py_DECREF(env); return NULL; }
    }
    SET(REMOTE_ADDR, c->peer_addr_obj);

    /* wsgi.input – reuse singleton BytesIO(b"") for zero-body requests (GET, HEAD, etc.).
     * No seek needed: an empty BytesIO has only one possible position, so it can be
     * handed to the app as-is.  Safe to share because WSGI dispatch is serialized. */
    if (c->content_length == 0) {
        if (PyDict_SetItem(env, k->wsgi_input, g_server.empty_wsgi_input) < 0) {
            Py_DECREF(env); return NULL;
        }
    } else {
        const char *body_ptr = c->read_buf + c->headers_end;
        Py_ssize_t  body_len = (Py_ssize_t)c->read_len - c->headers_end;
        if (body_len < 0) body_len = 0;
        if ((size_t)body_len > c->content_length) body_len = (Py_ssize_t)c->content_length;
        PyObject *body_bytes = PyBytes_FromStringAndSize(body_ptr, body_len);
        if (!body_bytes) { Py_DECREF(env); return NULL; }
        PyObject *wsgi_input = PyObject_CallFunctionObjArgs(g_server.io_bytesio, body_bytes, NULL);
        Py_DECREF(body_bytes);
        if (!wsgi_input) { Py_DECREF(env); return NULL; }
        int rc = PyDict_SetItem(env, k->wsgi_input, wsgi_input);
        Py_DECREF(wsgi_input);
        if (rc < 0) { Py_DECREF(env); return NULL; }
    }

    /* Per-request headers: HTTP_XXX, CONTENT_TYPE, CONTENT_LENGTH */
    for (size_t i = 0; i < c->num_headers; i++) {
        const char *hn = c->headers[i].name;
        size_t      hnl = c->headers[i].name_len;
        const char *hv = c->headers[i].value;
        size_t      hvl = c->headers[i].value_len;

        if (hnl == 12 && strncasecmp(hn, "content-type", 12) == 0) {
            SET_NEW(CONTENT_TYPE, PyUnicode_FromStringAndSize(hv, (Py_ssize_t)hvl));
            continue;
        }
        if (hnl == 14 && strncasecmp(hn, "content-length", 14) == 0) {
            SET_NEW(CONTENT_LENGTH, PyUnicode_FromStringAndSize(hv, (Py_ssize_t)hvl));
            continue;
        }

        /* General header → HTTP_UPPER_CASE_WITH_UNDERSCORES */
        char key_buf[256];
        if (hnl + 5 >= sizeof(key_buf)) continue; /* skip absurdly long names */
        key_buf[0] = 'H'; key_buf[1] = 'T'; key_buf[2] = 'T';
        key_buf[3] = 'P'; key_buf[4] = '_';
        for (size_t j = 0; j < hnl; j++) {
            unsigned char ch = (unsigned char)hn[j];
            key_buf[5 + j] = (char)(ch >= 'a' && ch <= 'z'
                                        ? ch - 32
                                        : (ch == '-' ? '_' : ch));
        }
        key_buf[5 + hnl] = '\0';

        PyObject *hdr_key = PyUnicode_FromStringAndSize(key_buf, (Py_ssize_t)(hnl + 5));

        PyObject *val = PyUnicode_FromStringAndSize(hv, (Py_ssize_t)hvl);
        int rc = 0;
        if (hdr_key && val) rc = PyDict_SetItem(env, hdr_key, val);
        Py_XDECREF(hdr_key); Py_XDECREF(val);
        if (rc < 0) { Py_DECREF(env); return NULL; }
    }

#undef SET
#undef SET_NEW

    return env;
}

/* ---- 500 error response ---- */

static void send_500(client_t *c) {
    static const char body[] = "Internal Server Error";
    static const char response[] =
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 21\r\n"
        "Connection: close\r\n\r\n"
        "Internal Server Error";
    (void)body;

    c->keep_alive = false;
    memcpy(c->resp_hdr, response, sizeof(response) - 1);
    c->resp_hdr_len = sizeof(response) - 1;
    c->resp_body = NULL;
    write_response(c);
}

/* ---- Main WSGI dispatch ---- */

void wsgi_call_application(client_t *c) {
    /* GIL must be held by caller */

    PyObject *environ = build_environ(c);
    if (!environ) {
        PyErr_Clear();
        send_500(c);
        return;
    }

    StartResponse *sr = (StartResponse *)StartResponse_type.tp_alloc(&StartResponse_type, 0);
    if (!sr) {
        Py_DECREF(environ);
        PyErr_Clear();
        send_500(c);
        return;
    }
    sr->client = c;

    PyObject *result = PyObject_CallFunctionObjArgs(g_server.app, environ, (PyObject *)sr, NULL);
    Py_DECREF(environ);
    Py_DECREF(sr);

    if (!result) {
        PyErr_Print();
        send_500(c);
        return;
    }

    PyObject *body = collect_body(result);
    Py_DECREF(result);

    if (!body) {
        PyErr_Print();
        send_500(c);
        return;
    }

    if (!c->resp_status) {
        /* App never called start_response */
        Py_DECREF(body);
        PyErr_SetString(PyExc_RuntimeError, "WSGI app did not call start_response");
        PyErr_Print();
        send_500(c);
        return;
    }

    Py_ssize_t body_len = PyBytes_GET_SIZE(body);
    if (format_response_headers(c, body_len) < 0) {
        Py_DECREF(body);
        PyErr_Clear();
        send_500(c);
        return;
    }

    c->resp_body = body; /* write_response holds this until on_write fires */
    write_response(c);
}

/* ---- Module-level init ---- */

int wsgi_init(PyObject *module) {
    if (PyType_Ready(&StartResponse_type) < 0) return -1;

    g_noop_write = PyCFunction_New(&_noop_write_method, NULL);
    if (!g_noop_write) return -1;

    Py_INCREF(&StartResponse_type);
    if (PyModule_AddObject(module, "StartResponse", (PyObject *)&StartResponse_type) < 0) {
        Py_DECREF(&StartResponse_type);
        return -1;
    }

    return 0;
}
