#include "server.h"
#include "wsgi.h"
#include "asgi.h"
#include "hdrcache.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

server_t g_server;

/* ---- Client pool ---- */

/* Reserve a slab so most allocs are free-list pops (no malloc).
 *
 * The slab is handed out with a bump pointer rather than pre-linked into a
 * free list: writing next_free into all 4096 objects touched a byte inside
 * nearly every 16KB page of the 107MB reservation, which made 65MB of it
 * resident at startup for a server that may only ever see a few connections.
 * calloc()'s pages are zero-fill-on-demand, so leaving them untouched costs
 * only virtual address space until a connection actually needs one. */
static int pool_init(int cap) {
    g_server.slab = calloc(cap, sizeof(client_t));
    if (!g_server.slab) return -1;
    g_server.pool_cap = cap;
    g_server.pool_used = 0;
    g_server.free_list = NULL;
    return 0;
}

client_t *client_alloc(void) {
    client_t *c;
    if (g_server.free_list) {
        c = g_server.free_list;
        g_server.free_list = c->next_free;
    } else if (g_server.pool_used < g_server.pool_cap) {
        c = (client_t *)((char *)g_server.slab
                         + (size_t)g_server.pool_used * sizeof(client_t));
        g_server.pool_used++;
    } else {
        /* Pool exhausted – fall back to malloc */
        c = (client_t *)malloc(sizeof(client_t));
        if (!c) return NULL;
    }
    /*
     * Only the scalar prefix is cleared -- see the static assertions in
     * server.h.  Zeroing all 27384 bytes cost about 260ns per accept and
     * evicted L1 and L2 wholesale, to initialise buffers whose contents are
     * already unreachable: read_buf is bounded by read_len, resp_hdr by
     * resp_hdr_len and headers[] by num_headers, and all three counters are
     * in the cleared prefix.
     */
    memset(c, 0, CLIENT_ZERO_LEN);
    return c;
}

void client_free(client_t *c) {
    /* Check whether this client came from the slab */
    char *base  = (char *)g_server.slab;
    char *end   = base + g_server.pool_cap * sizeof(client_t);
    char *ptr   = (char *)c;
    if (ptr >= base && ptr < end) {
        c->next_free = g_server.free_list;
        g_server.free_list = c;
    } else {
        free(c);
    }
}

/* Python objects cached for the whole connection, not just one request.
 * The GIL must be held. */
static void client_clear_conn_cache(client_t *c) {
    Py_CLEAR(c->peer_addr_obj);
    Py_CLEAR(c->asgi_client_obj);
    Py_CLEAR(c->asgi_capsule);
}

void client_reset(client_t *c) {
    /*
     * A read may have delivered more than one request.  Everything past the
     * request we just answered belongs to the next one, so slide it to the
     * front of the buffer rather than dropping it.  consumed == 0 means no
     * request was ever parsed, in which case there is nothing to keep.
     */
    int consumed = c->headers_end + (int)c->content_length;
    int leftover = (consumed > 0 && c->read_len > consumed)
                       ? c->read_len - consumed : 0;
    if (leftover > 0)
        memmove(c->read_buf, c->read_buf + consumed, (size_t)leftover);

    c->read_len = leftover;
    c->last_len = 0;
    c->method = NULL;
    c->method_len = 0;
    c->path = NULL;
    c->path_len = 0;
    c->minor_version = 0;
    c->num_headers = 0;
    c->headers_end = 0;
    c->content_length = 0;
    c->resp_hdr_len = 0;
    /* resp_body / resp_status / resp_pyheaders cleared in on_write */
}

/* ---- Forward declarations ---- */

static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void on_write(uv_write_t *req, int status);
static void on_close(uv_handle_t *handle);
static void on_new_connection(uv_stream_t *server, int status);
#ifdef FREASTAL_TLS
static void on_tls_hs_write(uv_write_t *req, int status);
static void tls_hs_send(client_t *c, ptls_buffer_t *outbuf);
static void tls_on_read_data(client_t *c, uv_stream_t *stream, const char *data, size_t nread);
static void tls_write_response_impl(client_t *c);
static void tls_spill_drain(client_t *c);
static void tls_read_flow(client_t *c, uv_stream_t *stream);
static bool tls_send_close_notify(client_t *c);
static void on_tls_close_notify_write(uv_write_t *req, int status);
#endif

/* ---- libuv I/O callbacks ---- */

/*
 * Point libuv's read buffer at the unused tail of the client's embedded
 * read_buf.  This avoids any per-read allocation.
 */
static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)suggested_size;
    client_t *c = (client_t *)handle;
#ifdef FREASTAL_TLS
    if (c->tls) {
        /*
         * Deliberately not bounded by the free space in read_buf, the way the
         * plaintext branch below is: libuv is being handed a *ciphertext*
         * buffer, and how much plaintext it becomes is not known until
         * ptls_receive() has run.  Whatever read_buf cannot take is kept in
         * the spill and folded back in by tls_spill_drain().
         */
        buf->base = c->tls_enc;
        buf->len  = TLS_ENC_BUF_SIZE;
        return;
    }
#endif
    int remaining = READ_BUF_SIZE - c->read_len;
    if (remaining <= 0) {
        buf->base = NULL;
        buf->len  = 0;
        return;
    }
    buf->base = c->read_buf + c->read_len;
    buf->len  = (size_t)remaining;
}

int http_dispatch(client_t *c, uv_stream_t *stream) {
    c->num_headers = MAX_HEADERS;
    int pret = phr_parse_request(
        c->read_buf, (size_t)c->read_len,
        &c->method,  &c->method_len,
        &c->path,    &c->path_len,
        &c->minor_version,
        c->headers, &c->num_headers,
        (size_t)c->last_len
    );

    if (pret == -2) { c->last_len = c->read_len; return 0; }

    if (pret < 0) {
        static const char bad_req[] =
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        uv_buf_t b = uv_buf_init((char *)bad_req, sizeof(bad_req) - 1);
        uv_write(&c->write_req, stream, &b, 1, NULL);
        uv_close((uv_handle_t *)&c->handle, on_close);
        return -1;
    }

    c->headers_end = pret;
    c->content_length = 0;
    c->keep_alive = (c->minor_version == 1);

    for (size_t i = 0; i < c->num_headers; i++) {
        const char *n  = c->headers[i].name;
        size_t      nl = c->headers[i].name_len;
        const char *v  = c->headers[i].value;
        size_t      vl = c->headers[i].value_len;

        if (nl == 14 && strncasecmp(n, "content-length", 14) == 0) {
            char tmp[32];
            size_t copy = (vl < sizeof(tmp) - 1) ? vl : sizeof(tmp) - 1;
            memcpy(tmp, v, copy); tmp[copy] = '\0';
            c->content_length = (size_t)strtoul(tmp, NULL, 10);
        } else if (nl == 10 && strncasecmp(n, "connection", 10) == 0) {
            if (vl >= 5 && strncasecmp(v, "close", 5) == 0)
                c->keep_alive = false;
            else if (vl >= 10 && strncasecmp(v, "keep-alive", 10) == 0)
                c->keep_alive = true;
        }
    }

    size_t body_received = (size_t)(c->read_len - pret);
    if (body_received < c->content_length) return 0;

    /*
     * Reading stays armed across the dispatch.  Disarming it here and
     * re-arming in on_write cost one extra kernel round trip per request on
     * Linux, for an epoll registration change that was never needed:
     * uv__io_stop() zeroes w->events without issuing EPOLL_CTL_DEL, so the
     * next uv__io_poll() picks EPOLL_CTL_ADD for an fd that is still
     * registered, takes EEXIST, and has to resubmit as EPOLL_CTL_MOD
     * (libuv 1.52.1 src/unix/core.c and src/unix/linux.c).  Measured on
     * Linux 7.0 aarch64 with 20k keep-alive requests: 2 io_uring_enter per
     * request before, 1 after -- 5.01 syscalls/req down to 4.01.
     *
     * in_flight is what keeps the protocol correct in its place: a pipelined
     * request that arrives now accumulates in read_buf and is dispatched by
     * on_write, so responses cannot interleave on the wire.
     *
     * The encrypted path used to stop the read here, because a TLS read
     * cannot be bounded by the free space in read_buf.  It no longer needs
     * to: what does not fit is kept in the spill (see tls_spill_drain) and
     * tls_read_flow() stops the read only once there is genuinely nowhere to
     * put more.
     */
    c->in_flight = true;
    GIL_LOCK();
    if (g_server.asgi_mode)
        asgi_dispatch(c);
    else
        wsgi_call_application(c);
    GIL_UNLOCK();
    return 1;
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    client_t *c = (client_t *)stream;

    if (nread < 0) {
        /*
         * Reading is armed while a response is in flight, so this can now
         * fire with a write outstanding.  Closing here would complete that
         * write with UV_ECANCELED and on_write would then close a second
         * time, which libuv aborts on -- so leave the close to on_write, and
         * only make sure it takes the close branch when it runs.  The
         * per-request Python objects belong to that response and must not be
         * cleared underneath it either.
         */
        if (c->in_flight) {
            c->keep_alive = false;
            c->read_armed = false;
            uv_read_stop(stream);
            return;
        }
        GIL_LOCK();
        Py_CLEAR(c->resp_status);
        Py_CLEAR(c->resp_pyheaders);
        Py_CLEAR(c->resp_body);
        client_clear_conn_cache(c);
        GIL_UNLOCK();
        uv_close((uv_handle_t *)&c->handle, on_close);
        return;
    }
    if (nread == 0) return;

#ifdef FREASTAL_TLS
    if (c->tls) {
        tls_on_read_data(c, stream, buf->base, (size_t)nread);
        return;
    }
#endif

    c->read_len += (int)nread;

    /* While a response is in flight the bytes just accumulate; on_write
     * dispatches them once the wire is free again. */
    if (likely(!c->in_flight) && unlikely(http_dispatch(c, stream) < 0))
        return;                                     /* connection closed */

    /*
     * The one case that still has to disarm the read: read_buf is full and
     * only the in-flight response can make room.  alloc_cb answers a full
     * buffer with a zero-length uv_buf_t, which libuv reports as UV_ENOBUFS
     * and which would kill a connection that is merely pipelining hard.
     * on_write re-arms once client_reset() has slid the leftover down.
     *
     * A full buffer with nothing in flight is a different thing -- a request
     * whose headers exceed READ_BUF_SIZE -- and still ends in UV_ENOBUFS and
     * a closed connection, as before.
     */
    if (unlikely(c->read_len >= READ_BUF_SIZE) && c->in_flight) {
        uv_read_stop(stream);
        c->read_armed = false;
    }
}

/*
 * write_response – send headers and body together as a single writev.
 */
void write_response(client_t *c) {
#ifdef FREASTAL_TLS
    if (c->tls) { tls_write_response_impl(c); return; }
#endif
    c->write_bufs[0] = uv_buf_init(c->resp_hdr, (size_t)c->resp_hdr_len);

    int nbufs = 1;
    if (c->resp_body && PyBytes_GET_SIZE(c->resp_body) > 0) {
        c->write_bufs[1] = uv_buf_init(
            PyBytes_AS_STRING(c->resp_body),
            (size_t)PyBytes_GET_SIZE(c->resp_body)
        );
        nbufs = 2;
    }

    uv_write(&c->write_req, (uv_stream_t *)&c->handle,
             c->write_bufs, (unsigned int)nbufs, on_write);
}

static void on_write(uv_write_t *req, int status) {
    client_t *c = CONTAINER_OF(req, client_t, write_req);
#ifdef FREASTAL_TLS
    /* uv_write held a pointer into every block of the chain until now; this is
     * the earliest point at which they may go back to the pool.  It runs before
     * the close branch below, so a connection torn down here still releases
     * them; tls_conn_free() repeats the call for the paths that never got a
     * write, and it is idempotent. */
    if (c->tls) tls_release_wbuf(c);
#endif

    GIL_LOCK();
    Py_CLEAR(c->resp_status);
    Py_CLEAR(c->resp_pyheaders);
    Py_CLEAR(c->resp_body);
    Py_CLEAR(c->asgi_task);
    if (status < 0 || !c->keep_alive)
        client_clear_conn_cache(c);
    GIL_UNLOCK();

    if (status < 0 || !c->keep_alive) {
#ifdef FREASTAL_TLS
        /*
         * The one close a TLS peer is entitled to see coming.  This branch is
         * the whole of freastal's clean shutdown -- `Connection: close`, an
         * HTTP/1.0 request, or a peer that went away mid-response -- and the
         * three guards are what separate it from the closes that must stay
         * silent.  status < 0 means the socket already refused this response,
         * so a further write would only fail; tls_broken means the record
         * layer is unusable and an alert encrypted with it would be garbage;
         * !tls_hs_done means there are no application keys to encrypt it with
         * at all (unreachable from here, since on_write runs only behind a
         * response, but the alert is only meaningful once the keys exist and
         * saying so is cheaper than proving it).  Every other close path --
         * tls_read_failed(), the oversized request in tls_read_flow(), the
         * out-of-memory bail in tls_write_response_impl() -- calls uv_close()
         * directly and is deliberately not routed through here.
         *
         * Without this a client that reads to EOF cannot tell an orderly
         * close from a truncation attack, and OpenSSL responds by discarding
         * the session, so a NewSessionTicket issued on this connection can
         * never be resumed from (#57).
         */
        if (c->tls && status >= 0 && !c->tls_broken && c->tls_hs_done &&
            tls_send_close_notify(c))
            return;                 /* on_tls_close_notify_write() closes */
#endif
        uv_close((uv_handle_t *)&c->handle, on_close);
        return;
    }

    /* Keep-alive: reset for the next request */
    client_reset(c);
    c->in_flight = false;

#ifdef FREASTAL_TLS
    /* client_reset() has just slid read_buf down, so anything a read could not
     * fit into it goes back in now -- before the parse below, which is what
     * makes the request it belongs to complete. */
    if (c->tls) tls_spill_drain(c);
#endif

    /* A pipelined request may already be buffered.  Dispatch it directly. */
    if (c->read_len > 0 && http_dispatch(c, (uv_stream_t *)&c->handle) < 0)
        return;

#ifdef FREASTAL_TLS
    if (c->tls) { tls_read_flow(c, (uv_stream_t *)&c->handle); return; }
#endif

    /* Reading is normally still armed, so there is nothing to do here.  It is
     * only ever off because on_read hit a full read_buf, and it goes back on
     * as soon as read_buf has room and no response is outstanding. */
    if (unlikely(!c->read_armed) && !c->in_flight) {
        c->read_armed = true;
        uv_read_start((uv_stream_t *)&c->handle, alloc_cb, on_read);
    }
}

static void on_close(uv_handle_t *handle) {
    client_t *c = (client_t *)handle;
    /* Per-request objects are cleared before uv_close, but not every teardown
     * path goes through on_write (a malformed request and the TLS errors close
     * directly), and the slab recycles this client_t. This is the one funnel
     * they all share; on the ordinary paths the cache is already empty and the
     * GIL is not taken. */
    if (c->peer_addr_obj || c->asgi_client_obj || c->asgi_capsule) {
        GIL_LOCK();
        client_clear_conn_cache(c);
        GIL_UNLOCK();
    }
#ifdef FREASTAL_TLS
    tls_conn_free(c);
#endif
    client_free(c);
}

static void on_new_connection(uv_stream_t *server, int status) {
    if (status < 0) return;

    client_t *c = client_alloc();
    if (unlikely(!c)) {
        /* Pool and malloc exhausted – accept and immediately drop */
        uv_tcp_t tmp;
        uv_tcp_init(g_server.loop, &tmp);
        if (uv_accept(server, (uv_stream_t *)&tmp) == 0)
            uv_close((uv_handle_t *)&tmp, NULL);
        return;
    }

    uv_tcp_init(g_server.loop, &c->handle);

    if (uv_accept(server, (uv_stream_t *)&c->handle) != 0) {
        uv_close((uv_handle_t *)&c->handle, on_close);
        return;
    }

    /* Disable Nagle – critical for low-latency small responses */
    uv_tcp_nodelay(&c->handle, 1);

#ifdef FREASTAL_TLS
    if (g_server.tls_enabled) tls_conn_init(c);
#endif

    /* Cache peer address and port once per connection */
    struct sockaddr_storage addr;
    int addrlen = sizeof(addr);
    if (uv_tcp_getpeername(&c->handle, (struct sockaddr *)&addr, &addrlen) == 0) {
        uv_ip4_name((const struct sockaddr_in *)&addr, c->peer_addr, PEER_ADDR_LEN);
        c->peer_port = ntohs(((const struct sockaddr_in *)&addr)->sin_port);
    } else {
        c->peer_addr[0] = '\0';
        c->peer_port = 0;
    }

    c->read_armed = true;
    uv_read_start((uv_stream_t *)&c->handle, alloc_cb, on_read);
}

/* ---- Key internment ---- */

static int init_wsgi_keys(void) {
    wsgi_keys_t *k = &g_server.keys;

#define INTERN(field, str) \
    do { k->field = PyUnicode_InternFromString(str); \
         if (!k->field) return -1; } while (0)

    INTERN(REQUEST_METHOD,  "REQUEST_METHOD");
    INTERN(SCRIPT_NAME,     "SCRIPT_NAME");
    INTERN(PATH_INFO,       "PATH_INFO");
    INTERN(QUERY_STRING,    "QUERY_STRING");
    INTERN(SERVER_NAME,     "SERVER_NAME");
    INTERN(SERVER_PORT,     "SERVER_PORT");
    INTERN(SERVER_PROTOCOL, "SERVER_PROTOCOL");
    INTERN(SERVER_SOFTWARE, "SERVER_SOFTWARE");
    INTERN(CONTENT_TYPE,    "CONTENT_TYPE");
    INTERN(CONTENT_LENGTH,  "CONTENT_LENGTH");
    INTERN(REMOTE_ADDR,     "REMOTE_ADDR");
    INTERN(wsgi_version,    "wsgi.version");
    INTERN(wsgi_url_scheme, "wsgi.url_scheme");
    INTERN(wsgi_input,      "wsgi.input");
    INTERN(wsgi_errors,     "wsgi.errors");
    INTERN(wsgi_multithread,   "wsgi.multithread");
    INTERN(wsgi_multiprocess,  "wsgi.multiprocess");
    INTERN(wsgi_run_once,      "wsgi.run_once");
    INTERN(http_1_0,          "HTTP/1.0");
    INTERN(http_1_1,          "HTTP/1.1");
    INTERN(wsgi_url_scheme_val, "http");
#ifdef FREASTAL_TLS
    INTERN(wsgi_url_scheme_https_val, "https");
#endif
    INTERN(empty_str,          "");
    INTERN(server_software_val, "freastal/1.0");

#undef INTERN

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", g_server.port);
    k->server_port_val = PyUnicode_FromString(port_str);
    if (!k->server_port_val) return -1;

    k->server_name_val = PyUnicode_FromString(g_server.host);
    if (!k->server_name_val) return -1;

    /* wsgi.version = (1, 0) */
    k->wsgi_version_val = PyTuple_Pack(2, PyLong_FromLong(1), PyLong_FromLong(0));
    if (!k->wsgi_version_val) return -1;

    return 0;
}

/* ---- Server init / run ---- */

/*
 * Will libuv honour UV_TCP_REUSEPORT on THIS machine?
 *
 * setup.py can only answer a different question -- does the enum exist in the
 * uv.h we compiled against -- and that answer is not the one callers need.  It
 * is true on macOS, where every REUSEPORT bind then fails with ENOTSUP, and it
 * is fixed at build time for a wheel that gets run on other machines.
 *
 * Asking the kernel instead is worse, not better.  macOS *has* SO_REUSEPORT:
 * setsockopt succeeds, a second bind to the same port succeeds, and then the
 * last binder takes every connection while the first gets none -- measured
 * here at 40 out of 40.  That is BSD rebind semantics, not Linux's
 * connection-distributing SO_REUSEPORT (FreeBSD added a separate option,
 * SO_REUSEPORT_LB, to get the Linux behaviour, and that is what libuv uses
 * there).  So a setsockopt probe answers a question nobody asked -- "does the
 * option exist" -- and hands back a server where one worker serves everything.
 *
 * Which makes libuv's refusal a feature: it tracks the distinction we actually
 * need.  And its own header is the argument against writing that list down
 * anywhere in here -- uv.h, verbatim:
 *
 *     This flag is available only on Linux 3.9+, DragonFlyBSD 3.6+,
 *     FreeBSD 12.0+, Solaris 11.4, and AIX 7.2.5+ for now.
 *
 * Note the version floors, and the "for now".  A platform *name* is not the
 * capability either: Linux 3.8 and FreeBSD 11 compile the enum and fail the
 * behaviour, which is the same mistake as the compile-time probe one layer
 * down.  Any table we kept here would be wrong for some machine and stale for
 * the rest, so keep none: ask libuv directly, by doing the exact bind serve()
 * would do, on an ephemeral loopback port, and throwing the socket away.  The
 * side effect is one socket held for the length of a bind(); the answer is
 * cached because it cannot change under a running process.
 */
int server_reuseport_supported(void) {
#ifndef FREASTAL_REUSEPORT
    /* Built against a uv.h with no UV_TCP_REUSEPORT: there is no flag to pass,
     * so the honest answer is no, whatever the running kernel could do. */
    return 0;
#else
    static int cached = -1;
    if (cached >= 0)
        return cached;

    uv_loop_t loop;
    if (uv_loop_init(&loop) != 0) {
        /* Don't cache a failure that says nothing about REUSEPORT. */
        return 0;
    }

    int supported = 0;
    uv_tcp_t probe;
    if (uv_tcp_init(&loop, &probe) == 0) {
        struct sockaddr_in addr;
        uv_ip4_addr("127.0.0.1", 0, &addr);
        supported = uv_tcp_bind(&probe, (const struct sockaddr *)&addr,
                                UV_TCP_REUSEPORT) == 0;
        uv_close((uv_handle_t *)&probe, NULL);
    }
    /* uv_loop_close() returns EBUSY unless the close callback has run. */
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);

    cached = supported;
    return cached;
#endif
}

int server_init(PyObject *app, const char *host, int port, bool reuse_port,
                const char *certfile, const char *keyfile, int listen_fd) {
#ifndef FREASTAL_TLS
    /* This build has no picotls, so a certfile cannot be honoured.  Accepting
     * it and carrying on is a silent downgrade: the server comes up in
     * plaintext on the port the caller meant to be TLS, serves every request
     * in the clear, and reports nothing.  Whether OpenSSL was present is a
     * build-time fact, but it has to be visible at runtime or it turns into
     * that. */
    if (certfile != NULL || keyfile != NULL) {
        PyErr_SetString(PyExc_RuntimeError,
            "freastal: this build has no TLS support, so certfile/keyfile "
            "cannot be honoured -- serving would fall back to plaintext on "
            "the port you meant to be TLS. Rebuild with OpenSSL headers "
            "available, or install a wheel from PyPI. freastal.has_tls "
            "reports what this build can do.");
        return -1;
    }
#endif
    memset(&g_server, 0, sizeof(g_server));

    Py_INCREF(app);
    g_server.app  = app;
    strncpy(g_server.host, host, sizeof(g_server.host) - 1);
    g_server.port = port;

    if (pool_init(4096) < 0) return -1;

    if (init_wsgi_keys() < 0) return -1;

    if (hdr_cache_init() < 0) return -1;

    /* Cache io.BytesIO */
    PyObject *io = PyImport_ImportModule("io");
    if (!io) return -1;
    g_server.io_bytesio = PyObject_GetAttrString(io, "BytesIO");
    Py_DECREF(io);
    if (!g_server.io_bytesio) return -1;

    /* Cache sys.stderr */
    g_server.sys_stderr = PySys_GetObject("stderr"); /* borrowed ref – no INCREF */

    /* Pre-create BytesIO(b"") singleton reused for every zero-body request */
    {
        PyObject *empty_b = PyBytes_FromStringAndSize("", 0);
        if (!empty_b) return -1;
        g_server.empty_wsgi_input = PyObject_CallFunctionObjArgs(
            g_server.io_bytesio, empty_b, NULL);
        Py_DECREF(empty_b);
        if (!g_server.empty_wsgi_input) return -1;
    }

    /* Pre-build the environ template (needs the keys, sys.stderr and the
     * BytesIO singleton above). */
    if (wsgi_init_environ_template() < 0) return -1;

    g_server.loop = uv_default_loop();

    uv_tcp_init(g_server.loop, &g_server.handle);

    if (listen_fd >= 0) {
        /* A listening socket the caller already bound.  freastal/__init__.py
         * binds it once in the parent and hands the same socket to every
         * worker, because libuv only honours UV_TCP_REUSEPORT where the kernel
         * actually distributes connections -- letting each worker bind for
         * itself makes workers>1 impossible everywhere else (EADDRINUSE for
         * all but the first), and sharing one bound socket needs no flag at all.
         *
         * dup() so ownership is unambiguous: libuv closes whatever fd it is
         * given when the handle closes, and the caller's socket object closes
         * its own.  Handing the same descriptor to both is a double close, and
         * the second one lands on whatever unrelated fd got that number next. */
        int owned = dup(listen_fd);
        if (owned < 0) {
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
        int rc = uv_tcp_open(&g_server.handle, (uv_os_sock_t)owned);
        if (rc != 0) {
            close(owned);
            PyErr_Format(PyExc_OSError, "freastal: uv_tcp_open failed on fd %d: %s",
                         listen_fd, uv_strerror(rc));
            return -1;
        }
    } else {
        struct sockaddr_in addr;
        /* uv_ip4_addr() fills in the family and the port before it parses the
         * address, so a failure it does not report leaves a well-formed
         * sockaddr for 0.0.0.0 on the requested port.  serve(host="localhost")
         * therefore used to listen on every interface, on the right port, and
         * behave correctly in every visible way -- which is why it went
         * unnoticed.  A caller asking for loopback got a public listener. */
        int rc = uv_ip4_addr(host, port, &addr);
        if (rc != 0) {
            PyErr_Format(PyExc_ValueError,
                "freastal: host must be a dotted-quad IPv4 address, not %s -- "
                "freastal does not resolve names. Use 127.0.0.1 for loopback, "
                "or 0.0.0.0 for every interface.", host);
            return -1;
        }

        /* UV_TCP_REUSEPORT availability is probed at build time by setup.py and
         * re-exported as _freastal.HAS_REUSE_PORT, so a caller that asks for it
         * on a build without it is refused in Python rather than having the
         * request quietly dropped here. */
#ifdef FREASTAL_REUSEPORT
        unsigned int bind_flags = reuse_port ? UV_TCP_REUSEPORT : 0;
#else
        (void)reuse_port;
        unsigned int bind_flags = 0;
#endif
        /* The errno matters: ENOTSUP (libuv refusing UV_TCP_REUSEPORT on this
         * platform) and EADDRINUSE are very different problems and used to be
         * reported with the same bare message. */
        rc = uv_tcp_bind(&g_server.handle, (const struct sockaddr *)&addr, bind_flags);
        if (rc != 0) {
            PyErr_Format(PyExc_OSError, "freastal: uv_tcp_bind failed on %s:%d: %s",
                         host, port, uv_strerror(rc));
            return -1;
        }
    }

    int rc = uv_listen((uv_stream_t *)&g_server.handle, LISTEN_BACKLOG, on_new_connection);
    if (rc != 0) {
        PyErr_Format(PyExc_OSError, "freastal: uv_listen failed on %s:%d: %s",
                     host, port, uv_strerror(rc));
        return -1;
    }

#ifdef FREASTAL_TLS
    if (certfile && keyfile) {
        if (tls_server_init(certfile, keyfile) < 0)
            return -1;
    }
#endif

    return 0;
}

void server_run(void) {
    /*
     * Release the GIL for the event loop.  libuv callbacks re-acquire it
     * via GIL_LOCK() before touching any Python objects.
     */
    Py_BEGIN_ALLOW_THREADS
    uv_run(g_server.loop, UV_RUN_DEFAULT);
    Py_END_ALLOW_THREADS
}


#ifdef FREASTAL_TLS

typedef struct {
    uv_write_t req;
    client_t  *client;
    /* data follows immediately after this struct in the allocation */
} tls_hs_write_t;

static void on_tls_hs_write(uv_write_t *req, int status) {
    tls_hs_write_t *hw = (tls_hs_write_t *)req;
    client_t *c = hw->client;
    free(hw);
    if (status < 0)
        uv_close((uv_handle_t *)&c->handle, on_close);
}

static void tls_hs_send(client_t *c, ptls_buffer_t *outbuf) {
    if (outbuf->off == 0) { ptls_buffer_dispose(outbuf); return; }
    size_t len = outbuf->off;
    tls_hs_write_t *hw = malloc(sizeof(tls_hs_write_t) + len);
    if (!hw) { ptls_buffer_dispose(outbuf); return; }
    hw->client = c;
    memcpy((char *)hw + sizeof(tls_hs_write_t), outbuf->base, len);
    ptls_buffer_dispose(outbuf);
    uv_buf_t uvbuf = uv_buf_init((char *)hw + sizeof(tls_hs_write_t), (unsigned)len);
    uv_write(&hw->req, (uv_stream_t *)&c->handle, &uvbuf, 1, on_tls_hs_write);
}

/*
 * Overflow plaintext.
 *
 * alloc_cb cannot bound a TLS read by the free space in read_buf, so a read
 * can decrypt to more plaintext than read_buf has room for.  This used to end
 * the connection; it now keeps the surplus here and folds it back in from
 * on_write, once client_reset() has slid read_buf down.  The two requests that
 * overlap in read_buf are then dispatched in order exactly as they are on the
 * plaintext path, where the same situation just means the socket backs up for
 * a moment.
 *
 * One invariant makes the rest of this safe to reason about: the spill is
 * non-empty only while read_buf is completely full, because tls_spill_stash()
 * is reached only after read_buf has been filled and tls_spill_drain() empties
 * it into whatever room there is.  So a non-empty spill always has an
 * in-flight response, or a request too large to serve, behind it -- never a
 * connection that has quietly stopped making progress.
 *
 * A block is taken from the pool the first time a connection overflows and
 * goes straight back the moment it drains, so an idle connection never holds
 * one.  tls_conn_free() releases any block still held, and every close path
 * reaches it through on_close.
 */
static int tls_spill_stash(client_t *c, const uint8_t *src, size_t len) {
    if (unlikely((size_t)c->tls_spill_len + len > TLS_SPILL_SIZE))
        return -1;                          /* see TLS_SPILL_SIZE: unreachable */
    if (c->tls_spill == NULL && (c->tls_spill = tls_spill_get()) == NULL)
        return -1;
    memcpy(c->tls_spill + c->tls_spill_len, src, len);
    c->tls_spill_len += (int)len;
    return 0;
}

static void tls_spill_drain(client_t *c) {
    if (likely(c->tls_spill_len == 0)) return;
    size_t room = (size_t)(READ_BUF_SIZE - c->read_len);
    if (room == 0) return;
    size_t take = (size_t)c->tls_spill_len < room ? (size_t)c->tls_spill_len : room;
    memcpy(c->read_buf + c->read_len, c->tls_spill, take);
    c->read_len += (int)take;
    c->tls_spill_len -= (int)take;
    if (c->tls_spill_len > 0)
        memmove(c->tls_spill, c->tls_spill + take, (size_t)c->tls_spill_len);
    else
        tls_release_spill(c);   /* empty: back to the pool, not held to close */
}

/*
 * Give up on a connection whose TLS state is unusable.
 *
 * Reading stays armed across a response now, so a decryption failure can be
 * discovered while uv_write still holds the response buffers.  Closing here
 * would complete that write with UV_ECANCELED, and on_write would then close
 * a second time, which libuv aborts on -- the same trap the nread < 0 branch
 * of on_read documents.  uv_is_closing() cannot be the answer either: it
 * would stop this close from repeating, not on_write's.  So when a response
 * is outstanding, stop reading and let on_write do the closing; keep_alive =
 * false is what makes it take that branch.
 */
static void tls_read_failed(client_t *c, uv_stream_t *stream) {
    /* Set on both branches, though only the deferred one can read it back:
     * it is what stops on_write() from following the response with a
     * close_notify.  The connection got here because picotls could not make
     * sense of the record layer, so an alert encrypted with it is worth
     * nothing to the peer -- and ptls_send_alert() would happily produce one,
     * since it asks only whether the encryption keys exist.  A close with no
     * close_notify is the honest signal here: something went wrong. */
    c->tls_broken = true;
    if (unlikely(c->in_flight)) {
        c->keep_alive = false;
        if (c->read_armed) { uv_read_stop(stream); c->read_armed = false; }
        return;
    }
    uv_close((uv_handle_t *)&c->handle, on_close);
}

/*
 * Decide whether the connection should be reading, having just changed what
 * read_buf and the spill hold.  The encrypted counterpart of the tail of
 * on_read(): reading stays armed across a response and stops only when a read
 * would have nowhere to put what it delivered.
 */
static void tls_read_flow(client_t *c, uv_stream_t *stream) {
    if (unlikely(uv_is_closing((uv_handle_t *)&c->handle))) return;

    if (unlikely(c->read_len >= READ_BUF_SIZE && !c->in_flight)) {
        /*
         * read_buf is full, no complete request came out of it, and no
         * response is running that could free any of it -- so the request is
         * itself larger than READ_BUF_SIZE and nothing will ever finish it.
         * The plaintext path reaches the same verdict by way of a zero-length
         * alloc_cb and UV_ENOBUFS.
         */
        if (c->read_armed) { uv_read_stop(stream); c->read_armed = false; }
        uv_close((uv_handle_t *)&c->handle, on_close);
        return;
    }

    bool want = (c->read_len < READ_BUF_SIZE) && (c->tls_spill_len == 0);
    if (want == c->read_armed) return;
    if (want) {
        c->read_armed = true;
        uv_read_start(stream, alloc_cb, on_read);
    } else {
        uv_read_stop(stream);
        c->read_armed = false;
    }
}

/*
 * Release a decrypt buffer -- and only the part of it picotls owns.
 *
 * ptls_buffer_dispose() is the wrong call on this path.  It runs
 * ptls_clear_memory(base, off) unconditionally, and base is read_buf, so
 * disposing would zero the request that was just decrypted: silently, after
 * the fact, and only for the sizes that reached this far.
 *
 * is_allocated is picotls's own ownership flag and answers the question
 * exactly.  ptls_buffer_init() clears it; ptls_buffer_reserve_aligned() is the
 * only writer, and it sets the flag in the same statement in which it replaces
 * base with an allocation of its own.  So the flag is set if and only if there
 * is something to free -- and, on the paths that keep the plaintext, if and
 * only if the plaintext is somewhere other than read_buf.
 *
 * Worth being explicit that is_allocated = 0 does NOT stop picotls growing the
 * buffer, which is the assumption the write side's tls_release_wbuf() is also
 * careful not to make: ptls_buffer_reserve_aligned() mallocs, copies, and only
 * then consults the flag, to decide whether the old base should be freed as
 * well as scrubbed.  A fixed-capacity buffer is therefore not a hard limit
 * that fails loudly; it is a threshold above which picotls quietly takes the
 * buffer over.  Detecting that is the whole job of this function and of the
 * branch in tls_on_read_data().
 */
static inline void tls_plain_release(ptls_buffer_t *plain) {
    if (unlikely(plain->is_allocated))
        ptls_buffer_dispose(plain);
}

static void tls_on_read_data(client_t *c, uv_stream_t *stream,
                              const char *data, size_t nread) {
    if (!c->tls_hs_done) {
        uint8_t hs_small[4096];
        ptls_buffer_t outbuf;
        ptls_buffer_init(&outbuf, hs_small, sizeof(hs_small));
        size_t inlen = nread;
        int ret = ptls_handshake(c->tls, &outbuf, data, &inlen, NULL);
        tls_hs_send(c, &outbuf);
        if (ret == 0) {
            c->tls_hs_done = true;
            if (inlen < nread)
                tls_on_read_data(c, stream, data + inlen, nread - inlen);
        } else if (ret != PTLS_ERROR_IN_PROGRESS) {
            tls_read_failed(c, stream);
        }
        return;
    }
    /*
     * Decrypt straight into read_buf's free tail.
     *
     * ptls_receive() appends to the buffer it is handed and honours whatever
     * off it already carries, so pointing that buffer at read_buf + read_len
     * puts the plaintext exactly where phr_parse_request() wants it: no
     * staging buffer, no memcpy, no allocation and no ptls_clear_memory()
     * sweep over the request body.  The two branches after the loop are what
     * makes that safe; see tls_plain_release() and the growth case below.
     *
     * What lands past read_len is not always request bytes.  handle_input()
     * decrypts every record in place at base + off and only advances off for
     * application data, so a KeyUpdate or an encrypted alert is decrypted into
     * read_buf's tail and then left there as scratch.  That is harmless --
     * read_len is what bounds the request, and client_reset() slides only
     * within it -- and it is not a new exposure either: the request body has
     * always been left in read_buf, which client_alloc() deliberately does not
     * clear.  What is gone is the *second* copy the old staging buffer made,
     * scrubbed or not.
     *
     * A sweep can also produce nothing at all: a record split across reads
     * leaves picotls holding a fragment in recvbuf.rec, and a KeyUpdate
     * consumes a whole record without emitting a byte.  Both come back with
     * off == 0 and must leave read_buf alone, which falls out of appending.
     */
    /*
     * Two sizes, and the difference between them is the whole trick.  `room`
     * is what this sweep may keep: read_buf's free space, the bound every
     * other part of the server is written against.  The capacity handed to
     * picotls is that plus TLS_DECRYPT_SLACK, because handle_input() reserves
     * against a record's *wire* length and then advances off by the shorter
     * plaintext -- so a reservation legitimately overhangs what it will keep
     * by one record's framing.  Without the overhang the last 22 bytes of
     * read_buf are unusable and a request that ends there takes an allocation
     * it does not need; with exactly that much, a record decrypts in place
     * whenever its plaintext fits, and `off` still cannot pass READ_BUF_SIZE
     * (see TLS_DECRYPT_SLACK for the arithmetic).
     */
    size_t room = (size_t)(READ_BUF_SIZE - c->read_len);
    ptls_buffer_t plain;
    ptls_buffer_init(&plain, c->read_buf + c->read_len,
                     (size_t)(READ_BUF_ALLOC - c->read_len));
    /*
     * ptls_receive() stops as soon as it has decrypted one record's worth of
     * application data and reports how much of the input that consumed, so a
     * read carrying several records needs several calls.  Two pipelined
     * requests that the peer flushed separately arrive exactly that way -
     * two small records in one segment - and decrypting only the first
     * silently discards the second, leaving the client waiting for a
     * response that is never sent.  The handshake branch above already
     * drains its residual; this one has to as well.
     *
     * Each call appends to the same buffer, so all of the read's plaintext
     * lands in read_buf together and the pipelined requests behind the first
     * are dispatched from there by on_write, exactly as on the plaintext
     * path.
     */
    size_t off = 0;
    while (off < nread) {
        size_t inlen = nread - off;
        if (ptls_receive(c->tls, &plain, data + off, &inlen) != 0) {
            tls_plain_release(&plain);
            tls_read_failed(c, stream);
            return;
        }
        if (unlikely(inlen == 0)) break;   /* no progress; nothing left to parse */
        off += inlen;
    }

    size_t produced = plain.off;
    int    stashed  = 0;
    if (likely(!plain.is_allocated)) {
        /*
         * The whole sweep landed in read_buf, which is the ordinary case and
         * the point of the exercise: there is nothing to copy, nothing to
         * free and nothing to scrub.
         *
         * `produced > room` is the slack arithmetic stated as a runtime
         * check.  A satisfied reservation can overhang room by at most the
         * framing it accounted for and did not use, so off lands at or below
         * READ_BUF_SIZE however many records the sweep decrypted; the only
         * way past that is the growth branch of ptls_buffer_reserve(), which
         * is exactly what is_allocated reports.  So this is a standing guard
         * on that reading of picotls, not a case with a behaviour of its own
         * -- but it is the one that would catch a slack that stopped being
         * one record's worth.
         */
        if (unlikely(produced > room)) {
            tls_read_failed(c, stream);
            return;
        }
        c->read_len += (int)produced;
    } else {
        /*
         * picotls needed more capacity than read_buf's tail had and moved the
         * buffer into an allocation of its own, copying what was already
         * there along with it.  Nothing is lost -- plain.base holds the whole
         * sweep -- but the plaintext is no longer in read_buf, so it has to
         * be put back the way the pre-#38 code always did it.
         *
         * Two situations reach here, and neither is an error.  A request in
         * the top TLS_RECORD_OVERHEAD bytes of read_buf: the record's framing
         * needs room the payload leaves nothing for.  And a read whose
         * plaintext genuinely overruns read_buf, which is ordinary pipelining
         * -- two requests straddling the end of the buffer -- and is what the
         * spill exists for.
         */
        g_server.tls_read_grows++;
        size_t take = produced < room ? produced : room;
        memcpy(c->read_buf + c->read_len, plain.base, take);
        c->read_len += (int)take;
        if (unlikely(take < produced)) {
            g_server.tls_read_spills++;
            stashed = tls_spill_stash(c, plain.base + take, produced - take);
        }
        ptls_buffer_dispose(&plain);        /* picotls owns it; free and scrub */
    }
    if (produced == 0) return;              /* a partial record, or a KeyUpdate */
    if (unlikely(stashed < 0)) {
        tls_read_failed(c, stream);
        return;
    }

    /*
     * Reading is armed across a response now, so this can run with one in
     * flight.  Dispatching then would put a second response on the wire
     * underneath the first; the bytes just accumulate instead and on_write
     * dispatches them, which is exactly what the plaintext on_read() does.
     */
    if (likely(!c->in_flight) && unlikely(http_dispatch(c, stream) < 0))
        return;
    tls_read_flow(c, stream);
}

/* Bytes ptls_send_v() will append for a plaintext run of len: the payload plus
 * one lot of record framing (5-byte header, content-type byte, AEAD tag) for
 * each 16KB record it is split into.  Rounds up, and never under-counts. */
static inline size_t tls_encrypted_size(size_t len, size_t rec_overhead) {
    return len + (len / TLS_MAX_RECORD_PLAINTEXT + 1) * rec_overhead;
}

/* Records ptls_send_v() splits a plaintext run of len into.  Zero for an empty
 * run, which it turns into no record at all -- unlike tls_encrypted_size(),
 * which deliberately over-counts so that it can be used to size a buffer. */
static inline size_t tls_record_count(size_t len) {
    return (len + TLS_MAX_RECORD_PLAINTEXT - 1) / TLS_MAX_RECORD_PLAINTEXT;
}

/* Cut the next `want` bytes out of the header/body vector pair, starting at
 * the cursor (*veci, *vecoff), and write them into out[] as up to two vectors;
 * advances the cursor.  Returns how many vectors were written.
 *
 * The caller has already checked that `want` bytes remain, so the cursor never
 * runs off the end of vec[]. */
static inline size_t tls_slice(const ptls_iovec_t *vec, size_t *veci, size_t *vecoff,
                               size_t want, ptls_iovec_t *out) {
    size_t n = 0;
    while (want != 0) {
        size_t avail = vec[*veci].len - *vecoff;
        size_t take  = avail < want ? avail : want;
        out[n++] = ptls_iovec_init(vec[*veci].base + *vecoff, take);
        if ((*vecoff += take) == vec[*veci].len) {
            (*veci)++;
            *vecoff = 0;
        }
        want -= take;
    }
    return n;
}

/* Take a block for this response and point its trailer at its own data area.
 * The caller has already linked the block into the chain, so a failure after
 * this point still gets it back via tls_release_wbuf(). */
static inline tls_wseg_t *tls_wseg_open(void *block) {
    tls_wseg_t *seg = TLS_WSEG_OF(block);
    seg->next             = NULL;
    seg->buf.base         = (uint8_t *)block;
    seg->buf.capacity     = TLS_WBUF_SIZE;
    seg->buf.off          = 0;
    seg->buf.is_allocated = 0;
    seg->buf.align_bits   = 0;
    return seg;
}

static void tls_write_response_impl(client_t *c) {
    size_t      hdr_len  = (size_t)c->resp_hdr_len;
    const char *body     = NULL;
    size_t      body_len = 0;
    if (c->resp_body && PyBytes_GET_SIZE(c->resp_body) > 0) {
        body     = PyBytes_AS_STRING(c->resp_body);
        body_len = (size_t)PyBytes_GET_SIZE(c->resp_body);
    }

    /*
     * One record, no copy.  A second record costs a 5-byte header, a fresh
     * AEAD setup and a 16-byte tag, which for a ~130-byte response header is
     * nearly all of what sending it costs; every other server in this class
     * avoids it by memcpying the body in behind the header, because its TLS
     * library will only encrypt one contiguous buffer.  freastal used to do
     * the same, and only up to RESP_HDR_SIZE, so 8KB was both the copy budget
     * and -- for no reason to do with TLS -- the record-framing threshold.
     *
     * ptls_send_v() takes the header and the body as two vectors and encrypts
     * them into one record straight out of the Python bytes, so neither the
     * copy nor the threshold exists any more.  See vendor/patches/.
     */
    ptls_iovec_t vec[2];
    size_t       veccnt = 0;
    if (hdr_len != 0)
        vec[veccnt++] = ptls_iovec_init(c->resp_hdr, hdr_len);
    if (body_len != 0)
        vec[veccnt++] = ptls_iovec_init(body, body_len);
    size_t total  = hdr_len + body_len;
    size_t rec_oh = ptls_get_record_overhead(c->tls);

    /*
     * Every record goes in a pooled block, and blocks are chained into one
     * uv_write, so nothing here allocates and nothing here is memset on
     * release however large the response is.  ptls_send_v() would otherwise
     * append every record of a run into one contiguous buffer, so the loop
     * below hands it a single record's worth at a time: exactly one record per
     * call, into a block whose remaining capacity was checked first.
     *
     * Records pack greedily rather than one to a block.  A block holds 16896
     * bytes and a maximal record is 16406, so a final short record -- up to
     * 468 bytes of plaintext -- rides behind a maximal one instead of costing
     * a block and a uv_write iovec of its own.
     *
     * The one thing that does not segment is a response big enough to drain
     * the pool: past TLS_WSEG_MAX blocks it takes a single oversized buffer
     * from tls_bigbuf_get(), which freastal owns and retains -- handed to
     * picotls with is_allocated = 0, exactly as a pooled block is, so it is
     * neither freed nor swept by picotls on release.  The block opened here
     * then carries only the chain node.
     *
     * Both counts below are taken over the whole stream, header included,
     * because that is what ptls_send_v() cuts records out of.  Counting the
     * header's records separately and adding -- which is what this did when
     * the header was its own send -- predicts one record too many whenever the
     * header fits in the slack of the body's last record.  That is enough to
     * push a response needing exactly TLS_WSEG_MAX blocks onto the oversized
     * path, and to reserve a record's framing more than the buffer needs.
     * Under-counting would be the dangerous direction: it would run the chain
     * past the end of uvbufs[TLS_WSEG_MAX].
     */
    size_t nrec      = tls_record_count(total);
    bool   oversized = unlikely(nrec > TLS_WSEG_MAX);

    void *block = tls_wbuf_get();
    if (unlikely(!block)) { uv_close((uv_handle_t *)&c->handle, on_close); return; }
    c->tls_wblock   = block;                 /* released by on_write or tls_conn_free */
    tls_wseg_t *seg = tls_wseg_open(block);
    size_t      nseg = 1;

    if (oversized) {
        size_t need  = tls_encrypted_size(total, rec_oh);
        size_t cap   = 0;
        void  *whole = tls_bigbuf_get(need, &cap);
        if (unlikely(!whole)) { uv_close((uv_handle_t *)&c->handle, on_close); return; }
        c->tls_wbig           = whole;       /* released by tls_release_wbuf() */
        seg->buf.base         = (uint8_t *)whole;
        seg->buf.capacity     = cap;
        seg->buf.is_allocated = 0;           /* ours: no free, and no memset on release */
    }

    /* Cursor into vec: which vector, and how far into it.  The header and the
     * body are one plaintext stream now, so a record boundary can fall inside
     * the body vector -- past 16KB it always does -- and tls_slice() is what
     * splits it.  Records therefore straddle the header/body seam instead of
     * starting over at it, which is the whole point. */
    size_t veci = 0, vecoff = 0;

    for (size_t off = 0; off < total;) {
        size_t chunk = total - off;
        if (!oversized && chunk > TLS_MAX_RECORD_PLAINTEXT)
            chunk = TLS_MAX_RECORD_PLAINTEXT;

        if (!oversized && seg->buf.off + chunk + rec_oh > TLS_WBUF_SIZE) {
            if (unlikely(nseg == TLS_WSEG_MAX)) goto abandon;  /* unreachable: nrec bounds nseg */
            void *nblock = tls_wbuf_get();
            if (unlikely(!nblock)) goto abandon;
            seg->next = nblock;
            seg       = tls_wseg_open(nblock);
            nseg++;
        }

        ptls_iovec_t part[2];
        size_t       partcnt = tls_slice(vec, &veci, &vecoff, chunk, part);

        /* A KeyUpdate record, or an overhead this sizing did not predict,
         * can still make picotls reserve past the block and swap in an
         * allocation of its own.  That stays correct: the uv_buf below is
         * built from buf.base, and release compares it against the block. */
        if (unlikely(ptls_send_v(c->tls, &seg->buf, part, partcnt) != 0))
            goto abandon;
        off += chunk;
    }

    uv_buf_t uvbufs[TLS_WSEG_MAX];           /* uv_write copies these out */
    unsigned nbufs = 0;
    for (void *b = c->tls_wblock; b != NULL; b = TLS_WSEG_OF(b)->next) {
        ptls_buffer_t *buf = &TLS_WSEG_OF(b)->buf;
        uvbufs[nbufs++] = uv_buf_init((char *)buf->base, (unsigned)buf->off);
    }
    uv_write(&c->write_req, (uv_stream_t *)&c->handle, uvbufs, nbufs, on_write);
    return;

abandon:
    /* Out of memory, or picotls refused to encrypt.  Some of the response is
     * already encrypted and the connection's record sequence has moved on, so
     * there is nothing to do but drop it; on_close releases every block. */
    uv_close((uv_handle_t *)&c->handle, on_close);
}

static void on_tls_close_notify_write(uv_write_t *req, int status) {
    client_t *c = CONTAINER_OF(req, client_t, write_req);
    /* status is not consulted: the connection is going away either way, and
     * a peer that vanished before the alert landed is exactly the case the
     * alert could not have helped. */
    (void)status;
    tls_release_wbuf(c);            /* uv_write held the block until now */
    uv_close((uv_handle_t *)&c->handle, on_close);
}

/*
 * Encrypt a close_notify and put it on the wire, closing when it lands.
 *
 * The alert is one record of 24 bytes, so it borrows a pooled block through
 * the same chain the response used -- on_write() released that chain at its
 * top, and c->write_req is free again now that the response it carried has
 * completed, so both are reused rather than paid for a second time.  Setting
 * c->tls_wblock before anything can fail is what keeps the block from
 * leaking: every return below either hands it to uv_write, whose callback
 * releases it, or leaves it for tls_conn_free() to collect on the close the
 * caller is about to do.
 *
 * Returns true when the close has become on_tls_close_notify_write()'s job.
 * False means nothing was written and the caller must close: out of blocks,
 * picotls declined to build the record, or uv_write failed outright and so
 * will never call back.  An unclean close is the right fallback -- it is what
 * the connection would have got anyway -- and none of the three is worth
 * failing a request over.
 */
static bool tls_send_close_notify(client_t *c) {
    /*
     * Closing used to happen in this same loop turn, so nothing could arrive
     * between deciding to close and the connection being gone.  The alert
     * write opens exactly one turn of gap, and reading is armed across a
     * response, so on_read can now fire on a connection that has already said
     * goodbye.  Nothing good can come of what it would deliver -- the peer was
     * told the connection is ending -- and letting tls_on_read_data() run
     * there would put a second user of c->write_req behind this one.  So stop
     * reading first and let the gap be uneventful.
     */
    if (c->read_armed) {
        uv_read_stop((uv_stream_t *)&c->handle);
        c->read_armed = false;
    }

    void *block = tls_wbuf_get();
    if (unlikely(!block)) return false;
    c->tls_wblock   = block;
    tls_wseg_t *seg = tls_wseg_open(block);

    if (unlikely(ptls_send_alert(c->tls, &seg->buf, PTLS_ALERT_LEVEL_WARNING,
                                 PTLS_ALERT_CLOSE_NOTIFY) != 0))
        return false;
    if (unlikely(seg->buf.off == 0)) return false;

    uv_buf_t b = uv_buf_init((char *)seg->buf.base, (unsigned)seg->buf.off);
    return uv_write(&c->write_req, (uv_stream_t *)&c->handle, &b, 1,
                    on_tls_close_notify_write) == 0;
}

#endif /* FREASTAL_TLS */
