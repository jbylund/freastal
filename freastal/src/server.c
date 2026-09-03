#include "server.h"
#include "wsgi.h"
#include "asgi.h"
#include "hdrcache.h"
#include <sys/socket.h>
#include <arpa/inet.h>

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
     */
    c->in_flight = true;
#ifdef FREASTAL_TLS
    /* TLS records decrypt into read_buf and the plaintext size cannot be
     * predicted from the ciphertext, so there is no read at which the
     * encrypted path could safely stop.  Keep its existing behaviour of not
     * reading at all while a response is outstanding. */
    if (c->tls) { uv_read_stop(stream); c->read_armed = false; }
#endif
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
    /* uv_write held a pointer into tls_wbuf until now; this is the earliest
     * point at which the block may go back to the pool. */
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
        uv_close((uv_handle_t *)&c->handle, on_close);
        return;
    }

    /* Keep-alive: reset for the next request */
    client_reset(c);
    c->in_flight = false;

    /* A pipelined request may already be buffered.  Dispatch it directly. */
    if (c->read_len > 0 && http_dispatch(c, (uv_stream_t *)&c->handle) < 0)
        return;

    /* Reading is normally still armed, so there is nothing to do here.  It is
     * only ever off because on_read hit a full read_buf, or because this is
     * the TLS path, and in both cases it goes back on as soon as read_buf has
     * room and no response is outstanding. */
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

int server_init(PyObject *app, const char *host, int port, bool reuse_port,
                const char *certfile, const char *keyfile) {
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

    struct sockaddr_in addr;
    uv_ip4_addr(host, port, &addr);

    /* UV_TCP_REUSEPORT availability is probed at build time by setup.py */
#ifdef FREASTAL_REUSEPORT
    unsigned int bind_flags = reuse_port ? UV_TCP_REUSEPORT : 0;
#else
    (void)reuse_port;
    unsigned int bind_flags = 0;
#endif
    if (uv_tcp_bind(&g_server.handle, (const struct sockaddr *)&addr, bind_flags) != 0) {
        PyErr_Format(PyExc_OSError, "freastal: uv_tcp_bind failed on %s:%d", host, port);
        return -1;
    }

    if (uv_listen((uv_stream_t *)&g_server.handle, LISTEN_BACKLOG, on_new_connection) != 0) {
        PyErr_SetString(PyExc_OSError, "freastal: uv_listen failed");
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
            uv_close((uv_handle_t *)&c->handle, on_close);
        }
        return;
    }
    uint8_t plain_small[4096];
    ptls_buffer_t plain;
    ptls_buffer_init(&plain, plain_small, sizeof(plain_small));
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
            ptls_buffer_dispose(&plain);
            uv_close((uv_handle_t *)&c->handle, on_close);
            return;
        }
        if (unlikely(inlen == 0)) break;   /* no progress; nothing left to parse */
        off += inlen;
    }
    if (plain.off == 0) { ptls_buffer_dispose(&plain); return; }
    if (c->read_len + (int)plain.off > READ_BUF_SIZE) {
        ptls_buffer_dispose(&plain);
        uv_close((uv_handle_t *)&c->handle, on_close);
        return;
    }
    memcpy(c->read_buf + c->read_len, plain.base, plain.off);
    c->read_len += (int)plain.off;
    ptls_buffer_dispose(&plain);
    http_dispatch(c, stream);
}

/* Bytes ptls_send() will append for a plaintext run of len: the payload plus
 * one lot of record framing (5-byte header, content-type byte, AEAD tag) for
 * each 16KB record it is split into.  Rounds up, and never under-counts. */
static inline size_t tls_encrypted_size(size_t len, size_t rec_overhead) {
    return len + (len / TLS_MAX_RECORD_PLAINTEXT + 1) * rec_overhead;
}

/* Records ptls_send() splits a plaintext run of len into.  Zero for an empty
 * run, which it turns into no record at all -- unlike tls_encrypted_size(),
 * which deliberately over-counts so that it can be used to size a buffer. */
static inline size_t tls_record_count(size_t len) {
    return (len + TLS_MAX_RECORD_PLAINTEXT - 1) / TLS_MAX_RECORD_PLAINTEXT;
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
     * One record instead of two.  A second record costs a 5-byte header, a
     * fresh AEAD setup and a 16-byte tag, which for a ~130-byte response
     * header is nearly all of what sending it costs.  resp_hdr is 8KB and
     * already holds the header, so a body that fits behind it can be appended
     * there and the two sent as a single record for the price of copying the
     * body -- the trade lighttpd makes in chunkqueue_small_resp_optim().
     *
     * Above that the copy is the more expensive half, so large bodies keep
     * their own record and are encrypted straight out of the Python bytes.
     */
    if (body_len != 0 && hdr_len + body_len <= RESP_HDR_SIZE) {
        memcpy(c->resp_hdr + hdr_len, body, body_len);
        hdr_len += body_len;
        body     = NULL;
        body_len = 0;
    }

    /* The plaintext to encrypt, in wire order. */
    const uint8_t *run[2]    = { (const uint8_t *)c->resp_hdr, (const uint8_t *)body };
    size_t         runlen[2] = { hdr_len, body_len };
    size_t         rec_oh    = ptls_get_record_overhead(c->tls);

    /*
     * Every record goes in a pooled block, and blocks are chained into one
     * uv_write, so nothing here allocates and nothing here is memset on
     * release however large the response is.  ptls_send() would otherwise
     * append every record of a run into one contiguous buffer, so the loop
     * below hands it a single record's worth at a time: exactly one record per
     * call, into a block whose remaining capacity was checked first.
     *
     * Records pack greedily rather than one to a block.  A block holds 16896
     * bytes and a maximal record is 16406, so a response header's record --
     * a hundred-odd bytes on the wire -- rides in front of the first body
     * record instead of costing a block and an iovec of its own.
     *
     * The one thing that does not segment is a response big enough to drain
     * the pool: past TLS_WSEG_MAX blocks it takes a single oversized buffer
     * from tls_bigbuf_get(), which freastal owns and retains -- handed to
     * picotls with is_allocated = 0, exactly as a pooled block is, so it is
     * neither freed nor swept by picotls on release.  The block opened here
     * then carries only the chain node.
     */
    size_t nrec      = tls_record_count(hdr_len) + tls_record_count(body_len);
    bool   oversized = unlikely(nrec > TLS_WSEG_MAX);

    void *block = tls_wbuf_get();
    if (unlikely(!block)) { uv_close((uv_handle_t *)&c->handle, on_close); return; }
    c->tls_wblock   = block;                 /* released by on_write or tls_conn_free */
    tls_wseg_t *seg = tls_wseg_open(block);
    size_t      nseg = 1;

    if (oversized) {
        size_t need = tls_encrypted_size(hdr_len, rec_oh)
                      + (body_len ? tls_encrypted_size(body_len, rec_oh) : 0);
        size_t cap   = 0;
        void  *whole = tls_bigbuf_get(need, &cap);
        if (unlikely(!whole)) { uv_close((uv_handle_t *)&c->handle, on_close); return; }
        c->tls_wbig           = whole;       /* released by tls_release_wbuf() */
        seg->buf.base         = (uint8_t *)whole;
        seg->buf.capacity     = cap;
        seg->buf.is_allocated = 0;           /* ours: no free, and no memset on release */
    }

    for (int r = 0; r < 2; r++) {
        size_t off = 0;
        while (off < runlen[r]) {
            size_t chunk = runlen[r] - off;
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

            /* A KeyUpdate record, or an overhead this sizing did not predict,
             * can still make picotls reserve past the block and swap in an
             * allocation of its own.  That stays correct: the uv_buf below is
             * built from buf.base, and release compares it against the block. */
            if (unlikely(ptls_send(c->tls, &seg->buf, run[r] + off, chunk) != 0))
                goto abandon;
            off += chunk;
        }
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

#endif /* FREASTAL_TLS */
