#include "server.h"
#include "wsgi.h"
#include "asgi.h"
#include <sys/socket.h>
#include <arpa/inet.h>

server_t g_server;

/* ---- Client pool ---- */

/* Pre-allocate a slab so most allocs are free-list pops (no malloc) */
static int pool_init(int cap) {
    g_server.slab = calloc(cap, sizeof(client_t));
    if (!g_server.slab) return -1;
    g_server.pool_cap = cap;
    g_server.free_list = NULL;

    /* Build free list in reverse so first alloc returns index 0 */
    char *base = (char *)g_server.slab;
    for (int i = cap - 1; i >= 0; i--) {
        client_t *c = (client_t *)(base + i * sizeof(client_t));
        c->next_free = g_server.free_list;
        g_server.free_list = c;
    }
    return 0;
}

client_t *client_alloc(void) {
    client_t *c;
    if (g_server.free_list) {
        c = g_server.free_list;
        g_server.free_list = c->next_free;
    } else {
        /* Pool exhausted – fall back to malloc */
        c = (client_t *)malloc(sizeof(client_t));
        if (!c) return NULL;
    }
    memset(c, 0, sizeof(client_t));
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

void client_reset(client_t *c) {
    c->read_len = 0;
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

void http_dispatch(client_t *c, uv_stream_t *stream) {
    c->num_headers = MAX_HEADERS;
    int pret = phr_parse_request(
        c->read_buf, (size_t)c->read_len,
        &c->method,  &c->method_len,
        &c->path,    &c->path_len,
        &c->minor_version,
        c->headers, &c->num_headers,
        (size_t)c->last_len
    );

    if (pret == -2) { c->last_len = c->read_len; return; }

    if (pret < 0) {
        static const char bad_req[] =
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        uv_buf_t b = uv_buf_init((char *)bad_req, sizeof(bad_req) - 1);
        uv_write(&c->write_req, stream, &b, 1, NULL);
        uv_close((uv_handle_t *)&c->handle, on_close);
        return;
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
    if (body_received < c->content_length) { c->last_len = c->read_len; return; }

    uv_read_stop(stream);
    GIL_LOCK();
    if (g_server.asgi_mode)
        asgi_dispatch(c);
    else
        wsgi_call_application(c);
    GIL_UNLOCK();
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    client_t *c = (client_t *)stream;

    if (nread < 0) {
        GIL_LOCK();
        Py_CLEAR(c->resp_status);
        Py_CLEAR(c->resp_pyheaders);
        Py_CLEAR(c->resp_body);
        Py_CLEAR(c->peer_addr_obj);
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
    http_dispatch(c, stream);
}

/*
 * write_response_uv – normal uv_write path (writev via two bufs).
 * Used for small responses and as fallback when io_uring is unavailable.
 */
static void write_response_uv(client_t *c) {
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

/*
 * write_response – dispatch to the io_uring fixed-buffer path for large
 * responses, fall back to uv_write for small ones or when io_uring is off.
 */
void write_response(client_t *c) {
#ifdef FREASTAL_TLS
    if (c->tls) { tls_write_response_impl(c); return; }
#endif
#ifdef FREASTAL_IOURING
    if (g_server.iouring.enabled) {
        Py_ssize_t body_len = c->resp_body ? PyBytes_GET_SIZE(c->resp_body) : 0;
        size_t total = (size_t)c->resp_hdr_len + (size_t)body_len;
        if (total > IOURING_LARGE_THRESH) {
            const char *body_ptr = c->resp_body ? PyBytes_AS_STRING(c->resp_body) : NULL;
            if (iouring_write(c, c->resp_hdr, (size_t)c->resp_hdr_len,
                              body_ptr, (size_t)body_len) == 0)
                return;  /* io_uring submission succeeded */
        }
    }
#endif
    write_response_uv(c);
}

static void on_write(uv_write_t *req, int status) {
    client_t *c = CONTAINER_OF(req, client_t, write_req);
#ifdef FREASTAL_TLS
    if (c->tls) ptls_buffer_dispose(&c->tls_wbuf);
#endif

    GIL_LOCK();
    Py_CLEAR(c->resp_status);
    Py_CLEAR(c->resp_pyheaders);
    Py_CLEAR(c->resp_body);
    Py_CLEAR(c->asgi_task);
    if (status < 0 || !c->keep_alive)
        Py_CLEAR(c->peer_addr_obj);
    GIL_UNLOCK();

    if (status < 0 || !c->keep_alive) {
        uv_close((uv_handle_t *)&c->handle, on_close);
        return;
    }

    /* Keep-alive: reset and re-arm for the next request */
    client_reset(c);
    uv_read_start((uv_stream_t *)&c->handle, alloc_cb, on_read);
}

static void on_close(uv_handle_t *handle) {
    client_t *c = (client_t *)handle;
    /* Python objects already cleared before calling uv_close */
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

#ifdef FREASTAL_IOURING
    /* Soft failure: log and continue without registered buffers */
    iouring_init(g_server.loop, &g_server.iouring);
#endif

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

/* ============================================================
 * io_uring registered-buffer write path
 *
 * Active only when compiled with -DFREASTAL_IOURING (liburing present).
 * libuv 1.45+ also independently uses io_uring for its internal event
 * loop on Linux, providing syscall-batching for all I/O paths.
 *
 * This layer adds registered fixed-buffers on top, eliminating
 * per-write get_user_pages() overhead for responses > IOURING_LARGE_THRESH.
 * Benefit is most pronounced in the 12-50KB range targeted here.
 * ============================================================ */
#ifdef FREASTAL_IOURING

static void on_iouring_event(uv_poll_t *handle, int status, int events);

int iouring_init(uv_loop_t *loop, iouring_ctx_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->free_top = -1;

    if (io_uring_queue_init(IOURING_QUEUE_DEPTH, &ctx->ring, 0) < 0) {
        fprintf(stderr, "[freastal] io_uring_queue_init failed – uv_write fallback active\n");
        return 0; /* soft failure */
    }

    /* Allocate page-aligned slab for registered buffers */
    ctx->bufs = (char *)aligned_alloc(4096,
                    (size_t)IOURING_BUF_COUNT * IOURING_BUF_SIZE);
    if (!ctx->bufs) {
        io_uring_queue_exit(&ctx->ring);
        return 0;
    }

    /* Register the slab with the kernel.  After this, each write_fixed
     * submission references a buffer by index, skipping page-pinning overhead. */
    struct iovec iov[IOURING_BUF_COUNT];
    for (int i = 0; i < IOURING_BUF_COUNT; i++) {
        iov[i].iov_base = ctx->bufs + (size_t)i * IOURING_BUF_SIZE;
        iov[i].iov_len  = IOURING_BUF_SIZE;
    }
    if (io_uring_register_buffers(&ctx->ring, iov, IOURING_BUF_COUNT) < 0) {
        fprintf(stderr, "[freastal] io_uring_register_buffers failed – uv_write fallback active\n");
        free(ctx->bufs); ctx->bufs = NULL;
        io_uring_queue_exit(&ctx->ring);
        return 0;
    }

    /* Build LIFO free stack: index IOURING_BUF_COUNT-1 is on top initially */
    ctx->free_top = IOURING_BUF_COUNT - 1;
    for (int i = 0; i < IOURING_BUF_COUNT; i++)
        ctx->free_stack[i] = i;

    /* Watch the ring fd from libuv's event loop so completions are processed
     * as part of the normal event loop tick, not a separate thread. */
    uv_poll_init(loop, &ctx->poll, ctx->ring.ring_fd);
    uv_poll_start(&ctx->poll, UV_READABLE, on_iouring_event);

    ctx->enabled = true;
    fprintf(stderr, "[freastal] io_uring registered-buffer path enabled "
                    "(%d x %dKB buffers, threshold %dB)\n",
            IOURING_BUF_COUNT, IOURING_BUF_SIZE / 1024, IOURING_LARGE_THRESH);
    return 0;
}

static int iou_alloc_buf(iouring_ctx_t *ctx) {
    if (ctx->free_top < 0) return -1;
    return ctx->free_stack[ctx->free_top--];
}

static void iou_free_buf(iouring_ctx_t *ctx, int idx) {
    ctx->free_stack[++ctx->free_top] = idx;
}

int iouring_write(client_t *c,
                  const char *headers, size_t headers_len,
                  const char *body,    size_t body_len) {
    iouring_ctx_t *ctx = &g_server.iouring;
    size_t total = headers_len + body_len;

    if (total > IOURING_BUF_SIZE) return -1; /* exceeds one buffer */

    int buf_idx = iou_alloc_buf(ctx);
    if (buf_idx < 0) return -1; /* all buffers in flight – fall back */

    /* Copy response into the registered buffer */
    char *buf = ctx->bufs + (size_t)buf_idx * IOURING_BUF_SIZE;
    memcpy(buf, headers, headers_len);
    if (body_len > 0)
        memcpy(buf + headers_len, body, body_len);

    uv_os_fd_t fd;
    if (uv_fileno((uv_handle_t *)&c->handle, &fd) != 0) {
        iou_free_buf(ctx, buf_idx);
        return -1;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        /* Submission queue full – flush and retry once */
        io_uring_submit(&ctx->ring);
        sqe = io_uring_get_sqe(&ctx->ring);
        if (!sqe) { iou_free_buf(ctx, buf_idx); return -1; }
    }

    /* write_fixed: kernel uses the pre-registered buffer; no get_user_pages */
    io_uring_prep_write_fixed(sqe, (int)fd, buf, (unsigned int)total, 0, buf_idx);
    io_uring_sqe_set_data(sqe, c);  /* recover client in completion handler */
    c->iouring_buf_idx = buf_idx;

    io_uring_submit(&ctx->ring);
    return 0;
}

static void on_iouring_event(uv_poll_t *handle, int status, int events) {
    (void)handle; (void)status; (void)events;
    iouring_ctx_t *ctx = &g_server.iouring;

    struct io_uring_cqe *cqe;
    unsigned head;
    unsigned nr = 0;  /* count consumed, not raw ring head */

    io_uring_for_each_cqe(&ctx->ring, head, cqe) {
        client_t *c    = (client_t *)io_uring_cqe_get_data(cqe);
        int write_res  = cqe->res;
        int buf_idx    = c->iouring_buf_idx;

        iou_free_buf(ctx, buf_idx);
        c->iouring_buf_idx = -1;

        GIL_LOCK();
        Py_CLEAR(c->resp_status);
        Py_CLEAR(c->resp_pyheaders);
        Py_CLEAR(c->resp_body);
        Py_CLEAR(c->asgi_task);
        GIL_UNLOCK();

        if (write_res < 0 || !c->keep_alive) {
            uv_close((uv_handle_t *)&c->handle, on_close);
        } else {
            client_reset(c);
            uv_read_start((uv_stream_t *)&c->handle, alloc_cb, on_read);
        }
        nr++;
    }
    io_uring_cq_advance(&ctx->ring, nr);
}

#endif /* FREASTAL_IOURING */

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
    size_t inlen = nread;
    if (ptls_receive(c->tls, &plain, data, &inlen) != 0) {
        ptls_buffer_dispose(&plain);
        uv_close((uv_handle_t *)&c->handle, on_close);
        return;
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

static void tls_write_response_impl(client_t *c) {
    /* tls_wbuf outlives this function (uv_write holds a reference), so
     * we must heap-back the buffer. is_allocated=1 forces realloc on grow. */
    c->tls_wbuf.base = malloc(8192);
    c->tls_wbuf.capacity = c->tls_wbuf.base ? 8192 : 0;
    c->tls_wbuf.off = 0;
    c->tls_wbuf.is_allocated = 1;
    c->tls_wbuf.align_bits = 0;
    if (!c->tls_wbuf.base) { uv_close((uv_handle_t *)&c->handle, on_close); return; }
    ptls_send(c->tls, &c->tls_wbuf, c->resp_hdr, (size_t)c->resp_hdr_len);
    if (c->resp_body && PyBytes_GET_SIZE(c->resp_body) > 0)
        ptls_send(c->tls, &c->tls_wbuf,
                  PyBytes_AS_STRING(c->resp_body),
                  (size_t)PyBytes_GET_SIZE(c->resp_body));
    uv_buf_t uvbuf = uv_buf_init((char *)c->tls_wbuf.base, (unsigned)c->tls_wbuf.off);
    uv_write(&c->write_req, (uv_stream_t *)&c->handle, &uvbuf, 1, on_write);
}

#endif /* FREASTAL_TLS */
