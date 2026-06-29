#ifndef FREASTAL_SERVER_H
#define FREASTAL_SERVER_H

#include <Python.h>
#include <uv.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "picohttpparser.h"
#ifdef FREASTAL_TLS
#  include <picotls.h>
#  include <picotls/openssl.h>
#  define TLS_ENC_BUF_SIZE READ_BUF_SIZE
typedef struct {
    ptls_context_t               ctx;
    ptls_openssl_sign_certificate_t sign_cert;
} tls_server_t;
#endif

#if defined(__GNUC__) || defined(__clang__)
#  define likely(x)   __builtin_expect(!!(x), 1)
#  define unlikely(x) __builtin_expect(!!(x), 0)
#else
#  define likely(x)   (x)
#  define unlikely(x) (x)
#endif

#define CONTAINER_OF(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

/* GIL helpers: acquire/release from a non-Python thread context */
#define GIL_LOCK()    PyGILState_STATE _gilstate = PyGILState_Ensure()
#define GIL_UNLOCK()  PyGILState_Release(_gilstate)

#define READ_BUF_SIZE   (16 * 1024)   /* embedded per-client read buffer */
#define RESP_HDR_SIZE   (8  * 1024)   /* embedded per-client response header buffer */
#define MAX_HEADERS     64
#define LISTEN_BACKLOG  4096
#define PEER_ADDR_LEN   64

typedef struct client_s {
    uv_tcp_t         handle;                  /* MUST be first */
    struct client_s *next_free;               /* free-list link (valid only when pooled) */

    /* --- Read state --- */
    char    read_buf[READ_BUF_SIZE];
    int     read_len;                         /* bytes accumulated in read_buf */
    int     last_len;                         /* read_len at previous parse attempt */

    /* --- Parsed request (pointers into read_buf, valid until client_reset) --- */
    const char       *method;
    size_t            method_len;
    const char       *path;
    size_t            path_len;
    int               minor_version;
    struct phr_header headers[MAX_HEADERS];
    size_t            num_headers;
    int               headers_end;            /* byte offset of first body byte */
    size_t            content_length;

    /* --- Per-request Python response objects (set by start_response) --- */
    PyObject *resp_status;                    /* str "200 OK" etc. */
    PyObject *resp_pyheaders;                 /* list of (name, value) str tuples */
    PyObject *resp_body;                      /* bytes; held until write completes */

    /* --- Response write state --- */
    uv_write_t write_req;                     /* embedded; avoids one malloc per write */
    char       resp_hdr[RESP_HDR_SIZE];
    int        resp_hdr_len;
    uv_buf_t   write_bufs[2];                 /* [headers_buf, body_buf] */

    /* --- Connection metadata --- */
    char     peer_addr[PEER_ADDR_LEN];
    uint16_t peer_port;
    bool     keep_alive;
    PyObject *peer_addr_obj;           /* cached PyUnicode of peer_addr; reused across keep-alive requests */

    /* --- ASGI task (NULL in WSGI mode) --- */
    PyObject *asgi_task;

#ifdef FREASTAL_TLS
    char         *tls_enc;                    /* heap-alloc'd on TLS accept, NULL for plain HTTP */
    ptls_t       *tls;
    bool          tls_hs_done;
    ptls_buffer_t tls_wbuf;  /* encrypted response buf; alive until on_write */
#endif

#ifdef FREASTAL_IOURING
    int  iouring_buf_idx;  /* registered buffer in use for current write, or -1 */
#endif
} client_t;

/* ---- io_uring registered-buffer context ---- */
/*
 * When compiled with -DFREASTAL_IOURING (liburing detected), responses whose
 * total size (headers + body) exceeds IOURING_LARGE_THRESH are copied into
 * a pre-registered kernel buffer and sent with io_uring write_fixed.
 * This avoids the per-write get_user_pages() call that dominates at 12-50KB.
 *
 * For responses below the threshold the normal uv_write path is used.
 * libuv 1.45+ also transparently uses io_uring for its internal event loop
 * on Linux, giving ~10% syscall-batching gain even on the normal path.
 */
#ifdef FREASTAL_IOURING
#include <liburing.h>

#define IOURING_BUF_COUNT    128          /* max concurrent in-flight writes */
#define IOURING_BUF_SIZE     (64 * 1024)  /* bytes per registered buffer (64KB) */
#define IOURING_QUEUE_DEPTH  256
#define IOURING_LARGE_THRESH 4096         /* engage fixed-buf path above this size */

typedef struct {
    struct io_uring  ring;
    char            *bufs;                 /* slab: BUF_COUNT * BUF_SIZE bytes */
    int              free_stack[IOURING_BUF_COUNT];
    int              free_top;             /* -1 = empty */
    uv_poll_t        poll;
    bool             enabled;
} iouring_ctx_t;
#endif /* FREASTAL_IOURING */

/* Per-connection state.
 * uv_tcp_t MUST be the first field so that (client_t *) casts to (uv_tcp_t *)
 * and to (uv_stream_t *) work correctly as required by libuv.
 */

/* Pre-interned Python string keys for WSGI environ */
typedef struct {
    PyObject *REQUEST_METHOD;
    PyObject *SCRIPT_NAME;
    PyObject *PATH_INFO;
    PyObject *QUERY_STRING;
    PyObject *SERVER_NAME;
    PyObject *SERVER_PORT;
    PyObject *SERVER_PROTOCOL;
    PyObject *SERVER_SOFTWARE;
    PyObject *CONTENT_TYPE;
    PyObject *CONTENT_LENGTH;
    PyObject *REMOTE_ADDR;
    PyObject *wsgi_version;
    PyObject *wsgi_url_scheme;
    PyObject *wsgi_input;
    PyObject *wsgi_errors;
    PyObject *wsgi_multithread;
    PyObject *wsgi_multiprocess;
    PyObject *wsgi_run_once;

    /* Pre-built values */
    PyObject *http_1_0;               /* "HTTP/1.0" */
    PyObject *http_1_1;               /* "HTTP/1.1" */
    PyObject *server_name_val;        /* host string */
    PyObject *server_port_val;        /* port string */
    PyObject *server_software_val;    /* "freastal/1.0" */
    PyObject *wsgi_version_val;       /* (1, 0) tuple */
    PyObject *wsgi_url_scheme_val;    /* "http" */
#ifdef FREASTAL_TLS
    PyObject *wsgi_url_scheme_https_val;
#endif
    PyObject *empty_str;              /* "" */
} wsgi_keys_t;

/* Global server state */
typedef struct {
    uv_loop_t  *loop;
    uv_tcp_t    handle;
    PyObject   *app;
    char        host[64];
    int         port;

    /* Slab-allocated client pool */
    client_t   *free_list;
    void       *slab;                 /* malloc'd slab holding pool objects */
    int         pool_cap;
    int         pool_size;            /* active connections */

    wsgi_keys_t keys;

    /* Cached Python objects */
    PyObject   *io_bytesio;           /* io.BytesIO class */
    PyObject   *noop_write;           /* legacy wsgi write() no-op */
    PyObject   *sys_stderr;           /* sys.stderr reference */
    PyObject   *empty_wsgi_input;     /* BytesIO(b"") singleton; reused for zero-body requests */

#ifdef FREASTAL_IOURING
    iouring_ctx_t iouring;
#endif
#ifdef FREASTAL_TLS
    tls_server_t  tls;
    bool          tls_enabled;
#endif

    /* ASGI mode (runtime-selected; zero-init = WSGI) */
    bool       asgi_mode;
    PyObject  *asgi_loop;           /* asyncio event loop */
    PyObject  *asgi_run_once;       /* loop._run_once method */
    PyObject  *asgi_run_request;    /* _asgi_protocol.run_asgi_request */
    uv_check_t asgi_check;          /* post-I/O coroutine stepper */
    uv_poll_t  asgi_poll;           /* watches asyncio's selector fd for async I/O */
    bool       asgi_poll_active;

    /* Pre-built ASGI scope objects */
    PyObject  *asgi_type_http;
    PyObject  *asgi_http_11;
    PyObject  *asgi_http_10;
    PyObject  *asgi_scheme_http;
    PyObject  *asgi_empty_str;
    PyObject  *asgi_empty_bytes;
    PyObject  *asgi_version_dict;   /* {"version": "3.0"} */
    PyObject  *asgi_server_tuple;   /* (host, port) */

    /* asyncio._set_running_loop: required on Python 3.14+ where context.run()
     * validates the C-level running-loop thread-local before stepping a Task. */
    PyObject  *asyncio_set_running_loop;
} server_t;

extern server_t g_server;

/* Server lifecycle */
int  server_init(PyObject *app, const char *host, int port, bool reuse_port,
                 const char *certfile, const char *keyfile);
void server_run(void);

/* Client pool */
client_t *client_alloc(void);
void      client_free(client_t *c);
void      client_reset(client_t *c);

/* Kick off async write of the formatted response */
void write_response(client_t *c);

#ifdef FREASTAL_IOURING
/* Initialise the io_uring registered-buffer context (soft failure: returns 0) */
int  iouring_init(uv_loop_t *loop, iouring_ctx_t *ctx);
/* Submit a write_fixed for headers+body; returns 0 on success, -1 to fall back */
int  iouring_write(client_t *c,
                   const char *headers, size_t headers_len,
                   const char *body,    size_t body_len);
#endif

void http_dispatch(client_t *c, uv_stream_t *stream);

int       asgi_server_init(PyObject *loop);
void      asgi_dispatch(client_t *c);
PyObject *asgi_send_response_c(PyObject *self, PyObject *args);

#ifdef FREASTAL_TLS
#include "tls.h"
#endif

#endif /* FREASTAL_SERVER_H */
