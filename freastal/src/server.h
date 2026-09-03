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
/* Ciphertext handed to picotls in one read.
 *
 * Sized to a whole maximal record rather than to read_buf.  A record picotls
 * cannot see the end of is copied into tls->recvbuf.rec and reassembled there
 * -- a malloc, a copy and a free per record -- and at READ_BUF_SIZE that is
 * not an edge case but the steady state for a peer sending full-size records,
 * because a maximal record is 16645 wire bytes and the buffer offered was
 * 16384.  The extra 261 bytes per connection buy the whole of that back.
 *
 * This is the read-side twin of the write path's TLS_WBUF_SIZE, which is a
 * maximal record plus its framing for the same reason. */
#  define TLS_ENC_BUF_SIZE         (5 + TLS_MAX_ENC_RECORD)
/* Recycled encryption-output block.  TLS 1.3 caps a record's plaintext at
 * 16KB and frames it with 22 bytes, so one block of this size holds the
 * ciphertext of a whole maximal record with room to spare -- enough that a
 * response header's record rides along in front of it.  A response too large
 * for one block is encrypted into a chain of them, one uv_write iovec each,
 * rather than falling off onto a per-response malloc. */
#  define TLS_MAX_RECORD_PLAINTEXT (16 * 1024)
#  define TLS_WBUF_SIZE            (TLS_MAX_RECORD_PLAINTEXT + 512)
/* Cap on retained blocks.  The pool's natural high-water mark is the number of
 * responses in flight at once, but a one-off burst should not pin its peak. */
#  define TLS_WBUF_POOL_MAX        256
/* Plaintext that one read produced and read_buf had no room for.
 *
 * A read hands picotls at most TLS_ENC_BUF_SIZE fresh ciphertext bytes on top
 * of the one incomplete record it may already be holding, which parse_record()
 * caps at 5 + PTLS_MAX_ENCRYPTED_RECORD_SIZE (vendor/picotls/lib/picotls.c).
 * Every record costs at least 22 bytes of framing, so the plaintext a single
 * ptls_receive() sweep can emit is strictly below the sum of the two; two
 * whole encrypted records is comfortably above it.  Only one sweep's surplus
 * is ever held, because tls_read_flow() stops reading while the spill is
 * non-empty, so the bound does not accumulate across reads.
 *
 * The derivation is checked below rather than trusted: the assertion states
 * the same sum the paragraph argues.  Nothing exercises the bound at its limit
 * -- the largest overflow seen while developing this was around 14KB -- so
 * tls_spill_stash() still range-checks rather than trusting its argument. */
#  define TLS_MAX_ENC_RECORD       (16384 + 256)
#  define TLS_SPILL_SIZE           (TLS_ENC_BUF_SIZE + TLS_MAX_ENC_RECORD)
/* Spill blocks are recycled through a free list, like the encryption blocks
 * above, and handed back the moment one drains.  The high-water mark is then
 * the number of connections overflowing at the same instant rather than the
 * number that have ever overflowed, which is what keeps a pipelining-heavy
 * workload from pinning 32KB on every open connection. */
#  define TLS_SPILL_POOL_MAX       64
/*
 * What a record costs the buffer it is decrypted into, over and above the
 * plaintext that comes out of it.
 *
 * handle_input() (vendor/picotls/lib/picotls.c) reserves 5 + rec.length before
 * touching a record, where rec.length is the *encrypted* body, and then
 * decrypts in place at base + off.  A TLS 1.3 record body is the plaintext
 * plus one inner content-type byte plus the AEAD tag, so
 *
 *     reserve = 5 + plaintext + 1 + tag_size (+ padding)
 *
 * Every suite in ptls_openssl_cipher_suites[] -- AES-128-GCM, AES-256-GCM,
 * ChaCha20-Poly1305 -- has a 16-byte tag, which fixes the constant part at 22.
 * Padding only ever makes the reserve larger and picotls strips it after
 * decrypting, so a peer that pads is caught by tls_on_read_data()'s fallback
 * rather than by this number.
 */
#  define TLS_RECORD_OVERHEAD      22
/*
 * The largest reserve one record can ask for.  parse_record_header() refuses
 * an APPDATA record whose body exceeds PTLS_MAX_ENCRYPTED_RECORD_SIZE, which
 * is what TLS_MAX_ENC_RECORD mirrors; handle_input() adds the 5-byte header.
 *
 * read_buf is smaller than this, and deliberately so -- sizing it to cover a
 * maximal record would cost 16KB on every client_t, TLS or not.  So no
 * arrangement of read_buf can *rule out* picotls growing the buffer it is
 * handed, and tls_on_read_data() detects growth instead of proving it away.
 * What is proved away is the case that matters: a request that stays within
 * TLS_READ_ZEROCOPY_MAX decrypts into read_buf with no growth, hence no
 * allocation and no copy.
 */
#  define TLS_MAX_DECRYPT_RESERVE  (5 + TLS_MAX_ENC_RECORD)
/*
 * Physical tail behind read_buf, so that a reservation can overhang what it
 * will actually keep.
 *
 * A record needs TLS_RECORD_OVERHEAD more bytes of capacity than the plaintext
 * it yields, so without a tail the last 22 bytes of read_buf are room no
 * record can decrypt into, and a request sized to the end of the buffer falls
 * onto an allocation despite fitting.  Exactly TLS_RECORD_OVERHEAD of tail
 * closes that band and no more: a satisfied reservation leaves at most
 *
 *     off <= (READ_BUF_SIZE + slack) - 5 - 1 - tag == READ_BUF_SIZE
 *
 * so read_len still cannot pass READ_BUF_SIZE and every bound downstream that
 * assumes so is untouched.  A wider tail would break that, not improve it.
 */
#  define TLS_DECRYPT_SLACK        TLS_RECORD_OVERHEAD
/*
 * The zero-copy guarantee, stated as a size.  With the slack above, a record
 * decrypts into read_buf exactly when its plaintext fits there -- so the
 * guarantee covers every request read_buf can hold at all, and anything past
 * it is refused rather than copied.
 */
#  define TLS_READ_ZEROCOPY_MAX    READ_BUF_SIZE
_Static_assert(TLS_RECORD_OVERHEAD == 5 + 1 + 16,
               "5-byte record header, one inner content-type byte, 16-byte "
               "AEAD tag; revisit if a suite with another tag size is added");
_Static_assert(TLS_MAX_DECRYPT_RESERVE <= TLS_SPILL_SIZE,
               "the growth fallback copies a whole sweep back out of picotls's "
               "buffer, and what read_buf cannot take goes to the spill");
/* Blocks one response may claim.  The cap is about pool fairness, not about
 * iovec limits: letting one response take half of a 256-block pool would push
 * every connection sharing the loop onto malloc for as long as it took to
 * drain.  Past this a response takes a single oversized buffer instead --
 * still freastal's, not picotls's, so there is no ptls_clear_memory() on that
 * path either.  See tls_bigbuf_get() for how it is retained and reused. */
#  define TLS_WSEG_MAX             128
/* Largest oversized buffer worth keeping between responses.  One is retained
 * per loop; anything above this is freed on release rather than pinned. */
#  define TLS_BIGBUF_KEEP_MAX      (2 * 1024 * 1024)

/*
 * Trailer carried in the tail of every block, past the ciphertext.  Chaining
 * the blocks through themselves costs client_t one head pointer instead of an
 * array of TLS_WSEG_MAX segments -- 2KB per connection slot, over a 4096-slot
 * pool -- and costs no allocation of its own.
 *
 * buf.base is what picotls actually wrote into, which is the block itself
 * unless a reservation outgrew the capacity advertised to it, in which case
 * picotls swapped in an allocation of its own and buf owns that.
 */
typedef struct tls_wseg_s {
    void         *next;              /* next block of this response, or NULL */
    ptls_buffer_t buf;
} tls_wseg_t;

/* What tls_wbuf_get() allocates; the first TLS_WBUF_SIZE bytes are picotls's. */
#  define TLS_WBLOCK_SIZE     (TLS_WBUF_SIZE + sizeof(tls_wseg_t))
#  define TLS_WSEG_OF(block)  ((tls_wseg_t *)((uint8_t *)(block) + TLS_WBUF_SIZE))

_Static_assert(TLS_WBUF_SIZE % _Alignof(tls_wseg_t) == 0,
               "the block trailer must land on its own alignment");
_Static_assert(TLS_WBUF_SIZE >= TLS_MAX_RECORD_PLAINTEXT + 64,
               "a maximal TLS record must fit in one block, or the chain "
               "walk in tls_write_response_impl() cannot make progress");

/*
 * Session-ticket sealing keys.
 *
 * A ticket carries the session's resumption secret, sealed under a key this
 * process holds, and hands it back to the client to keep.  Whoever holds the
 * sealing key can open every ticket ever sealed under it, so the key's
 * lifetime -- not the ticket's -- is what bounds the damage from a later
 * compromise of the process.  A key minted once at startup and held for the
 * process lifetime makes that bound the uptime: a month-old server hands an
 * attacker a month of tickets.  So the key is rotated, and the retired ones
 * are zeroized rather than kept "just in case".
 *
 * The ring is what makes rotation invisible to clients.  The newest key seals;
 * every key still in the ring can unseal.  A ticket names its key (the 16-byte
 * label in the clear at the front), so the lookup is by name, not by trial
 * decryption, and rotation costs nothing on the resumption path.
 *
 * The three numbers below are one constraint, not three choices.  A key
 * becomes current at t0 and stops sealing at t0+ROTATE; the last ticket it
 * seals is accepted until t0+ROTATE+LIFETIME; the slot is reused -- and the
 * key destroyed -- at t0+RING*ROTATE.  For no client to be told "resume with
 * this" and then handed a full handshake for a ticket that has not expired:
 *
 *     LIFETIME <= (RING - 1) * ROTATE
 *
 * 2h/1h/3 satisfies that exactly.  LIFETIME is 2h because that is OpenSSL's
 * own default session timeout and comfortably inside RFC 8446's 7-day ceiling,
 * and because the workload resumption is for -- a user returning to a tab, a
 * dropped connection reopened, a client that does not pool -- lives in minutes
 * to a couple of hours, not in days.  The 24h the issue calls "typical" would
 * buy a few percent more hits at the top of the tail and cost 12x the key
 * exposure.
 *
 * Given LIFETIME, the constraint fixes the exposure: the oldest key in the
 * ring is RING*ROTATE = LIFETIME*RING/(RING-1) old, so the window can never be
 * shorter than LIFETIME itself and RING only picks the multiple -- 2x at
 * RING=2, 1.5x at RING=3, 1.25x at RING=5.  RING=3 takes most of the drop
 * for 243 bytes of key material and one timer an hour; going to RING=5 would
 * halve the rotation period to shave the multiple by a further 0.25x.  So:
 * worst case, an attacker who takes the process at time T can open tickets
 * sealed as far back as T-3h, against "everything since boot" today.
 *
 * What that attacker gets is bounded further by require_dhe_on_psk (see
 * tls_server_init): a resumed handshake still does a fresh ECDHE, so a
 * recovered resumption secret does not decrypt recorded traffic.
 */
#  define TLS_TICKET_NAME_LEN   16      /* picotls' TICKET_LABEL_SIZE, fixed by the format */
#  define TLS_TICKET_AES_LEN    32      /* AES-256-CBC */
#  define TLS_TICKET_HMAC_LEN   32      /* HMAC-SHA256 */
#  define TLS_TICKET_RING       3
#  define TLS_TICKET_ROTATE_MS  (60u * 60u * 1000u)   /* 1 hour */
#  define TLS_TICKET_LIFETIME_S (2u * 60u * 60u)      /* 2 hours */
_Static_assert((uint64_t)TLS_TICKET_LIFETIME_S * 1000u <=
                   (uint64_t)(TLS_TICKET_RING - 1) * TLS_TICKET_ROTATE_MS,
               "a ticket would outlive the key that can open it: clients would "
               "be handed a surprise full handshake inside ticket_lifetime");

typedef struct {
    uint8_t name[TLS_TICKET_NAME_LEN];
    uint8_t aes[TLS_TICKET_AES_LEN];
    uint8_t hmac[TLS_TICKET_HMAC_LEN];
    /* False for a slot that has never been filled and for one just zeroized.
     * Load-bearing, not bookkeeping: a zeroized slot's name is sixteen zero
     * bytes under an all-zero key, all of which an attacker knows, so matching
     * one would let anybody forge a ticket. */
    bool    live;
} tls_ticket_key_t;

typedef struct {
    ptls_context_t               ctx;
    ptls_openssl_sign_certificate_t sign_cert;
    ptls_encrypt_ticket_t        ticket_cb;   /* ctx.encrypt_ticket points here */
    tls_ticket_key_t             ticket_keys[TLS_TICKET_RING];
    int                          ticket_cur;  /* the slot that seals; the rest only unseal */
    uv_timer_t                   ticket_timer;
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
#ifndef FREASTAL_TLS
#  define TLS_DECRYPT_SLACK 0         /* no decrypt path: no reservation to overhang */
#endif
/* What read_buf actually occupies.  READ_BUF_SIZE is what may be *kept*; the
 * slack past it is transit space a TLS reservation may overhang into.  Every
 * bound in the server is written against READ_BUF_SIZE -- this name appears
 * only where the array's real width is meant. */
#define READ_BUF_ALLOC  (READ_BUF_SIZE + TLS_DECRYPT_SLACK)
/* Embedded per-client response header buffer.
 *
 * This is not scratch space with slack in it: it is the largest response
 * header block freastal will emit, and a block that does not fit is answered
 * with a 500 rather than truncated (format_response_headers() in wsgi.c,
 * format_response_asgi() in asgi.c).  The TLS write path used to borrow the
 * unused tail to coalesce a small body behind the header; it hands picotls two
 * iovecs instead now and copies nothing, so nothing borrows this any more.
 *
 * Which means shrinking it buys memory -- 4096 connection slots per worker, so
 * every 1KB off is 4MB -- at the price of rejecting responses that work today.
 * 8KB is the conventional bound (Apache's, and nginx's for request headers),
 * and a handful of Set-Cookie headers or a long CSP gets a fair way into it,
 * so the size stays until someone measures real header blocks rather than
 * guessing at them. */
#define RESP_HDR_SIZE   (8  * 1024)
#define MAX_HEADERS     64
#define LISTEN_BACKLOG  4096
#define PEER_ADDR_LEN   64

#ifdef FREASTAL_TLS
/* Down here rather than beside the TLS sizes above: both of these expand to
 * READ_BUF_SIZE, which that block is written against but cannot assert on,
 * because it is defined a few lines up from here. */
_Static_assert(TLS_SPILL_SIZE >= TLS_ENC_BUF_SIZE + TLS_MAX_ENC_RECORD,
               "one sweep's surplus plaintext must fit the spill: the fresh "
               "ciphertext a read delivers, plus the one partial record "
               "picotls may already be holding, bound it from above");
_Static_assert(TLS_READ_ZEROCOPY_MAX == READ_BUF_SIZE,
               "the slack is what lifts the zero-copy bound to the whole of "
               "read_buf; if it shrinks, this is the line that says so");
_Static_assert(READ_BUF_ALLOC - TLS_DECRYPT_SLACK == READ_BUF_SIZE,
               "the slack is transit space for a reservation, never capacity "
               "read_len may use");
#endif

/*
 * Per-connection state.
 *
 * Field order is load-bearing, in two ways:
 *
 *  - uv_tcp_t MUST be first so that (client_t *) casts to (uv_tcp_t *) and to
 *    (uv_stream_t *) work, as libuv requires.
 *
 *  - The three large buffers MUST be the last fields, in this order.  A
 *    client_t is 27KB, of which 26.5KB is buffer space, and it is recycled
 *    from a slab on every accept.  client_alloc() therefore clears only the
 *    scalar prefix (760 bytes) and leaves the buffers alone: read_buf is
 *    bounded by read_len, resp_hdr by resp_hdr_len and headers[] by
 *    num_headers, all three of which live in the cleared prefix.  The
 *    static assertions below the struct hold that invariant.
 */
typedef struct client_s {
    uv_tcp_t         handle;                  /* MUST be first */
    struct client_s *next_free;               /* free-list link (valid only when pooled) */

    /* --- Read state --- */
    int     read_len;                         /* bytes accumulated in read_buf */
    int     last_len;                         /* read_len at previous parse attempt */

    /* --- Parsed request (pointers into read_buf, valid until client_reset) --- */
    const char       *method;
    size_t            method_len;
    const char       *path;
    size_t            path_len;
    int               minor_version;
    size_t            num_headers;
    int               headers_end;            /* byte offset of first body byte */
    size_t            content_length;

    /* --- Per-request Python response objects (set by start_response) --- */
    PyObject *resp_status;                    /* str "200 OK" etc. */
    PyObject *resp_pyheaders;                 /* list of (name, value) str tuples */
    PyObject *resp_body;                      /* bytes; held until write completes */

    /* --- Response write state --- */
    uv_write_t write_req;                     /* embedded; avoids one malloc per write */
    int        resp_hdr_len;
    uv_buf_t   write_bufs[2];                 /* [headers_buf, body_buf] */

    /* --- Connection metadata --- */
    char     peer_addr[PEER_ADDR_LEN];
    uint16_t peer_port;
    bool     keep_alive;
    bool     in_flight;                /* a response is being produced; no second request may be parsed */
    bool     read_armed;               /* uv_read_start() is in effect for this handle */
    PyObject *peer_addr_obj;           /* cached PyUnicode of peer_addr; reused across keep-alive requests */

    /* --- ASGI per-connection state (NULL in WSGI mode) --- */
    PyObject *asgi_task;
    PyObject *asgi_client_obj;          /* cached (peer_ip, peer_port) scope tuple */
    PyObject *asgi_capsule;             /* cached capsule holding this client_t */

#ifdef FREASTAL_TLS
    char         *tls_enc;                    /* heap-alloc'd on TLS accept, NULL for plain HTTP */
    ptls_t       *tls;
    bool          tls_hs_done;
    void         *tls_wblock; /* head of the encrypted response's block chain; alive until on_write */
    void         *tls_wbig;   /* oversized buffer for a response past TLS_WSEG_MAX, or NULL */
    bool          tls_broken; /* the record layer is unusable; no close_notify may be sent */
    char         *tls_spill;                  /* pooled overflow block, held only while tls_spill_len > 0 */
    int           tls_spill_len;              /* bytes held in tls_spill; 0 means no block is held */
#endif

    /* --- Large buffers; NOT cleared by client_alloc().  Keep last. --- */
    struct phr_header headers[MAX_HEADERS];
    char              resp_hdr[RESP_HDR_SIZE];
    char              read_buf[READ_BUF_ALLOC];
} client_t;

/* Bytes client_alloc() clears: everything up to the first large buffer. */
#define CLIENT_ZERO_LEN  offsetof(client_t, headers)

/* The reason client_alloc() may stop at CLIENT_ZERO_LEN is that the tail is
 * exactly headers[] + resp_hdr[] + read_buf[] and nothing else.  Reordering or
 * appending a field would silently start leaking a previous connection's
 * state into the next one, so make it a build error instead. */
_Static_assert(offsetof(client_t, handle) == 0,
               "uv_tcp_t handle must be the first field of client_t");
_Static_assert(offsetof(client_t, headers) + MAX_HEADERS * sizeof(struct phr_header)
                   == offsetof(client_t, resp_hdr),
               "resp_hdr must directly follow headers[]");
_Static_assert(offsetof(client_t, resp_hdr) + RESP_HDR_SIZE
                   == offsetof(client_t, read_buf),
               "read_buf must directly follow resp_hdr");
/* Not an equality: READ_BUF_ALLOC carries a 22-byte TLS tail, which leaves
 * client_t with a few bytes of alignment padding behind read_buf.  Rounding
 * the tail up to swallow that padding would be the wrong fix -- the slack is
 * exactly one record's framing on purpose, and widening it would let a
 * satisfied reservation leave read_len past READ_BUF_SIZE.  So the assertion
 * says what is actually meant: nothing but padding may follow read_buf. */
_Static_assert(sizeof(client_t) - offsetof(client_t, read_buf) - READ_BUF_ALLOC
                   < _Alignof(client_t),
               "read_buf must be the last field of client_t");


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

/* Pre-interned Python string keys for the ASGI scope entries that change from
 * request to request.  The constant entries never need a key object: they ride
 * along inside the scope template. */
typedef struct {
    PyObject *http_version;
    PyObject *method;
    PyObject *path;
    PyObject *raw_path;
    PyObject *query_string;
    PyObject *client;
    PyObject *headers;
} asgi_keys_t;

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
    int         pool_used;            /* slab objects handed out at least once */

    wsgi_keys_t keys;

    /* Cached Python objects */
    PyObject   *io_bytesio;           /* io.BytesIO class */
    PyObject   *noop_write;           /* legacy wsgi write() no-op */
    PyObject   *sys_stderr;           /* sys.stderr reference */
    PyObject   *empty_wsgi_input;     /* BytesIO(b"") singleton; reused for zero-body requests */

#ifdef FREASTAL_TLS
    tls_server_t  tls;
    bool          tls_enabled;
    void         *tls_wbuf_pool;      /* free list of TLS_WBLOCK_SIZE blocks, linked through their first word */
    int           tls_wbuf_pool_n;
    void         *tls_spill_pool;     /* same, for TLS_SPILL_SIZE read-overflow blocks */
    int           tls_spill_pool_n;
    void         *tls_bigbuf;         /* one retained oversized buffer, or NULL */
    size_t        tls_bigbuf_cap;     /* its capacity; meaningless when tls_bigbuf is NULL */
    /* Accounting, so that "released exactly once" and "no malloc in the
     * steady state" are properties a test can assert rather than claims.
     * Two integer ops per TLS response, alongside the pool counter above. */
    unsigned long tls_wbuf_live;      /* blocks handed out and not yet returned */
    unsigned long tls_bigbuf_live;    /* oversized buffers handed out and not yet returned */
    unsigned long tls_wbuf_mallocs;   /* malloc() calls made by the two getters */
    /* Read path.  The zero-copy claim -- a request inside
     * TLS_READ_ZEROCOPY_MAX is decrypted straight into read_buf, with no
     * allocation and no copy -- is invisible from the wire in exactly the same
     * way, so it gets a counter too.  tls_read_grows counts the sweeps in
     * which picotls replaced the buffer it was handed, which is the one event
     * that costs both a malloc and a copy back. */
    unsigned long tls_read_grows;
    unsigned long tls_read_spills;    /* sweeps that left plaintext in the spill */
#endif

    /* ASGI mode (runtime-selected; zero-init = WSGI) */
    bool       asgi_mode;
    PyObject  *asgi_loop;           /* asyncio event loop */
    PyObject  *asgi_run_once;       /* loop._run_once method */
    PyObject  *asgi_run_request;    /* _asgi_protocol.run_asgi_request */
    uv_check_t asgi_check;          /* post-I/O coroutine stepper */
    uv_poll_t  asgi_poll;           /* watches asyncio's selector fd for async I/O */
    bool       asgi_poll_active;

    /* Keeping libuv awake while asyncio still has work.  libuv blocks in its
     * poll phase whenever nothing is pending, which would stop uv_check_t from
     * firing and strand any suspended task.  An active uv_idle_t forces
     * uv_backend_timeout() to 0 so the next iteration happens immediately;
     * asgi_timer wakes the loop for asyncio's next scheduled callback. */
    uv_idle_t  asgi_idle;
    uv_timer_t asgi_timer;
    bool       asgi_idle_active;
    bool       asgi_timer_active;
    PyObject  *asgi_ready;          /* loop._ready deque (callbacks due now) */
    PyObject  *asgi_scheduled;      /* loop._scheduled heap of TimerHandle */
    PyObject  *asgi_loop_time;      /* loop.time bound method */

    /* Pre-built ASGI scope objects */
    PyObject  *asgi_type_http;
    PyObject  *asgi_http_11;
    PyObject  *asgi_http_10;
    PyObject  *asgi_scheme_http;
#ifdef FREASTAL_TLS
    PyObject  *asgi_scheme_https;
#endif
    PyObject  *asgi_empty_str;
    PyObject  *asgi_empty_bytes;
    PyObject  *asgi_version_dict;   /* {"version": "3.0"} */
    PyObject  *asgi_server_tuple;   /* (host, port) */

    /* Fully-populated scope, copied per request.  Never mutated after init. */
    PyObject  *asgi_scope_template;
#ifdef FREASTAL_TLS
    /* Same shape, scheme="https"; picked per request on c->tls, the way
     * the WSGI path keeps two environ templates. */
    PyObject  *asgi_scope_template_https;
#endif
    asgi_keys_t asgi_keys;
} server_t;

extern server_t g_server;

/* Shared response-formatting helpers.  Both the WSGI and ASGI formatters
 * emit Content-Length, so the integer writer lives here rather than being
 * duplicated in each of them. */
/* Two ASCII digits per entry, so decimal conversion costs one divide per two
 * digits instead of one per digit (Alexandrescu's method, as in fmt). */
static const char TWO_DIGITS[] =
    "00010203040506070809" "10111213141516171819"
    "20212223242526272829" "30313233343536373839"
    "40414243444546474849" "50515253545556575859"
    "60616263646566676869" "70717273747576777879"
    "80818283848586878889" "90919293949596979899";

/* Digits in the decimal form of u; zero counts as one digit. */
static inline int uint_ndigits(uint64_t u) {
    int d = 1;
    for (;;) {
        if (u < 10)    return d;
        if (u < 100)   return d + 1;
        if (u < 1000)  return d + 2;
        if (u < 10000) return d + 3;
        u /= 10000;
        d += 4;
    }
}

/*
 * Write a non-negative integer as decimal ASCII.  Returns bytes written, -1 on
 * overflow.  Sizing the field first lets the digits be filled in place, which
 * saves both the temporary buffer and the reversing pass a per-digit loop needs.
 */
static inline int write_uint(char *dst, int remaining, Py_ssize_t n) {
    uint64_t u = (uint64_t)n;
    int      d = uint_ndigits(u);
    if (unlikely(d > remaining)) return -1;

    char *p = dst + d;
    while (u >= 100) {
        unsigned i = (unsigned)(u % 100) * 2;
        u /= 100;
        p -= 2;
        p[0] = TWO_DIGITS[i];
        p[1] = TWO_DIGITS[i + 1];
    }
    if (u >= 10) {
        unsigned i = (unsigned)u * 2;
        p[-2] = TWO_DIGITS[i];
        p[-1] = TWO_DIGITS[i + 1];
    } else {
        p[-1] = (char)('0' + u);
    }
    return d;
}

/* Server lifecycle */
/* listen_fd < 0 binds host:port here; otherwise it is an already-bound
 * listening socket the caller owns and server_init dup()s. */
int  server_reuseport_supported(void);
int  server_init(PyObject *app, const char *host, int port, bool reuse_port,
                 const char *certfile, const char *keyfile, int listen_fd);
void server_run(void);

/* Client pool */
client_t *client_alloc(void);
void      client_free(client_t *c);
void      client_reset(client_t *c);

/* Kick off async write of the formatted response */
void write_response(client_t *c);

/* Parse and dispatch whatever is buffered in c->read_buf.
 * Returns  1 if a request was dispatched (a response is now in flight),
 *          0 if more bytes are needed (caller must ensure reading is armed),
 *         -1 if the connection was closed. */
int http_dispatch(client_t *c, uv_stream_t *stream);

int       asgi_server_init(PyObject *loop);
void      asgi_dispatch(client_t *c);
PyObject *asgi_send_response_c(PyObject *self, PyObject *args);

#ifdef FREASTAL_TLS
#include "tls.h"
#endif

#endif /* FREASTAL_SERVER_H */
