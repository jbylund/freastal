#ifdef FREASTAL_TLS
#include "server.h"
#include "tls.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#  include <openssl/core_names.h>
#  include <openssl/params.h>
#else
#  include <openssl/hmac.h>
#endif
#include <stdio.h>

/*
 * picotls' own default, ptls_openssl_key_exchanges[], holds secp256r1 and
 * nothing else.  Chrome and Firefox do list P-256 in supported_groups, but
 * neither ever sends a P-256 key share -- they guess X25519MLKEM768 and
 * X25519 -- so a P-256-only server matches nothing in the first ClientHello
 * and has to answer with a HelloRetryRequest.  That is an extra round trip on
 * every new browser connection, plus a keygen both ends then discard, before
 * settling on the slower of the two curves anyway.
 *
 * Membership, not order, is what fixes it.  Both selection sites in picotls
 * iterate the *client's* list on the outside and ours on the inside:
 * select_key_share() walks the client's key_share entries and assigns
 * *selected only while it is still NULL, and select_negotiated_group() walks
 * the client's supported_groups and returns on its first hit.  The client's
 * preference decides; the order below is documentation.
 *
 * secp384r1 and secp521r1 are deliberately absent.  RFC 8446 makes secp256r1
 * mandatory for conformant TLS 1.3 clients, so P-256 is already the universal
 * floor and the larger curves buy no interop -- what they would buy is a
 * client-chosen cost, since an unauthenticated peer that offers secp521r1 --
 * as a key share, or first in supported_groups on the retry path -- would
 * make us do a P-521 ECDH per handshake for no security X25519 does not
 * already give us.  ptls_openssl_key_exchanges_all[] is not the answer
 * either: on top of those two curves it carries the bare mlkem512/768/1024
 * groups, which have no classical component at all, whereas the hybrid keeps
 * X25519 underneath as a floor.
 *
 * Both macros below are always defined by picotls/openssl.h, to 0 when the
 * algorithm is unavailable, and secp256r1 is unconditional, so every
 * combination yields a valid list.  OpenSSL < 3.5 degrades to
 * {x25519, secp256r1}; CI builds that path and the tests confirm it
 * negotiates X25519 without a retry.  LibreSSL sets neither macro and would
 * land back on today's {secp256r1} -- read off the header, not built here.
 */
static ptls_key_exchange_algorithm_t *freastal_key_exchanges[] = {
#if PTLS_OPENSSL_HAVE_X25519MLKEM768
    &ptls_openssl_x25519mlkem768,
#endif
#if PTLS_OPENSSL_HAVE_X25519
    &ptls_openssl_x25519,
#endif
    &ptls_openssl_secp256r1,
    NULL};

/*
 * ---------------------------------------------------------------------------
 * Session tickets
 * ---------------------------------------------------------------------------
 *
 * picotls does the sealing and the framing; what it wants from us is a key.
 * Both ptls_openssl_{encrypt,decrypt}_ticket helpers take an OpenSSL-shaped
 * key callback: on seal it writes the key name and IV into space picotls has
 * already reserved at the front of the ticket and initializes the cipher and
 * MAC contexts; on unseal it is handed the name and IV read off the wire and
 * either finds that key or returns 0 to say it cannot.  Returning 0 there is
 * not an error path -- picotls turns it into "this PSK identity did not
 * decrypt", skips it, and the handshake proceeds as a full one.  That is the
 * behaviour a client gets today for every connection, so a ticket sealed by a
 * key this process no longer has costs a handshake, never a failure.
 *
 * Nothing here takes a lock, and nothing here needs one.  A freastal worker is
 * a *process*, not a thread -- freastal/__init__.py starts them with
 * multiprocessing.Process -- with one libuv loop on one thread, and libuv runs
 * the rotation timer's callback and the handshake callbacks that read the ring
 * one at a time on that thread.  The ring is per-process state reached only
 * from loop callbacks.  The consequence of per-process is under
 * "Multiple workers" at the bottom of this block.
 */

/* AES-256-CBC's block size.  picotls hands the callback EVP_MAX_IV_LENGTH
 * bytes of room for the IV and then advances past all of it regardless of what
 * the cipher used, so the assert is what keeps the write in bounds. */
#define TLS_TICKET_IV_LEN 16
_Static_assert(EVP_MAX_IV_LENGTH >= TLS_TICKET_IV_LEN,
               "the ticket IV would not fit the space picotls reserves for it");

/*
 * OpenSSL 3 replaced HMAC_CTX with EVP_MAC_CTX and picotls carries a helper
 * pair for each.  The pair is chosen here rather than assumed: the _evp pair
 * is compiled only under `#if OPENSSL_VERSION_NUMBER >= 0x30000000L` in
 * picotls/openssl.h, so naming it unconditionally would not degrade on an
 * older OpenSSL or on LibreSSL (which reports 0x20000000L) -- it would fail to
 * link.  The two paths differ only in how the MAC context is keyed; everything
 * below is shared.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
typedef EVP_MAC_CTX tls_ticket_mac_ctx_t;
#  define tls_ticket_seal_impl   ptls_openssl_encrypt_ticket_evp
#  define tls_ticket_unseal_impl ptls_openssl_decrypt_ticket_evp

static int tls_ticket_mac_init(EVP_MAC_CTX *hctx, const uint8_t *key, size_t len) {
    /* OSSL_PARAM_construct_utf8_string takes a mutable char *, so the digest
     * name cannot be a string literal here. */
    char digest[] = "SHA256";
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end()};
    return EVP_MAC_init(hctx, key, len, params);
}
#else
typedef HMAC_CTX tls_ticket_mac_ctx_t;
#  define tls_ticket_seal_impl   ptls_openssl_encrypt_ticket
#  define tls_ticket_unseal_impl ptls_openssl_decrypt_ticket

static int tls_ticket_mac_init(HMAC_CTX *hctx, const uint8_t *key, size_t len) {
    return HMAC_Init_ex(hctx, key, (int)len, EVP_sha256(), NULL);
}
#endif

/* Fill a slot with fresh key material.  ptls_openssl_random_bytes() abort()s
 * if RAND_bytes fails rather than returning, so there is no partial key to
 * guard against and no failure for the callers to handle. */
static void tls_ticket_key_mint(tls_ticket_key_t *k) {
    ptls_openssl_random_bytes(k->name, TLS_TICKET_NAME_LEN);
    ptls_openssl_random_bytes(k->aes, TLS_TICKET_AES_LEN);
    ptls_openssl_random_bytes(k->hmac, TLS_TICKET_HMAC_LEN);
    k->live = true;
}

/* The name is public -- it rides in the clear at the front of every ticket --
 * so an ordinary memcmp is the right comparison; the secret this guards is the
 * HMAC, which picotls verifies after we hand back the key.  The `live` test is
 * the one that matters: see tls_ticket_key_t in server.h. */
static const tls_ticket_key_t *tls_ticket_key_by_name(const unsigned char *name) {
    const tls_server_t *ts = &g_server.tls;
    for (int i = 0; i < TLS_TICKET_RING; i++) {
        const tls_ticket_key_t *k = &ts->ticket_keys[i];
        if (k->live && memcmp(k->name, name, TLS_TICKET_NAME_LEN) == 0)
            return k;
    }
    return NULL;
}

static int tls_ticket_key_cb(unsigned char *name, unsigned char *iv,
                             EVP_CIPHER_CTX *cctx, tls_ticket_mac_ctx_t *hctx,
                             int enc) {
    const tls_ticket_key_t *k;

    if (enc) {
        /* Only the newest key seals.  The older ones in the ring exist so that
         * tickets issued before the last rotation still open. */
        k = &g_server.tls.ticket_keys[g_server.tls.ticket_cur];
        if (unlikely(!k->live))
            return 0;
        memcpy(name, k->name, TLS_TICKET_NAME_LEN);
        ptls_openssl_random_bytes(iv, TLS_TICKET_IV_LEN);
        if (!EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(), NULL, k->aes, iv))
            return 0;
    } else {
        /* No key of that name: rotated out, or minted by a different worker
         * process.  0 means "cannot open", which costs a full handshake. */
        if ((k = tls_ticket_key_by_name(name)) == NULL)
            return 0;
        if (!EVP_DecryptInit_ex(cctx, EVP_aes_256_cbc(), NULL, k->aes, iv))
            return 0;
    }
    return tls_ticket_mac_init(hctx, k->hmac, TLS_TICKET_HMAC_LEN);
}

static int tls_ticket_encrypt(ptls_encrypt_ticket_t *self, ptls_t *tls,
                              int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src) {
    (void)self;
    (void)tls;
    return is_encrypt ? tls_ticket_seal_impl(dst, src, tls_ticket_key_cb)
                      : tls_ticket_unseal_impl(dst, src, tls_ticket_key_cb);
}

/* Advance the ring by one step.  Split out of the timer callback so a test
 * can drive rotation without waiting an hour of wall clock: the ring's whole
 * contract -- a retired key still opens tickets until the constraint says it
 * cannot -- is otherwise unexercised code, which is precisely the
 * silent-degradation failure this feature is prone to. */
void tls_ticket_rotate_once(void) {
    tls_server_t *ts = &g_server.tls;
    int next = (ts->ticket_cur + 1) % TLS_TICKET_RING;
    ptls_clear_memory(&ts->ticket_keys[next], sizeof(ts->ticket_keys[next]));
    tls_ticket_key_mint(&ts->ticket_keys[next]);
    ts->ticket_cur = next;
}

static void tls_ticket_rotate(uv_timer_t *timer) {
    (void)timer;
    tls_ticket_rotate_once();
}

/*
 * Multiple workers.
 *
 * With --workers N and SO_REUSEPORT the kernel picks the worker, so a client
 * resuming lands on the issuing process about 1/N of the time and otherwise
 * offers a ticket nobody can open -- which the callback above turns into the
 * full handshake it would have had anyway.  So workers > 1 is no worse than
 * today and workers = 1 is strictly better; what is missing is the last
 * (N-1)/N of the win.
 *
 * The fix the issue proposes -- derive the key once and let it be inherited
 * across the fork -- does not work here.  freastal/__init__.py starts workers
 * with multiprocessing.Process, whose default start method is `spawn` on
 * macOS: the child re-imports and runs tls_server_init() in a fresh
 * interpreter with nothing inherited.  On Linux the default is fork, so that
 * design would work on one platform and silently not on the other, which is
 * worse than not having it.
 *
 * Sharing it explicitly is possible -- pass the key through the spawn pickle,
 * or seed every worker from one master secret and derive per-epoch keys from
 * the wall clock so rotation needs no coordination -- but both undo what this
 * change is for.  The first puts key material in immutable Python bytes that
 * cannot be zeroized and may be copied by the GC or paged out; the second
 * makes a single long-lived master the thing worth stealing, and every key
 * past and future derives from it.  Doing it properly means an operator-owned
 * key, rotated out of band, the way nginx's ssl_session_ticket_key works.
 * That is a deployment interface, not a line of C, and it is not this issue.
 */

int tls_server_init(const char *certfile, const char *keyfile) {
    tls_server_t *ts = &g_server.tls;
    memset(ts, 0, sizeof(*ts));

    if (ptls_load_certificates(&ts->ctx, certfile) != 0) {
        fprintf(stderr, "[freastal] TLS: failed to load cert from %s\n", certfile);
        return -1;
    }

    FILE *fp = fopen(keyfile, "r");
    if (!fp) {
        fprintf(stderr, "[freastal] TLS: cannot open key %s\n", keyfile);
        return -1;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "[freastal] TLS: failed to parse key from %s\n", keyfile);
        return -1;
    }
    ptls_openssl_init_sign_certificate(&ts->sign_cert, pkey);
    EVP_PKEY_free(pkey);

    ts->ctx.random_bytes     = ptls_openssl_random_bytes;
    ts->ctx.get_time         = &ptls_get_time;
    ts->ctx.key_exchanges    = freastal_key_exchanges;
    /*
     * ptls_openssl_cipher_suites[] names AES-256-GCM-SHA384 first, which reads
     * like a misordering but is not, and is left alone on purpose.  The memset
     * above leaves ctx.server_cipher_preference at 0, so select_cipher()
     * honors the *client's* order and this list is only a membership filter:
     * browsers on AES-capable hardware ask for AES-128-GCM-SHA256 first and
     * get it, browsers without AES instructions ask for ChaCha20-Poly1305
     * first and get that.  Both are the right answer for the peer that asked,
     * and choosing for them here would only make one of the two cases worse.
     * Entry 0 is not wholly arbitrary -- cipher_suites[0]->hash is the one
     * fixed position picotls reads, as the HMAC hash for stateless-retry
     * cookies (calc_cookie_signature, plus the two sites that size and verify
     * that signature), and that path needs a hash before any suite has been
     * negotiated.  But picotls.h documents no ordering rule for the list, and
     * we pass no handshake properties, so cookies are never enabled here.
     * picotls annotates its own array "ciphers used with sha384 (must be
     * first)"; whatever that is for, the vendored order is left as it is.
     */
    ts->ctx.cipher_suites    = ptls_openssl_cipher_suites;
    ts->ctx.sign_certificate = &ts->sign_cert.super;

    /*
     * Session tickets.  Without encrypt_ticket picotls mints none, so every
     * reconnect repeats the certificate signature -- the single most expensive
     * thing in the handshake -- and a browser reopening a connection pays it
     * again.  ticket_lifetime is what goes on the wire as the client's
     * lifetime hint, and picotls also enforces it on the way back in
     * (`now - issue_at > ticket_lifetime * 1000` in the PSK loop), so a ticket
     * older than this is refused even by a key that could still open it.
     *
     * One key now; the timer mints the rest.  Pre-filling the whole ring at
     * startup would be worse, not better -- a key minted now but not sealing
     * until (RING-1) rotations from now would sit in memory for RING rotations
     * beyond that, which is the opposite of the point.
     */
    ts->ticket_cur = 0;
    tls_ticket_key_mint(&ts->ticket_keys[0]);
    ts->ticket_cb.cb           = tls_ticket_encrypt;
    ts->ctx.encrypt_ticket     = &ts->ticket_cb;
    ts->ctx.ticket_lifetime    = TLS_TICKET_LIFETIME_S;

    /*
     * Make resumption use (EC)DHE, not the ticket secret alone.
     *
     * Left at 0, picotls picks HANDSHAKE_MODE_PSK whenever the client offers
     * psk_ke, and the resumed connection's traffic keys then come only from
     * the secret inside the ticket.  Anyone who later takes the sealing key
     * and had recorded the traffic can decrypt it: the resumed session has no
     * forward secrecy at all, and rotating the key does nothing for sessions
     * already on the wire.  With this set, the resumed handshake still does a
     * fresh ECDHE, so a recovered ticket key gives an attacker the resumption
     * secret and no plaintext.  It bounds *impersonation* within the ticket
     * window, which is what a bounded key lifetime is for.
     *
     * It costs one ECDH per resumption -- the same one a full handshake does,
     * and not the operation resumption is saving; the certificate signature
     * is.  It is also free in interop: picotls only drops the psk_ke bit, so a
     * client offering psk_dhe_ke (OpenSSL, BoringSSL and NSS all offer that
     * and nothing else) is unaffected, and a hypothetical psk_ke-only client
     * gets a full handshake rather than a failure.
     */
    ts->ctx.require_dhe_on_psk = 1;

    /*
     * ctx.max_early_data_size stays 0: 0-RTT is deliberately off.  Early data
     * is replayable by design and a general-purpose WSGI/ASGI server cannot
     * know whether the application's handlers are idempotent.  Note that this
     * is what keeps the ticket from carrying an early_data extension in
     * send_session_ticket(), so clients are never invited to try.
     *
     * The memset() at the top of this function is what zeroes it; there is
     * deliberately no assignment here, because an assignment is exactly what
     * a future edit would overwrite.  What is here instead is a check, run
     * after every other field is set, so that a line anywhere above it that
     * turns early data on is caught before the listener ever answers.  It
     * costs one branch at startup and turns a silent behaviour change into a
     * server that refuses to start and says why.
     */
    if (ts->ctx.max_early_data_size != 0) {
        fprintf(stderr,
                "[freastal] TLS: refusing to start with 0-RTT early data "
                "enabled; early data is replayable and freastal cannot know "
                "whether your handlers are idempotent\n");
        return -1;
    }

    /*
     * Rotation runs on the loop, which is the only thread that reads the ring;
     * see the block above tls_ticket_key_mint().  g_server.loop is already set
     * -- server_init() assigns it well before it calls us.
     *
     * The handle is unref'd on purpose.  An hourly repeating timer is a
     * referenced handle that would keep uv_run() from ever returning on its
     * own; the listening socket already has that effect today, so this changes
     * nothing now, and stops the ticket ring from being the reason a loop that
     * has otherwise finished will not stop.
     */
    uv_timer_init(g_server.loop, &ts->ticket_timer);
    uv_unref((uv_handle_t *)&ts->ticket_timer);
    uv_timer_start(&ts->ticket_timer, tls_ticket_rotate, TLS_TICKET_ROTATE_MS,
                   TLS_TICKET_ROTATE_MS);

    g_server.tls_enabled = true;
    fprintf(stderr,
            "[freastal] TLS 1.3 enabled (picotls + OpenSSL backend); session "
            "tickets on, %u s lifetime, key rotates every %u s\n",
            (unsigned)TLS_TICKET_LIFETIME_S, (unsigned)(TLS_TICKET_ROTATE_MS / 1000u));
    return 0;
}

/*
 * Encryption-output blocks live in a per-loop free list rather than on the
 * client_t, the way h2o recycles its socket SSL buffers.  A connection needs
 * one only between write_response() and on_write(), so the pool's high-water
 * mark is the number of responses in flight at once -- tens -- whereas a
 * per-connection buffer would cost a block for every open connection, idle
 * ones included, against a 4096-slot pool.  Recycling a handful of blocks also
 * keeps them hot in cache instead of scattering one per connection.
 *
 * The free-list link lives in the first word of the block itself, so the pool
 * costs no memory of its own.
 */
void *tls_wbuf_get(void) {
    void *block = g_server.tls_wbuf_pool;
    if (likely(block != NULL)) {
        g_server.tls_wbuf_pool = *(void **)block;
        g_server.tls_wbuf_pool_n--;
        g_server.tls_wbuf_live++;
        return block;
    }
    block = malloc(TLS_WBLOCK_SIZE);
    if (likely(block != NULL)) {
        g_server.tls_wbuf_mallocs++;
        g_server.tls_wbuf_live++;
    }
    return block;
}

void tls_wbuf_put(void *block) {
    g_server.tls_wbuf_live--;
    if (unlikely(g_server.tls_wbuf_pool_n >= TLS_WBUF_POOL_MAX)) {
        free(block);
        return;
    }
    *(void **)block = g_server.tls_wbuf_pool;
    g_server.tls_wbuf_pool = block;
    g_server.tls_wbuf_pool_n++;
}

/*
 * A response past TLS_WSEG_MAX blocks does not segment; it takes one buffer of
 * its own.  Handing that to picotls with is_allocated = 1 -- which is what the
 * pre-segmentation code did at every size over 16,739 bytes -- would make
 * ptls_buffer_dispose() responsible for it, and ptls_buffer__release_memory()
 * memsets buf->off bytes before freeing.  There is nothing there to scrub:
 * ptls_send_v() encrypts straight from the caller's plaintext into this
 * buffer and never stages a plaintext copy in it, so every byte of it has already
 * gone out on the wire in the clear.
 *
 * So freastal owns this one too, and keeps one per loop rather than returning
 * it to malloc every time.  A single slot is enough: it is held only between
 * write_response() and on_write(), and responses this large are rare enough
 * that two in flight at once is not the case worth sizing for -- the second
 * just allocates.  The slot ratchets up to the largest size seen, so a run of
 * them settles on one buffer instead of walking through malloc sizes, and
 * anything past TLS_BIGBUF_KEEP_MAX is freed rather than pinned per worker.
 */
void *tls_bigbuf_get(size_t need, size_t *cap_out) {
    void *buf = g_server.tls_bigbuf;
    if (buf != NULL && g_server.tls_bigbuf_cap >= need) {
        g_server.tls_bigbuf     = NULL;
        *cap_out                = g_server.tls_bigbuf_cap;
        g_server.tls_bigbuf_cap = 0;
        g_server.tls_bigbuf_live++;
        return buf;
    }
    *cap_out = need;
    buf = malloc(need);
    if (likely(buf != NULL)) {
        g_server.tls_wbuf_mallocs++;
        g_server.tls_bigbuf_live++;
    }
    return buf;
}

void tls_bigbuf_put(void *buf, size_t cap) {
    g_server.tls_bigbuf_live--;
    if (unlikely(cap > TLS_BIGBUF_KEEP_MAX)) { free(buf); return; }
    if (g_server.tls_bigbuf != NULL) {
        /* Keep whichever is larger; the smaller one would never be picked. */
        if (cap <= g_server.tls_bigbuf_cap) { free(buf); return; }
        free(g_server.tls_bigbuf);
    }
    g_server.tls_bigbuf     = buf;
    g_server.tls_bigbuf_cap = cap;
}

/*
 * Ownership of each segment's buffer is decided by comparing its base against
 * the block it was opened on, not by is_allocated.
 *
 * When the block came from the pool picotls was handed a buffer it does not
 * own (is_allocated = 0), so ptls_buffer_dispose() would neither free it nor
 * return it here -- and its ptls_clear_memory() pass would sweep the entire
 * record for nothing, since ptls_send_v() encrypts straight from the caller's
 * plaintext into this buffer and so it only ever holds ciphertext.
 *
 * picotls can still swap a block out from under us -- a KeyUpdate record, or
 * any reservation the sizing failed to anticipate -- in which case base no
 * longer points at the pooled block and the replacement is picotls-owned and
 * must be freed.  Checking base rather than trusting the sizing is what keeps
 * that from being either a leak or a double free.
 *
 * So base tells the three cases apart:
 *
 *   base == block        the ciphertext is in the block itself: no dispose,
 *                        straight back to the pool.
 *   base == c->tls_wbig  an oversized response (past TLS_WSEG_MAX blocks).
 *                        That buffer is freastal's too, handed over with
 *                        is_allocated = 0, so it goes back to the retained
 *                        slot and picotls never sweeps it either.  The block
 *                        carries only the chain node.
 *   anything else        picotls replaced what we gave it and owns the
 *                        replacement; dispose frees that.  If it displaced the
 *                        oversized buffer, ours is still live and its capacity
 *                        is no longer recorded anywhere, so it goes back to
 *                        malloc rather than to the slot.
 *
 * Every segment of the chain is released, which matters because a response is
 * one uv_write over all of them: they live and die together.
 */
void tls_release_wbuf(client_t *c) {
    void *block = c->tls_wblock;
    void *big   = c->tls_wbig;
    bool  big_returned = false;

    c->tls_wblock = NULL;
    c->tls_wbig   = NULL;

    while (block != NULL) {
        tls_wseg_t *seg  = TLS_WSEG_OF(block);
        void       *next = seg->next;
        void       *base = (void *)seg->buf.base;
        if (unlikely(base != block)) {
            if (likely(big != NULL && base == big)) {
                tls_bigbuf_put(big, seg->buf.capacity);
                big_returned = true;
            } else {
                ptls_buffer_dispose(&seg->buf);     /* picotls owns what it points at */
            }
        }
        tls_wbuf_put(block);
        block = next;
    }

    /* The oversized buffer is normally returned by the walk above.  It is not
     * only when picotls outgrew it and swapped in an allocation of its own,
     * which dispose has just freed -- ours is still live, and its capacity is
     * no longer recorded anywhere, so it goes back to malloc rather than to
     * the retained slot. */
    if (unlikely(big != NULL && !big_returned)) {
        g_server.tls_bigbuf_live--;
        free(big);
    }
}

/* Same free-list-in-the-first-word shape as tls_wbuf_get()/put() above. */
void *tls_spill_get(void) {
    void *block = g_server.tls_spill_pool;
    if (block != NULL) {
        g_server.tls_spill_pool = *(void **)block;
        g_server.tls_spill_pool_n--;
        return block;
    }
    return malloc(TLS_SPILL_SIZE);
}

void tls_spill_put(void *block) {
    if (unlikely(g_server.tls_spill_pool_n >= TLS_SPILL_POOL_MAX)) {
        free(block);
        return;
    }
    *(void **)block = g_server.tls_spill_pool;
    g_server.tls_spill_pool = block;
    g_server.tls_spill_pool_n++;
}

void tls_release_spill(client_t *c) {
    if (c->tls_spill != NULL) {
        tls_spill_put(c->tls_spill);
        c->tls_spill = NULL;
    }
    c->tls_spill_len = 0;
}

void tls_conn_init(client_t *c) {
    c->tls_enc     = malloc(TLS_ENC_BUF_SIZE);
    c->tls         = ptls_new(&g_server.tls.ctx, 1 /* is_server */);
    c->tls_hs_done = false;
    c->tls_broken  = false;
    c->tls_wblock  = NULL;
    c->tls_wbig      = NULL;
    c->tls_spill     = NULL;
    c->tls_spill_len = 0;
}

void tls_conn_free(client_t *c) {
    free(c->tls_enc); c->tls_enc = NULL;
    /* Reached on every close path, including the ones that never wrote a
     * response (400 Bad Request, handshake failure) and plaintext connections,
     * for which both releases are a no-op.  The spill is normally handed back
     * by tls_spill_drain() as soon as it empties; this catches a connection
     * torn down while one was still held.
     *
     * The tls_release_wbuf() call is normally redundant -- on_write has
     * already run it, and it is idempotent -- but it is load-bearing on the
     * paths where tls_write_response_impl() closes without ever reaching
     * uv_write: a block or the oversized buffer could not be allocated, or
     * ptls_send_v() failed partway through and it took the abandon branch.
     * Those are all out-of-memory paths, so no test reaches them without an
     * allocation-failure hook; deleting this as dead code would leak the whole
     * chain the first time the pool and malloc both came up empty. */
    tls_release_spill(c);
    if (c->tls) { ptls_free(c->tls); c->tls = NULL; }
    tls_release_wbuf(c);
    c->tls_hs_done = false;
    c->tls_broken  = false;
}

#endif /* FREASTAL_TLS */
