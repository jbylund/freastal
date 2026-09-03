#ifdef FREASTAL_TLS
#include "server.h"
#include "tls.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <stdio.h>

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
    ts->ctx.key_exchanges    = ptls_openssl_key_exchanges;
    ts->ctx.cipher_suites    = ptls_openssl_cipher_suites;
    ts->ctx.sign_certificate = &ts->sign_cert.super;

    g_server.tls_enabled = true;
    fprintf(stderr, "[freastal] TLS 1.3 enabled (picotls + OpenSSL backend)\n");
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
 * ptls_send() encrypts straight from the caller's plaintext into this buffer
 * and never stages a plaintext copy in it, so every byte of it has already
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
 * record for nothing, since ptls_send() encrypts straight from the caller's
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

void tls_conn_init(client_t *c) {
    c->tls_enc     = malloc(TLS_ENC_BUF_SIZE);
    c->tls         = ptls_new(&g_server.tls.ctx, 1 /* is_server */);
    c->tls_hs_done = false;
    c->tls_wblock  = NULL;
    c->tls_wbig    = NULL;
}

void tls_conn_free(client_t *c) {
    free(c->tls_enc); c->tls_enc = NULL;
    if (c->tls) { ptls_free(c->tls); c->tls = NULL; }
    /* Reached on every close path, including the ones that never wrote a
     * response (400 Bad Request, handshake failure) and plaintext connections,
     * for which this is a no-op. */
    tls_release_wbuf(c);
    c->tls_hs_done = false;
}

#endif /* FREASTAL_TLS */
