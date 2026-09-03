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
        return block;
    }
    return malloc(TLS_WBUF_SIZE);
}

void tls_wbuf_put(void *block) {
    if (unlikely(g_server.tls_wbuf_pool_n >= TLS_WBUF_POOL_MAX)) {
        free(block);
        return;
    }
    *(void **)block = g_server.tls_wbuf_pool;
    g_server.tls_wbuf_pool = block;
    g_server.tls_wbuf_pool_n++;
}

/*
 * Ownership of tls_wbuf is decided by tls_wblock, not by is_allocated.
 *
 * When the block came from the pool picotls was handed a buffer it does not
 * own (is_allocated = 0), so ptls_buffer_dispose() would neither free it nor
 * return it here -- and its ptls_clear_memory() pass would sweep the entire
 * record for nothing, since ptls_send() encrypts straight from the caller's
 * plaintext into this buffer and so it only ever holds ciphertext.
 *
 * picotls can still swap the block out from under us -- a KeyUpdate record, or
 * any reservation the size estimate failed to anticipate -- in which case base
 * no longer points at the pooled block and the replacement is picotls-owned
 * and must be freed.  Checking base rather than trusting the estimate is what
 * keeps that from being either a leak or a double free.
 */
void tls_release_wbuf(client_t *c) {
    void *block = c->tls_wblock;
    if (block != NULL) {
        c->tls_wblock = NULL;
        if (unlikely((void *)c->tls_wbuf.base != block))
            ptls_buffer_dispose(&c->tls_wbuf);      /* picotls outgrew the block */
        else
            memset(&c->tls_wbuf, 0, sizeof(c->tls_wbuf));
        tls_wbuf_put(block);
    } else if (c->tls_wbuf.base != NULL) {
        ptls_buffer_dispose(&c->tls_wbuf);
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
    c->tls_wblock  = NULL;
    c->tls_spill     = NULL;
    c->tls_spill_len = 0;
    memset(&c->tls_wbuf, 0, sizeof(c->tls_wbuf));
}

void tls_conn_free(client_t *c) {
    free(c->tls_enc); c->tls_enc = NULL;
    tls_release_spill(c);
    if (c->tls) { ptls_free(c->tls); c->tls = NULL; }
    /* Reached on every close path, including the ones that never wrote a
     * response (400 Bad Request, handshake failure) and plaintext connections,
     * for which this is a no-op. */
    tls_release_wbuf(c);
    c->tls_hs_done = false;
}

#endif /* FREASTAL_TLS */
