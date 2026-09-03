#ifdef FREASTAL_TLS
#include "server.h"
#include "tls.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
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
 * client-chosen cost, since an unauthenticated peer listing secp521r1 first
 * would make us do a P-521 ECDH per handshake for no security X25519 does not
 * already give us.  ptls_openssl_key_exchanges_all[] is nearly this list but
 * also carries the bare mlkem512/768/1024 groups, which have no classical
 * component; the hybrid keeps X25519 underneath as a floor.
 *
 * Both macros below are always defined by picotls/openssl.h, to 0 when the
 * algorithm is unavailable, and secp256r1 is unconditional -- so OpenSSL < 3.5
 * degrades to {x25519, secp256r1} and LibreSSL, which has neither, lands back
 * on today's {secp256r1}.
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
     * The SHA384 suite leads the array for picotls' own reason: it reads
     * cipher_suites[0]->hash when it needs a digest before a suite has been
     * negotiated, as in the cookie signature on the retry path.
     */
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

void tls_conn_init(client_t *c) {
    c->tls_enc     = malloc(TLS_ENC_BUF_SIZE);
    c->tls         = ptls_new(&g_server.tls.ctx, 1 /* is_server */);
    c->tls_hs_done = false;
    c->tls_wblock  = NULL;
    memset(&c->tls_wbuf, 0, sizeof(c->tls_wbuf));
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
