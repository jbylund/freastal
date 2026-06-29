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

void tls_conn_init(client_t *c) {
    c->tls_enc     = malloc(TLS_ENC_BUF_SIZE);
    c->tls         = ptls_new(&g_server.tls.ctx, 1 /* is_server */);
    c->tls_hs_done = false;
    memset(&c->tls_wbuf, 0, sizeof(c->tls_wbuf));
}

void tls_conn_free(client_t *c) {
    free(c->tls_enc); c->tls_enc = NULL;
    if (c->tls) { ptls_free(c->tls); c->tls = NULL; }
    ptls_buffer_dispose(&c->tls_wbuf);
    c->tls_hs_done = false;
}

#endif /* FREASTAL_TLS */
