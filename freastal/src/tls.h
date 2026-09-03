#pragma once
#ifdef FREASTAL_TLS
#include <stdbool.h>
#include <stddef.h>
/* Forward declaration only — avoids circular include with server.h */
typedef struct client_s client_t;
int  tls_server_init(const char *certfile, const char *keyfile);
void tls_conn_init(client_t *c);
void tls_conn_free(client_t *c);

/* Encryption-output blocks, recycled across connections by the event loop. */
void *tls_wbuf_get(void);
void  tls_wbuf_put(void *block);
/* Oversized encryption buffer for a response too large to segment.  Returns
 * NULL only if the allocation failed; *cap_out is the usable size, which may
 * exceed need when the retained buffer was reused. */
void *tls_bigbuf_get(size_t need, size_t *cap_out);
void  tls_bigbuf_put(void *buf, size_t cap);
/* Hand back every block tls_write_response_impl() chained onto c->tls_wblock.
 * Safe to call on a connection that never wrote one, plaintext included. */
void  tls_release_wbuf(client_t *c);
#endif /* FREASTAL_TLS */
