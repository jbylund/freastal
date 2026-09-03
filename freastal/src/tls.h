#pragma once
#ifdef FREASTAL_TLS
#include <stdbool.h>
/* Forward declaration only — avoids circular include with server.h */
typedef struct client_s client_t;
int  tls_server_init(const char *certfile, const char *keyfile);
void tls_conn_init(client_t *c);
void tls_conn_free(client_t *c);

/* Encryption-output blocks, recycled across connections by the event loop. */
void *tls_wbuf_get(void);
void  tls_wbuf_put(void *block);
/* Hand back whatever tls_write_response_impl() left in c->tls_wbuf.  Safe to
 * call on a connection that never wrote one, plaintext connections included. */
void  tls_release_wbuf(client_t *c);

/* Read-overflow blocks, recycled the same way. */
void *tls_spill_get(void);
void  tls_spill_put(void *block);
/* Release c->tls_spill if it holds one.  Safe on a connection that never
 * overflowed, and on plaintext connections. */
void  tls_release_spill(client_t *c);
#endif /* FREASTAL_TLS */
