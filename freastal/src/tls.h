#pragma once
#ifdef FREASTAL_TLS
#include <stdbool.h>
/* Forward declaration only — avoids circular include with server.h */
typedef struct client_s client_t;
int  tls_server_init(const char *certfile, const char *keyfile);
void tls_conn_init(client_t *c);
void tls_conn_free(client_t *c);
#endif /* FREASTAL_TLS */
