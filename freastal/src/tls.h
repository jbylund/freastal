#pragma once
#ifdef FREASTAL_TLS
#include <stdbool.h>
#include <stddef.h>
/* Forward declaration only — avoids circular include with server.h */
typedef struct client_s client_t;
/* ring_fd, if >= 0, is a read-only descriptor for the shared session-ticket
 * ring the process that called serve() created.  The worker maps it and mints
 * no keys of its own.  The descriptor stays the caller's to close. */
int  tls_server_init(const char *certfile, const char *keyfile, int ring_fd);

/* --- the shared session-ticket ring, owner side --------------------------
 * Called from the process that calls serve() with workers > 1, which never
 * runs tls_server_init().  All three set a Python exception on failure. */
/* Create the ring, mint its first key, and hand back the READ-ONLY descriptor
 * to pass to the workers.  The caller owns that descriptor. */
int  tls_ticket_ring_create(int *ro_fd_out);
/* Advance the shared ring one step.  The owner is the only writer. */
int  tls_ticket_ring_rotate_owned(void);
/* Zeroize, unmap and close.  Idempotent; safe when no ring was created. */
void tls_ticket_ring_destroy(void);
/* The owning pid, or -1 when this process owns no ring. */
int  tls_ticket_ring_owner_pid(void);
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

/* Read-overflow blocks, recycled the same way. */
void *tls_spill_get(void);
void  tls_spill_put(void *block);
/* Release c->tls_spill if it holds one.  Safe on a connection that never
 * overflowed, and on plaintext connections. */
void  tls_release_spill(client_t *c);
#endif /* FREASTAL_TLS */

/* Advance the process-local ticket key ring one step. */
void tls_ticket_rotate_once(void);
/* Test/ops hook: advance whichever ring this process is actually using, and
 * do not return until this process can see the result.  Owner and workers=1
 * rotate in place; a worker asks the owner and waits for the new key to show
 * up through the shared mapping.  0, or -1 with a Python exception set. */
int  tls_ticket_rotate_hook(void);
