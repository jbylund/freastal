#ifndef FREASTAL_WSGI_H
#define FREASTAL_WSGI_H

#include "server.h"

/* Called (with GIL held) once a complete HTTP request has been received */
void wsgi_call_application(client_t *c);

/* Module-level init: register the StartResponse type */
int wsgi_init(PyObject *module);

/* Build the pre-populated environ template(s).  Must be called from
 * server_init() after the interned keys, sys.stderr and the BytesIO
 * singleton are in place. */
int wsgi_init_environ_template(void);

#endif /* FREASTAL_WSGI_H */
