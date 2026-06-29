#ifndef FREASTAL_WSGI_H
#define FREASTAL_WSGI_H

#include "server.h"

/* Called (with GIL held) once a complete HTTP request has been received */
void wsgi_call_application(client_t *c);

/* Module-level init: register the StartResponse type */
int wsgi_init(PyObject *module);

#endif /* FREASTAL_WSGI_H */
