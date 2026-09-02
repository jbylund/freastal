#ifndef FREASTAL_HDRCACHE_H
#define FREASTAL_HDRCACHE_H

#include <Python.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Pre-built Python objects for the request header *names* that recur on
 * essentially every request ("host", "user-agent", "accept", ...).  Without
 * this both scope builders allocate a fresh name object per header per
 * request and then throw it away again.  Header *values* are genuinely
 * per-request and are not cached.
 */
typedef struct {
    const char   *name;       /* canonical, lowercase */
    unsigned char len;
    PyObject     *asgi_name;  /* bytes, lowercase       -> ASGI scope["headers"] */
    PyObject     *wsgi_key;   /* str, "HTTP_UPPER_CASE" -> WSGI environ key */
} hdr_cache_entry;

/* Build the cached objects.  Called once from server_init(). */
int hdr_cache_init(void);

/*
 * Case-insensitive lookup of a wire header name; NULL if it is not cached.
 * `name` is never dereferenced when `len` is 0, which is what picohttpparser
 * reports for an obs-fold continuation line.
 *
 * Callers must Py_INCREF what they take out of the entry.  These objects are
 * server-wide singletons that get handed to application code, so returning a
 * borrowed reference would let an app decref the cache out from under us.
 */
const hdr_cache_entry *hdr_cache_lookup(const char *name, size_t len);

#endif /* FREASTAL_HDRCACHE_H */
