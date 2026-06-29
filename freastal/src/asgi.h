#pragma once
/* ASGI mode: asyncio coroutine scheduler driven from libuv's event loop.
 *
 * Two handles keep asyncio alive inside uv_run():
 *   uv_check_t  – fires after every I/O poll; runs ready coroutines.
 *   uv_poll_t   – watches asyncio's selector fd; fires when async I/O
 *                 completes (DB calls, outbound HTTP, etc.) so those
 *                 waiting coroutines are resumed promptly.
 */

#include <Python.h>

typedef struct client_s client_t;

/* Call between server_init() and server_run(). */
int        asgi_server_init(PyObject *loop);

/* Called from http_dispatch() when g_server.asgi_mode is true.
 * GIL must be held by caller. */
void       asgi_dispatch(client_t *c);

/* Exposed to Python as _freastal.asgi_send_response(capsule, status, headers, body).
 * Called from _asgi_protocol.py::send() inside the running asyncio task. */
PyObject  *asgi_send_response_c(PyObject *self, PyObject *args);
