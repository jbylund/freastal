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

/* Line libuv's next poll up with asyncio's outstanding work. */
void       asgi_arm_wakeups(void);

/* Exposed to Python as _freastal.asgi_send_response(capsule, status, headers, body).
 * Called from _asgi_protocol.py::send() inside the running asyncio task. */
PyObject  *asgi_send_response_c(PyObject *self, PyObject *args);

/* Call from module init.  Publishes ASGI_CORO_DONE, the sentinel
 * asgi_coro_step() returns when the app's coroutine has returned. */
int        asgi_init(PyObject *m);

/* Exposed to Python as _freastal.asgi_coro_step(coro[, ctx]).
 * Called from _asgi_protocol.py to drive the app's coroutine. */
PyObject  *asgi_coro_step_c(PyObject *self, PyObject *const *args, Py_ssize_t nargs);
