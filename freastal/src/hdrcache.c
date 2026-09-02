#include "hdrcache.h"
#include <string.h>

/* Longest cached name.  A longer header name is rejected by one compare. */
#define HDR_CACHE_MAX_LEN 32

/*
 * Cached names, sorted by length (hdr_cache_init() verifies).  Sorting is what
 * makes the lookup cheap: hdr_offset[] turns the name's length into the exact
 * slice of the table that could match, so every other length costs a single
 * array load.
 */
static const char *const hdr_names[] = {
    "dnt",
    "host",
    "range",
    "accept", "cookie", "expect", "origin", "pragma",
    "referer", "upgrade",
    "if-match", "priority",
    "sec-ch-ua", "x-real-ip",
    "connection", "keep-alive", "user-agent",
    "content-type", "max-forwards", "x-request-id",
    "authorization", "cache-control", "if-none-match",
    "accept-charset", "content-length", "sec-fetch-dest", "sec-fetch-mode",
    "sec-fetch-site", "sec-fetch-user",
    "accept-encoding", "accept-language", "x-forwarded-for",
    "sec-ch-ua-mobile", "x-forwarded-host", "x-requested-with",
    "if-modified-since", "transfer-encoding", "x-forwarded-proto",
    "sec-ch-ua-platform",
    "if-unmodified-since",
    "upgrade-insecure-requests",
};

#define HDR_CACHE_N (sizeof(hdr_names) / sizeof(hdr_names[0]))

static hdr_cache_entry hdr_table[HDR_CACHE_N];

/* hdr_offset[L] is the first entry of length >= L, so the entries of length L
 * are exactly [hdr_offset[L], hdr_offset[L + 1]). */
static unsigned char hdr_offset[HDR_CACHE_MAX_LEN + 2];

/*
 * ASCII case-insensitive compare against a reference that is known lowercase.
 * Upper and lower letters differ only in bit 5 -- but so do pairs like
 * '?' (0x3f) and '_' (0x5f), so the bit-5 shortcut is only sound once the
 * reference byte has been confirmed to be a letter.
 */
static inline bool hdr_eq_ci(const char *s, const char *lower, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char a = (unsigned char)s[i];
        unsigned char b = (unsigned char)lower[i];
        if (a == b) continue;
        if ((a ^ 0x20u) != b || b < 'a' || b > 'z') return false;
    }
    return true;
}

const hdr_cache_entry *hdr_cache_lookup(const char *name, size_t len) {
    /* Also the guard that keeps a zero-length obs-fold name from being read. */
    if (len == 0 || len > HDR_CACHE_MAX_LEN) return NULL;

    unsigned char c0 = (unsigned char)name[0];
    if (c0 >= 'A' && c0 <= 'Z') c0 |= 0x20;

    unsigned i   = hdr_offset[len];
    unsigned end = hdr_offset[len + 1];
    for (; i < end; i++) {
        const hdr_cache_entry *e = &hdr_table[i];
        /* First-byte filter first: it settles almost every same-length miss. */
        if ((unsigned char)e->name[0] != c0) continue;
        if (hdr_eq_ci(name + 1, e->name + 1, len - 1)) return e;
    }
    return NULL;
}

int hdr_cache_init(void) {
    if (hdr_table[0].asgi_name) return 0;  /* one server per process, but be idempotent */

    unsigned char prev = 0;
    for (unsigned i = 0; i < HDR_CACHE_N; i++) {
        const char *n   = hdr_names[i];
        size_t      len = strlen(n);

        /* Properties of the table above, not of anything a client can send:
         * a violation here is a source-level mistake, caught at startup. */
        if (len == 0 || len > HDR_CACHE_MAX_LEN || len < prev) {
            PyErr_Format(PyExc_RuntimeError,
                         "freastal: header cache table not sorted by length at '%s'", n);
            return -1;
        }
        prev = (unsigned char)len;

        char key[HDR_CACHE_MAX_LEN + 6];
        memcpy(key, "HTTP_", 5);
        for (size_t j = 0; j < len; j++) {
            char ch = n[j];
            key[5 + j] = (ch >= 'a' && ch <= 'z') ? (char)(ch - 32)
                                                  : (ch == '-' ? '_' : ch);
        }
        key[5 + len] = '\0';

        hdr_table[i].name      = n;
        hdr_table[i].len       = (unsigned char)len;
        hdr_table[i].asgi_name = PyBytes_FromStringAndSize(n, (Py_ssize_t)len);
        /* Interned so that a dict lookup from Python against the same literal
         * settles on a pointer compare, and so the hash is computed once. */
        hdr_table[i].wsgi_key  = PyUnicode_InternFromString(key);
        if (!hdr_table[i].asgi_name || !hdr_table[i].wsgi_key) return -1;
    }

    unsigned idx = 0;
    for (unsigned L = 0; L < HDR_CACHE_MAX_LEN + 2; L++) {
        while (idx < HDR_CACHE_N && hdr_table[idx].len < L) idx++;
        hdr_offset[L] = (unsigned char)idx;
    }
    return 0;
}
