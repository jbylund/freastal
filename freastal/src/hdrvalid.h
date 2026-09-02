#ifndef FREASTAL_HDRVALID_H
#define FREASTAL_HDRVALID_H

#include <Python.h>
#include <stdbool.h>

/*
 * Validation for response headers supplied by the application.
 *
 * Both formatters copy application-provided names and values into the response
 * buffer verbatim.  An application that reflects unvalidated input into a
 * header - a Location built from a query parameter, an echoed Set-Cookie - can
 * therefore inject a CR LF pair and with it arbitrary extra headers, or split
 * the response entirely (CWE-113).  A NUL is nearly as bad: it terminates the
 * field early for anything downstream that treats the block as a C string,
 * so a proxy and this server can disagree about where a header ends.
 *
 * Checking here, where the header first arrives from the application, rather
 * than in the formatters, means the WSGI and ASGI paths share one
 * implementation and neither formatter's hot loop grows a branch.
 *
 * uvicorn does the equivalent with two compiled regexes per header, which its
 * own profiling puts at roughly 725ns per request.  A 256-entry byte table is
 * about 1ns per byte, so being stricter than uvicorn costs nothing here.
 */

/*
 * Field-name characters, from RFC 9110's "token" production:
 *
 *   tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
 *           "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
 *
 * This excludes CR, LF, NUL, SP and ":" by construction, so a name cannot
 * terminate its own field or fake a second one.
 */
static const unsigned char freastal_tchar[256] = {
    /* 0x00-0x1f: all control characters are rejected */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    /* 0x20 SP  ! " #  $ % & '  ( ) * +  , - . / */
    0,1,0,1, 1,1,1,1, 0,0,1,1, 0,1,1,0,
    /* 0-9 then : ; < = > ? */
    1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0,
    /* @ A-O */
    0,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,
    /* P-Z then [ \ ] ^ _ */
    1,1,1,1, 1,1,1,1, 1,1,1,0, 0,0,1,1,
    /* ` a-o */
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,
    /* p-z then { | } ~ DEL */
    1,1,1,1, 1,1,1,1, 1,1,1,0, 1,0,1,0,
    /* 0x80-0xff: not token characters */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
};

/* A field-name must be a non-empty token. */
static inline bool freastal_hdr_name_ok(const char *s, Py_ssize_t n) {
    if (n <= 0) return false;
    for (Py_ssize_t i = 0; i < n; i++)
        if (!freastal_tchar[(unsigned char)s[i]]) return false;
    return true;
}

/*
 * A field-value may hold VCHAR, SP, HTAB and obs-text (0x80-0xff).  Rejecting
 * the rest is what stops CR, LF and NUL; obs-text is permitted because PEP
 * 3333 hands values through as latin-1 and real applications do emit them.
 * Leading and trailing whitespace is legal on the wire and left alone.
 */
static inline bool freastal_hdr_value_ok(const char *s, Py_ssize_t n) {
    for (Py_ssize_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\t') continue;              /* HTAB is allowed */
        if (c < 0x20 || c == 0x7f) return false;  /* CTL, incl. CR/LF/NUL */
    }
    return true;
}

/*
 * The WSGI status line is copied in after "HTTP/1.1 ", so it can split the
 * response just as a header can.  PEP 3333 specifies "999 Message"; require a
 * 3-digit code and reject controls in the reason phrase.
 */
static inline bool freastal_status_ok(const char *s, Py_ssize_t n) {
    if (n < 3) return false;
    for (int i = 0; i < 3; i++)
        if (s[i] < '0' || s[i] > '9') return false;
    if (n > 3 && s[3] != ' ') return false;
    return freastal_hdr_value_ok(s + 3, n - 3);
}

#endif /* FREASTAL_HDRVALID_H */
