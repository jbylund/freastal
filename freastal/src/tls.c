#ifdef FREASTAL_TLS
#include "server.h"
#include "tls.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#  include <openssl/core_names.h>
#  include <openssl/params.h>
#else
#  include <openssl/hmac.h>
#endif
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#  include <sys/syscall.h>
#endif

/*
 * picotls' own default, ptls_openssl_key_exchanges[], holds secp256r1 and
 * nothing else.  Chrome and Firefox do list P-256 in supported_groups, but
 * neither ever sends a P-256 key share -- they guess X25519MLKEM768 and
 * X25519 -- so a P-256-only server matches nothing in the first ClientHello
 * and has to answer with a HelloRetryRequest.  That is an extra round trip on
 * every new browser connection, plus a keygen both ends then discard, before
 * settling on the slower of the two curves anyway.
 *
 * Membership, not order, is what fixes it.  Both selection sites in picotls
 * iterate the *client's* list on the outside and ours on the inside:
 * select_key_share() walks the client's key_share entries and assigns
 * *selected only while it is still NULL, and select_negotiated_group() walks
 * the client's supported_groups and returns on its first hit.  The client's
 * preference decides; the order below is documentation.
 *
 * secp384r1 and secp521r1 are deliberately absent.  RFC 8446 makes secp256r1
 * mandatory for conformant TLS 1.3 clients, so P-256 is already the universal
 * floor and the larger curves buy no interop -- what they would buy is a
 * client-chosen cost, since an unauthenticated peer that offers secp521r1 --
 * as a key share, or first in supported_groups on the retry path -- would
 * make us do a P-521 ECDH per handshake for no security X25519 does not
 * already give us.  ptls_openssl_key_exchanges_all[] is not the answer
 * either: on top of those two curves it carries the bare mlkem512/768/1024
 * groups, which have no classical component at all, whereas the hybrid keeps
 * X25519 underneath as a floor.
 *
 * Both macros below are always defined by picotls/openssl.h, to 0 when the
 * algorithm is unavailable, and secp256r1 is unconditional, so every
 * combination yields a valid list.  OpenSSL < 3.5 degrades to
 * {x25519, secp256r1}; CI builds that path and the tests confirm it
 * negotiates X25519 without a retry.  LibreSSL sets neither macro and would
 * land back on today's {secp256r1} -- read off the header, not built here.
 */
static ptls_key_exchange_algorithm_t *freastal_key_exchanges[] = {
#if PTLS_OPENSSL_HAVE_X25519MLKEM768
    &ptls_openssl_x25519mlkem768,
#endif
#if PTLS_OPENSSL_HAVE_X25519
    &ptls_openssl_x25519,
#endif
    &ptls_openssl_secp256r1,
    NULL};

/*
 * ---------------------------------------------------------------------------
 * Session tickets
 * ---------------------------------------------------------------------------
 *
 * picotls does the sealing and the framing; what it wants from us is a key.
 * Both ptls_openssl_{encrypt,decrypt}_ticket helpers take an OpenSSL-shaped
 * key callback: on seal it writes the key name and IV into space picotls has
 * already reserved at the front of the ticket and initializes the cipher and
 * MAC contexts; on unseal it is handed the name and IV read off the wire and
 * either finds that key or returns 0 to say it cannot.  Returning 0 there is
 * not an error path -- picotls turns it into "this PSK identity did not
 * decrypt", skips it, and the handshake proceeds as a full one.  That is the
 * behaviour a client gets today for every connection, so a ticket sealed by a
 * key this process no longer has costs a handshake, never a failure.
 *
 * Nothing here takes a lock, and nothing here needs one.  A freastal worker is
 * a *process*, not a thread -- freastal/__init__.py starts them with
 * multiprocessing.Process -- with one libuv loop on one thread, and libuv runs
 * the rotation timer's callback and the handshake callbacks that read the ring
 * one at a time on that thread.
 *
 * With workers > 1 the ring itself is shared memory written by a *different
 * process*, which does need something -- but a lock is still not it.  There is
 * exactly one writer, it writes once an hour, and the readers are on the
 * latency path, so the synchronisation is a seqlock: the writer brackets its
 * two copies with an odd sequence number and a reader that saw one retries.
 * Readers never block the writer and the writer never blocks a reader; the
 * worst case for a reader is that it gives up and declines the ticket, which
 * costs one full handshake.  See "Multiple workers: the shared ring" at the
 * bottom of this file, and "The shared ring" in server.h.
 */

/* AES-256-CBC's block size.  picotls hands the callback EVP_MAX_IV_LENGTH
 * bytes of room for the IV and then advances past all of it regardless of what
 * the cipher used, so the assert is what keeps the write in bounds. */
#define TLS_TICKET_IV_LEN 16
_Static_assert(EVP_MAX_IV_LENGTH >= TLS_TICKET_IV_LEN,
               "the ticket IV would not fit the space picotls reserves for it");

/*
 * OpenSSL 3 replaced HMAC_CTX with EVP_MAC_CTX and picotls carries a helper
 * pair for each.  The pair is chosen here rather than assumed: the _evp pair
 * is compiled only under `#if OPENSSL_VERSION_NUMBER >= 0x30000000L` in
 * picotls/openssl.h, so naming it unconditionally would not degrade on an
 * older OpenSSL or on LibreSSL (which reports 0x20000000L) -- it would fail to
 * link.  The two paths differ only in how the MAC context is keyed; everything
 * below is shared.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
typedef EVP_MAC_CTX tls_ticket_mac_ctx_t;
#  define tls_ticket_seal_impl   ptls_openssl_encrypt_ticket_evp
#  define tls_ticket_unseal_impl ptls_openssl_decrypt_ticket_evp

static int tls_ticket_mac_init(EVP_MAC_CTX *hctx, const uint8_t *key, size_t len) {
    /* OSSL_PARAM_construct_utf8_string takes a mutable char *, so the digest
     * name cannot be a string literal here. */
    char digest[] = "SHA256";
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end()};
    return EVP_MAC_init(hctx, key, len, params);
}
#else
typedef HMAC_CTX tls_ticket_mac_ctx_t;
#  define tls_ticket_seal_impl   ptls_openssl_encrypt_ticket
#  define tls_ticket_unseal_impl ptls_openssl_decrypt_ticket

static int tls_ticket_mac_init(HMAC_CTX *hctx, const uint8_t *key, size_t len) {
    return HMAC_Init_ex(hctx, key, (int)len, EVP_sha256(), NULL);
}
#endif

/* Fill a slot with fresh key material.  ptls_openssl_random_bytes() abort()s
 * if RAND_bytes fails rather than returning, so there is no partial key to
 * guard against and no failure for the callers to handle. */
static void tls_ticket_key_mint(tls_ticket_key_t *k) {
    ptls_openssl_random_bytes(k->name, TLS_TICKET_NAME_LEN);
    ptls_openssl_random_bytes(k->aes, TLS_TICKET_AES_LEN);
    ptls_openssl_random_bytes(k->hmac, TLS_TICKET_HMAC_LEN);
    k->live = true;
}

/*
 * One line, one write(2).
 *
 * stderr is unbuffered, and glibc turns an unbuffered fprintf into a separate
 * write per conversion in the format string, so N workers logging their
 * startup lines to one inherited descriptor shred each other into unreadable
 * fragments.  Formatting first and writing the result once keeps each line
 * whole -- which matters because "did every worker join the shared ring?" is
 * a question an operator, and the test suite, answers from this log.
 */
static void tls_log(const char *fmt, ...) {
    char line[512];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if ((size_t)n >= sizeof(line))
        n = (int)sizeof(line) - 1;
    fwrite(line, 1, (size_t)n, stderr);
    fflush(stderr);
}

/*
 * The clock the ring's rotation deadline is written and read against.
 *
 * Not the wall clock: it is settable, and an NTP step backwards would make a
 * stalled ring look fresh -- the direction that loses the property the
 * staleness guard exists for.  A monotonic clock is system-wide on both
 * platforms, so the owner's deadline and a worker's reading of it are the
 * same timeline across the process boundary.
 *
 * Which monotonic clock is not a detail.  The deadline is written here, in C,
 * but the sleep that is supposed to meet it is threading.Event.wait() in the
 * owner's rotation thread (freastal/__init__.py), so the two have to be the
 * same clock or the deadline means nothing.  CPython's time.monotonic() --
 * which is what Event.wait() times out against -- is clock_gettime(
 * CLOCK_MONOTONIC) on Linux and CLOCK_UPTIME_RAW on Apple platforms, where
 * CLOCK_MONOTONIC is a *different* clock that keeps counting across a system
 * sleep.  Using CLOCK_MONOTONIC on macOS made a laptop that had been asleep
 * for a few hours declare a ring stale that its owner had every intention of
 * rotating on time; a test caught it because the test could not compute a
 * deadline the C side agreed with.
 *
 * So both clocks stop across a suspend, and the owner's sleep stops with
 * them: a suspended box comes back with its rotation late by exactly the
 * length of the sleep, and nothing declares the ring stale for it.
 */
#if defined(__APPLE__) && defined(CLOCK_UPTIME_RAW)
#  define TLS_TICKET_CLOCK CLOCK_UPTIME_RAW
#else
#  define TLS_TICKET_CLOCK CLOCK_MONOTONIC
#endif

static uint64_t tls_monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(TLS_TICKET_CLOCK, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ------------------------------------------------------------------------
 * Owner-side state.
 *
 * Deliberately not in tls_server_t.  The process that owns the ring is the
 * one that called serve() with workers > 1, and it never runs
 * tls_server_init(): it binds a listening socket, starts the workers and
 * waits in join().  It has no g_server to put this in.
 * ------------------------------------------------------------------------ */
static tls_ticket_ring_t *g_ring_owned;
static size_t             g_ring_owned_len;
static int                g_ring_owned_fd = -1;   /* the read-write descriptor */
static const char        *g_ring_owned_how = "";  /* how it was created, for the banner */
static bool               g_ring_owned_locked;    /* mlock() took */

/*
 * Publish one rotation, seqlock-style.
 *
 * `seq` odd means "mid-publish, do not trust anything below me"; the two
 * fences are what stop the compiler or the CPU from letting a key byte escape
 * the odd window.  The mint happens in the caller, outside the window, so the
 * window itself is two ~81-byte copies and two stores -- on the order of a
 * hundred nanoseconds -- rather than three RAND_bytes calls.  That is the
 * difference between a reader retrying and a reader exhausting its budget.
 *
 * The ptls_clear_memory() is not redundant with the memcpy that follows it,
 * which does overwrite all of the current struct.  It is what keeps "a
 * retired key is destroyed" true of any field a later edit adds to
 * tls_ticket_key_t but forgets to fill in, and true of the padding.
 */
static void tls_ticket_ring_publish(tls_ticket_ring_t *r, int slot,
                                    const tls_ticket_key_t *fresh) {
    uint32_t s = atomic_load_explicit(&r->seq, memory_order_relaxed);

    atomic_store_explicit(&r->seq, s + 1u, memory_order_relaxed);
    atomic_thread_fence(memory_order_acq_rel);

    ptls_clear_memory(&r->keys[slot], sizeof(r->keys[slot]));
    memcpy(&r->keys[slot], fresh, sizeof(*fresh));
    r->cur           = slot;
    r->rotate_due_ms = tls_monotonic_ms() + (uint64_t)r->rotate_ms;

    atomic_thread_fence(memory_order_release);
    atomic_store_explicit(&r->seq, s + 2u, memory_order_relaxed);
}

/* What a worker copies out from under the seqlock before it looks at
 * anything.  Copying first and searching afterwards keeps the racing read to
 * one memcpy instead of a memcmp loop over memory the owner may be
 * rewriting. */
typedef struct {
    int32_t          cur;
    tls_ticket_key_t keys[TLS_TICKET_RING];
} tls_ticket_snapshot_t;

/* Seqlock read.  False means the owner held the window for longer than the
 * budget, which the caller turns into a declined ticket -- one full
 * handshake, never a wrong key. */
static bool tls_ticket_ring_read(const tls_ticket_ring_t *r,
                                 tls_ticket_snapshot_t *out) {
    for (int attempt = 0; attempt < TLS_TICKET_SEQ_RETRIES; attempt++) {
        uint32_t s1 = atomic_load_explicit(&r->seq, memory_order_relaxed);
        if (unlikely(s1 == 0u || (s1 & 1u) != 0u)) {
            /* The owner is in another process, so there is nothing to be
             * gained by spinning on a hot loop once the obvious retry has
             * failed: give the scheduler the chance to run it. */
            if (attempt >= 4)
                sched_yield();
            continue;
        }
        atomic_thread_fence(memory_order_acquire);

        out->cur = r->cur;
        memcpy(out->keys, r->keys, sizeof(out->keys));

        atomic_thread_fence(memory_order_acquire);
        if (likely(atomic_load_explicit(&r->seq, memory_order_relaxed) == s1))
            return true;
        ptls_clear_memory(out, sizeof(*out));
    }
    return false;
}

/*
 * Has the owner stopped rotating?
 *
 * A ring nobody rotates has keys with no bounded lifetime, which is the one
 * property the ring exists to provide -- see the exposure argument and the
 * second _Static_assert in server.h.  The owner renews the deadline on every
 * rotation; blowing through it by a whole further grace period means the
 * owner is gone (kill -9 on the supervisor leaves the workers orphaned and
 * still serving), not that it is running a little late.
 *
 * Only rotate_due_ms is read, but it is still read under the seqlock: it is
 * written inside the same window as the keys, and a torn 64-bit read of it
 * could say "fresh" for an hour.  Losing the race is reported as "not stale",
 * because a lost race means the owner was writing, which is the opposite of
 * absent.
 */
static bool tls_ticket_ring_is_stale(const tls_ticket_ring_t *r) {
    for (int attempt = 0; attempt < TLS_TICKET_SEQ_RETRIES; attempt++) {
        uint32_t s1 = atomic_load_explicit(&r->seq, memory_order_relaxed);
        uint64_t due;
        if (unlikely(s1 == 0u || (s1 & 1u) != 0u))
            continue;
        atomic_thread_fence(memory_order_acquire);
        due = r->rotate_due_ms;
        atomic_thread_fence(memory_order_acquire);
        if (likely(atomic_load_explicit(&r->seq, memory_order_relaxed) == s1))
            return tls_monotonic_ms() > due + (uint64_t)r->grace_ms;
    }
    return false;
}

/*
 * Stop using -- and stop holding -- a ring the owner has abandoned.
 *
 * Turning the feature off in the context, rather than declining inside the
 * ticket callback, is not a stylistic choice.  picotls treats a refusal to
 * *seal* as an error and fails the whole handshake (send_session_ticket ->
 * server_finish_handshake -> Exit), so a callback that declined here would
 * turn "the supervisor died" into "this server answers nothing at all".
 * Clearing ticket_lifetime is what actually stops issuance --
 * num_tickets_to_send is set to 0 when it is zero -- and clearing
 * encrypt_ticket is what stops acceptance.  Both are read once per handshake
 * inside a single ptls_handshake() call, and this runs between connections on
 * the same thread, so no connection is ever half-way through observing them.
 *
 * Unmapping is the part an operator would care about.  A worker cannot
 * zeroize a read-only mapping and does not hold the descriptor any more, so
 * dropping the mapping is the only lever it has over the key material.  Once
 * every process that mapped the region is gone the kernel frees the pages,
 * and the region has no name and no link, so nothing can map them again.  A
 * worker that has not noticed yet keeps them alive -- which is why this
 * bounds the failure rather than fixing it.
 */
static void tls_ticket_ring_disable(const char *why) {
    tls_server_t *ts = &g_server.tls;
    void *base = (void *)ts->ticket_shared;
    size_t len = ts->ticket_shared_len;

    ts->ctx.ticket_lifetime = 0;
    ts->ctx.encrypt_ticket  = NULL;
    ts->ticket_shared       = NULL;
    ts->ticket_shared_len   = 0;
    if (base != NULL) {
        munlock(base, len);
        munmap(base, len);
    }
    tls_log("[freastal] TLS: dropped the shared session-ticket ring (%s); "
            "session tickets are now off, so every reconnect pays for a full "
            "handshake until the server is restarted\n", why);
}

/*
 * Pick the key to use out of the shared ring, into caller-owned scratch.
 *
 * The copy is the point.  A pointer into the shared page would be a pointer
 * into memory the owner may rewrite between here and EVP_EncryptInit_ex, and
 * the failure that produces -- one key's name paired with another key's bytes
 * -- is a ticket that no key can ever open.  The scratch is zeroized by the
 * caller as soon as OpenSSL has taken its own copy of the key schedule.
 */
static bool tls_ticket_key_pick_shared(const unsigned char *name, int enc,
                                       tls_ticket_key_t *out) {
    const tls_ticket_ring_t *r = g_server.tls.ticket_shared;
    tls_ticket_snapshot_t snap;
    bool ok = false;

    if (unlikely(!tls_ticket_ring_read(r, &snap)))
        return false;

    if (enc) {
        /* Only the newest key seals.  The older ones in the ring exist so that
         * tickets issued before the last rotation still open. */
        if (likely(snap.cur >= 0 && snap.cur < TLS_TICKET_RING &&
                   snap.keys[snap.cur].live)) {
            memcpy(out, &snap.keys[snap.cur], sizeof(*out));
            ok = true;
        }
    } else {
        for (int i = 0; i < TLS_TICKET_RING; i++) {
            if (snap.keys[i].live &&
                memcmp(snap.keys[i].name, name, TLS_TICKET_NAME_LEN) == 0) {
                memcpy(out, &snap.keys[i], sizeof(*out));
                ok = true;
                break;
            }
        }
    }

    ptls_clear_memory(&snap, sizeof(snap));
    return ok;
}

/* The name is public -- it rides in the clear at the front of every ticket --
 * so an ordinary memcmp is the right comparison; the secret this guards is the
 * HMAC, which picotls verifies after we hand back the key.  The `live` test is
 * the one that matters: see tls_ticket_key_t in server.h. */
static const tls_ticket_key_t *tls_ticket_key_by_name(const unsigned char *name) {
    const tls_server_t *ts = &g_server.tls;
    for (int i = 0; i < TLS_TICKET_RING; i++) {
        const tls_ticket_key_t *k = &ts->ticket_keys[i];
        if (k->live && memcmp(k->name, name, TLS_TICKET_NAME_LEN) == 0)
            return k;
    }
    return NULL;
}

static int tls_ticket_key_cb(unsigned char *name, unsigned char *iv,
                             EVP_CIPHER_CTX *cctx, tls_ticket_mac_ctx_t *hctx,
                             int enc) {
    const tls_ticket_key_t *k;
    /* Written only on the shared path; the process-local path below still
     * points straight into g_server and copies nothing, so workers=1 pays
     * for none of this. */
    tls_ticket_key_t shared_key;
    int rc = 0;

    if (g_server.tls.ticket_shared != NULL) {
        if (unlikely(!tls_ticket_key_pick_shared(name, enc, &shared_key))) {
            /*
             * On the unseal path a refusal is the ordinary answer: picotls
             * skips the PSK identity and the client gets the full handshake
             * it would have had anyway.
             *
             * On the seal path it is not.  picotls treats a failure to seal
             * as an error and fails the handshake, so refusing here would
             * turn a lost seqlock race -- the writer descheduled inside a
             * hundred-nanosecond window, 64 times -- into a dead connection.
             * Sealing under a one-shot key instead costs that one client a
             * resumption it will be declined for later, and nothing else: the
             * key is on the stack, is in no ring, and is zeroized below.
             */
            if (!enc)
                return 0;
            tls_ticket_key_mint(&shared_key);
        }
        k = &shared_key;
    } else if (enc) {
        k = &g_server.tls.ticket_keys[g_server.tls.ticket_cur];
        if (unlikely(!k->live))
            return 0;
    } else {
        /* No key of that name: rotated out, or -- with a process-local ring --
         * minted by a different worker process.  0 means "cannot open", which
         * costs a full handshake. */
        if ((k = tls_ticket_key_by_name(name)) == NULL)
            return 0;
    }

    if (enc) {
        memcpy(name, k->name, TLS_TICKET_NAME_LEN);
        ptls_openssl_random_bytes(iv, TLS_TICKET_IV_LEN);
        if (likely(EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(), NULL, k->aes, iv)))
            rc = tls_ticket_mac_init(hctx, k->hmac, TLS_TICKET_HMAC_LEN);
    } else {
        if (likely(EVP_DecryptInit_ex(cctx, EVP_aes_256_cbc(), NULL, k->aes, iv)))
            rc = tls_ticket_mac_init(hctx, k->hmac, TLS_TICKET_HMAC_LEN);
    }

    /* OpenSSL has taken its own copy of the key schedule by now, so this one
     * has no reason to stay on the stack -- where the next connection's
     * handshake would be free to leave it readable indefinitely.  Harmless on
     * the process-local path, which never wrote it. */
    ptls_clear_memory(&shared_key, sizeof(shared_key));
    return rc;
}

static int tls_ticket_encrypt(ptls_encrypt_ticket_t *self, ptls_t *tls,
                              int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src) {
    (void)self;
    (void)tls;
    return is_encrypt ? tls_ticket_seal_impl(dst, src, tls_ticket_key_cb)
                      : tls_ticket_unseal_impl(dst, src, tls_ticket_key_cb);
}

/* Advance the process-local ring by one step.  Split out of the timer
 * callback so a test can drive rotation without waiting an hour of wall
 * clock: the ring's whole contract -- a retired key still opens tickets until
 * the constraint says it cannot -- is otherwise unexercised code, which is
 * precisely the silent-degradation failure this feature is prone to. */
void tls_ticket_rotate_once(void) {
    tls_server_t *ts = &g_server.tls;
    int next = (ts->ticket_cur + 1) % TLS_TICKET_RING;
    ptls_clear_memory(&ts->ticket_keys[next], sizeof(ts->ticket_keys[next]));
    tls_ticket_key_mint(&ts->ticket_keys[next]);
    ts->ticket_cur = next;
}

static void tls_ticket_rotate(uv_timer_t *timer) {
    (void)timer;
    tls_ticket_rotate_once();
}

/*
 * ---------------------------------------------------------------------------
 * Multiple workers: the shared ring
 * ---------------------------------------------------------------------------
 *
 * The design, the two alternatives it was chosen over, and the honest ledger
 * of what sharing makes better and worse, are all in server.h above
 * tls_ticket_ring_t.  What is here is how the region is made, handed over,
 * and destroyed.
 *
 * Two rejected alternatives, so a later reader does not re-propose them:
 *
 *   * Pass a key through the spawn pickle.  The key then lives in immutable
 *     Python bytes -- in the parent, in the pipe, and in every child -- which
 *     nothing can zeroize and the GC is free to copy.  It also cannot rotate:
 *     the pickle happens once, at start.
 *   * Share one long-lived seed and derive each epoch from it.  It rotates in
 *     lockstep for free and needs none of this, and it is wrong for exactly
 *     one reason: whoever takes the seed has every epoch, past and future.
 *     Rotation would then bound nothing, and the "an attacker who takes the
 *     process at time T gets tickets back to T-3h" claim in server.h would be
 *     false rather than conservative.  Parent-owned rotation is chosen over
 *     it precisely so that a retired key is *destroyed*, not derivable.
 *
 * How the region is created, and what an attacker can reach:
 *
 *   Linux -- memfd_create().  The region has no name and no link anywhere in
 *   any filesystem: not /dev/shm, not /tmp, nothing to open by path and
 *   nothing to race.  It is reachable only as /proc/<pid>/fd/<n> of a process
 *   that holds a descriptor, which needs ptrace_may_access on that process --
 *   i.e. an attacker who can already read its /proc/<pid>/mem, and so could
 *   already read the keys out of the process directly.  So on Linux the
 *   region is not a wider door than the per-process ring it replaces.
 *
 *   macOS, and Linux without memfd -- shm_open(O_CREAT|O_EXCL, 0600) under a
 *   128-bit random name, unlinked microseconds later, before any worker
 *   exists.  This one IS a slightly wider door and it is worth being straight
 *   about: for the length of that window, a process running as the same user
 *   that guesses the name can open it.  Guessing 128 bits of CSPRNG output
 *   inside a few microseconds is not an attack, and root does not need the
 *   window, but the window is not zero the way memfd's is.
 *
 *   Either way the descriptor handed to a worker is O_RDONLY, so a worker
 *   maps it MAP_SHARED|PROT_READ and mmap with PROT_WRITE on it fails with
 *   EACCES.  Sharing is MAP_SHARED and not MAP_PRIVATE on purpose and it is
 *   load-bearing twice over: MAP_PRIVATE would copy-on-write, so a worker
 *   would never see a rotation (silent divergence, the exact failure this
 *   change exists to remove) and would keep its own copy of every retired key
 *   alive for the life of the process (the exact property rotation exists to
 *   provide).
 *
 *   The mapping is mlock()ed so the keys are not written to swap, and marked
 *   MADV_DONTDUMP where that exists.  On Linux a MAP_SHARED file-backed
 *   mapping is already outside the default /proc/<pid>/coredump_filter of
 *   0x33, so the ring is *less* likely to reach a core file than the
 *   process-local ring it replaces, which lives in ordinary anonymous
 *   private memory that every core dump includes.
 */

/* Bytes of CSPRNG in an shm_open() name.  12 is as many as fit: macOS caps a
 * POSIX shm name at PSHMNAMLEN = 31 characters and "/f" plus 24 hex digits is
 * 26.  96 bits is not a number anything guesses inside the microseconds
 * between the O_EXCL create and the shm_unlink. */
#define TLS_RING_NAME_RANDOM 12

#if defined(__linux__)
#  ifndef MFD_CLOEXEC
#    define MFD_CLOEXEC 0x0001U
#  endif
/* Called through syscall() rather than the glibc wrapper, which only appeared
 * in glibc 2.27: the kernel has had the call since 3.17 and a wheel built on
 * an older toolchain should still get the anonymous region at run time. */
static int tls_memfd_create(const char *name, unsigned int flags) {
#  ifdef SYS_memfd_create
    return (int)syscall(SYS_memfd_create, name, flags);
#  else
    (void)name; (void)flags;
    errno = ENOSYS;
    return -1;
#  endif
}
#endif

/* Open the backing object twice: read-write for the owner, read-only for the
 * workers.  Both descriptors are close-on-exec -- a ticket key has no business
 * surviving into an unrelated program the application happens to exec. */
static int tls_ticket_ring_open(int *rw_out, int *ro_out, const char **how_out) {
    int rw = -1, ro = -1;

#if defined(__linux__)
    rw = tls_memfd_create("freastal-ticket-ring", MFD_CLOEXEC);
    if (rw >= 0) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", rw);
        ro = open(path, O_RDONLY | O_CLOEXEC);
        if (ro >= 0) {
            *rw_out = rw; *ro_out = ro; *how_out = "memfd, anonymous";
            return 0;
        }
        /* No /proc: there is no way to derive a read-only descriptor for this
         * object, and handing the workers a writable one would quietly drop
         * the property that a worker cannot plant a sealing key.  Fall back to
         * the named object, which can be opened read-only by name, rather than
         * downgrade silently. */
        close(rw);
        rw = -1;
    }
#endif

    for (int attempt = 0; attempt < 8; attempt++) {
        uint8_t rnd[TLS_RING_NAME_RANDOM];
        char name[2 + 2 * TLS_RING_NAME_RANDOM + 1];
        ptls_openssl_random_bytes(rnd, sizeof(rnd));
        memcpy(name, "/f", 2);
        for (size_t i = 0; i < sizeof(rnd); i++)
            snprintf(name + 2 + 2 * i, 3, "%02x", rnd[i]);

        rw = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (rw < 0) {
            if (errno == EEXIST)
                continue;          /* 128 bits collided; humour it and retry */
            return -1;
        }
        ro = shm_open(name, O_RDONLY, 0600);
        /* Unlink before anything else can happen, and before any worker
         * exists.  The descriptors keep the object alive with no name. */
        shm_unlink(name);
        ptls_clear_memory(name, sizeof(name));
        if (ro < 0) {
            int saved = errno;
            close(rw);
            errno = saved;
            return -1;
        }
        (void)fcntl(rw, F_SETFD, FD_CLOEXEC);
        (void)fcntl(ro, F_SETFD, FD_CLOEXEC);
        *rw_out = rw; *ro_out = ro; *how_out = "shm, unlinked";
        return 0;
    }
    errno = EEXIST;
    return -1;
}

/* One page, whatever the page is here.  The struct is a few hundred bytes;
 * rounding to a page keeps mlock() and madvise() operating on exactly what
 * was mapped. */
static size_t tls_ticket_ring_len(void) {
    long pg = sysconf(_SC_PAGESIZE);
    size_t page = (pg > 0) ? (size_t)pg : 4096u;
    size_t need = sizeof(tls_ticket_ring_t);
    return ((need + page - 1) / page) * page;
}

/* Keep the keys out of swap and out of core files, both best-effort: a
 * container with RLIMIT_MEMLOCK at 0 must still be able to run a server.
 * Whether it took is reported rather than assumed -- an operator who cares
 * should be able to see it, not infer it. */
static bool tls_ticket_ring_harden(void *base, size_t len) {
#ifdef MADV_DONTDUMP
    (void)madvise(base, len, MADV_DONTDUMP);
#endif
    return mlock(base, len) == 0;
}

/*
 * Create the ring and return the read-only descriptor for the workers.  The
 * region is fully initialised -- one key minted, seq at 2, deadline set --
 * before this returns, and this returns before the first worker exists, so
 * there is no window in which a worker can map a half-written ring.  A worker
 * that somehow saw seq == 0 refuses to start rather than sealing under zeros.
 */
int tls_ticket_ring_create(int *ro_fd_out) {
    int rw = -1, ro = -1;
    const char *how = "";
    size_t len = tls_ticket_ring_len();
    void *base = MAP_FAILED;
    tls_ticket_key_t first;

    if (g_ring_owned != NULL) {
        PyErr_SetString(PyExc_RuntimeError,
            "freastal: this process already owns a session-ticket ring. Two "
            "concurrent serve() calls in one process would need two, and the "
            "second would leak the first; run them in separate processes.");
        return -1;
    }

    if (tls_ticket_ring_open(&rw, &ro, &how) < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    if (ftruncate(rw, (off_t)len) != 0)
        goto err;
    base = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, rw, 0);
    if (base == MAP_FAILED)
        goto err;

    memset(base, 0, len);
    g_ring_owned        = (tls_ticket_ring_t *)base;
    g_ring_owned_len    = len;
    g_ring_owned_fd     = rw;
    g_ring_owned_how    = how;
    g_ring_owned_locked = tls_ticket_ring_harden(base, len);

    g_ring_owned->magic      = TLS_TICKET_RING_MAGIC;
    g_ring_owned->abi        = TLS_TICKET_RING_ABI;
    g_ring_owned->ring_slots = TLS_TICKET_RING;
    g_ring_owned->key_stride = (uint32_t)sizeof(tls_ticket_key_t);
    g_ring_owned->rotate_ms  = TLS_TICKET_ROTATE_MS;
    g_ring_owned->grace_ms   = TLS_TICKET_STALE_GRACE_MS;
    g_ring_owned->owner_pid  = (int32_t)getpid();

    tls_ticket_key_mint(&first);
    tls_ticket_ring_publish(g_ring_owned, 0, &first);
    ptls_clear_memory(&first, sizeof(first));

    tls_log("[freastal] TLS: session-ticket key ring shared with the workers "
            "(%s, %zu bytes, %s); this process rotates it every %u s\n",
            how, len, g_ring_owned_locked ? "mlocked" : "NOT mlocked, may swap",
            (unsigned)(TLS_TICKET_ROTATE_MS / 1000u));

    *ro_fd_out = ro;
    return 0;

err:
    PyErr_SetFromErrno(PyExc_OSError);
    if (base != MAP_FAILED)
        munmap(base, len);
    g_ring_owned = NULL;
    g_ring_owned_fd = -1;
    close(rw);
    close(ro);
    return -1;
}

/* Advance the shared ring one step.  The owner is the only writer, which is
 * the whole of the lockstep story: there is no election, no cross-process
 * lock, and no way for two rings to drift apart, because there is one ring. */
int tls_ticket_ring_rotate_owned(void) {
    tls_ticket_key_t fresh;
    int next;

    if (g_ring_owned == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
            "freastal: this process owns no session-ticket ring to rotate");
        return -1;
    }
    /* Minted outside the seqlock window on purpose; see
     * tls_ticket_ring_publish(). */
    tls_ticket_key_mint(&fresh);
    next = (g_ring_owned->cur + 1) % TLS_TICKET_RING;
    tls_ticket_ring_publish(g_ring_owned, next, &fresh);
    ptls_clear_memory(&fresh, sizeof(fresh));
    return 0;
}

int tls_ticket_ring_owner_pid(void) {
    return g_ring_owned != NULL ? (int)g_ring_owned->owner_pid : -1;
}

/*
 * Destroy the ring.  Idempotent, and reached from the owner on every exit
 * path Python can still run code on: a clean return from serve(), the
 * SIGINT/SIGTERM handler (which raises SystemExit through the finally), and
 * an exception out of the worker loop.
 *
 * Zeroizing before unmapping is what makes the destruction unconditional
 * rather than an argument about page reuse.  It writes through to the one
 * physical page every worker has mapped, so the keys are gone from every
 * address space at once, not merely from this one -- MAP_SHARED again.
 *
 * On the paths Python cannot run -- SIGKILL, an abort inside the interpreter
 * -- nothing here runs, and the guarantee falls back to the kernel: the last
 * mapping and the last descriptor go away with the last process, the object
 * has no name to reopen, and the pages return to the allocator, which zeroes
 * them before any process can fault them in again.  So they are unreachable
 * from user space, but not scrubbed by us.
 */
void tls_ticket_ring_destroy(void) {
    if (g_ring_owned != NULL) {
        ptls_clear_memory(g_ring_owned, g_ring_owned_len);
        if (g_ring_owned_locked)
            munlock(g_ring_owned, g_ring_owned_len);
        munmap(g_ring_owned, g_ring_owned_len);
        g_ring_owned = NULL;
        g_ring_owned_len = 0;
        g_ring_owned_locked = false;
    }
    if (g_ring_owned_fd >= 0) {
        close(g_ring_owned_fd);
        g_ring_owned_fd = -1;
    }
}

/*
 * Map the owner's ring into a worker, read-only.
 *
 * Refusing rather than falling back to a process-local ring is deliberate.  A
 * fallback would come up, serve every request correctly, and resume about 1/N
 * of the time -- which is indistinguishable from working, and is the exact
 * silent failure this whole change exists to remove.  A worker that cannot
 * join the shared ring exits and says why, and _run_workers turns that into a
 * RuntimeError out of serve().
 */
static int tls_ticket_ring_attach(int fd) {
    size_t len = tls_ticket_ring_len();
    void *base = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
    const tls_ticket_ring_t *r;

    if (base == MAP_FAILED) {
        fprintf(stderr, "[freastal] TLS: cannot map the shared ticket ring: %s\n",
                strerror(errno));
        return -1;
    }
    r = (const tls_ticket_ring_t *)base;

    /* The descriptor comes from our own parent, so a mismatch here means a
     * caller passed something else entirely.  Check before believing any
     * offset in it; reading key material out of the wrong struct shape is not
     * a mistake worth making cheaply. */
    if (r->magic != TLS_TICKET_RING_MAGIC || r->abi != TLS_TICKET_RING_ABI ||
        r->ring_slots != TLS_TICKET_RING ||
        r->key_stride != (uint32_t)sizeof(tls_ticket_key_t) ||
        /* The owner publishes its rotation period and its grace, and this
         * worker enforces its own compiled-in ceiling on both, so the window
         * server.h reasons about is a property of the binary rather than of
         * whatever the process on the other end of the descriptor claims. */
        r->rotate_ms > TLS_TICKET_ROTATE_MS ||
        r->grace_ms > TLS_TICKET_STALE_GRACE_MS ||
        atomic_load_explicit(&r->seq, memory_order_acquire) == 0u) {
        fprintf(stderr,
                "[freastal] TLS: the descriptor passed as the shared ticket "
                "ring is not one, or was built by a different freastal; "
                "refusing to start rather than serving with keys no other "
                "worker shares\n");
        munmap(base, len);
        return -1;
    }

    tls_ticket_ring_harden(base, len);
    g_server.tls.ticket_shared     = r;
    g_server.tls.ticket_shared_len = len;
    return 0;
}

/*
 * The ops/test hook behind _freastal._rotate_ticket_key().
 *
 * What "rotate the ring" means depends on who is asking, and the shared ring
 * changed the answer for a worker:
 *
 *   * A process with its own ring -- workers=1, the common case -- rotates it
 *     in place, exactly as before.  Unchanged code, unchanged tests.
 *   * A worker rotates nothing.  Its mapping is read-only, and a worker that
 *     could rotate would be a worker that could write key material every
 *     other worker then sealed under.  It asks the owner (SIGUSR1) and waits
 *     until the owner's new key is visible *through the shared mapping*
 *     before returning, so the hook still means "one rotation step of the
 *     ring the next connection will be sealed under" -- and now exercises the
 *     real production path, owner writes and worker observes, rather than a
 *     per-process shortcut that would prove nothing about lockstep.
 *
 * SIGUSR1 is a deliberate operator-facing interface as well as a test hook:
 * "rotate the ticket keys now" is a real thing to want, and rotating early is
 * always safe -- the worst it costs is that clients holding the oldest key
 * fall back to a full handshake sooner than they would have.  It is not an
 * escalation: the sender must already be the same user or root, and could
 * SIGKILL the server instead.
 */
int tls_ticket_rotate_hook(void) {
    const tls_ticket_ring_t *r = g_server.tls.ticket_shared;
    uint32_t before;
    int pid;
    int rc = -1;

    if (g_ring_owned != NULL)
        return tls_ticket_ring_rotate_owned();

    if (r == NULL) {
        if (!g_server.tls_enabled) {
            PyErr_SetString(PyExc_RuntimeError, "freastal: TLS is not enabled");
            return -1;
        }
        /* A worker whose shared ring was dropped (tls_ticket_ring_disable)
         * has a process-local ring that is all zeros and unused.  Rotating it
         * would report success and change nothing, which is the one answer
         * this hook must never give. */
        if (g_server.tls.ctx.encrypt_ticket == NULL) {
            PyErr_SetString(PyExc_RuntimeError,
                "freastal: session tickets are off in this process, so there "
                "is no ring to rotate");
            return -1;
        }
        tls_ticket_rotate_once();
        return 0;
    }

    before = atomic_load_explicit(&r->seq, memory_order_acquire);
    pid    = (int)r->owner_pid;
    if (kill(pid, SIGUSR1) != 0) {
        PyErr_Format(PyExc_OSError,
            "freastal: cannot ask the ticket-ring owner (pid %d) to rotate: %s",
            pid, strerror(errno));
        return -1;
    }

    /* Two increments is one complete publish; anything odd is mid-publish.
     * 5 s at 1 ms is far past anything the owner's thread needs and short
     * enough that a test fails rather than hangs. */
    Py_BEGIN_ALLOW_THREADS
    for (int i = 0; i < 5000; i++) {
        uint32_t now = atomic_load_explicit(&r->seq, memory_order_acquire);
        if (now >= before + 2u && (now & 1u) == 0u) { rc = 0; break; }
        {
            struct timespec ms = {0, 1000000};
            nanosleep(&ms, NULL);
        }
    }
    Py_END_ALLOW_THREADS

    if (rc != 0)
        PyErr_Format(PyExc_TimeoutError,
            "freastal: the ticket-ring owner (pid %d) did not publish a "
            "rotation within 5 s", pid);
    return rc;
}

int tls_server_init(const char *certfile, const char *keyfile, int ring_fd) {
    tls_server_t *ts = &g_server.tls;
    memset(ts, 0, sizeof(*ts));

    if (ptls_load_certificates(&ts->ctx, certfile) != 0) {
        fprintf(stderr, "[freastal] TLS: failed to load cert from %s\n", certfile);
        return -1;
    }

    FILE *fp = fopen(keyfile, "r");
    if (!fp) {
        fprintf(stderr, "[freastal] TLS: cannot open key %s\n", keyfile);
        return -1;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "[freastal] TLS: failed to parse key from %s\n", keyfile);
        return -1;
    }
    ptls_openssl_init_sign_certificate(&ts->sign_cert, pkey);
    EVP_PKEY_free(pkey);

    ts->ctx.random_bytes     = ptls_openssl_random_bytes;
    ts->ctx.get_time         = &ptls_get_time;
    ts->ctx.key_exchanges    = freastal_key_exchanges;
    /*
     * ptls_openssl_cipher_suites[] names AES-256-GCM-SHA384 first, which reads
     * like a misordering but is not, and is left alone on purpose.  The memset
     * above leaves ctx.server_cipher_preference at 0, so select_cipher()
     * honors the *client's* order and this list is only a membership filter:
     * browsers on AES-capable hardware ask for AES-128-GCM-SHA256 first and
     * get it, browsers without AES instructions ask for ChaCha20-Poly1305
     * first and get that.  Both are the right answer for the peer that asked,
     * and choosing for them here would only make one of the two cases worse.
     * Entry 0 is not wholly arbitrary -- cipher_suites[0]->hash is the one
     * fixed position picotls reads, as the HMAC hash for stateless-retry
     * cookies (calc_cookie_signature, plus the two sites that size and verify
     * that signature), and that path needs a hash before any suite has been
     * negotiated.  But picotls.h documents no ordering rule for the list, and
     * we pass no handshake properties, so cookies are never enabled here.
     * picotls annotates its own array "ciphers used with sha384 (must be
     * first)"; whatever that is for, the vendored order is left as it is.
     */
    ts->ctx.cipher_suites    = ptls_openssl_cipher_suites;
    ts->ctx.sign_certificate = &ts->sign_cert.super;

    /*
     * Session tickets.  Without encrypt_ticket picotls mints none, so every
     * reconnect repeats the certificate signature -- the single most expensive
     * thing in the handshake -- and a browser reopening a connection pays it
     * again.  ticket_lifetime is what goes on the wire as the client's
     * lifetime hint, and picotls also enforces it on the way back in
     * (`now - issue_at > ticket_lifetime * 1000` in the PSK loop), so a ticket
     * older than this is refused even by a key that could still open it.
     *
     * One key now; the timer mints the rest.  Pre-filling the whole ring at
     * startup would be worse, not better -- a key minted now but not sealing
     * until (RING-1) rotations from now would sit in memory for RING rotations
     * beyond that, which is the opposite of the point.
     *
     * With workers > 1 there is no ring to fill here: the process that called
     * serve() minted one before this process existed and handed down a
     * read-only descriptor for it.  Map that instead, and mint nothing --
     * a local ring in a worker is not a harmless extra, it is the divergence
     * this is meant to end.
     */
    if (ring_fd >= 0) {
        /* The descriptor is the caller's to close -- py_serve does it as soon
         * as server_init returns, either way.  A worker keeps only the
         * mapping, which is what holds the object open; retaining the
         * descriptor as well would be one more handle on key material, and
         * would keep the region alive after tls_ticket_ring_detach(). */
        if (tls_ticket_ring_attach(ring_fd) < 0)
            return -1;
    } else {
        ts->ticket_cur = 0;
        tls_ticket_key_mint(&ts->ticket_keys[0]);
    }
    ts->ticket_cb.cb           = tls_ticket_encrypt;
    ts->ctx.encrypt_ticket     = &ts->ticket_cb;
    ts->ctx.ticket_lifetime    = TLS_TICKET_LIFETIME_S;

    /*
     * Make resumption use (EC)DHE, not the ticket secret alone.
     *
     * Left at 0, picotls picks HANDSHAKE_MODE_PSK whenever the client offers
     * psk_ke, and the resumed connection's traffic keys then come only from
     * the secret inside the ticket.  Anyone who later takes the sealing key
     * and had recorded the traffic can decrypt it: the resumed session has no
     * forward secrecy at all, and rotating the key does nothing for sessions
     * already on the wire.  With this set, the resumed handshake still does a
     * fresh ECDHE, so a recovered ticket key gives an attacker the resumption
     * secret and no plaintext.  It bounds *impersonation* within the ticket
     * window, which is what a bounded key lifetime is for.
     *
     * It costs one ECDH per resumption -- the same one a full handshake does,
     * and not the operation resumption is saving; the certificate signature
     * is.  It is also free in interop: picotls only drops the psk_ke bit, so a
     * client offering psk_dhe_ke (OpenSSL, BoringSSL and NSS all offer that
     * and nothing else) is unaffected, and a hypothetical psk_ke-only client
     * gets a full handshake rather than a failure.
     */
    ts->ctx.require_dhe_on_psk = 1;

    /*
     * ctx.max_early_data_size stays 0: 0-RTT is deliberately off.  Early data
     * is replayable by design and a general-purpose WSGI/ASGI server cannot
     * know whether the application's handlers are idempotent.  Note that this
     * is what keeps the ticket from carrying an early_data extension in
     * send_session_ticket(), so clients are never invited to try.
     *
     * The memset() at the top of this function is what zeroes it; there is
     * deliberately no assignment here, because an assignment is exactly what
     * a future edit would overwrite.  What is here instead is a check, run
     * after every other field is set, so that a line anywhere above it that
     * turns early data on is caught before the listener ever answers.  It
     * costs one branch at startup and turns a silent behaviour change into a
     * server that refuses to start and says why.
     */
    if (ts->ctx.max_early_data_size != 0) {
        fprintf(stderr,
                "[freastal] TLS: refusing to start with 0-RTT early data "
                "enabled; early data is replayable and freastal cannot know "
                "whether your handlers are idempotent\n");
        return -1;
    }

    /*
     * Rotation runs on the loop, which is the only thread that reads the ring;
     * see the block above tls_ticket_key_mint().  g_server.loop is already set
     * -- server_init() assigns it well before it calls us.
     *
     * The handle is unref'd on purpose.  An hourly repeating timer is a
     * referenced handle that would keep uv_run() from ever returning on its
     * own; the listening socket already has that effect today, so this changes
     * nothing now, and stops the ticket ring from being the reason a loop that
     * has otherwise finished will not stop.
     *
     * A worker on the shared ring starts no timer at all.  That is the
     * lockstep guarantee stated as code: N timers on N loops would be N
     * clocks, they would drift within one period, and cross-worker resumption
     * would stop working an hour after deployment -- silently, and after
     * passing every test that does not rotate.  There is one writer and one
     * clock, in the process that owns the ring.
     */
    if (ts->ticket_shared == NULL) {
        uv_timer_init(g_server.loop, &ts->ticket_timer);
        uv_unref((uv_handle_t *)&ts->ticket_timer);
        uv_timer_start(&ts->ticket_timer, tls_ticket_rotate, TLS_TICKET_ROTATE_MS,
                       TLS_TICKET_ROTATE_MS);
    }

    g_server.tls_enabled = true;
    tls_log("[freastal] TLS 1.3 enabled (picotls + OpenSSL backend); session "
            "tickets on, %u s lifetime, key rotates every %u s (%s)\n",
            (unsigned)TLS_TICKET_LIFETIME_S, (unsigned)(TLS_TICKET_ROTATE_MS / 1000u),
            ts->ticket_shared ? "ring shared with the other workers, rotated by "
                                "the process that called serve()"
                              : "ring private to this process");
    return 0;
}

/*
 * Encryption-output blocks live in a per-loop free list rather than on the
 * client_t, the way h2o recycles its socket SSL buffers.  A connection needs
 * one only between write_response() and on_write(), so the pool's high-water
 * mark is the number of responses in flight at once -- tens -- whereas a
 * per-connection buffer would cost a block for every open connection, idle
 * ones included, against a 4096-slot pool.  Recycling a handful of blocks also
 * keeps them hot in cache instead of scattering one per connection.
 *
 * The free-list link lives in the first word of the block itself, so the pool
 * costs no memory of its own.
 */
void *tls_wbuf_get(void) {
    void *block = g_server.tls_wbuf_pool;
    if (likely(block != NULL)) {
        g_server.tls_wbuf_pool = *(void **)block;
        g_server.tls_wbuf_pool_n--;
        g_server.tls_wbuf_live++;
        return block;
    }
    block = malloc(TLS_WBLOCK_SIZE);
    if (likely(block != NULL)) {
        g_server.tls_wbuf_mallocs++;
        g_server.tls_wbuf_live++;
    }
    return block;
}

void tls_wbuf_put(void *block) {
    g_server.tls_wbuf_live--;
    if (unlikely(g_server.tls_wbuf_pool_n >= TLS_WBUF_POOL_MAX)) {
        free(block);
        return;
    }
    *(void **)block = g_server.tls_wbuf_pool;
    g_server.tls_wbuf_pool = block;
    g_server.tls_wbuf_pool_n++;
}

/*
 * A response past TLS_WSEG_MAX blocks does not segment; it takes one buffer of
 * its own.  Handing that to picotls with is_allocated = 1 -- which is what the
 * pre-segmentation code did at every size over 16,739 bytes -- would make
 * ptls_buffer_dispose() responsible for it, and ptls_buffer__release_memory()
 * memsets buf->off bytes before freeing.  There is nothing there to scrub:
 * ptls_send_v() encrypts straight from the caller's plaintext into this
 * buffer and never stages a plaintext copy in it, so every byte of it has already
 * gone out on the wire in the clear.
 *
 * So freastal owns this one too, and keeps one per loop rather than returning
 * it to malloc every time.  A single slot is enough: it is held only between
 * write_response() and on_write(), and responses this large are rare enough
 * that two in flight at once is not the case worth sizing for -- the second
 * just allocates.  The slot ratchets up to the largest size seen, so a run of
 * them settles on one buffer instead of walking through malloc sizes, and
 * anything past TLS_BIGBUF_KEEP_MAX is freed rather than pinned per worker.
 */
void *tls_bigbuf_get(size_t need, size_t *cap_out) {
    void *buf = g_server.tls_bigbuf;
    if (buf != NULL && g_server.tls_bigbuf_cap >= need) {
        g_server.tls_bigbuf     = NULL;
        *cap_out                = g_server.tls_bigbuf_cap;
        g_server.tls_bigbuf_cap = 0;
        g_server.tls_bigbuf_live++;
        return buf;
    }
    *cap_out = need;
    buf = malloc(need);
    if (likely(buf != NULL)) {
        g_server.tls_wbuf_mallocs++;
        g_server.tls_bigbuf_live++;
    }
    return buf;
}

void tls_bigbuf_put(void *buf, size_t cap) {
    g_server.tls_bigbuf_live--;
    if (unlikely(cap > TLS_BIGBUF_KEEP_MAX)) { free(buf); return; }
    if (g_server.tls_bigbuf != NULL) {
        /* Keep whichever is larger; the smaller one would never be picked. */
        if (cap <= g_server.tls_bigbuf_cap) { free(buf); return; }
        free(g_server.tls_bigbuf);
    }
    g_server.tls_bigbuf     = buf;
    g_server.tls_bigbuf_cap = cap;
}

/*
 * Ownership of each segment's buffer is decided by comparing its base against
 * the block it was opened on, not by is_allocated.
 *
 * When the block came from the pool picotls was handed a buffer it does not
 * own (is_allocated = 0), so ptls_buffer_dispose() would neither free it nor
 * return it here -- and its ptls_clear_memory() pass would sweep the entire
 * record for nothing, since ptls_send_v() encrypts straight from the caller's
 * plaintext into this buffer and so it only ever holds ciphertext.
 *
 * picotls can still swap a block out from under us -- a KeyUpdate record, or
 * any reservation the sizing failed to anticipate -- in which case base no
 * longer points at the pooled block and the replacement is picotls-owned and
 * must be freed.  Checking base rather than trusting the sizing is what keeps
 * that from being either a leak or a double free.
 *
 * So base tells the three cases apart:
 *
 *   base == block        the ciphertext is in the block itself: no dispose,
 *                        straight back to the pool.
 *   base == c->tls_wbig  an oversized response (past TLS_WSEG_MAX blocks).
 *                        That buffer is freastal's too, handed over with
 *                        is_allocated = 0, so it goes back to the retained
 *                        slot and picotls never sweeps it either.  The block
 *                        carries only the chain node.
 *   anything else        picotls replaced what we gave it and owns the
 *                        replacement; dispose frees that.  If it displaced the
 *                        oversized buffer, ours is still live and its capacity
 *                        is no longer recorded anywhere, so it goes back to
 *                        malloc rather than to the slot.
 *
 * Every segment of the chain is released, which matters because a response is
 * one uv_write over all of them: they live and die together.
 */
void tls_release_wbuf(client_t *c) {
    void *block = c->tls_wblock;
    void *big   = c->tls_wbig;
    bool  big_returned = false;

    c->tls_wblock = NULL;
    c->tls_wbig   = NULL;

    while (block != NULL) {
        tls_wseg_t *seg  = TLS_WSEG_OF(block);
        void       *next = seg->next;
        void       *base = (void *)seg->buf.base;
        if (unlikely(base != block)) {
            if (likely(big != NULL && base == big)) {
                tls_bigbuf_put(big, seg->buf.capacity);
                big_returned = true;
            } else {
                ptls_buffer_dispose(&seg->buf);     /* picotls owns what it points at */
            }
        }
        tls_wbuf_put(block);
        block = next;
    }

    /* The oversized buffer is normally returned by the walk above.  It is not
     * only when picotls outgrew it and swapped in an allocation of its own,
     * which dispose has just freed -- ours is still live, and its capacity is
     * no longer recorded anywhere, so it goes back to malloc rather than to
     * the retained slot. */
    if (unlikely(big != NULL && !big_returned)) {
        g_server.tls_bigbuf_live--;
        free(big);
    }
}

/* Same free-list-in-the-first-word shape as tls_wbuf_get()/put() above. */
void *tls_spill_get(void) {
    void *block = g_server.tls_spill_pool;
    if (block != NULL) {
        g_server.tls_spill_pool = *(void **)block;
        g_server.tls_spill_pool_n--;
        return block;
    }
    return malloc(TLS_SPILL_SIZE);
}

void tls_spill_put(void *block) {
    if (unlikely(g_server.tls_spill_pool_n >= TLS_SPILL_POOL_MAX)) {
        free(block);
        return;
    }
    *(void **)block = g_server.tls_spill_pool;
    g_server.tls_spill_pool = block;
    g_server.tls_spill_pool_n++;
}

void tls_release_spill(client_t *c) {
    if (c->tls_spill != NULL) {
        tls_spill_put(c->tls_spill);
        c->tls_spill = NULL;
    }
    c->tls_spill_len = 0;
}

void tls_conn_init(client_t *c) {
    /* Checked here rather than in the ticket callback, and once per
     * connection rather than once per ticket, because this is a point at
     * which the ticket configuration can safely be changed: no connection is
     * inside ptls_handshake() on this thread.  See tls_ticket_ring_disable(). */
    if (unlikely(g_server.tls.ticket_shared != NULL &&
                 tls_ticket_ring_is_stale(g_server.tls.ticket_shared)))
        tls_ticket_ring_disable("its owner stopped rotating it");

    c->tls_enc     = malloc(TLS_ENC_BUF_SIZE);
    c->tls         = ptls_new(&g_server.tls.ctx, 1 /* is_server */);
    c->tls_hs_done = false;
    c->tls_broken  = false;
    c->tls_wblock  = NULL;
    c->tls_wbig      = NULL;
    c->tls_spill     = NULL;
    c->tls_spill_len = 0;
}

void tls_conn_free(client_t *c) {
    free(c->tls_enc); c->tls_enc = NULL;
    /* Reached on every close path, including the ones that never wrote a
     * response (400 Bad Request, handshake failure) and plaintext connections,
     * for which both releases are a no-op.  The spill is normally handed back
     * by tls_spill_drain() as soon as it empties; this catches a connection
     * torn down while one was still held.
     *
     * The tls_release_wbuf() call is normally redundant -- on_write has
     * already run it, and it is idempotent -- but it is load-bearing on the
     * paths where tls_write_response_impl() closes without ever reaching
     * uv_write: a block or the oversized buffer could not be allocated, or
     * ptls_send_v() failed partway through and it took the abandon branch.
     * Those are all out-of-memory paths, so no test reaches them without an
     * allocation-failure hook; deleting this as dead code would leak the whole
     * chain the first time the pool and malloc both came up empty. */
    tls_release_spill(c);
    if (c->tls) { ptls_free(c->tls); c->tls = NULL; }
    tls_release_wbuf(c);
    c->tls_hs_done = false;
    c->tls_broken  = false;
}

#endif /* FREASTAL_TLS */
