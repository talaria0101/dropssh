/* events.c - the machine-readable event stream, on stderr, so stdout stays a
 * byte pipe.
 *
 * ⛔ EVENTS GO TO STDERR AND STDOUT STAYS A CLEAN BYTE PIPE. `dropssh connect`
 * is what ssh's ProxyCommand runs, and a single byte on its stdout lands in
 * the middle of an ssh version string: the handshake then fails with a message
 * that names a protocol problem rather than the log line that caused it. So
 * every event here is written to stderr, and the ONLY stdout write in this
 * project is the relay write in connect.c.
 *
 * ⛔ `--json` WAS A FLAG NOTHING READ, AND A FLAG THAT IS ACCEPTED AND IGNORED
 * IS WORSE THAN ONE THAT IS REFUSED: an operator who passes it believes they
 * have machine-readable output and does not. The flag is now either honoured
 * in full or refused by name. There is no mode in which a verb prints JSON on
 * some runs and prose on others.
 *
 * The event names are the ones docs/relay-issues.md R4 asked for, and each
 * carries the fields needed to answer the NEXT question without a rebuild:
 * a session_close with bytes in and out and a duration answers "was it a
 * stall or a transfer", and a reconnect with its backoff answers "is it
 * retrying or stuck".
 *
 * ⛔ NO EVENT EVER CARRIES A TOKEN, A KEY, A PATH PREFIX OR A SESSION'S BYTES.
 * A credential in a log line is a credential in every copy of that log line.
 * The session id is the relay's own random hex and is included, because it is
 * how an operator correlates their session with the relay's; it authorises
 * nothing without the token that opened the socket. */
#include "events.h"
#include "util.h"
#include "tls.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t elock = PTHREAD_MUTEX_INITIALIZER;
static int ev_json = 0;

void dropssh_events_set_json(int on) {
    pthread_mutex_lock(&elock);
    ev_json = on;
    pthread_mutex_unlock(&elock);
}

int dropssh_events_json(void) {
    pthread_mutex_lock(&elock);
    int v = ev_json;
    pthread_mutex_unlock(&elock);
    return v;
}

/* One line, one write, under one lock. A line assembled from three fprintf
 * calls can interleave with another thread's, and a log that interleaves is a
 * log nobody can parse -- which is the whole reason this exists. */
static void emit(const char *json_or_empty, const char *plain_fmt, ...) {
    va_list ap;
    char plain[512];
    va_start(ap, plain_fmt);
    vsnprintf(plain, sizeof plain, plain_fmt, ap);
    va_end(ap);

    int j;
    pthread_mutex_lock(&elock);
    j = ev_json;
    if (j) {
        fprintf(stderr, "%s %s\n", json_or_empty, plain);
    } else {
        fprintf(stderr, "dropssh: %s\n", plain);
    }
    fflush(stderr);
    pthread_mutex_unlock(&elock);
}

/* The JSON form is the event name plus the plain text as a single string
 * field, rather than a hand-built object per event. A hand-built object per
 * event is a place for a missing comma, an unescaped quote in a session id,
 * and a field that appears in one event and not another; this cannot be
 * malformed because there is exactly one shape. The fields an operator
 * actually parses programmatically (they are the ones in the plain text) are
 * also available through `dropssh doctor` and `relay --status`, which are
 * typed rather than string-matched. */
void dropssh_event(const char *name, const char *fmt, ...) {
    va_list ap;
    char plain[512];
    va_start(ap, fmt);
    vsnprintf(plain, sizeof plain, fmt, ap);
    va_end(ap);

    char esc[600];
    size_t o = 0;
    for (size_t i = 0; plain[i] && o + 7 < sizeof esc; i++) {
        unsigned char c = (unsigned char)plain[i];
        switch (c) {
        case '"':  esc[o++] = '\\'; esc[o++] = '"';  break;
        case '\\': esc[o++] = '\\'; esc[o++] = '\\'; break;
        case '\n': esc[o++] = '\\'; esc[o++] = 'n';  break;
        case '\r': esc[o++] = '\\'; esc[o++] = 'r';  break;
        case '\t': esc[o++] = '\\'; esc[o++] = 't';  break;
        default:
            if (c < 0x20) {
                o += (size_t)snprintf(esc + o, sizeof esc - o, "\\u%04x", c);
            } else {
                esc[o++] = (char)c;
            }
        }
    }
    esc[o] = 0;

    int j;
    pthread_mutex_lock(&elock);
    j = ev_json;
    if (j) {
        fprintf(stderr, "{\"event\":\"%s\",\"detail\":\"%s\"}\n", name, esc);
    } else {
        fprintf(stderr, "dropssh: %s\n", plain);
    }
    fflush(stderr);
    pthread_mutex_unlock(&elock);
    (void)emit;
}

/* The first line of a --json run, so a consumer can tell a dropssh event
 * stream from a relay's log or a dropbear's, before it has parsed anything. */
void dropssh_events_banner(const char *verb) {
    int j;
    pthread_mutex_lock(&elock);
    j = ev_json;
    if (j) {
        fprintf(stderr, "{\"event\":\"start\",\"verb\":\"%s\","
                        "\"version\":\"%s\",\"tls\":\"%s\"}\n",
                verb, dropssh_version(), dropssh_tls_backend());
        fflush(stderr);
    }
    pthread_mutex_unlock(&elock);
}
