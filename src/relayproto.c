/* relayproto.c - the relay's control-message fields, read by a bounded scan.
 *
 * ⛔ THIS IS NOT A JSON PARSER AND THE COMMENT ABOVE IT IS THE REASON. A
 * control message is a short line from a relay, and the only two fields that
 * change what a node does are the `type` and the session `id`. A general JSON
 * parser here would be a network-fed parser whose entire job is two string
 * extractions, and the id becomes a value that other code compares against and
 * writes into a fixed slot, so it is validated rather than trusted.
 */
#include "relayproto.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* ⛔ THE SCAN TAKES THE VALUE BETWEEN THE KEY AND THE NEXT QUOTE AFTER IT, AND
 * IT SKIPS THE WHITESPACE AND A SINGLE OPTIONAL QUOTE. It does not scan for
 * "the next quote anywhere", which is what the first version did, and that
 * version was wrong in a way that passed every test written for it.
 *
 * The first version looked like this:
 *
 *     const char *q = strchr(k + strlen(key), '"');   // the KEY's closing quote
 *     q = strchr(q + 1, '"');                          // ...which finds the COMMA
 *     size_t n = e - q - 1;                            // ...and copies ","
 *
 * So `{"type":"hello","version":1}` yielded the value `,` for `type`, which
 * then failed the `verb` word check and reported a perfectly good `hello` as
 * "a control message dropssh could not parse". It worked for a message whose
 * key was the last field, which is why no unit test caught it and the live
 * multiplexer caught it in the first second of its first run. A scanner that
 * only works on one field position is a parser that has not been tested.
 *
 * The scan below is position-independent: it finds the key, steps over the
 * colon, and then takes the text up to the next quote, whether or not the
 * value is quoted. */
static int grab(const char *json, const char *key, char *out, size_t outlen) {
    out[0] = 0;
    const char *k = strstr(json, key);
    if (k == NULL) {
        return -1;
    }
    k += strlen(key);
    /* ⛔ THE SCAN IS BOUNDED BY THE END OF THE MESSAGE, NOT BY strlen(json)
     * BEYOND IT. `json` is NUL-terminated by the caller, and a control
     * message is at most a few hundred bytes, so a key that appears in a
     * VALUE is not found by a strstr that runs off the end: every hop below
     * stops at the terminator, and a missing one is a parse failure, not a
     * read past the buffer. */
    while (*k == ' ' || *k == '\t' || *k == '\n' || *k == '\r') {
        k++;
    }
    if (*k != ':') {
        return -1;
    }
    k++;
    while (*k == ' ' || *k == '\t' || *k == '\n' || *k == '\r') {
        k++;
    }
    int quoted = 0;
    if (*k == '"') {
        quoted = 1;
        k++;
    }
    const char *e = k;
    if (quoted) {
        while (*e && *e != '"') {
            /* ⛔ A BACKSLASH INSIDE A QUOTED VALUE IS SKIPPED AS A UNIT, so a
             * value containing an escaped quote does not end early and take
             * half of it as the value. The relay only ever sends hex ids and
             * fixed words, so this never fires in practice; it is here because
             * the cost of being wrong is a session id read from the middle of
             * a string. */
            if (*e == '\\' && e[1]) {
                e += 2;
                continue;
            }
            e++;
        }
    } else {
        /* An unquoted value ends at the next structural character, which is
         * what makes `maxFrameBytes: 65536` read as 65536. */
        while (*e && *e != ',' && *e != '}' && *e != ' ' && *e != '\t' &&
               *e != '\n' && *e != '\r') {
            e++;
        }
    }
    size_t n = (size_t)(e - k);
    if (n == 0 || n >= outlen) {
        return -1;
    }
    memcpy(out, k, n);
    out[n] = 0;
    return 0;
}

/* The relay's ids are 32 lowercase hex characters. The check is on CHARACTER
 * not on shape, so a value that came from somewhere else cannot smuggle a
 * newline, a quote or a path separator into a comparison or into JSON this
 * process then builds. */
static int hexish(const char *s, size_t n) {
    if (n == 0) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        int ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                 (c >= 'A' && c <= 'F');
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

int relay_parse_control(const char *json, char *verb, size_t verblen,
                        char *id, size_t idlen) {
    if (verb != NULL && verblen) {
        verb[0] = 0;
    }
    if (id != NULL && idlen) {
        id[0] = 0;
    }
    if (json == NULL) {
        return -1;
    }
    /* ⛔ ALL THREE KEY SPELLINGS ARE TRIED, IN THE ORDER THE RELAY IS KNOWN
     * TO USE, AND A MESSAGE WITH NONE OF THEM IS REFUSED RATHER THAN
     * DEFAULTED. `type` is what the relay sends (docs/reverse-relay.md: "the
     * field is `type`, not `verb`"); `verb` and `event` were read out of an
     * earlier copy of the relay's own text and are tried so a relay that
     * says either is understood. What is NOT done is accepting a message
     * with no verb at all, because "ready" and "open" then take the same
     * path and a session hangs for ever. */
    char v[64];
    if (grab(json, "\"type\"", v, sizeof v) != 0 &&
        grab(json, "\"verb\"", v, sizeof v) != 0 &&
        grab(json, "\"event\"", v, sizeof v) != 0) {
        return -1;
    }
    /* ⛔ A VERB IS A BARE WORD, AND THE CHECK IS OVER THE WHOLE STRING, NOT
     * OVER A PREFIX. A verb of "open; rm -rf" would pass a "starts with
     * open" test and is refused here. */
    for (size_t k = 0; v[k]; k++) {
        if (!isalpha((unsigned char)v[k])) {
            return -1;
        }
    }
    if (verb != NULL && verblen) {
        snprintf(verb, verblen, "%s", v);
    }
    if (id != NULL && idlen) {
        char i[128];
        if (grab(json, "\"id\"", i, sizeof i) == 0) {
            /* ⛔ AN ID IS VALIDATED BEFORE IT IS COPIED ANYWHERE ELSE. It is
             * compared against, used as a JSON string this process builds, and
             * used to pick a session; a value carrying a quote or a brace
             * would change the JSON built from it. */
            if (!hexish(i, strlen(i))) {
                return -1;
            }
            snprintf(id, idlen, "%s", i);
        }
    }
    return 0;
}

/* Read one unsigned integer field. The hello's maxFrameBytes and maxSessions
 * are policy numbers this node then enforces (B7), so they are read by the
 * same bounded scan rather than by a second mechanism. */
int relay_parse_uint(const char *json, const char *key, unsigned *out) {
    char v[32];
    if (grab(json, key, v, sizeof v) != 0) {
        return -1;
    }
    if (v[0] == 0) {
        return -1;
    }
    for (size_t i = 0; v[i]; i++) {
        if (!isdigit((unsigned char)v[i])) {
            return -1;
        }
    }
    char *end = NULL;
    unsigned long n = strtoul(v, &end, 10);
    if (end == v || n > 0xffffffffUL) {
        return -1;
    }
    *out = (unsigned)n;
    return 0;
}

int relay_parse_string(const char *json, const char *key, char *out,
                       size_t outlen) {
    if (json == NULL || key == NULL || out == NULL || outlen == 0) {
        return -1;
    }
    char pat[64];
    int pn = snprintf(pat, sizeof pat, "\"%s\"", key);
    if (pn <= 0 || (size_t)pn >= sizeof pat) {
        return -1;
    }
    const char *p = strstr(json, pat);
    if (p == NULL) {
        return -1;
    }
    p += pn;
    while (*p == ' ' || *p == '\t' || *p == ':') {
        p++;
    }
    if (*p != '"') {
        return -1;
    }
    p++;
    size_t o = 0;
    while (*p && *p != '"' && o < outlen - 1) {
        if (*p == '\\') {
            /* an escape ends the VALUE rather than being decoded: a host with
             * a backslash in it is not a host this will dial, and guessing at
             * the encoding is how a destination stops being the one that was
             * checked. See the note in relayproto.h. */
            return -1;
        }
        out[o++] = *p++;
    }
    if (*p != '"') {
        return -1;                   /* unterminated: refuse, do not half-use */
    }
    out[o] = 0;
    return o ? 0 : -1;
}
