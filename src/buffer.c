/* buffer.c - the growable buffer every transport layer moves bytes through.
 *
 * One implementation, one write path. Two read paths for the same bytes is
 * how a layer ends up disagreeing with itself about what it has already
 * consumed, and that class of bug is silent.
 */
#include "transport.h"

#include <stdlib.h>
#include <string.h>

void buf_init(buffer *b) {
    b->p = NULL;
    b->len = 0;
    b->cap = 0;
    b->at = 0;
}

void buf_free(buffer *b) {
    free(b->p);
    buf_init(b);
}

void buf_reset(buffer *b) {
    b->len = 0;
    b->at = 0;
}

int buf_reserve(buffer *b, size_t extra) {
    size_t need = b->at + b->len + extra;
    if (need <= b->cap) {
        return 0;
    }
    /* The live bytes are the ones not yet consumed, so a compaction is tried
     * before a realloc. A long session then allocates once per growth rather
     * than once per byte, without the read cursor going stale. */
    if (b->at > 0) {
        memmove(b->p, b->p + b->at, b->len);
        b->at = 0;
        if (need <= b->cap) {
            return 0;
        }
    }
    size_t cap = b->cap ? b->cap : 1024;
    while (cap < need) {
        if (cap > (size_t)1 << 40) {
            return -1;
        }
        cap *= 2;
    }
    unsigned char *np = realloc(b->p, cap);
    if (np == NULL) {
        return -1;
    }
    b->p = np;
    b->cap = cap;
    return 0;
}

int buf_append(buffer *b, const void *data, size_t len) {
    if (len == 0) {
        return 0;
    }
    if (buf_reserve(b, len) != 0) {
        return -1;
    }
    memcpy(b->p + b->at + b->len, data, len);
    b->len += len;
    return 0;
}

void buf_consume(buffer *b, size_t n) {
    if (n >= b->len) {
        b->len = 0;
        b->at = 0;
        return;
    }
    b->at += n;
    b->len -= n;
    /* Compacting here rather than on the next append keeps a reader that only
     * ever consumes from holding on to the head of a large stream forever. */
    if (b->at >= 4096 && b->at * 2 >= b->cap) {
        memmove(b->p, b->p + b->at, b->len);
        b->at = 0;
    }
}
