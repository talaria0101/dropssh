#include "relayproto.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int hexish(const char *s, size_t n) {
    if (n == 0) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        int ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                 (c >= 'A' && c <= 'F') || c == '-';
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

static int grab(const char *json, const char *key, char *out, size_t outlen) {
    out[0] = 0;
    const char *k = strstr(json, key);
    if (k == NULL) {
        return -1;
    }
    const char *q = strchr(k + strlen(key), '"');
    if (q == NULL) {
        return -1;
    }
    /* Skip to the opening quote of the value: the key's own closing quote,
     * then a colon, then the value's opening quote. */
    q = strchr(q + 1, '"');
    if (q == NULL) {
        return -1;
    }
    const char *e = strchr(q + 1, '"');
    if (e == NULL) {
        return -1;
    }
    size_t n = (size_t)(e - q - 1);
    if (n == 0 || n >= outlen) {
        return -1;
    }
    memcpy(out, q + 1, n);
    out[n] = 0;
    return 0;
}

int relay_parse_control(const char *json, char *verb, size_t verblen,
                        char *id, size_t idlen) {
    verb[0] = 0;
    id[0] = 0;
    char v[64], i[128];
    if (grab(json, "\"verb\"", v, sizeof v) != 0 &&
        grab(json, "\"type\"", v, sizeof v) != 0 &&
        grab(json, "\"event\"", v, sizeof v) != 0) {
        return -1;
    }
    for (size_t k = 0; v[k]; k++) {
        if (!((v[k] >= 'a' && v[k] <= 'z') || (v[k] >= 'A' && v[k] <= 'Z'))) {
            return -1;
        }
    }
    if (grab(json, "\"id\"", i, sizeof i) == 0) {
        if (!hexish(i, strlen(i))) {
            return -1;
        }
        snprintf(id, idlen, "%s", i);
    }
    snprintf(verb, verblen, "%s", v);
    return 0;
}
