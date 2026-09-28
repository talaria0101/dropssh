/* relayproto.h - the small pieces of the relay's reverse protocol dropssh
 * needs on the node side.
 *
 * ⛔ THE CONTROL MESSAGES ARE PARSED BY SCAN, NOT BY A JSON PARSER, AND THE
 * SCAN IS BOUNDED. They arrive as short lines from a relay, and the only
 * fields that change what the node does are the type and the session id. A
 * general JSON parser here would be a network-fed parser whose only job is
 * two string extractions, and the id becomes a value that other code compares
 * against and writes into JSON this process builds, so it is validated rather
 * than trusted.
 */
#ifndef DROPSSH_RELAYPROTO_H
#define DROPSSH_RELAYPROTO_H

#include <stddef.h>

/* Extract the control verb and the session id from a control message. Returns
 * 0 on success.
 *
 * ⛔ `id` AND `verb` MAY EACH BE NULL, and a caller that wants only the verb
 * passes NULL for the id. The first version indexed both unconditionally, so
 * `dropssh connect` -- which wants the verb and has no use for an id --
 * crashed on a NULL id the first time a control frame arrived. A parameter
 * that is documented as required cannot be passed as NULL, so the signature
 * says what is optional rather than leaving the reader to guess. */
int relay_parse_control(const char *json, char *verb, size_t verblen,
                        char *id, size_t idlen);

/* Read one unsigned integer field, e.g. maxFrameBytes. Returns 0 on success.
 * A value that is not a plain decimal number is refused rather than coerced,
 * because these are limits this node then enforces and a relay sending
 * "maxSessions: -1" must not become UINT_MAX. */
int relay_parse_uint(const char *json, const char *key, unsigned *out);

/* ⛔ Read one STRING field into a fixed buffer, bounded and WITHOUT UNESCAPING.
 *
 * The caller supplies the buffer and the length, so a hostile control frame
 * cannot make this allocate and cannot overflow: the copy stops at the
 * caller's bound and at the closing quote, whichever comes first, and a
 * truncated result is a value the caller then refuses rather than a value it
 * acts on.
 *
 * ⛔ AND ESCAPES ARE LEFT AS THE ESCAPER WROTE THEM. The one field read this
 * way is a SOCKS destination host, which this project validates by comparing
 * it against the one the operator named; unescaping would let a control frame
 * encode a character the sender never put in, and a destination that survives
 * unescaping but is not the one named is exactly the open-proxy case the
 * comparison exists to prevent. A backslash in a host is a host no operator
 * will name, and it is refused by the comparison rather than decoded here. */
int relay_parse_string(const char *json, const char *key, char *out,
                       size_t outlen);

#endif /* DROPSSH_RELAYPROTO_H */
