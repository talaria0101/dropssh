/* relayproto.h - the small pieces of the relay's reverse protocol dropssh
 * needs on the node side.
 *
 * ⛔ THE CONTROL MESSAGES ARE PARSED BY SCAN, NOT BY A JSON PARSER, AND THE
 * SCAN IS BOUNDED. They arrive as short lines from a relay, and the only two
 * fields that change what the node does are the verb and the session id. A
 * general JSON parser here would be a network-fed parser whose only job is
 * two string extractions, and the id becomes a filename-shaped token that
 * other code compares against, so it is validated rather than trusted.
 */
#ifndef DROPSSH_RELAYPROTO_H
#define DROPSSH_RELAYPROTO_H

#include <stddef.h>

/* Extract "verb" and "id" from a control message. Returns 0 on success. A
 * `verb` is a bare word and an `id` is the relay's own 32 hex characters;
 * anything else is refused, so a message cannot smuggle a newline or a path
 * separator into a comparison or a name. */
int relay_parse_control(const char *json, char *verb, size_t verblen,
                        char *id, size_t idlen);

#endif /* DROPSSH_RELAYPROTO_H */
