/* util.h - the small shared things: randomness, base64, sha1, sleeping, and
 * the proxy/verify settings that a process reads once and everything else
 * reads from.
 *
 * ⛔ THE PROXY AND VERIFY SETTINGS ARE PROCESS-WIDE AND SET ONCE, FROM THE
 * ENVIRONMENT OR THE COMMAND LINE, BEFORE ANY CONNECTION IS MADE. They are not
 * per-connection options because a single dropssh process has one egress, and
 * a design where they could differ per connection would let one session verify
 * certificates and another not, with nothing on the command line saying so.
 */
#ifndef DROPSSH_UTIL_H
#define DROPSSH_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* Randomness from the kernel, with the fallbacks named rather than silent. */
void dropssh_random(void *out, size_t len);
void dropssh_random_b64(char *out, size_t outlen, size_t nbytes);

void dropssh_b64_encode(const unsigned char *in, size_t len, char *out,
                        size_t outlen);
int  dropssh_b64_decode(const char *in, unsigned char *out, size_t outlen,
                        size_t *outlen_out);

/* SHA-1 is here for exactly one thing: the RFC 6455 Sec-WebSocket-Accept
 * value, which is defined as base64(sha1(key + GUID)). It is not used for
 * anything that needs to be collision resistant, and a reader looking for a
 * second use should be told this is the only one. */
void dropssh_sha1(const void *data, size_t len, unsigned char out[20]);
void dropssh_ws_accept(const char *key, char *out, size_t outlen);

void dropssh_sleep_ms(unsigned ms);
unsigned dropssh_now_ms(void);

const char *dropssh_proxy_host(void);
int         dropssh_proxy_port(void);
int         dropssh_insecure(void);
void        dropssh_set_insecure(int v);

const char *dropssh_version(void);
const char *dropssh_gitdescribe(void);

#endif /* DROPSSH_UTIL_H */
