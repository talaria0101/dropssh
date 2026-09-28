/* events.h - the event stream, and the one place that decides whether a run
 * is prose or JSON.
 *
 * ⛔ THIS IS THE ANSWER TO A DEAD FLAG. `--json` was accepted by main.c, set
 * a field, and nothing ever read it: no verb emitted a machine-readable line.
 * An operator who passed it believed they had one. So the mode is decided here,
 * once, from one setter, and every event goes through one function that either
 * writes the human line or the JSON object. There is no third path.
 */
#ifndef DROPSSH_EVENTS_H
#define DROPSSH_EVENTS_H

/* Turn JSON mode on or off for the whole process. A process has one stdout
 * and one event stream, so this is a process-wide setting rather than a
 * per-verb one, the same reasoning as the proxy and verification settings in
 * util.h. */
void dropssh_events_set_json(int on);
int  dropssh_events_json(void);

/* One event. `name` is the event name (registered, session_open, ...), and the
 * rest becomes the human line and the JSON "detail" string.
 *
 * ⛔ EVERY EVENT IS ON STDERR. stdout is ssh's byte pipe and nothing else may
 * write to it. */
void dropssh_event(const char *name, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Emitted once at the start of a JSON run, and nothing at all in prose mode. */
void dropssh_events_banner(const char *verb);

#endif /* DROPSSH_EVENTS_H */
