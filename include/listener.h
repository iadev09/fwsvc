#ifndef FWSVC_LISTENER_H
#define FWSVC_LISTENER_H

#include <stdbool.h>

typedef struct Listener Listener;

Listener *listener_init(const char *conninfo, const char *channel);
void listener_free(Listener *listener);
const char *listener_last_error(Listener *listener);

int listener_ensure(Listener **listener, const char *conninfo, const char *channel);
int listener_poll(Listener *listener, int timeout_ms, bool *out_event_received);
int listener_wait(Listener **listener, const char *conninfo, const char *channel, int timeout_ms,
                  bool *out_event_received);
int listener_pop_event(Listener *listener, char **out_channel, char **out_payload);

#endif /* FWSVC_LISTENER_H */
