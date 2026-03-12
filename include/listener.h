#ifndef FWSVC_LISTENER_H
#define FWSVC_LISTENER_H

#include <stdbool.h>

typedef struct Listener Listener;

Listener *listener_init(const char *conninfo, const char *channel);
void listener_free(Listener *listener);
const char *listener_last_error(Listener *listener);

int listener_poll(Listener *listener, int timeout_ms, bool *out_event_received);

#endif /* FWSVC_LISTENER_H */
