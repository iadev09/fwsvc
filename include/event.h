#ifndef FWSVC_EVENT_H
#define FWSVC_EVENT_H

typedef struct Listener Listener;

int fw_apply_blacklist_event(const char *conninfo, const char *op, const char *source);
int fw_apply_service_allowed_event(const char *conninfo, const char *op, int service_id, const char *source);
int fw_dispatch_event(const char *conninfo, const char *payload);
void fw_drain_listener_events(Listener *listener, const char *conninfo);

#endif /* FWSVC_EVENT_H */
