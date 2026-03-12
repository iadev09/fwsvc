#ifndef SERVICE_H
#define SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum { SERVICE_SCOPE_PUBLIC = 0, SERVICE_SCOPE_PRIVATE = 1 } ServiceScope;

typedef struct {
    ServiceScope scope;
    char *name; /* db: services.name */
    char *chain_name; /* db: service_chains.chain_name (view) */

    /* Optional flags from services */
    bool logging;

    /* Flattened lists (you can split into separate structs later) */
    char **ips;
    size_t ip_count;

    uint16_t *tcp_ports;
    size_t tcp_port_count;

    uint16_t *udp_ports;
    size_t udp_port_count;

    /* private only */
    char **allowed_sources;
    char **allowed_comments;
    size_t allowed_count;
} Service;

void service_free(Service *s);
void service_list_free(Service *services, size_t count);

#endif
