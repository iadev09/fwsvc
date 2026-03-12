
#include "service.h"
#include <stdlib.h>

void service_free(Service *svc) {
    if (!svc) {
        return;
    }

    free(svc->name);
    free(svc->chain_name);

    if (svc->ips) {
        for (size_t i = 0; i < svc->ip_count; i++) {
            free(svc->ips[i]);
        }
        free((void *) svc->ips);
    }

    if (svc->allowed_sources) {
        for (size_t i = 0; i < svc->allowed_count; i++) {
            free(svc->allowed_sources[i]);
        }
        free((void *) svc->allowed_sources);
    }

    if (svc->allowed_comments) {
        for (size_t i = 0; i < svc->allowed_count; i++) {
            free(svc->allowed_comments[i]);
        }
        free((void *) svc->allowed_comments);
    }

    free(svc->tcp_ports);
    free(svc->udp_ports);
}

void service_list_free(Service *services, size_t count) {
    if (!services) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        service_free(&services[i]);
    }

    free(services);
}
