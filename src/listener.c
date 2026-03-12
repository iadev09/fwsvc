#include "listener.h"
#include <errno.h>
#include <libpq-fe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

struct Listener {
    char *conninfo;
    char *channel;
    PGconn *conn;
    char **event_channels;
    char **event_payloads;
    size_t event_count;
    size_t event_capacity;
};

static int listener_push_event(Listener *listener, const PGnotify *notify) {
    if (!listener || !notify || !notify->relname) {
        return 1;
    }

    if (listener->event_count == listener->event_capacity) {
        size_t new_capacity = listener->event_capacity == 0 ? 4 : listener->event_capacity * 2;
        char **new_channels = (char **) realloc((void *) listener->event_channels, sizeof(char *) * new_capacity);
        if (!new_channels) {
            return 1;
        }
        char **new_payloads = (char **) realloc((void *) listener->event_payloads, sizeof(char *) * new_capacity);
        if (!new_payloads) {
            listener->event_channels = new_channels;
            return 1;
        }
        listener->event_channels = new_channels;
        listener->event_payloads = new_payloads;
        listener->event_capacity = new_capacity;
    }

    listener->event_channels[listener->event_count] = strdup(notify->relname);
    listener->event_payloads[listener->event_count] = strdup(notify->extra ? notify->extra : "");
    if (!listener->event_channels[listener->event_count] || !listener->event_payloads[listener->event_count]) {
        free(listener->event_channels[listener->event_count]);
        free(listener->event_payloads[listener->event_count]);
        listener->event_channels[listener->event_count] = nullptr;
        listener->event_payloads[listener->event_count] = nullptr;
        return 1;
    }

    listener->event_count++;
    return 0;
}

static int listener_connect(Listener *listener) {
    if (!listener) {
        return 1;
    }

    if (listener->conn) {
        PQfinish(listener->conn);
        listener->conn = nullptr;
    }

    listener->conn = PQconnectdb(listener->conninfo);
    if (!listener->conn || PQstatus(listener->conn) != CONNECTION_OK) {
        return 1;
    }

    size_t query_len = strlen("LISTEN ") + strlen(listener->channel) + 1;
    char *query = (char *) calloc(query_len + 1, 1);
    if (!query) {
        return 1;
    }
    strcpy(query, "LISTEN ");
    strcat(query, listener->channel);

    PGresult *res = PQexec(listener->conn, query);
    free(query);
    if (!res || PQresultStatus(res) != PGRES_COMMAND_OK) {
        if (res) {
            PQclear(res);
        }
        return 1;
    }
    PQclear(res);
    return 0;
}

Listener *listener_init(const char *conninfo, const char *channel) {
    if (!conninfo || !channel) {
        return nullptr;
    }

    Listener *listener = (Listener *) calloc(1, sizeof(*listener));
    if (!listener) {
        return nullptr;
    }

    listener->conninfo = strdup(conninfo);
    listener->channel = strdup(channel);
    if (!listener->conninfo || !listener->channel) {
        listener_free(listener);
        return nullptr;
    }

    if (listener_connect(listener) != 0) {
        listener_free(listener);
        return nullptr;
    }

    return listener;
}

int listener_ensure(Listener **listener, const char *conninfo, const char *channel) {
    if (!listener) {
        return 1;
    }
    if (*listener) {
        return 0;
    }

    *listener = listener_init(conninfo, channel);
    if (!*listener) {
        usleep(1000000);
        return 1;
    }
    return 0;
}

void listener_free(Listener *listener) {
    if (!listener) {
        return;
    }

    if (listener->conn) {
        PQfinish(listener->conn);
    }
    for (size_t i = 0; i < listener->event_count; i++) {
        free(listener->event_channels[i]);
        free(listener->event_payloads[i]);
    }
    free((void *) listener->event_channels);
    free((void *) listener->event_payloads);
    free(listener->conninfo);
    free(listener->channel);
    free(listener);
}

const char *listener_last_error(Listener *listener) {
    if (!listener || !listener->conn) {
        return "listener not initialized";
    }

    return PQerrorMessage(listener->conn);
}

int listener_poll(Listener *listener, int timeout_ms, bool *out_event_received) {
    if (!listener || !out_event_received) {
        return 1;
    }

    *out_event_received = false;

    if (!listener->conn || PQstatus(listener->conn) != CONNECTION_OK) {
        return listener_connect(listener);
    }

    int sock = PQsocket(listener->conn);
    if (sock < 0) {
        return 1;
    }

    fd_set input_mask;
    FD_ZERO(&input_mask);
    FD_SET(sock, &input_mask);

    struct timeval timeout = {
            .tv_sec = timeout_ms / 1000,
            .tv_usec = (__suseconds_t) (timeout_ms % 1000) * 1000,
    };

    int ready = select(sock + 1, &input_mask, nullptr, nullptr, &timeout);
    if (ready < 0) {
        if (errno == EINTR) {
            return 0;
        }
        return 1;
    }
    if (ready == 0) {
        return 0;
    }

    if (PQconsumeInput(listener->conn) == 0) {
        return 1;
    }

    PGnotify *notify = nullptr;
    bool event_received = false;
    while ((notify = PQnotifies(listener->conn)) != nullptr) {
        printf("fwsvc: notify channel=%s payload=%s\n", notify->relname, notify->extra ? notify->extra : "");
        fflush(stdout);
        if (listener_push_event(listener, notify) != 0) {
            PQfreemem(notify);
            return 1;
        }
        *out_event_received = true;
        event_received = true;
        PQfreemem(notify);
    }
    if (event_received) {
        printf("fwsvc: notify poll ok\n");
        fflush(stdout);
    }

    return 0;
}

int listener_wait(Listener **listener, const char *conninfo, const char *channel, int timeout_ms,
                  bool *out_event_received) {
    if (!listener || !out_event_received) {
        return 1;
    }
    if (listener_ensure(listener, conninfo, channel) != 0) {
        return 1;
    }
    if (listener_poll(*listener, timeout_ms, out_event_received) == 0) {
        return 0;
    }

    fprintf(stderr, "Listener poll failed: %s\n", listener_last_error(*listener));
    listener_free(*listener);
    *listener = nullptr;
    usleep(1000000);
    return 1;
}

int listener_pop_event(Listener *listener, char **out_channel, char **out_payload) {
    if (!listener || !out_channel || !out_payload) {
        return -1;
    }
    if (listener->event_count == 0) {
        *out_channel = nullptr;
        *out_payload = nullptr;
        return 0;
    }

    *out_channel = listener->event_channels[0];
    *out_payload = listener->event_payloads[0];

    for (size_t i = 1; i < listener->event_count; i++) {
        listener->event_channels[i - 1] = listener->event_channels[i];
        listener->event_payloads[i - 1] = listener->event_payloads[i];
    }
    listener->event_count--;
    listener->event_channels[listener->event_count] = nullptr;
    listener->event_payloads[listener->event_count] = nullptr;
    return 1;
}
