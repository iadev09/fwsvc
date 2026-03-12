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
};

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
    char *query = calloc(query_len + 1, 1);
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

    Listener *listener = calloc(1, sizeof(*listener));
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

void listener_free(Listener *listener) {
    if (!listener) {
        return;
    }

    if (listener->conn) {
        PQfinish(listener->conn);
    }
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
    while ((notify = PQnotifies(listener->conn)) != nullptr) {
        printf("fwsvc: notify channel=%s payload=%s\n", notify->relname, notify->extra ? notify->extra : "");
        fflush(stdout);
        *out_event_received = true;
        PQfreemem(notify);
    }

    return 0;
}
