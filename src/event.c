#include "event.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "db.h"
#include "fw.h"
#include "listener.h"

static int json_extract_string(const char *json, const char *key, char *out, size_t out_size) {
    if (!json || !key || !out || out_size == 0) {
        return 1;
    }

    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) {
        return 1;
    }
    p = strchr(p, ':');
    if (!p) {
        return 1;
    }
    p++;
    while (*p == ' ') {
        p++;
    }
    if (*p != '"') {
        return 1;
    }
    p++;

    size_t len = 0;
    while (p[len] != '\0' && p[len] != '"' && len + 1 < out_size) {
        out[len] = p[len];
        len++;
    }
    if (p[len] != '"') {
        return 1;
    }
    out[len] = '\0';
    return 0;
}

static int json_extract_int(const char *json, const char *key, int *out_value) {
    if (!json || !key || !out_value) {
        return 1;
    }

    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) {
        return 1;
    }
    p = strchr(p, ':');
    if (!p) {
        return 1;
    }
    p++;
    while (*p == ' ') {
        p++;
    }

    char *end = nullptr;
    long value = strtol(p, &end, 10);
    if (end == p) {
        return 1;
    }
    *out_value = (int) value;
    return 0;
}
static int resolve_persist_path(char *persist_path, size_t persist_path_size) {
    if (fw_detect_persist_path(persist_path, persist_path_size) != 0) {
        fprintf(stderr, "fwsvc: failed to detect iptables persist path for this distribution\n");
        return 1;
    }
    return 0;
}

int fw_apply_blacklist_event(const char *conninfo, const char *op, const char *source) {
    if (!conninfo || !op || !source || source[0] == '\0') {
        return 1;
    }

    char snapshot_path[64] = {0};
    if (fw_save_snapshot(snapshot_path, sizeof(snapshot_path)) != 0) {
        fprintf(stderr, "fwsvc: failed to snapshot iptables state\n");
        return 1;
    }

    char persist_path[PATH_MAX] = {0};
    if (resolve_persist_path(persist_path, sizeof(persist_path)) != 0) {
        unlink(snapshot_path);
        return 1;
    }

    int rc = 1;
    if (strcmp(op, "insert") == 0) {
        Db *db = db_open(conninfo);
        char *comment = nullptr;
        if (!db || !db_ping(db) || db_fetch_blacklist_comment(db, source, &comment) != 0) {
            fprintf(stderr, "fwsvc: blacklist add failed source=%s\n", source);
            if (db) {
                db_close(db);
            }
            unlink(snapshot_path);
            return 1;
        }

        rc = fw_apply_blacklist_insert(source, comment);
        if (rc == 2) {
            printf("fwsvc: blacklist add skipped source=%s (already present)\n", source);
            fflush(stdout);
            rc = 0;
        } else if (rc == 0) {
            printf("fwsvc: blacklist add ok source=%s\n", source);
            fflush(stdout);
        } else {
            fprintf(stderr, "fwsvc: blacklist add failed source=%s\n", source);
        }
        free(comment);
        db_close(db);
    } else if (strcmp(op, "delete") == 0) {
        int found = 0;
        rc = fw_apply_blacklist_delete(source, &found);
        if (rc != 0) {
            fprintf(stderr, "fwsvc: blacklist delete failed source=%s\n", source);
        } else if (!found) {
            printf("fwsvc: blacklist delete skipped source=%s (not found)\n", source);
            fflush(stdout);
        } else {
            printf("fwsvc: blacklist delete ok source=%s\n", source);
            fflush(stdout);
        }
    } else {
        unlink(snapshot_path);
        return 1;
    }

    if (rc == 0 && fw_persist_state(persist_path) != 0) {
        fprintf(stderr, "fwsvc: failed to persist iptables state to %s\n", persist_path);
        rc = 1;
    }
    if (rc != 0) {
        if (fw_restore_snapshot(snapshot_path) != 0) {
            fprintf(stderr, "fwsvc: failed to restore iptables snapshot\n");
        }
    }

    unlink(snapshot_path);
    return rc;
}

int fw_apply_service_allowed_event(const char *conninfo, const char *op, int service_id, const char *source) {
    if (!conninfo || !op || service_id <= 0 || !source || source[0] == '\0') {
        return 1;
    }

    char snapshot_path[64] = {0};
    if (fw_save_snapshot(snapshot_path, sizeof(snapshot_path)) != 0) {
        fprintf(stderr, "fwsvc: failed to snapshot iptables state\n");
        return 1;
    }

    char persist_path[PATH_MAX] = {0};
    if (resolve_persist_path(persist_path, sizeof(persist_path)) != 0) {
        unlink(snapshot_path);
        return 1;
    }

    Db *db = db_open(conninfo);
    Service service = {0};
    if (!db || !db_ping(db) || db_fetch_service_by_id(db, service_id, &service) != 0 ||
        service.scope != SERVICE_SCOPE_PRIVATE) {
        fprintf(stderr, "fwsvc: service_allowed apply failed service_id=%d source=%s\n", service_id, source);
        if (db) {
            db_close(db);
        }
        unlink(snapshot_path);
        return 1;
    }

    int rc = 1;
    if (strcmp(op, "insert") == 0) {
        char *comment = nullptr;
        if (db_fetch_service_allowed_comment(db, service_id, source, &comment) != 0) {
            fprintf(stderr, "fwsvc: service_allowed add failed service_id=%d source=%s\n", service_id, source);
            service_free(&service);
            db_close(db);
            unlink(snapshot_path);
            return 1;
        }

        rc = fw_apply_service_allowed_insert(&service, source, comment);
        if (rc == 2) {
            printf("fwsvc: service_allowed add skipped service_id=%d source=%s (already present)\n", service_id,
                   source);
            fflush(stdout);
            rc = 0;
        } else if (rc == 0) {
            printf("fwsvc: service_allowed add ok service_id=%d source=%s\n", service_id, source);
            fflush(stdout);
        } else {
            fprintf(stderr, "fwsvc: service_allowed add failed service_id=%d source=%s\n", service_id, source);
        }
        free(comment);
    } else if (strcmp(op, "delete") == 0) {
        int found = 0;
        rc = fw_apply_service_allowed_delete(&service, source, &found);
        if (rc != 0) {
            fprintf(stderr, "fwsvc: service_allowed delete failed service_id=%d source=%s\n", service_id, source);
        } else if (!found) {
            printf("fwsvc: service_allowed delete skipped service_id=%d source=%s (not found)\n", service_id,
                   source);
            fflush(stdout);
        } else {
            printf("fwsvc: service_allowed delete ok service_id=%d source=%s\n", service_id, source);
            fflush(stdout);
        }
    } else {
        service_free(&service);
        db_close(db);
        unlink(snapshot_path);
        return 1;
    }

    if (rc == 0 && fw_persist_state(persist_path) != 0) {
        fprintf(stderr, "fwsvc: failed to persist iptables state to %s\n", persist_path);
        rc = 1;
    }
    if (rc != 0) {
        if (fw_restore_snapshot(snapshot_path) != 0) {
            fprintf(stderr, "fwsvc: failed to restore iptables snapshot\n");
        }
    }

    service_free(&service);
    db_close(db);
    unlink(snapshot_path);
    return rc;
}

int fw_dispatch_event(const char *conninfo, const char *payload) {
    if (!payload) {
        return 0;
    }

    char entity[64] = {0};
    char op[32] = {0};
    char source[128] = {0};
    if (json_extract_string(payload, "entity", entity, sizeof(entity)) != 0 ||
        json_extract_string(payload, "op", op, sizeof(op)) != 0 ||
        json_extract_string(payload, "source", source, sizeof(source)) != 0) {
        return 0;
    }

    if (strcmp(entity, "global_blacklist") == 0) {
        return fw_apply_blacklist_event(conninfo, op, source);
    }

    if (strcmp(entity, "service_allowed") == 0) {
        int service_id = 0;
        if (json_extract_int(payload, "service_id", &service_id) != 0) {
            return 0;
        }
        return fw_apply_service_allowed_event(conninfo, op, service_id, source);
    }

    return 0;
}

void fw_drain_listener_events(Listener *listener, const char *conninfo) {
    char *event_channel = nullptr;
    char *event_payload = nullptr;
    while (listener_pop_event(listener, &event_channel, &event_payload) > 0) {
        if (fw_dispatch_event(conninfo, event_payload) != 0) {
            fprintf(stderr, "fwsvc: notify apply failed channel=%s\n", event_channel);
        }
        free(event_channel);
        free(event_payload);
        event_channel = nullptr;
        event_payload = nullptr;
    }
}
