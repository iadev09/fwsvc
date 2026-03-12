#include "reload.h"
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "db.h"
#include "fw.h"
#include "net.h"

static int fw_debug_enabled(void) {
    const char *value = getenv("FW_DEBUG");
    return value && value[0] != '\0' && strcmp(value, "0") != 0 ? 1 : 0;
}

static void fw_debug_log(const char *fmt, ...) {
    if (!fw_debug_enabled()) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    fputs("fwsvc[debug]: ", stdout);
    // NOLINTNEXTLINE(clang-diagnostic-format-nonliteral)
    vfprintf(stdout, fmt, ap);
    fputc('\n', stdout);
    fflush(stdout);
    va_end(ap);
}

static int persist_iptables_state_for_host(char *persist_path, size_t persist_path_size) {
    if (fw_detect_persist_path(persist_path, persist_path_size) != 0) {
        fprintf(stderr, "fwsvc: failed to detect iptables persist path for this distribution\n");
        return 1;
    }
    fw_debug_log("persist path=%s", persist_path);
    return 0;
}

int fw_reload_once(const char *conninfo) {
    char public_if[64] = {0};
    if (net_detect_public_interface(public_if, sizeof(public_if)) == 0) {
        fw_debug_log("detected public interface=%s", public_if);
    } else {
        fprintf(stderr, "fwsvc: failed to detect public interface\n");
    }

    Db *db = db_open(conninfo);
    if (!db || !db_ping(db)) {
        fprintf(stderr, "DB connection failed: %s\n", db ? db_last_error(db) : "unknown error");
        if (db) {
            db_close(db);
        }
        return 1;
    }

    Fw *fw = fw_init(db, public_if);
    if (!fw) {
        fprintf(stderr, "FW init failed\n");
        db_close(db);
        return 1;
    }

    char snapshot_path[64] = {0};
    if (fw_save_snapshot(snapshot_path, sizeof(snapshot_path)) != 0) {
        fprintf(stderr, "fwsvc: failed to snapshot iptables state\n");
        fw_free(fw);
        db_close(db);
        return 1;
    }

    char persist_path[PATH_MAX] = {0};
    if (persist_iptables_state_for_host(persist_path, sizeof(persist_path)) != 0) {
        unlink(snapshot_path);
        fw_free(fw);
        db_close(db);
        return 1;
    }

    int rc = fw_apply(fw);
    if (rc == 0 && fw_persist_state(persist_path) != 0) {
        fprintf(stderr, "fwsvc: failed to persist iptables state to %s\n", persist_path);
        rc = 1;
    }
    if (rc != 0) {
        if (fw_restore_snapshot(snapshot_path) != 0) {
            fprintf(stderr, "fwsvc: failed to restore iptables snapshot\n");
        }
    } else {
        printf("fwsvc: firewall reload completed\n");
        fflush(stdout);
    }

    unlink(snapshot_path);
    fw_free(fw);
    db_close(db);
    return rc;
}
