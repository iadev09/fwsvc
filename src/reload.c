#include "reload.h"
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
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

static int save_iptables_snapshot(char *path_buf, size_t path_buf_size) {
    if (!path_buf || path_buf_size == 0) {
        return 1;
    }

    snprintf(path_buf, path_buf_size, "/tmp/fwsvc-iptables-XXXXXX");
    int fd = mkstemp(path_buf);
    if (fd < 0) {
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(fd);
        unlink(path_buf);
        return 1;
    }
    if (pid == 0) {
        dup2(fd, STDOUT_FILENO);
        close(fd);
        execl("/sbin/iptables-save", "/sbin/iptables-save", "--counters", (char *) nullptr);
        _exit(127);
    }

    close(fd);
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        unlink(path_buf);
        return 1;
    }
    return 0;
}

static int restore_iptables_snapshot(const char *path) {
    if (!path) {
        return 1;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(fd);
        return 1;
    }
    if (pid == 0) {
        dup2(fd, STDIN_FILENO);
        close(fd);
        execl("/sbin/iptables-restore", "/sbin/iptables-restore", "--counters", (char *) nullptr);
        _exit(127);
    }

    close(fd);
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}

static int starts_with_word(const char *haystack, const char *needle) {
    if (!haystack || !needle) {
        return 0;
    }

    size_t needle_len = strlen(needle);
    return strncmp(haystack, needle, needle_len) == 0 &&
                           (haystack[needle_len] == '\0' || haystack[needle_len] == ' ' || haystack[needle_len] == '\n')
                   ? 1
                   : 0;
}

static int string_contains_word(const char *haystack, const char *needle) {
    if (!haystack || !needle) {
        return 0;
    }

    const char *p = haystack;
    while ((p = strstr(p, needle)) != nullptr) {
        if ((p == haystack || p[-1] == ' ' || p[-1] == '"' || p[-1] == '=') &&
            (p[strlen(needle)] == '\0' || p[strlen(needle)] == ' ' || p[strlen(needle)] == '"' ||
             p[strlen(needle)] == '\n')) {
            return 1;
        }
        p++;
    }
    return 0;
}

static int detect_iptables_persist_path(char *path_buf, size_t path_buf_size) {
    if (!path_buf || path_buf_size == 0) {
        return 1;
    }

    FILE *fp = fopen("/etc/os-release", "r");
    if (!fp) {
        return 1;
    }

    char line[512];
    int is_debian_family = 0;
    int is_rhel_family = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (starts_with_word(line, "ID=debian") || starts_with_word(line, "ID=ubuntu")) {
            is_debian_family = 1;
        }
        if (starts_with_word(line, "ID=rhel") || starts_with_word(line, "ID=centos") ||
            starts_with_word(line, "ID=rocky") || starts_with_word(line, "ID=almalinux") ||
            starts_with_word(line, "ID=fedora")) {
            is_rhel_family = 1;
        }
        if (starts_with_word(line, "ID_LIKE=")) {
            if (string_contains_word(line, "debian")) {
                is_debian_family = 1;
            }
            if (string_contains_word(line, "rhel") || string_contains_word(line, "fedora")) {
                is_rhel_family = 1;
            }
        }
    }
    fclose(fp);

    if (is_debian_family) {
        snprintf(path_buf, path_buf_size, "/etc/iptables/rules.v4");
        return access("/etc/iptables", F_OK) == 0 ? 0 : 1;
    }

    if (is_rhel_family) {
        snprintf(path_buf, path_buf_size, "/etc/sysconfig/iptables");
        return access("/etc/sysconfig", F_OK) == 0 ? 0 : 1;
    }

    return 1;
}

static int persist_iptables_state(const char *path) {
    if (!path || path[0] == '\0') {
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        return 1;
    }
    if (pid == 0) {
        execl("/sbin/iptables-save", "/sbin/iptables-save", "-f", path, (char *) nullptr);
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
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
    if (save_iptables_snapshot(snapshot_path, sizeof(snapshot_path)) != 0) {
        fprintf(stderr, "fwsvc: failed to snapshot iptables state\n");
        fw_free(fw);
        db_close(db);
        return 1;
    }

    char persist_path[PATH_MAX] = {0};
    if (detect_iptables_persist_path(persist_path, sizeof(persist_path)) != 0) {
        fprintf(stderr, "fwsvc: failed to detect iptables persist path for this distribution\n");
        unlink(snapshot_path);
        fw_free(fw);
        db_close(db);
        return 1;
    }
    fw_debug_log("persist path=%s", persist_path);

    int rc = fw_apply(fw);
    if (rc == 0 && persist_iptables_state(persist_path) != 0) {
        fprintf(stderr, "fwsvc: failed to persist iptables state to %s\n", persist_path);
        rc = 1;
    }
    if (rc != 0) {
        if (restore_iptables_snapshot(snapshot_path) != 0) {
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
