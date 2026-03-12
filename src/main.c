#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>
#include "event.h"
#include "listener.h"
#include "reload.h"

static volatile sig_atomic_t g_exit = 0;
static volatile sig_atomic_t g_reload_count = 0;
static volatile sig_atomic_t g_applying = 0;

static const char *resolve_conninfo(void) {
    const char *conninfo = getenv("FW_DATABASE_URL");
    if (conninfo && conninfo[0] != '\0') {
        return conninfo;
    }

    conninfo = getenv("DATABASE_URL");
    if (conninfo && conninfo[0] != '\0') {
        return conninfo;
    }

    return nullptr;
}

static void handle_signal(int sig) {
    if (sig == SIGHUP) {
        g_reload_count++;
    } else {
        g_exit = 1;
        write(STDOUT_FILENO, "fwsvc: received termination signal\n", 37);
    }
}

static int acquire_single_instance_lock(void) {
    const char *lock_path = "/tmp/fwsvc.lock";
    const char *xdg_runtime_dir = getenv("XDG_RUNTIME_DIR");
    if (xdg_runtime_dir && xdg_runtime_dir[0] != '\0') {
        /* XDG_RUNTIME_DIR is expected to be an absolute path. */
        static char path_buf[512];
        if (snprintf(path_buf, sizeof(path_buf), "%s/%s", xdg_runtime_dir, "fwsvc.lock") > 0) {
            lock_path = path_buf;
        }
    }

    int fd = open(lock_path, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        /* Caller will print strerror(errno). */
        return -1;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        close(fd);
        errno = EWOULDBLOCK;
        return -1;
    }

    /* Keep fd open for process lifetime to hold the lock. */
    return fd;
}

int main(void) {
    const char *conninfo = resolve_conninfo();
    const char *notify_channel = "fwsvc_events";
    if (!conninfo) {
        fprintf(stderr, "FW_DATABASE_URL or DATABASE_URL must be set\n");
        return 1;
    }

    int lock_fd = acquire_single_instance_lock();
    if (lock_fd < 0) {
        if (errno == EWOULDBLOCK) {
            fprintf(stderr, "Another fwsvc instance is running (lock busy)\n");
        } else {
            fprintf(stderr, "Failed to acquire lock: %s\n", strerror(errno));
        }
        return 1;
    }


    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGHUP, handle_signal);


    Listener *listener = listener_init(conninfo, notify_channel);
    if (!listener) {
        fprintf(stderr, "Listener not ready for channel '%s'; will retry in main loop\n", notify_channel);
    }


    printf("fwsvc: started (pid: %d)\n", getpid());
    fflush(stdout);

    while (!g_exit) {
        bool event_received = false;
        if (listener_wait(&listener, conninfo, notify_channel, 1000, &event_received) != 0) {
            continue;
        }
        if (event_received) {
            fw_drain_listener_events(listener, conninfo);
            continue;
        }

        if (!g_applying && g_reload_count > 0) {
            /* Drain queued reload requests one-by-one. */
            while (!g_exit && g_reload_count > 0) {
                g_reload_count--;
                g_applying = 1;

                if (fw_reload_once(conninfo) != 0) {
                    fprintf(stderr, "Firewall reload failed\n");
                }

                g_applying = 0;
            }
        }
    }

    printf("fwsvc: shutting down (pid=%d)\n", getpid());
    fflush(stdout);

    listener_free(listener);
    close(lock_fd);
    return 0;
}
