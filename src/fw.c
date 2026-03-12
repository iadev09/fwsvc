#include "fw.h"
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "db.h"
#include "net.h"
#include "service.h"

struct Fw {
    Db *db; // borrowed, not owned
    char *public_if;
};

Fw *fw_init(Db *db, const char *public_if) {
    if (!db || !public_if || public_if[0] == '\0') {
        return nullptr;
    }
    Fw *fw = calloc(1, sizeof(*fw));
    if (!fw) {
        return nullptr;
    }
    fw->db = db;
    fw->public_if = strdup(public_if);
    if (!fw->public_if) {
        fw_free(fw);
        return nullptr;
    }
    return fw;
}

void fw_free(Fw *fw) {
    if (!fw) {
        return;
    }

    free(fw->public_if);
    free(fw);
}

static const char *scope_prefix(ServiceScope scope) {
    return (scope == SERVICE_SCOPE_PRIVATE) ? "Private_" : "Public_";
}

static int fw_fill_chain_names(Service *services, size_t count) {
    for (size_t i = 0; i < count; i++) {
        const char *prefix = scope_prefix(services[i].scope);
        const char *name = services[i].name ? services[i].name : "";

        size_t need = strlen(prefix) + strlen(name) + 1;
        services[i].chain_name = (char *) calloc(need, 1);
        if (!services[i].chain_name) {
            return 1;
        }

        snprintf(services[i].chain_name, need, "%s%s", prefix, name);
    }
    return 0;
}

static int fw_run_command(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *cmd = nullptr;
    // NOLINTNEXTLINE(clang-diagnostic-format-nonliteral)
    if (vasprintf(&cmd, fmt, ap) < 0) {
        va_end(ap);
        return 1;
    }
    va_end(ap);

    int rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr, "fwsvc: command failed: %s\n", cmd);
    }
    free(cmd);
    return rc == 0 ? 0 : 1;
}

static int fw_run_command_raw(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *cmd = nullptr;
    // NOLINTNEXTLINE(clang-diagnostic-format-nonliteral)
    if (vasprintf(&cmd, fmt, ap) < 0) {
        va_end(ap);
        return -1;
    }
    va_end(ap);

    int rc = system(cmd);
    free(cmd);
    return rc;
}

int fw_save_snapshot(char *path_buf, size_t path_buf_size) {
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

int fw_restore_snapshot(const char *path) {
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

static int fw_string_contains_word(const char *haystack, const char *needle) {
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

static void fw_strip_quotes_and_newline(char *value) {
    if (!value) {
        return;
    }

    value[strcspn(value, "\r\n")] = '\0';
    size_t len = strlen(value);
    if (len >= 2 && value[0] == '"' && value[len - 1] == '"') {
        memmove(value, value + 1, len - 2);
        value[len - 2] = '\0';
    }
}

int fw_detect_persist_path(char *path_buf, size_t path_buf_size) {
    if (!path_buf || path_buf_size == 0) {
        return 1;
    }

    FILE *fp = fopen("/etc/os-release", "r");
    if (!fp) {
        return 1;
    }

    char line[512];
    char id[128] = {0};
    char id_like[256] = {0};
    while (fgets(line, sizeof(line), fp)) {
        char *eq = strchr(line, '=');
        if (!eq) {
            continue;
        }
        *eq = '\0';
        char *key = line;
        char *value = eq + 1;
        fw_strip_quotes_and_newline(value);

        if (strcmp(key, "ID") == 0) {
            snprintf(id, sizeof(id), "%s", value);
        } else if (strcmp(key, "ID_LIKE") == 0) {
            snprintf(id_like, sizeof(id_like), "%s", value);
        }
    }
    fclose(fp);

    if (strcmp(id, "debian") == 0 || strcmp(id, "ubuntu") == 0 || fw_string_contains_word(id_like, "debian")) {
        snprintf(path_buf, path_buf_size, "/etc/iptables/rules.v4");
        return access("/etc/iptables", F_OK) == 0 ? 0 : 1;
    }

    if (strcmp(id, "rhel") == 0 || strcmp(id, "centos") == 0 || strcmp(id, "rocky") == 0 ||
        strcmp(id, "almalinux") == 0 || strcmp(id, "fedora") == 0 || fw_string_contains_word(id_like, "rhel") ||
        fw_string_contains_word(id_like, "fedora") || fw_string_contains_word(id_like, "centos")) {
        snprintf(path_buf, path_buf_size, "/etc/sysconfig/iptables");
        return access("/etc/sysconfig", F_OK) == 0 ? 0 : 1;
    }

    return 1;
}

int fw_persist_state(const char *path) {
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

static int fw_find_blacklist_rule(char *rule_buf, size_t rule_buf_size, const char *source) {
    if (!rule_buf || rule_buf_size == 0 || !source) {
        return -1;
    }

    FILE *fp = popen("/sbin/iptables-save -t filter", "r");
    if (!fp) {
        return -1;
    }

    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        char pattern[256];
        snprintf(pattern, sizeof(pattern), "-A BlackList -s %s ", source);
        if (strstr(line, pattern) == nullptr || strstr(line, "-j DROP") == nullptr) {
            continue;
        }

        line[strcspn(line, "\r\n")] = '\0';
        snprintf(rule_buf, rule_buf_size, "%s", line);
        found = 1;
        break;
    }

    pclose(fp);
    return found ? 0 : 1;
}

static int fw_reset_filter_table(void) {
    return fw_run_command("/sbin/iptables -w -t filter -P INPUT ACCEPT") == 0 &&
                   fw_run_command("/sbin/iptables -w -t filter -P FORWARD ACCEPT") == 0 &&
                   fw_run_command("/sbin/iptables -w -t filter -P OUTPUT ACCEPT") == 0 &&
                   fw_run_command("/sbin/iptables -w -t filter -F") == 0 &&
                   fw_run_command("/sbin/iptables -w -t filter -X") == 0
           ? 0
           : 1;
}

static int fw_reset_nat_table(void) {
    return fw_run_command("/sbin/iptables -w -t nat -F") == 0 && fw_run_command("/sbin/iptables -w -t nat -X") == 0
           ? 0
           : 1;
}

static int fw_add_input_jump(const char *ifname, const char *chain_name) {
    return fw_run_command("/sbin/iptables -w -A INPUT -i %s -m comment --comment \"fwsvc|jump|%s\" -j %s", ifname,
                          chain_name, chain_name);
}

static int fw_add_loopback_accept(void) {
    return fw_run_command("/sbin/iptables -w -A INPUT -i lo -m comment --comment \"fwsvc|base|loopback\" -j ACCEPT");
}

static int fw_add_established_accept(void) {
    return fw_run_command(
            "/sbin/iptables -w -A INPUT -m state --state ESTABLISHED,RELATED "
            "-m comment --comment \"fwsvc|base|established\" -j ACCEPT");
}

static int fw_add_final_drop(void) {
    return fw_run_command("/sbin/iptables -w -A INPUT -m comment --comment \"fwsvc|base|final-drop\" -j DROP");
}

static void fw_build_comment_arg(char *buf, size_t buf_size, const char *db_comment) {
    if (!buf || buf_size == 0) {
        return;
    }
    if (!db_comment || db_comment[0] == '\0') {
        buf[0] = '\0';
        return;
    }
    snprintf(buf, buf_size, " -m comment --comment \"%s\"", db_comment);
}

int fw_apply_blacklist_insert(const char *source, const char *comment) {
    if (!source || source[0] == '\0') {
        return 1;
    }

    char existing_rule[1024] = {0};
    if (fw_find_blacklist_rule(existing_rule, sizeof(existing_rule), source) == 0) {
        return 2;
    }

    char comment_arg[512] = {0};
    fw_build_comment_arg(comment_arg, sizeof(comment_arg), comment);
    return fw_run_command("/sbin/iptables -w -A BlackList -s %s%s -j DROP", source, comment_arg);
}

int fw_apply_blacklist_delete(const char *source, int *out_found) {
    if (out_found) {
        *out_found = 0;
    }
    if (!source || source[0] == '\0') {
        return 1;
    }

    char existing_rule[1024] = {0};
    if (fw_find_blacklist_rule(existing_rule, sizeof(existing_rule), source) != 0) {
        return 0;
    }

    char delete_rule[1024] = {0};
    snprintf(delete_rule, sizeof(delete_rule), "%s", existing_rule);
    if (strncmp(delete_rule, "-A ", 3) != 0) {
        return 1;
    }
    delete_rule[1] = 'D';
    if (out_found) {
        *out_found = 1;
    }
    return fw_run_command("/sbin/iptables -w %s", delete_rule);
}

int fw_apply_service_allowed_insert(const Service *service, const char *source, const char *comment) {
    if (!service || !service->chain_name || !source || source[0] == '\0') {
        return 1;
    }

    int inserted = 0;
    char comment_arg[512] = {0};
    fw_build_comment_arg(comment_arg, sizeof(comment_arg), comment);
    for (size_t i = 0; i < service->ip_count; i++) {
        for (size_t j = 0; j < service->tcp_port_count; j++) {
            int check_rc = fw_run_command_raw("/sbin/iptables -w -C %s -s %s -p tcp -m tcp -d %s --dport %u%s -j ACCEPT",
                                              service->chain_name, source, service->ips[i],
                                              (unsigned) service->tcp_ports[j], comment_arg);
            if (check_rc != 0) {
                if (fw_run_command("/sbin/iptables -w -A %s -s %s -p tcp -m tcp -d %s --dport %u%s -j ACCEPT",
                                   service->chain_name, source, service->ips[i], (unsigned) service->tcp_ports[j],
                                   comment_arg) != 0) {
                    return 1;
                }
                inserted = 1;
            }
        }
        for (size_t j = 0; j < service->udp_port_count; j++) {
            int check_rc = fw_run_command_raw("/sbin/iptables -w -C %s -s %s -p udp -m udp -d %s --dport %u%s -j ACCEPT",
                                              service->chain_name, source, service->ips[i],
                                              (unsigned) service->udp_ports[j], comment_arg);
            if (check_rc != 0) {
                if (fw_run_command("/sbin/iptables -w -A %s -s %s -p udp -m udp -d %s --dport %u%s -j ACCEPT",
                                   service->chain_name, source, service->ips[i], (unsigned) service->udp_ports[j],
                                   comment_arg) != 0) {
                    return 1;
                }
                inserted = 1;
            }
        }
    }

    return inserted ? 0 : 2;
}

int fw_apply_service_allowed_delete(const Service *service, const char *source, int *out_found) {
    if (out_found) {
        *out_found = 0;
    }
    if (!service || !service->chain_name || !source || source[0] == '\0') {
        return 1;
    }

    FILE *fp = popen("/sbin/iptables-save -t filter", "r");
    if (!fp) {
        return 1;
    }

    char line[1024];
    int deleted = 0;
    char chain_pattern[256];
    snprintf(chain_pattern, sizeof(chain_pattern), "-A %s -s %s ", service->chain_name, source);
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, chain_pattern) == nullptr || strstr(line, "-j ACCEPT") == nullptr) {
            continue;
        }
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "-A ", 3) != 0) {
            continue;
        }

        char delete_rule[1024];
        snprintf(delete_rule, sizeof(delete_rule), "%s", line);
        delete_rule[1] = 'D';
        if (fw_run_command("/sbin/iptables -w %s", delete_rule) == 0) {
            deleted = 1;
        } else {
            pclose(fp);
            return 1;
        }
    }
    pclose(fp);

    if (out_found) {
        *out_found = deleted;
    }
    return 0;
}

static int fw_apply_global_chain(const char *chain_name, const char *public_if, const FirewallListEntry *entries,
                                 size_t count, const char *target) {
    if (count == 0) {
        return 0;
    }

    if (fw_run_command("/sbin/iptables -w -N %s", chain_name) != 0) {
        return 1;
    }

    for (size_t i = 0; i < count; i++) {
        char comment_arg[512] = {0};
        fw_build_comment_arg(comment_arg, sizeof(comment_arg), entries[i].comment);
        if (fw_run_command("/sbin/iptables -w -A %s -s %s%s -j %s", chain_name, entries[i].source, comment_arg,
                           target) != 0) {
            return 1;
        }
    }

    return fw_add_input_jump(public_if, chain_name);
}

static int fw_apply_vpn_access(const char *public_if, const VpnTunnel *tunnels, size_t count) {
    if (!public_if || !tunnels || count == 0) {
        return 0;
    }

    if (fw_run_command("/sbin/iptables -w -N VpnAccess") != 0) {
        return 1;
    }

    for (size_t i = 0; i < count; i++) {
        if (fw_run_command("/sbin/iptables -w -A VpnAccess -i %s -p %s -m %s -d %s --dport %u "
                           "-m comment --comment \"VpnAccess\" -j ACCEPT",
                           public_if, tunnels[i].transport_protocol, tunnels[i].transport_protocol,
                           tunnels[i].address, (unsigned) tunnels[i].port) != 0) {
            return 1;
        }

        if (fw_run_command("/sbin/iptables -w -A VpnAccess -i %s "
                           "-m comment --comment \"VpnAccess\" -j ACCEPT",
                           tunnels[i].name) != 0) {
            return 1;
        }
    }

    return fw_run_command("/sbin/iptables -w -A INPUT -m comment --comment \"fwsvc|jump|VpnAccess\" -j VpnAccess");
}

static int fw_apply_vpn_nat(const char *public_if, const VpnTunnel *tunnels, size_t count) {
    if (!public_if || !tunnels || count == 0) {
        return 0;
    }

    for (size_t i = 0; i < count; i++) {
        if (strcmp(tunnels[i].nat_mode, "none") == 0) {
            continue;
        }

        const char *egress_if = tunnels[i].egress_interface[0] != '\0' ? tunnels[i].egress_interface : public_if;
        if (strcmp(tunnels[i].nat_mode, "masquerade") == 0) {
            if (fw_run_command("/sbin/iptables -w -t nat -A POSTROUTING -s %s -o %s "
                               "-m comment --comment \"VpnAccess\" -j MASQUERADE",
                               tunnels[i].network, egress_if) != 0) {
                return 1;
            }
            continue;
        }

        if (strcmp(tunnels[i].nat_mode, "snat") == 0) {
            if (tunnels[i].snat_to[0] == '\0') {
                return 1;
            }
            if (fw_run_command("/sbin/iptables -w -t nat -A POSTROUTING -s %s -o %s "
                               "-m comment --comment \"VpnAccess\" -j SNAT --to-source %s",
                               tunnels[i].network, egress_if, tunnels[i].snat_to) != 0) {
                return 1;
            }
            continue;
        }

        return 1;
    }

    return 0;
}

static int fw_append_unique_interface(char ***interfaces, size_t *count, const char *ifname) {
    for (size_t i = 0; i < *count; i++) {
        if (strcmp((*interfaces)[i], ifname) == 0) {
            return 0;
        }
    }

    char **new_interfaces = (char **) realloc((void *) *interfaces, sizeof(char *) * (*count + 1));
    if (!new_interfaces) {
        return 1;
    }
    *interfaces = new_interfaces;
    (*interfaces)[*count] = strdup(ifname);
    if (!(*interfaces)[*count]) {
        return 1;
    }
    (*count)++;
    return 0;
}

static void fw_free_interfaces(char **interfaces, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(interfaces[i]);
    }
    free((void *) interfaces);
}

static int fw_collect_service_interfaces(const Service *service, char ***out_interfaces, size_t *out_count) {
    if (!service || !out_interfaces || !out_count) {
        return 1;
    }

    *out_interfaces = nullptr;
    *out_count = 0;
    for (size_t i = 0; i < service->ip_count; i++) {
        char ifname[64] = {0};
        if (net_detect_interface_for_ip(service->ips[i], ifname, sizeof(ifname)) != 0) {
            fprintf(stderr, "fwsvc: failed to detect interface for service ip %s\n", service->ips[i]);
            fw_free_interfaces(*out_interfaces, *out_count);
            *out_interfaces = nullptr;
            *out_count = 0;
            return 1;
        }
        if (fw_append_unique_interface(out_interfaces, out_count, ifname) != 0) {
            fw_free_interfaces(*out_interfaces, *out_count);
            *out_interfaces = nullptr;
            *out_count = 0;
            return 1;
        }
    }
    return 0;
}

static int fw_apply_public_service(const Service *service) {
    if (fw_run_command("/sbin/iptables -w -N %s", service->chain_name) != 0) {
        return 1;
    }

    for (size_t i = 0; i < service->ip_count; i++) {
        for (size_t j = 0; j < service->tcp_port_count; j++) {
            if (fw_run_command("/sbin/iptables -w -A %s -p tcp -m tcp -d %s --dport %u "
                               "-m comment --comment \"%s\" -j ACCEPT",
                               service->chain_name, service->ips[i], (unsigned) service->tcp_ports[j],
                               service->chain_name) != 0) {
                return 1;
            }
        }
        for (size_t j = 0; j < service->udp_port_count; j++) {
            if (fw_run_command("/sbin/iptables -w -A %s -p udp -m udp -d %s --dport %u "
                               "-m comment --comment \"%s\" -j ACCEPT",
                               service->chain_name, service->ips[i], (unsigned) service->udp_ports[j],
                               service->chain_name) != 0) {
                return 1;
            }
        }
    }

    char **interfaces = nullptr;
    size_t interface_count = 0;
    if (fw_collect_service_interfaces(service, &interfaces, &interface_count) != 0) {
        return 1;
    }

    int rc = 0;
    for (size_t i = 0; i < interface_count; i++) {
        if (fw_add_input_jump(interfaces[i], service->chain_name) != 0) {
            rc = 1;
            break;
        }
    }
    fw_free_interfaces(interfaces, interface_count);
    return rc;
}

static int fw_apply_private_service(const Service *service) {
    if (fw_run_command("/sbin/iptables -w -N %s", service->chain_name) != 0) {
        return 1;
    }

    for (size_t i = 0; i < service->ip_count; i++) {
        for (size_t k = 0; k < service->allowed_count; k++) {
            for (size_t j = 0; j < service->tcp_port_count; j++) {
                char comment_arg[512] = {0};
                fw_build_comment_arg(comment_arg, sizeof(comment_arg), service->allowed_comments[k]);
                if (fw_run_command("/sbin/iptables -w -A %s -s %s -p tcp -m tcp -d %s --dport %u%s -j ACCEPT",
                                   service->chain_name, service->allowed_sources[k], service->ips[i],
                                   (unsigned) service->tcp_ports[j], comment_arg) != 0) {
                    return 1;
                }
            }
            for (size_t j = 0; j < service->udp_port_count; j++) {
                char comment_arg[512] = {0};
                fw_build_comment_arg(comment_arg, sizeof(comment_arg), service->allowed_comments[k]);
                if (fw_run_command("/sbin/iptables -w -A %s -s %s -p udp -m udp -d %s --dport %u%s -j ACCEPT",
                                   service->chain_name, service->allowed_sources[k], service->ips[i],
                                   (unsigned) service->udp_ports[j], comment_arg) != 0) {
                    return 1;
                }
            }
        }
    }

    char **interfaces = nullptr;
    size_t interface_count = 0;
    if (fw_collect_service_interfaces(service, &interfaces, &interface_count) != 0) {
        return 1;
    }

    int rc = 0;
    for (size_t i = 0; i < interface_count; i++) {
        if (fw_add_input_jump(interfaces[i], service->chain_name) != 0) {
            rc = 1;
            break;
        }
    }
    fw_free_interfaces(interfaces, interface_count);
    return rc;
}

int fw_apply(Fw *fw) {
    if (!fw || !fw->db || !fw->public_if) {
        return 1;
    }

    FirewallListEntry *whitelist = nullptr;
    size_t whitelist_count = 0;
    FirewallListEntry *blacklist = nullptr;
    size_t blacklist_count = 0;
    VpnTunnel *vpn_tunnels = nullptr;
    size_t vpn_tunnel_count = 0;
    Service *public_services = nullptr;
    size_t public_count = 0;
    Service *private_services = nullptr;
    size_t private_count = 0;

    if (db_fetch_global_whitelist(fw->db, &whitelist, &whitelist_count) != 0) {
        fprintf(stderr, "Failed to fetch whitelist: %s\n", db_last_error(fw->db));
        return 1;
    }

    if (db_fetch_global_blacklist(fw->db, &blacklist, &blacklist_count) != 0) {
        fprintf(stderr, "Failed to fetch blacklist: %s\n", db_last_error(fw->db));
        db_free_firewall_list(whitelist, whitelist_count);
        return 1;
    }

    if (db_fetch_services_by_scope(fw->db, SERVICE_SCOPE_PUBLIC, &public_services, &public_count) != 0) {
        fprintf(stderr, "Failed to fetch public services: %s\n", db_last_error(fw->db));
        db_free_firewall_list(whitelist, whitelist_count);
        db_free_firewall_list(blacklist, blacklist_count);
        return 1;
    }

    if (db_fetch_vpn_tunnels(fw->db, &vpn_tunnels, &vpn_tunnel_count) != 0) {
        fprintf(stderr, "Failed to fetch vpn tunnels: %s\n", db_last_error(fw->db));
        db_free_firewall_list(whitelist, whitelist_count);
        db_free_firewall_list(blacklist, blacklist_count);
        service_list_free(public_services, public_count);
        return 1;
    }

    if (db_fetch_services_by_scope(fw->db, SERVICE_SCOPE_PRIVATE, &private_services, &private_count) != 0) {
        fprintf(stderr, "Failed to fetch private services: %s\n", db_last_error(fw->db));
        db_free_firewall_list(whitelist, whitelist_count);
        db_free_firewall_list(blacklist, blacklist_count);
        db_free_vpn_tunnels(vpn_tunnels, vpn_tunnel_count);
        service_list_free(public_services, public_count);
        return 1;
    }

    if (fw_fill_chain_names(public_services, public_count) != 0 ||
        fw_fill_chain_names(private_services, private_count) != 0) {
        fprintf(stderr, "Failed to compute chain names\n");
        db_free_firewall_list(whitelist, whitelist_count);
        db_free_firewall_list(blacklist, blacklist_count);
        db_free_vpn_tunnels(vpn_tunnels, vpn_tunnel_count);
        service_list_free(public_services, public_count);
        service_list_free(private_services, private_count);
        return 1;
    }

    if (fw_reset_filter_table() != 0 || fw_reset_nat_table() != 0 || fw_add_loopback_accept() != 0 ||
        fw_add_established_accept() != 0 ||
        fw_apply_global_chain("WhiteList", fw->public_if, whitelist, whitelist_count, "ACCEPT") != 0 ||
        fw_apply_global_chain("BlackList", fw->public_if, blacklist, blacklist_count, "DROP") != 0) {
        db_free_firewall_list(whitelist, whitelist_count);
        db_free_firewall_list(blacklist, blacklist_count);
        db_free_vpn_tunnels(vpn_tunnels, vpn_tunnel_count);
        service_list_free(public_services, public_count);
        service_list_free(private_services, private_count);
        return 1;
    }

    for (size_t i = 0; i < private_count; i++) {
        if (fw_apply_private_service(&private_services[i]) != 0) {
            db_free_firewall_list(whitelist, whitelist_count);
            db_free_firewall_list(blacklist, blacklist_count);
            db_free_vpn_tunnels(vpn_tunnels, vpn_tunnel_count);
            service_list_free(public_services, public_count);
            service_list_free(private_services, private_count);
            return 1;
        }
    }

    for (size_t i = 0; i < public_count; i++) {
        if (fw_apply_public_service(&public_services[i]) != 0) {
            db_free_firewall_list(whitelist, whitelist_count);
            db_free_firewall_list(blacklist, blacklist_count);
            db_free_vpn_tunnels(vpn_tunnels, vpn_tunnel_count);
            service_list_free(public_services, public_count);
            service_list_free(private_services, private_count);
            return 1;
        }
    }

    if (fw_apply_vpn_access(fw->public_if, vpn_tunnels, vpn_tunnel_count) != 0) {
        db_free_firewall_list(whitelist, whitelist_count);
        db_free_firewall_list(blacklist, blacklist_count);
        db_free_vpn_tunnels(vpn_tunnels, vpn_tunnel_count);
        service_list_free(public_services, public_count);
        service_list_free(private_services, private_count);
        return 1;
    }

    if (fw_apply_vpn_nat(fw->public_if, vpn_tunnels, vpn_tunnel_count) != 0) {
        db_free_firewall_list(whitelist, whitelist_count);
        db_free_firewall_list(blacklist, blacklist_count);
        db_free_vpn_tunnels(vpn_tunnels, vpn_tunnel_count);
        service_list_free(public_services, public_count);
        service_list_free(private_services, private_count);
        return 1;
    }

    if (fw_add_final_drop() != 0) {
        db_free_firewall_list(whitelist, whitelist_count);
        db_free_firewall_list(blacklist, blacklist_count);
        db_free_vpn_tunnels(vpn_tunnels, vpn_tunnel_count);
        service_list_free(public_services, public_count);
        service_list_free(private_services, private_count);
        return 1;
    }

    db_free_firewall_list(whitelist, whitelist_count);
    db_free_firewall_list(blacklist, blacklist_count);
    db_free_vpn_tunnels(vpn_tunnels, vpn_tunnel_count);
    service_list_free(public_services, public_count);
    service_list_free(private_services, private_count);
    return 0;
}
