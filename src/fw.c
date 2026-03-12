#include "fw.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static const char *fw_rule_comment(const char *db_comment, const char *fallback) {
    return db_comment && db_comment[0] != '\0' ? db_comment : fallback;
}

static int fw_apply_global_chain(const char *chain_name, const char *public_if, const FirewallListEntry *entries,
                                 size_t count, const char *target, const char *fallback_comment) {
    if (count == 0) {
        return 0;
    }

    if (fw_run_command("/sbin/iptables -w -N %s", chain_name) != 0) {
        return 1;
    }

    for (size_t i = 0; i < count; i++) {
        if (fw_run_command("/sbin/iptables -w -A %s -s %s -m comment --comment \"%s\" -j %s", chain_name,
                           entries[i].source, fw_rule_comment(entries[i].comment, fallback_comment), target) != 0) {
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
                if (fw_run_command("/sbin/iptables -w -A %s -s %s -p tcp -m tcp -d %s --dport %u "
                                   "-m comment --comment \"%s\" -j ACCEPT",
                                   service->chain_name, service->allowed_sources[k], service->ips[i],
                                   (unsigned) service->tcp_ports[j],
                                   fw_rule_comment(service->allowed_comments[k], service->chain_name)) != 0) {
                    return 1;
                }
            }
            for (size_t j = 0; j < service->udp_port_count; j++) {
                if (fw_run_command("/sbin/iptables -w -A %s -s %s -p udp -m udp -d %s --dport %u "
                                   "-m comment --comment \"%s\" -j ACCEPT",
                                   service->chain_name, service->allowed_sources[k], service->ips[i],
                                   (unsigned) service->udp_ports[j],
                                   fw_rule_comment(service->allowed_comments[k], service->chain_name)) != 0) {
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
        fw_apply_global_chain("WhiteList", fw->public_if, whitelist, whitelist_count, "ACCEPT", "WhiteList") != 0 ||
        fw_apply_global_chain("BlackList", fw->public_if, blacklist, blacklist_count, "DROP", "BlackList") != 0) {
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
