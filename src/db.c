#include "db.h"
#include <libpq-fe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Db {
    PGconn *conn;
    const char *last_err; // points to libpq internal buffer
};

Db *db_open(const char *conninfo) {
    Db *db = calloc(1, sizeof(*db));
    if (!db) {
        return nullptr;
    }
    db->conn = PQconnectdb(conninfo);
    if (PQstatus(db->conn) != CONNECTION_OK) {
        db->last_err = PQerrorMessage(db->conn);
        return db; // caller can read error then close
    }
    return db;
}

void db_close(Db *db) {
    if (!db) {
        return;
    }
    if (db->conn) {
        PQfinish(db->conn);
    }
    free(db);
}

bool db_ping(Db *db) {
    if (db == nullptr || db->conn == nullptr) {
        return false;
    }

    return PQstatus(db->conn) == CONNECTION_OK;
}

const char *db_last_error(Db *db) {
    return db && db->last_err ? db->last_err : "unknown";
}

static void db_set_last_err(Db *db) {
    db->last_err = PQerrorMessage(db->conn);
}

void db_free_string_list(char **list, size_t count) {
    if (!list) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free(list[i]);
    }
    free((void *) list);
}

void db_free_firewall_list(FirewallListEntry *list, size_t count) {
    if (!list) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free(list[i].source);
        free(list[i].comment);
    }
    free(list);
}

static const char *db_scope_to_str(ServiceScope scope) {
    switch (scope) {
        case SERVICE_SCOPE_PRIVATE:
            return "private";
        case SERVICE_SCOPE_PUBLIC:
        default:
            return "public";
    }
}

static int db_fetch_string_list_for_service(Db *db, int service_id, const char *query, char ***out_list,
                                            size_t *out_count) {
    if (!db || !db->conn || !query || !out_list || !out_count) {
        return 1;
    }
    *out_list = NULL;
    *out_count = 0;

    char idbuf[32];
    snprintf(idbuf, sizeof(idbuf), "%d", service_id);
    const char *params[1] = {idbuf};

    PGresult *res = PQexecParams(db->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (!res) {
        db_set_last_err(db);
        return 1;
    }
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        db_set_last_err(db);
        PQclear(res);
        return 1;
    }

    int row_count = PQntuples(res);
    if (row_count <= 0) {
        PQclear(res);
        return 0;
    }
    size_t rows = (size_t) row_count;

    char **list = (char **) calloc(rows, sizeof(char *));
    if (!list) {
        PQclear(res);
        return 1;
    }

    for (size_t i = 0; i < rows; i++) {
        const char *val = PQgetvalue(res, (int) i, 0);
        list[i] = strdup(val ? val : "");
        if (!list[i]) {
            db_free_string_list(list, i);
            PQclear(res);
            return 1;
        }
    }

    PQclear(res);
    *out_list = list;
    *out_count = rows;
    return 0;
}

static int db_fetch_firewall_list(Db *db, const char *query, FirewallListEntry **out_list, size_t *out_count) {
    if (!db || !db->conn || !query || !out_list || !out_count) {
        return 1;
    }
    *out_list = nullptr;
    *out_count = 0;

    PGresult *res = PQexecParams(db->conn, query, 0, nullptr, nullptr, nullptr, nullptr, 0);
    if (!res) {
        db_set_last_err(db);
        return 1;
    }
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        db_set_last_err(db);
        PQclear(res);
        return 1;
    }

    int row_count = PQntuples(res);
    if (row_count <= 0) {
        PQclear(res);
        return 0;
    }
    size_t rows = (size_t) row_count;

    FirewallListEntry *list = calloc(rows, sizeof(*list));
    if (!list) {
        PQclear(res);
        return 1;
    }

    for (size_t i = 0; i < rows; i++) {
        const char *sourcev = PQgetvalue(res, (int) i, 0);
        const char *commentv = PQgetvalue(res, (int) i, 1);
        list[i].source = strdup(sourcev ? sourcev : "");
        list[i].comment = strdup(commentv ? commentv : "");
        if (!list[i].source || !list[i].comment) {
            db_free_firewall_list(list, i + 1);
            PQclear(res);
            return 1;
        }
    }

    PQclear(res);
    *out_list = list;
    *out_count = rows;
    return 0;
}

static int db_fetch_u16_list_for_service(Db *db, int service_id, const char *query, uint16_t **out_list,
                                         size_t *out_count) {
    if (!db || !db->conn || !query || !out_list || !out_count) {
        return 1;
    }
    *out_list = NULL;
    *out_count = 0;

    char idbuf[32];
    snprintf(idbuf, sizeof(idbuf), "%d", service_id);
    const char *params[1] = {idbuf};

    PGresult *res = PQexecParams(db->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (!res) {
        db_set_last_err(db);
        return 1;
    }
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        db_set_last_err(db);
        PQclear(res);
        return 1;
    }

    int row_count = PQntuples(res);
    if (row_count <= 0) {
        PQclear(res);
        return 0;
    }
    size_t rows = (size_t) row_count;

    uint16_t *list = calloc(rows, sizeof(uint16_t));
    if (!list) {
        PQclear(res);
        return 1;
    }

    for (size_t i = 0; i < rows; i++) {
        const char *val = PQgetvalue(res, (int) i, 0);
        if (!val) {
            free(list);
            PQclear(res);
            return 1;
        }
        long p = strtol(val, nullptr, 10);
        if (p < 0 || p > 65535) {
            free(list);
            PQclear(res);
            return 1;
        }
        list[i] = (uint16_t) p;
    }

    PQclear(res);
    *out_list = list;
    *out_count = rows;
    return 0;
}

static int db_fetch_allowed_list_for_service(Db *db, int service_id, Service *service) {
    if (!db || !db->conn || !service) {
        return 1;
    }

    const char *query =
            "SELECT source::text, COALESCE(comment, '') "
            "FROM firewall.service_allowed "
            "WHERE service_id = $1 "
            "ORDER BY created_at ASC, id ASC";

    char idbuf[32];
    snprintf(idbuf, sizeof(idbuf), "%d", service_id);
    const char *params[1] = {idbuf};
    PGresult *res = PQexecParams(db->conn, query, 1, nullptr, params, nullptr, nullptr, 0);
    if (!res) {
        db_set_last_err(db);
        return 1;
    }
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        db_set_last_err(db);
        PQclear(res);
        return 1;
    }

    int row_count = PQntuples(res);
    if (row_count <= 0) {
        PQclear(res);
        return 0;
    }
    size_t rows = (size_t) row_count;

    service->allowed_sources = (char **) calloc(rows, sizeof(char *));
    service->allowed_comments = (char **) calloc(rows, sizeof(char *));
    if (!service->allowed_sources || !service->allowed_comments) {
        PQclear(res);
        return 1;
    }

    for (size_t i = 0; i < rows; i++) {
        const char *sourcev = PQgetvalue(res, (int) i, 0);
        const char *commentv = PQgetvalue(res, (int) i, 1);
        service->allowed_sources[i] = strdup(sourcev ? sourcev : "");
        service->allowed_comments[i] = strdup(commentv ? commentv : "");
        if (!service->allowed_sources[i] || !service->allowed_comments[i]) {
            PQclear(res);
            return 1;
        }
    }

    PQclear(res);
    service->allowed_count = rows;
    return 0;
}

static int db_init_service_from_row(Service *service, ServiceScope scope, PGresult *res, int row_index, int *out_id) {
    if (!service || !res || !out_id) {
        return 1;
    }

    const char *idv = PQgetvalue(res, row_index, 0);
    const char *namev = PQgetvalue(res, row_index, 1);
    const char *logv = PQgetvalue(res, row_index, 2);

    *out_id = (int) strtol(idv ? idv : "0", nullptr, 10);

    service->scope = scope;
    service->name = strdup(namev ? namev : "");
    service->chain_name = nullptr; /* calculated by fw layer */
    service->logging = logv != nullptr && strcmp(logv, "t") == 0;

    return service->name ? 0 : 1;
}

static int db_populate_service_relations(Db *db, int service_id, Service *service, ServiceScope scope) {
    if (!db || !service) {
        return 1;
    }

    const char *q_ips =
            "SELECT address::text "
            "FROM firewall.service_ips "
            "WHERE service_id = $1 "
            "ORDER BY id ASC";
    if (db_fetch_string_list_for_service(db, service_id, q_ips, &service->ips, &service->ip_count) != 0) {
        return 1;
    }

    const char *q_tcp =
            "SELECT port::text "
            "FROM firewall.service_ports "
            "WHERE service_id = $1 AND transport_protocol = 'tcp' "
            "ORDER BY id ASC";
    if (db_fetch_u16_list_for_service(db, service_id, q_tcp, &service->tcp_ports, &service->tcp_port_count) != 0) {
        return 1;
    }

    const char *q_udp =
            "SELECT port::text "
            "FROM firewall.service_ports "
            "WHERE service_id = $1 AND transport_protocol = 'udp' "
            "ORDER BY id ASC";
    if (db_fetch_u16_list_for_service(db, service_id, q_udp, &service->udp_ports, &service->udp_port_count) != 0) {
        return 1;
    }

    if (scope == SERVICE_SCOPE_PRIVATE && db_fetch_allowed_list_for_service(db, service_id, service) != 0) {
        return 1;
    }

    return 0;
}


int db_fetch_services_by_scope(Db *db, ServiceScope scope, Service **out_services, size_t *out_count) {
    if (!out_services || !out_count) {
        return 1;
    }
    *out_services = nullptr;
    *out_count = 0;
    if (!db || !db->conn) {
        return 1;
    }

    const char *scope_str = db_scope_to_str(scope);

    const char *query =
            "SELECT id, name, logging "
            "FROM firewall.services "
            "WHERE scope = $1 AND enabled = true "
            "ORDER BY created_at ASC, id ASC";

    const char *params[1] = {scope_str};

    PGresult *res = PQexecParams(db->conn, query, 1, nullptr, params, nullptr, nullptr, 0);
    if (!res) {
        db_set_last_err(db);
        return 1;
    }
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        db_set_last_err(db);
        PQclear(res);
        return 1;
    }

    int row_count = PQntuples(res);
    if (row_count <= 0) {
        PQclear(res);
        return 0;
    }
    size_t rows = (size_t) row_count;

    Service *services = calloc(rows, sizeof(Service));
    if (!services) {
        PQclear(res);
        return 1;
    }

    for (size_t i = 0; i < rows; i++) {
        int service_id = 0;
        if (db_init_service_from_row(&services[i], scope, res, (int) i, &service_id) != 0) {
            service_list_free(services, i);
            PQclear(res);
            return 1;
        }

        if (db_populate_service_relations(db, service_id, &services[i], scope) != 0) {
            service_list_free(services, i + 1);
            PQclear(res);
            return 1;
        }
    }

    PQclear(res);
    *out_services = services;
    *out_count = rows;
    return 0;
}

int db_fetch_global_whitelist(Db *db, FirewallListEntry **out_list, size_t *out_count) {
    const char *query =
            "SELECT source::text, COALESCE(comment, '') "
            "FROM firewall.global_list_entries "
            "WHERE kind = 'whitelist' "
            "ORDER BY created_at ASC, id ASC";
    return db_fetch_firewall_list(db, query, out_list, out_count);
}

int db_fetch_global_blacklist(Db *db, FirewallListEntry **out_list, size_t *out_count) {
    const char *query =
            "SELECT source::text, COALESCE(comment, '') "
            "FROM firewall.global_list_entries "
            "WHERE kind = 'blacklist' "
            "ORDER BY created_at ASC, id ASC";
    return db_fetch_firewall_list(db, query, out_list, out_count);
}

void db_free_vpn_tunnels(VpnTunnel *tunnels, size_t count) {
    if (!tunnels) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free(tunnels[i].name);
        free(tunnels[i].transport_protocol);
        free(tunnels[i].address);
        free(tunnels[i].network);
        free(tunnels[i].nat_mode);
        free(tunnels[i].snat_to);
        free(tunnels[i].egress_interface);
    }
    free(tunnels);
}

int db_fetch_vpn_tunnels(Db *db, VpnTunnel **out_tunnels, size_t *out_count) {
    if (!db || !db->conn || !out_tunnels || !out_count) {
        return 1;
    }

    *out_tunnels = nullptr;
    *out_count = 0;

    const char *query =
            "SELECT name, transport_protocol::text, port::text, address::text, network::text, "
            "nat_mode::text, COALESCE(snat_to::text, ''), COALESCE(egress_interface, '') "
            "FROM firewall.vpn_tunnels "
            "WHERE enabled = true "
            "ORDER BY created_at ASC, id ASC";

    PGresult *res = PQexecParams(db->conn, query, 0, nullptr, nullptr, nullptr, nullptr, 0);
    if (!res) {
        db_set_last_err(db);
        return 1;
    }
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        db_set_last_err(db);
        PQclear(res);
        return 1;
    }

    int row_count = PQntuples(res);
    if (row_count <= 0) {
        PQclear(res);
        return 0;
    }
    size_t rows = (size_t) row_count;

    VpnTunnel *tunnels = calloc(rows, sizeof(*tunnels));
    if (!tunnels) {
        PQclear(res);
        return 1;
    }

    for (size_t i = 0; i < rows; i++) {
        const char *namev = PQgetvalue(res, (int) i, 0);
        const char *protocolv = PQgetvalue(res, (int) i, 1);
        const char *portv = PQgetvalue(res, (int) i, 2);
        const char *addressv = PQgetvalue(res, (int) i, 3);
        const char *networkv = PQgetvalue(res, (int) i, 4);
        const char *natmodev = PQgetvalue(res, (int) i, 5);
        const char *snattov = PQgetvalue(res, (int) i, 6);
        const char *egressifv = PQgetvalue(res, (int) i, 7);

        tunnels[i].name = strdup(namev ? namev : "");
        tunnels[i].transport_protocol = strdup(protocolv ? protocolv : "");
        tunnels[i].address = strdup(addressv ? addressv : "");
        tunnels[i].network = strdup(networkv ? networkv : "");
        tunnels[i].nat_mode = strdup(natmodev ? natmodev : "");
        tunnels[i].snat_to = strdup(snattov ? snattov : "");
        tunnels[i].egress_interface = strdup(egressifv ? egressifv : "");
        if (!tunnels[i].name || !tunnels[i].transport_protocol || !tunnels[i].address || !tunnels[i].network ||
            !tunnels[i].nat_mode || !tunnels[i].snat_to || !tunnels[i].egress_interface) {
            db_free_vpn_tunnels(tunnels, i + 1);
            PQclear(res);
            return 1;
        }

        long port = strtol(portv ? portv : "0", nullptr, 10);
        if (port <= 0 || port > 65535) {
            db_free_vpn_tunnels(tunnels, i + 1);
            PQclear(res);
            return 1;
        }
        tunnels[i].port = (uint16_t) port;
    }

    PQclear(res);
    *out_tunnels = tunnels;
    *out_count = rows;
    return 0;
}
