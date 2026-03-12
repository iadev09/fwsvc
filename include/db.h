#ifndef DB_H
#define DB_H

#include <stdbool.h>
#include <stddef.h>
#include "service.h"

typedef struct Db Db;

typedef struct FirewallListEntry {
    char *source;
    char *comment;
} FirewallListEntry;

typedef struct VpnTunnel {
    char *name;
    char *transport_protocol;
    uint16_t port;
    char *address;
    char *network;
    char *nat_mode;
    char *snat_to;
    char *egress_interface;
} VpnTunnel;

Db *db_open(const char *conninfo);
void db_close(Db *db);

bool db_ping(Db *db);
const char *db_last_error(Db *db);

/* Returns 0 on success, non-zero on error.
   scope must be "public" or "private".
   On success: *out_services is malloc'd array of Service.
   Caller must free using service_list_free(). */
int db_fetch_services_by_scope(Db *db, ServiceScope scope, Service **out_services, size_t *out_count);
int db_fetch_global_whitelist(Db *db, FirewallListEntry **out_list, size_t *out_count);
int db_fetch_global_blacklist(Db *db, FirewallListEntry **out_list, size_t *out_count);
int db_fetch_blacklist_comment(Db *db, const char *source, char **out_comment);
int db_fetch_service_allowed_comment(Db *db, int service_id, const char *source, char **out_comment);
int db_fetch_service_by_id(Db *db, int service_id, Service *out_service);
int db_fetch_vpn_tunnels(Db *db, VpnTunnel **out_tunnels, size_t *out_count);


/* Helper to free what db_fetch_chains_by_scope returns */
void db_free_string_list(char **list, size_t count);
void db_free_firewall_list(FirewallListEntry *list, size_t count);
void db_free_vpn_tunnels(VpnTunnel *tunnels, size_t count);

#endif
