#ifndef FWSVC_FW_H
#define FWSVC_FW_H

#include "service.h"
#include <stddef.h>

typedef struct Db Db;

typedef struct Fw Fw;

Fw *fw_init(Db *db, const char *public_if);
void fw_free(Fw *fw);

int fw_apply(Fw *fw);
int fw_apply_blacklist_insert(const char *source, const char *comment);
int fw_apply_blacklist_delete(const char *source, int *out_found);
int fw_apply_service_allowed_insert(const Service *service, const char *source, const char *comment);
int fw_apply_service_allowed_delete(const Service *service, const char *source, int *out_found);
int fw_save_snapshot(char *path_buf, size_t path_buf_size);
int fw_restore_snapshot(const char *path);
int fw_detect_persist_path(char *path_buf, size_t path_buf_size);
int fw_persist_state(const char *path);

#endif /* FWSVC_FW_H */
