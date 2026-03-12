#ifndef FWSVC_FW_H
#define FWSVC_FW_H

typedef struct Db Db;

typedef struct Fw Fw;

Fw *fw_init(Db *db, const char *public_if);
void fw_free(Fw *fw);

int fw_apply(Fw *fw);

#endif /* FWSVC_FW_H */
