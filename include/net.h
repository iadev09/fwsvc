#ifndef FWSVC_NET_H
#define FWSVC_NET_H

#include <stddef.h>

int net_detect_public_interface(char *buf, size_t buf_size);
int net_detect_interface_for_ip(const char *ip_or_cidr, char *buf, size_t buf_size);

#endif /* FWSVC_NET_H */
