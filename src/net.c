#include "net.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool is_tunnel_interface(const char *ifname) {
    return strncmp(ifname, "tun", 3) == 0 || strncmp(ifname, "tap", 3) == 0 || strncmp(ifname, "wg", 2) == 0 ||
           strncmp(ifname, "ppp", 3) == 0;
}

static void copy_token(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0) {
        return;
    }

    size_t i = 0;
    while (src[i] != '\0' && src[i] != ' ' && src[i] != '\n' && src[i] != '\t' && i + 1 < dst_size) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

int net_detect_public_interface(char *buf, size_t buf_size) {
    if (!buf || buf_size == 0) {
        return 1;
    }

    FILE *fp = popen("ip -4 route show default", "r");
    if (!fp) {
        return 1;
    }

    char line[512];
    int rc = 1;
    while (fgets(line, sizeof(line), fp)) {
        char *dev = strstr(line, " dev ");
        if (!dev) {
            continue;
        }

        char ifname[64] = {0};
        copy_token(ifname, sizeof(ifname), dev + 5);
        if (ifname[0] == '\0' || is_tunnel_interface(ifname)) {
            continue;
        }

        copy_token(buf, buf_size, ifname);
        rc = 0;
        break;
    }

    pclose(fp);
    return rc;
}

int net_detect_interface_for_ip(const char *ip_or_cidr, char *buf, size_t buf_size) {
    if (!ip_or_cidr || !buf || buf_size == 0) {
        return 1;
    }

    char ip[64] = {0};
    copy_token(ip, sizeof(ip), ip_or_cidr);
    char *slash = strchr(ip, '/');
    if (slash) {
        *slash = '\0';
    }

    FILE *fp = popen("ip -o -4 addr show", "r");
    if (!fp) {
        return 1;
    }

    char line[512];
    int rc = 1;
    while (fgets(line, sizeof(line), fp)) {
        char ifname[64] = {0};
        char local_addr[64] = {0};
        if (sscanf(line, "%*d: %63[^ ] %*s %63s", ifname, local_addr) != 2) {
            continue;
        }

        char *local_slash = strchr(local_addr, '/');
        if (local_slash) {
            *local_slash = '\0';
        }

        if (strcmp(local_addr, ip) != 0) {
            continue;
        }

        copy_token(buf, buf_size, ifname);
        rc = 0;
        break;
    }

    pclose(fp);
    return rc;
}
