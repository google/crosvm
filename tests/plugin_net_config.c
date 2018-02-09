/*
 * Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "crosvm.h"

/*
 * These must match the network arguments supplied to the plugin in plugins.rs.
 * IPv4 addresses here are in host-native byte order.
 */
const uint32_t expected_ip = 0x64735c05; // 100.115.92.5
const uint32_t expected_netmask = 0xfffffffc; // 255.255.255.252
const uint8_t expected_mac[] = {0xde, 0x21, 0xe8, 0x47, 0x6b, 0x6a};

int main(int argc, char** argv) {
    struct crosvm *crosvm;
    struct crosvm_net_config net_config;
    int ret = crosvm_connect(&crosvm);

    if (ret) {
        fprintf(stderr, "failed to connect to crosvm: %d\n", ret);
        return 1;
    }

    ret = crosvm_net_get_config(crosvm, &net_config);
    if (ret) {
        fprintf(stderr, "failed to get crosvm net config: %d\n", ret);
        return 1;
    }

    if (net_config.tap_fd < 0) {
        fprintf(stderr, "fd %d is < 0\n", net_config.tap_fd);
        return 1;
    }

    unsigned int features;
    if (ioctl(net_config.tap_fd, TUNGETFEATURES, &features) < 0) {
        fprintf(stderr,
                "failed to read tap features: %s\n",
                strerror(errno));
        return 1;
    }

    if (net_config.host_ip != htonl(expected_ip)) {
        char ip_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &net_config.host_ip, ip_addr, sizeof(ip_addr));
        fprintf(stderr, "ip %s != 100.115.92.5\n", ip_addr);
        return 1;
    }

    if (net_config.netmask != htonl(expected_netmask)) {
        char netmask[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &net_config.netmask, netmask, sizeof(netmask));
        fprintf(stderr, "netmask %s != 255.255.255.252\n", netmask);
        return 1;
    }

    if (memcmp(net_config.host_mac_address,
               expected_mac,
               sizeof(expected_mac)) != 0) {
        fprintf(stderr,
                "mac %02X:%02X:%02X:%02X:%02X:%02X != de:21:e8:47:6b:6a\n",
                net_config.host_mac_address[0],
                net_config.host_mac_address[1],
                net_config.host_mac_address[2],
                net_config.host_mac_address[3],
                net_config.host_mac_address[4],
                net_config.host_mac_address[5]);
        return 1;
    }

    return 0;
}
