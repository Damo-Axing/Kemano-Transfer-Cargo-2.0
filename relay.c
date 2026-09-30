#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX_CLIENTS 256
#define CLIENT_TIMEOUT_SEC 60

typedef struct {
    struct sockaddr_in addr;
    time_t last_seen;
    int active;
} relay_client_t;

int
main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <listen_port> <target_ip:port>\n", argv[0]);
        return 1;
    }

    int listen_port = atoi(argv[1]);
    char target_ip[64];
    int target_port;
    sscanf(argv[2], "%63[^:]:%d", target_ip, &target_port);

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons((uint16_t)target_port);
    inet_pton(AF_INET, target_ip, &target_addr.sin_addr);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = htons((uint16_t)listen_port);

    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind");
        return 1;
    }

    printf("[relay] UDP:%d -> %s:%d\n", listen_port, target_ip, target_port);

    relay_client_t clients[MAX_CLIENTS];
    memset(clients, 0, sizeof(clients));

    uint8_t buf[65535];

    while (1) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &from_len);
        if (n <= 0) continue;

        if (from.sin_addr.s_addr == target_addr.sin_addr.s_addr &&
            from.sin_port == target_addr.sin_port) {
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].active) {
                    sendto(sock, buf, n, 0,
                           (struct sockaddr *)&clients[i].addr,
                           sizeof(clients[i].addr));
                }
            }
        } else {
            int found = 0;
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].active &&
                    memcmp(&clients[i].addr, &from, sizeof(from)) == 0) {
                    clients[i].last_seen = time(NULL);
                    found = 1;
                    break;
                }
            }
            if (!found) {
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (!clients[i].active) {
                        clients[i].addr = from;
                        clients[i].last_seen = time(NULL);
                        clients[i].active = 1;
                        break;
                    }
                }
            }
            sendto(sock, buf, n, 0,
                   (struct sockaddr *)&target_addr, sizeof(target_addr));
        }

        time_t now = time(NULL);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active &&
                (now - clients[i].last_seen) > CLIENT_TIMEOUT_SEC) {
                clients[i].active = 0;
            }
        }
    }

    return 0;
}
