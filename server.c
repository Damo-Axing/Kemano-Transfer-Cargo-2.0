#include "ktc.h"
#include "crypto.h"
#include "packets.h"
#include "handshake.h"
#include "session.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>

typedef struct {
    char client_id[64];
    uint8_t handshake_key[HANDSHAKE_KEY_SIZE];
    uint8_t legend_key[LEGEND_KEY_SIZE];
} client_entry_t;

typedef struct {
    struct sockaddr_in addr;
    session_t session;
    time_t created_at;
    int active;
} session_entry_t;

static struct {
    int sock;
    uint16_t port;
    client_entry_t clients[MAX_CLIENTS];
    int client_count;
    session_entry_t sessions[MAX_SESSIONS];
    int session_count;
    uint64_t default_mask_profile;
    volatile int running;
    pthread_mutex_t lock;
} server;

static void *recv_thread(void *arg);
static void *tick_thread(void *arg);
static void handle_packet(const uint8_t *data, size_t len,
                          struct sockaddr_in *addr);
static int load_clients(const char *path);
static void signal_handler(int sig);

int
main(int argc, char **argv)
{
    struct sockaddr_in addr;
    pthread_t recv_tid, tick_tid;
    int opt = 1;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <port> <clients_dir>\n", argv[0]);
        return 1;
    }

    if (crypto_init() != 0) {
        fprintf(stderr, "FATAL: crypto_init failed\n");
        return 1;
    }

    server.port = (uint16_t)atoi(argv[1]);
    server.default_mask_profile = PROFILE_RAW;
    server.running = 0;
    server.client_count = 0;
    server.session_count = 0;
    pthread_mutex_init(&server.lock, NULL);

    if (load_clients(argv[2]) != 0) {
        fprintf(stderr, "FATAL: cannot load clients from %s\n", argv[2]);
        return 1;
    }
    printf("[server] Loaded %d clients\n", server.client_count);

    server.sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (server.sock < 0) {
        perror("socket");
        return 1;
    }

    setsockopt(server.sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(server.port);

    if (bind(server.sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server.sock);
        return 1;
    }

    printf("[server] Listening on UDP:%d\n", server.port);
    printf("[server] Blind handshake enabled\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    server.running = 1;

    pthread_create(&recv_tid, NULL, recv_thread, NULL);
    pthread_create(&tick_tid, NULL, tick_thread, NULL);

    pthread_join(recv_tid, NULL);
    pthread_join(tick_tid, NULL);

    close(server.sock);
    pthread_mutex_destroy(&server.lock);

    return 0;
}

static void *
recv_thread(void *arg)
{
    uint8_t buf[RECV_BUF_SIZE];
    struct sockaddr_in addr;
    socklen_t addr_len;
    ssize_t n;

    (void)arg;

    while (server.running) {
        addr_len = sizeof(addr);
        n = recvfrom(server.sock, buf, RECV_BUF_SIZE, 0,
                     (struct sockaddr *)&addr, &addr_len);

        if (n < 0) {
            if (errno == EINTR) continue;
            continue;
        }

        if (n == 0) continue;

        handle_packet(buf, (size_t)n, &addr);
    }

    return NULL;
}

static void *
tick_thread(void *arg)
{
    (void)arg;

    while (server.running) {
        usleep(100000);

        pthread_mutex_lock(&server.lock);

        for (int i = 0; i < server.session_count; i++) {
            if (!server.sessions[i].active) continue;

            session_t *s = &server.sessions[i].session;

            if (session_is_timed_out(s)) {
                s->closed = 1;
                server.sessions[i].active = 0;
            }

            if (s->closed) {
                server.sessions[i].active = 0;
            }
        }

        int new_count = 0;
        for (int i = 0; i < server.session_count; i++) {
            if (server.sessions[i].active) {
                if (new_count != i) {
                    server.sessions[new_count] = server.sessions[i];
                }
                new_count++;
            }
        }
        server.session_count = new_count;

        pthread_mutex_unlock(&server.lock);
    }

    return NULL;
}

static void
handle_packet(const uint8_t *data, size_t len,
              struct sockaddr_in *addr)
{
    pthread_mutex_lock(&server.lock);

    for (int i = 0; i < server.session_count; i++) {
        if (!server.sessions[i].active) continue;
        if (memcmp(&server.sessions[i].addr, addr, sizeof(*addr)) == 0) {
            session_t *s = &server.sessions[i].session;

            for (uint8_t sid = 0; sid < MAX_STREAMS; sid++) {
                uint32_t expected_seq = s->streams[sid].next_seq;
                cargo_frame_t frame;

                if (session_receive(s, data, len, sid, expected_seq, &frame) == 0) {
                    s->streams[sid].next_seq = frame.cargo_seq + 1;
                    if (frame.payload) free(frame.payload);
                    break;
                }
            }

            pthread_mutex_unlock(&server.lock);
            return;
        }
    }

    if (len == KTC0_SIZE) {
        for (int i = 0; i < server.client_count; i++) {
            server_handshake_t hs;
            int ret;

            ret = handshake_server_process_ktc0(
                server.clients[i].handshake_key,
                server.clients[i].legend_key,
                data, &hs);

            if (ret == 0) {
                printf("[server] Client '%s' authenticated\n",
                       server.clients[i].client_id);

                uint8_t ktca[KTCA_SIZE];
                handshake_server_build_ktca(&hs, server.default_mask_profile, ktca);

                sendto(server.sock, ktca, KTCA_SIZE, 0,
                       (struct sockaddr *)addr, sizeof(*addr));

                if (server.session_count < MAX_SESSIONS) {
                    int idx = server.session_count++;
                    server.sessions[idx].addr = *addr;
                    session_init(&server.sessions[idx].session,
                                 hs.session_key,
                                 server.default_mask_profile);
                    server.sessions[idx].created_at = time(NULL);
                    server.sessions[idx].active = 1;
                }

                sodium_memzero(&hs, sizeof(hs));

                pthread_mutex_unlock(&server.lock);
                return;
            }
        }
    }

    pthread_mutex_unlock(&server.lock);
}

static int
load_clients(const char *path)
{
    uint8_t test_root[ROOT_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };

    if (server.client_count >= MAX_CLIENTS) return -1;

    int idx = server.client_count++;
    snprintf(server.clients[idx].client_id, 64, "test-client");
    crypto_derive_handshake_key(test_root, server.clients[idx].handshake_key);
    crypto_derive_legend_key(test_root, server.clients[idx].legend_key);

    printf("[server] WARNING: using hardcoded test key from %s\n", path);
    return 0;
}

static void
signal_handler(int sig)
{
    (void)sig;
    server.running = 0;
}
