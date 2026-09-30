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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

int
main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <server_ip> <port> <keys_file>\n", argv[0]);
        return 1;
    }

    if (crypto_init() != 0) {
        fprintf(stderr, "FATAL: crypto_init failed\n");
        return 1;
    }

    client_keys_t keys;
    if (utils_load_keys(argv[3], &keys) != 0) {
        fprintf(stderr, "Cannot load keys from %s\n", argv[3]);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((uint16_t)atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &server_addr.sin_addr);

    uint8_t tpm_quote[TPM_QUOTE_SIZE] = {0};
    uint8_t hw_mac_proof[HW_MAC_PROOF_SIZE] = {0};

    client_handshake_t hs;
    if (handshake_client_prepare(keys.root_key, tpm_quote, hw_mac_proof, &hs) != 0) {
        fprintf(stderr, "Handshake prepare failed\n");
        return 1;
    }

    uint8_t ktc0[KTC0_SIZE];
    handshake_client_build_ktc0(&hs, tpm_quote, hw_mac_proof, ktc0);

    printf("[client] Sending KTC0 (%d bytes)\n", KTC0_SIZE);
    sendto(sock, ktc0, KTC0_SIZE, 0,
           (struct sockaddr *)&server_addr, sizeof(server_addr));

    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t ktca[KTCA_SIZE];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    ssize_t n = recvfrom(sock, ktca, KTCA_SIZE, 0,
                         (struct sockaddr *)&from_addr, &from_len);

    if (n != KTCA_SIZE) {
        fprintf(stderr, "[client] No valid KTCA received\n");
        close(sock);
        return 1;
    }

    client_session_t session;
    if (handshake_client_process_ktca(&hs, ktca, &session) != 0) {
        fprintf(stderr, "[client] KTCA verification failed\n");
        close(sock);
        return 1;
    }

    printf("[client] Connected. Mask profile: %lu\n", session.mask_profile);

    session_t sess;
    session_init(&sess, session.session_key, session.mask_profile);

    const char *msg = "Hello, KTC!";
    uint8_t frame_buf[2048];
    size_t frame_len;

    if (session_send_data(&sess, STREAM_DATA_MIN,
                          (const uint8_t *)msg, strlen(msg), 0,
                          frame_buf, &frame_len, sizeof(frame_buf)) == 0) {
        sendto(sock, frame_buf, frame_len, 0,
               (struct sockaddr *)&server_addr, sizeof(server_addr));
        printf("[client] Sent %zu bytes\n", frame_len);
    }

    uint8_t halt_buf[256];
    size_t halt_len;
    if (session_send_halt(&sess, halt_buf, &halt_len, sizeof(halt_buf)) == 0) {
        sendto(sock, halt_buf, halt_len, 0,
               (struct sockaddr *)&server_addr, sizeof(server_addr));
    }

    sodium_memzero(&hs, sizeof(hs));
    sodium_memzero(&sess, sizeof(sess));
    sodium_memzero(&keys, sizeof(keys));

    close(sock);
    return 0;
}
