#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "ktc.h"
#include "packets.h"
#include <stdint.h>

typedef struct {
    uint8_t handshake_key[HANDSHAKE_KEY_SIZE];
    uint8_t legend_key[LEGEND_KEY_SIZE];
    uint8_t client_priv[X25519_KEY_SIZE];
    uint8_t client_pub[X25519_KEY_SIZE];
    uint64_t timestamp;
    uint8_t legend_sig[LEGEND_SIG_SIZE];
} client_handshake_t;

typedef struct {
    uint8_t handshake_key[HANDSHAKE_KEY_SIZE];
    uint8_t server_priv[X25519_KEY_SIZE];
    uint8_t server_pub[X25519_KEY_SIZE];
    uint8_t server_proof[SERVER_PROOF_SIZE];
    uint64_t echoed_timestamp;
    uint8_t client_pub[X25519_KEY_SIZE];
    uint8_t session_key[SESSION_KEY_SIZE];
} server_handshake_t;

typedef struct {
    uint8_t session_key[SESSION_KEY_SIZE];
    uint64_t mask_profile;
} client_session_t;

int handshake_client_prepare(const uint8_t root_key[ROOT_KEY_SIZE],
                             const uint8_t tpm_quote[TPM_QUOTE_SIZE],
                             const uint8_t hw_mac_proof[HW_MAC_PROOF_SIZE],
                             client_handshake_t *state);

int handshake_client_build_ktc0(client_handshake_t *state,
                                const uint8_t tpm_quote[TPM_QUOTE_SIZE],
                                const uint8_t hw_mac_proof[HW_MAC_PROOF_SIZE],
                                uint8_t out[KTC0_SIZE]);

int handshake_client_process_ktca(client_handshake_t *state,
                                  const uint8_t data[KTCA_SIZE],
                                  client_session_t *session);

int handshake_server_process_ktc0(const uint8_t handshake_key[HANDSHAKE_KEY_SIZE],
                                  const uint8_t legend_key[LEGEND_KEY_SIZE],
                                  const uint8_t data[KTC0_SIZE],
                                  server_handshake_t *state);

int handshake_server_build_ktca(server_handshake_t *state,
                                uint64_t mask_profile,
                                uint8_t out[KTCA_SIZE]);

#endif /* HANDSHAKE_H */
