#ifndef PACKETS_H
#define PACKETS_H

#include "ktc.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t timestamp;
    uint8_t client_x25519[X25519_KEY_SIZE];
    uint8_t tpm_quote[TPM_QUOTE_SIZE];
    uint8_t hw_mac_proof[HW_MAC_PROOF_SIZE];
    uint8_t legend_sig[LEGEND_SIG_SIZE];
} ktc0_inner_t;

int packets_build_ktc0(const uint8_t handshake_key[HANDSHAKE_KEY_SIZE],
                       const ktc0_inner_t *inner,
                       uint8_t out[KTC0_SIZE]);

int packets_parse_ktc0(const uint8_t handshake_key[HANDSHAKE_KEY_SIZE],
                       const uint8_t data[KTC0_SIZE],
                       ktc0_inner_t *out);

typedef struct {
    uint64_t echoed_timestamp;
    uint8_t server_x25519[X25519_KEY_SIZE];
    uint8_t server_proof[SERVER_PROOF_SIZE];
    uint64_t mask_profile;
} ktca_inner_t;

int packets_build_ktca(const uint8_t handshake_key[HANDSHAKE_KEY_SIZE],
                       const ktca_inner_t *inner,
                       uint8_t out[KTCA_SIZE]);

int packets_parse_ktca(const uint8_t handshake_key[HANDSHAKE_KEY_SIZE],
                       const uint8_t data[KTCA_SIZE],
                       ktca_inner_t *out);

typedef struct {
    uint32_t cargo_seq;
    uint8_t stream_id;
    uint8_t flags;
    uint32_t payload_len;
    uint8_t *payload;
} cargo_frame_t;

int packets_build_cargo(const uint8_t session_key[SESSION_KEY_SIZE],
                        const cargo_frame_t *frame,
                        uint8_t *out, size_t *out_len,
                        size_t max_out_len);

int packets_parse_cargo(const uint8_t session_key[SESSION_KEY_SIZE],
                        const uint8_t *data, size_t data_len,
                        uint8_t stream_id, uint32_t expected_seq,
                        cargo_frame_t *out);

typedef struct {
    uint16_t count;
    uint32_t ack_seq;
    struct {
        uint32_t start;
        uint32_t end;
    } ranges[MAX_SACK_RANGES];
} sack_block_t;

int packets_build_sack(const sack_block_t *sack,
                       uint8_t *out, size_t *out_len,
                       size_t max_out_len);

int packets_parse_sack(const uint8_t *data, size_t data_len,
                       sack_block_t *out);

int packets_build_halt(const uint8_t session_key[SESSION_KEY_SIZE],
                       uint8_t stream_id, uint32_t cargo_seq,
                       uint8_t *out, size_t *out_len,
                       size_t max_out_len);

int packets_build_alive(const uint8_t session_key[SESSION_KEY_SIZE],
                        uint8_t stream_id, uint32_t cargo_seq,
                        uint8_t *out, size_t *out_len,
                        size_t max_out_len);

#endif /* PACKETS_H */
