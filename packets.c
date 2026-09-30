#include "packets.h"
#include "crypto.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <endian.h>

int
packets_build_ktc0(const uint8_t handshake_key[HANDSHAKE_KEY_SIZE],
                   const ktc0_inner_t *inner,
                   uint8_t out[KTC0_SIZE])
{
    uint8_t inner_buf[128];
    uint8_t nonce[NONCE_SIZE];
    size_t cipher_len;
    int ret;

    uint64_t ts_be = htobe64(inner->timestamp);
    memcpy(inner_buf, &ts_be, 8);
    memcpy(inner_buf + 8, inner->client_x25519, 32);
    memcpy(inner_buf + 40, inner->tpm_quote, 32);
    memcpy(inner_buf + 72, inner->hw_mac_proof, 32);
    memcpy(inner_buf + 104, inner->legend_sig, 24);
    memset(inner_buf + 128 - 8, 0, 8);

    ret = crypto_random_bytes(nonce, NONCE_SIZE);
    if (ret != 0) return -1;

    ret = crypto_aead_encrypt(handshake_key, nonce,
                              inner_buf, 128,
                              out + 12, &cipher_len);
    if (ret != 0) return -1;

    memcpy(out, nonce, 12);
    sodium_memzero(inner_buf, sizeof(inner_buf));
    return 0;
}

int
packets_parse_ktc0(const uint8_t handshake_key[HANDSHAKE_KEY_SIZE],
                   const uint8_t data[KTC0_SIZE],
                   ktc0_inner_t *out)
{
    uint8_t nonce[NONCE_SIZE];
    uint8_t plain[128];
    size_t plain_len;
    int ret;

    memcpy(nonce, data, 12);

    ret = crypto_aead_decrypt(handshake_key, nonce,
                              data + 12, KTC0_SIZE - 12,
                              plain, &plain_len);
    if (ret != 0) return -1;
    if (plain_len != 128) return -1;

    uint64_t ts_be;
    memcpy(&ts_be, plain, 8);
    out->timestamp = be64toh(ts_be);

    memcpy(out->client_x25519, plain + 8, 32);
    memcpy(out->tpm_quote, plain + 40, 32);
    memcpy(out->hw_mac_proof, plain + 72, 32);
    memcpy(out->legend_sig, plain + 104, 24);

    sodium_memzero(plain, sizeof(plain));
    return 0;
}

int
packets_build_ktca(const uint8_t handshake_key[HANDSHAKE_KEY_SIZE],
                   const ktca_inner_t *inner,
                   uint8_t out[KTCA_SIZE])
{
    uint8_t inner_buf[80];
    uint8_t nonce[NONCE_SIZE];
    size_t cipher_len;
    int ret;

    uint64_t ts_be = htobe64(inner->echoed_timestamp);
    uint64_t mp_be = htobe64(inner->mask_profile);

    memcpy(inner_buf, &ts_be, 8);
    memcpy(inner_buf + 8, inner->server_x25519, 32);
    memcpy(inner_buf + 40, inner->server_proof, 32);
    memcpy(inner_buf + 72, &mp_be, 8);

    ret = crypto_random_bytes(nonce, NONCE_SIZE);
    if (ret != 0) return -1;

    ret = crypto_aead_encrypt(handshake_key, nonce,
                              inner_buf, 80,
                              out + 12, &cipher_len);
    if (ret != 0) return -1;

    memcpy(out, nonce, 12);
    sodium_memzero(inner_buf, sizeof(inner_buf));
    return 0;
}

int
packets_parse_ktca(const uint8_t handshake_key[HANDSHAKE_KEY_SIZE],
                   const uint8_t data[KTCA_SIZE],
                   ktca_inner_t *out)
{
    uint8_t nonce[NONCE_SIZE];
    uint8_t plain[80];
    size_t plain_len;
    int ret;

    memcpy(nonce, data, 12);

    ret = crypto_aead_decrypt(handshake_key, nonce,
                              data + 12, KTCA_SIZE - 12,
                              plain, &plain_len);
    if (ret != 0) return -1;
    if (plain_len != 80) return -1;

    uint64_t ts_be, mp_be;
    memcpy(&ts_be, plain, 8);
    out->echoed_timestamp = be64toh(ts_be);

    memcpy(out->server_x25519, plain + 8, 32);
    memcpy(out->server_proof, plain + 40, 32);

    memcpy(&mp_be, plain + 72, 8);
    out->mask_profile = be64toh(mp_be);

    sodium_memzero(plain, sizeof(plain));
    return 0;
}

int
packets_build_cargo(const uint8_t session_key[SESSION_KEY_SIZE],
                    const cargo_frame_t *frame,
                    uint8_t *out, size_t *out_len,
                    size_t max_out_len)
{
    uint8_t nonce[NONCE_SIZE];
    uint8_t *inner;
    size_t inner_len;
    int ret;

    size_t header_size = 4 + 1 + 1 + 2;
    if (frame->flags & FLAG_EXT_LENGTH)
        header_size += 4;

    inner_len = header_size + frame->payload_len;
    inner = malloc(inner_len);
    if (!inner) return -1;

    uint32_t seq_be = htonl(frame->cargo_seq);
    uint16_t len_be;

    memcpy(inner, &seq_be, 4);
    inner[4] = frame->stream_id;
    inner[5] = frame->flags;

    if (frame->flags & FLAG_EXT_LENGTH) {
        len_be = 0;
        memcpy(inner + 6, &len_be, 2);
        uint32_t ext_be = htonl(frame->payload_len);
        memcpy(inner + 8, &ext_be, 4);
        if (frame->payload_len > 0)
            memcpy(inner + 12, frame->payload, frame->payload_len);
    } else {
        len_be = htons((uint16_t)frame->payload_len);
        memcpy(inner + 6, &len_be, 2);
        if (frame->payload_len > 0)
            memcpy(inner + 8, frame->payload, frame->payload_len);
    }

    crypto_cargo_nonce(frame->stream_id, frame->cargo_seq, nonce);

    ret = crypto_aead_encrypt(session_key, nonce,
                              inner, inner_len,
                              out, out_len);

    sodium_memzero(inner, inner_len);
    free(inner);

    if (ret != 0) return -1;
    if (*out_len > max_out_len) return -1;

    return 0;
}

int
packets_parse_cargo(const uint8_t session_key[SESSION_KEY_SIZE],
                    const uint8_t *data, size_t data_len,
                    uint8_t stream_id, uint32_t expected_seq,
                    cargo_frame_t *out)
{
    uint8_t nonce[NONCE_SIZE];
    uint8_t *plain;
    size_t plain_len;
    int ret;

    if (data_len < 24) return -1;

    crypto_cargo_nonce(stream_id, expected_seq, nonce);

    plain = malloc(data_len);
    if (!plain) return -1;

    ret = crypto_aead_decrypt(session_key, nonce,
                              data, data_len,
                              plain, &plain_len);
    if (ret != 0) {
        free(plain);
        return -1;
    }

    if (plain_len < 8) {
        free(plain);
        return -1;
    }

    uint32_t seq_be;
    memcpy(&seq_be, plain, 4);
    out->cargo_seq = ntohl(seq_be);
    out->stream_id = plain[4];
    out->flags = plain[5];

    if (out->flags & FLAG_EXT_LENGTH) {
        if (plain_len < 12) { free(plain); return -1; }
        uint32_t ext_be;
        memcpy(&ext_be, plain + 8, 4);
        out->payload_len = ntohl(ext_be);
        out->payload = malloc(out->payload_len);
        if (!out->payload) { free(plain); return -1; }
        if (12 + out->payload_len > plain_len) {
            free(out->payload);
            free(plain);
            return -1;
        }
        memcpy(out->payload, plain + 12, out->payload_len);
    } else {
        uint16_t len_be;
        memcpy(&len_be, plain + 6, 2);
        out->payload_len = ntohs(len_be);
        out->payload = malloc(out->payload_len);
        if (!out->payload) { free(plain); return -1; }
        if (8 + out->payload_len > plain_len) {
            free(out->payload);
            free(plain);
            return -1;
        }
        memcpy(out->payload, plain + 8, out->payload_len);
    }

    sodium_memzero(plain, data_len);
    free(plain);
    return 0;
}

int
packets_build_sack(const sack_block_t *sack,
                   uint8_t *out, size_t *out_len,
                   size_t max_out_len)
{
    size_t needed = 2 + 4 + sack->count * 8;
    if (needed > max_out_len) return -1;

    uint16_t count_be = htons(sack->count);
    uint32_t ack_be = htonl(sack->ack_seq);

    memcpy(out, &count_be, 2);
    memcpy(out + 2, &ack_be, 4);

    for (uint16_t i = 0; i < sack->count; i++) {
        uint32_t start_be = htonl(sack->ranges[i].start);
        uint32_t end_be = htonl(sack->ranges[i].end);
        memcpy(out + 6 + i * 8, &start_be, 4);
        memcpy(out + 10 + i * 8, &end_be, 4);
    }

    *out_len = needed;
    return 0;
}

int
packets_parse_sack(const uint8_t *data, size_t data_len,
                   sack_block_t *out)
{
    if (data_len < 6) return -1;

    uint16_t count_be;
    uint32_t ack_be;

    memcpy(&count_be, data, 2);
    memcpy(&ack_be, data + 2, 4);

    out->count = ntohs(count_be);
    out->ack_seq = ntohl(ack_be);

    if (out->count > MAX_SACK_RANGES) return -1;
    if (data_len < 6 + out->count * 8) return -1;

    for (uint16_t i = 0; i < out->count; i++) {
        uint32_t start_be, end_be;
        memcpy(&start_be, data + 6 + i * 8, 4);
        memcpy(&end_be, data + 10 + i * 8, 4);
        out->ranges[i].start = ntohl(start_be);
        out->ranges[i].end = ntohl(end_be);
    }

    return 0;
}

int
packets_build_halt(const uint8_t session_key[SESSION_KEY_SIZE],
                   uint8_t stream_id, uint32_t cargo_seq,
                   uint8_t *out, size_t *out_len,
                   size_t max_out_len)
{
    cargo_frame_t frame = {
        .cargo_seq = cargo_seq,
        .stream_id = stream_id,
        .flags = FLAG_HALT,
        .payload_len = 0,
        .payload = NULL,
    };
    return packets_build_cargo(session_key, &frame, out, out_len, max_out_len);
}

int
packets_build_alive(const uint8_t session_key[SESSION_KEY_SIZE],
                    uint8_t stream_id, uint32_t cargo_seq,
                    uint8_t *out, size_t *out_len,
                    size_t max_out_len)
{
    cargo_frame_t frame = {
        .cargo_seq = cargo_seq,
        .stream_id = stream_id,
        .flags = FLAG_ALIVE,
        .payload_len = 0,
        .payload = NULL,
    };
    return packets_build_cargo(session_key, &frame, out, out_len, max_out_len);
}
