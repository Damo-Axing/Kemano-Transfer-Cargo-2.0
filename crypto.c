#include "crypto.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <endian.h>

#define HANDSHAKE_CTX "KTCv2.0-Handshake"
#define LEGEND_CTX    "KTCv2.0-Legend"
#define SESSION_CTX   "KTCv2.0-Session"
#define HW_BIND_CTX   "KTCv2.0-HW-Bind"

int
crypto_init(void)
{
    if (sodium_init() < 0) {
        return -1;
    }
    return 0;
}

int
crypto_generate_root_key(uint8_t out[ROOT_KEY_SIZE])
{
    randombytes_buf(out, ROOT_KEY_SIZE);
    return 0;
}

static int
crypto_derive_key(const uint8_t *root_key, size_t root_len,
                  const char *context, size_t context_len,
                  uint8_t *out, size_t out_len)
{
    crypto_generichash_state state;

    if (crypto_generichash_init(&state, root_key, root_len, out_len) != 0)
        return -1;
    if (crypto_generichash_update(&state,
                                   (const uint8_t *)context,
                                   context_len) != 0)
        return -1;
    if (crypto_generichash_final(&state, out, out_len) != 0)
        return -1;

    sodium_memzero(&state, sizeof(state));
    return 0;
}

int
crypto_derive_handshake_key(const uint8_t root_key[ROOT_KEY_SIZE],
                            uint8_t out[HANDSHAKE_KEY_SIZE])
{
    return crypto_derive_key(root_key, ROOT_KEY_SIZE,
                             HANDSHAKE_CTX, strlen(HANDSHAKE_CTX),
                             out, HANDSHAKE_KEY_SIZE);
}

int
crypto_derive_legend_key(const uint8_t root_key[ROOT_KEY_SIZE],
                         uint8_t out[LEGEND_KEY_SIZE])
{
    return crypto_derive_key(root_key, ROOT_KEY_SIZE,
                             LEGEND_CTX, strlen(LEGEND_CTX),
                             out, LEGEND_KEY_SIZE);
}

int
crypto_derive_session_key(const uint8_t shared_secret[X25519_KEY_SIZE],
                          uint8_t out[SESSION_KEY_SIZE])
{
    return crypto_derive_key(shared_secret, X25519_KEY_SIZE,
                             SESSION_CTX, strlen(SESSION_CTX),
                             out, SESSION_KEY_SIZE);
}

int
crypto_generate_x25519_keypair(uint8_t priv[X25519_KEY_SIZE],
                               uint8_t pub[X25519_KEY_SIZE])
{
    crypto_box_keypair(pub, priv);
    return 0;
}

int
crypto_x25519_shared(const uint8_t priv[X25519_KEY_SIZE],
                     const uint8_t pub[X25519_KEY_SIZE],
                     uint8_t out[X25519_KEY_SIZE])
{
    if (crypto_scalarmult(out, priv, pub) != 0)
        return -1;
    return 0;
}

int
crypto_aead_encrypt(const uint8_t key[32],
                    const uint8_t nonce[NONCE_SIZE],
                    const uint8_t *plain, size_t plain_len,
                    uint8_t *cipher, size_t *cipher_len)
{
    crypto_aead_chacha20poly1305_ietf_encrypt(
        cipher, (unsigned long long *)cipher_len,
        plain, plain_len,
        NULL, 0, NULL,
        nonce, key);
    return 0;
}

int
crypto_aead_decrypt(const uint8_t key[32],
                    const uint8_t nonce[NONCE_SIZE],
                    const uint8_t *cipher, size_t cipher_len,
                    uint8_t *plain, size_t *plain_len)
{
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plain, (unsigned long long *)plain_len,
            NULL,
            cipher, cipher_len,
            NULL, 0,
            nonce, key) != 0) {
        return -1;
    }
    return 0;
}

int
crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                   const uint8_t *data, size_t data_len,
                   uint8_t out[32])
{
    crypto_auth_hmacsha256_state state;

    if (crypto_auth_hmacsha256_init(&state, key, key_len) != 0)
        return -1;
    if (crypto_auth_hmacsha256_update(&state, data, data_len) != 0)
        return -1;
    if (crypto_auth_hmacsha256_final(&state, out) != 0)
        return -1;

    sodium_memzero(&state, sizeof(state));
    return 0;
}

int
crypto_compute_legend_sig(const uint8_t legend_key[LEGEND_KEY_SIZE],
                          uint64_t timestamp,
                          const uint8_t client_x25519[X25519_KEY_SIZE],
                          const uint8_t tpm_quote[TPM_QUOTE_SIZE],
                          const uint8_t hw_mac_proof[HW_MAC_PROOF_SIZE],
                          uint8_t out[LEGEND_SIG_SIZE])
{
    uint8_t data[8 + 32 + 32 + 32];
    uint8_t hash[32];
    uint64_t ts_be = htobe64(timestamp);

    memcpy(data, &ts_be, 8);
    memcpy(data + 8, client_x25519, 32);
    memcpy(data + 40, tpm_quote, 32);
    memcpy(data + 72, hw_mac_proof, 32);

    if (crypto_hmac_sha256(legend_key, LEGEND_KEY_SIZE,
                           data, sizeof(data), hash) != 0)
        return -1;

    memcpy(out, hash, LEGEND_SIG_SIZE);
    sodium_memzero(hash, sizeof(hash));
    return 0;
}

int
crypto_compute_server_proof(const uint8_t legend_key[LEGEND_KEY_SIZE],
                            const uint8_t server_x25519[X25519_KEY_SIZE],
                            uint64_t echoed_timestamp,
                            uint8_t out[SERVER_PROOF_SIZE])
{
    uint8_t data[32 + 8];
    uint64_t ts_be = htobe64(echoed_timestamp);

    memcpy(data, server_x25519, 32);
    memcpy(data + 32, &ts_be, 8);

    return crypto_hmac_sha256(legend_key, LEGEND_KEY_SIZE,
                              data, sizeof(data), out);
}

int
crypto_compute_hw_mac_proof(const uint8_t device_secret[DEVICE_SECRET_SIZE],
                            const char *mac_address,
                            uint8_t out[HW_MAC_PROOF_SIZE])
{
    size_t mac_len = strlen(mac_address);
    size_t ctx_len = strlen(HW_BIND_CTX);
    size_t total = mac_len + ctx_len;

    uint8_t *data = malloc(total);
    if (!data) return -1;

    memcpy(data, mac_address, mac_len);
    memcpy(data + mac_len, HW_BIND_CTX, ctx_len);

    int ret = crypto_hmac_sha256(device_secret, DEVICE_SECRET_SIZE,
                                 data, total, out);
    sodium_memzero(data, total);
    free(data);
    return ret;
}

void
crypto_cargo_nonce(uint8_t stream_id, uint32_t cargo_seq,
                   uint8_t out[NONCE_SIZE])
{
    memset(out, 0, NONCE_SIZE);
    out[4] = stream_id;
    out[7] = (cargo_seq >> 24) & 0xFF;
    out[8] = (cargo_seq >> 16) & 0xFF;
    out[9] = (cargo_seq >> 8) & 0xFF;
    out[10] = cargo_seq & 0xFF;
}

int
crypto_random_bytes(uint8_t *buf, size_t len)
{
    randombytes_buf(buf, len);
    return 0;
}

int
crypto_verify_16(const uint8_t *a, const uint8_t *b)
{
    return sodium_memcmp(a, b, 16);
}

int
crypto_verify_24(const uint8_t *a, const uint8_t *b)
{
    return sodium_memcmp(a, b, 24);
}

int
crypto_verify_32(const uint8_t *a, const uint8_t *b)
{
    return sodium_memcmp(a, b, 32);
}
