#ifndef CRYPTO_H
#define CRYPTO_H

#include "ktc.h"
#include <stdint.h>
#include <stddef.h>

int crypto_init(void);

int crypto_generate_root_key(uint8_t out[ROOT_KEY_SIZE]);

int crypto_derive_handshake_key(const uint8_t root_key[ROOT_KEY_SIZE],
                                uint8_t out[HANDSHAKE_KEY_SIZE]);

int crypto_derive_legend_key(const uint8_t root_key[ROOT_KEY_SIZE],
                             uint8_t out[LEGEND_KEY_SIZE]);

int crypto_derive_session_key(const uint8_t shared_secret[X25519_KEY_SIZE],
                              uint8_t out[SESSION_KEY_SIZE]);

int crypto_generate_x25519_keypair(uint8_t priv[X25519_KEY_SIZE],
                                   uint8_t pub[X25519_KEY_SIZE]);

int crypto_x25519_shared(const uint8_t priv[X25519_KEY_SIZE],
                         const uint8_t pub[X25519_KEY_SIZE],
                         uint8_t out[X25519_KEY_SIZE]);

int crypto_aead_encrypt(const uint8_t key[32],
                        const uint8_t nonce[NONCE_SIZE],
                        const uint8_t *plain, size_t plain_len,
                        uint8_t *cipher, size_t *cipher_len);

int crypto_aead_decrypt(const uint8_t key[32],
                        const uint8_t nonce[NONCE_SIZE],
                        const uint8_t *cipher, size_t cipher_len,
                        uint8_t *plain, size_t *plain_len);

int crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t out[32]);

int crypto_compute_legend_sig(const uint8_t legend_key[LEGEND_KEY_SIZE],
                              uint64_t timestamp,
                              const uint8_t client_x25519[X25519_KEY_SIZE],
                              const uint8_t tpm_quote[TPM_QUOTE_SIZE],
                              const uint8_t hw_mac_proof[HW_MAC_PROOF_SIZE],
                              uint8_t out[LEGEND_SIG_SIZE]);

int crypto_compute_server_proof(const uint8_t legend_key[LEGEND_KEY_SIZE],
                                const uint8_t server_x25519[X25519_KEY_SIZE],
                                uint64_t echoed_timestamp,
                                uint8_t out[SERVER_PROOF_SIZE]);

int crypto_compute_hw_mac_proof(const uint8_t device_secret[DEVICE_SECRET_SIZE],
                                const char *mac_address,
                                uint8_t out[HW_MAC_PROOF_SIZE]);

void crypto_cargo_nonce(uint8_t stream_id, uint32_t cargo_seq,
                        uint8_t out[NONCE_SIZE]);

int crypto_random_bytes(uint8_t *buf, size_t len);

int crypto_verify_16(const uint8_t *a, const uint8_t *b);
int crypto_verify_24(const uint8_t *a, const uint8_t *b);
int crypto_verify_32(const uint8_t *a, const uint8_t *b);

#endif /* CRYPTO_H */
