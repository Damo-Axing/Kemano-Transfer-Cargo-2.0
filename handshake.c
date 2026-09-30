#include "handshake.h"
#include "crypto.h"
#include "packets.h"
#include <time.h>
#include <string.h>
#include <sodium.h>

int
handshake_client_prepare(const uint8_t root_key[ROOT_KEY_SIZE],
                         const uint8_t tpm_quote[TPM_QUOTE_SIZE],
                         const uint8_t hw_mac_proof[HW_MAC_PROOF_SIZE],
                         client_handshake_t *state)
{
    int ret;

    ret = crypto_derive_handshake_key(root_key, state->handshake_key);
    if (ret != 0) return -1;

    ret = crypto_derive_legend_key(root_key, state->legend_key);
    if (ret != 0) return -1;

    ret = crypto_generate_x25519_keypair(state->client_priv, state->client_pub);
    if (ret != 0) return -1;

    state->timestamp = (uint64_t)time(NULL) * 1000;

    ret = crypto_compute_legend_sig(state->legend_key,
                                    state->timestamp,
                                    state->client_pub,
                                    tpm_quote,
                                    hw_mac_proof,
                                    state->legend_sig);
    if (ret != 0) return -1;

    return 0;
}

int
handshake_client_build_ktc0(client_handshake_t *state,
                            const uint8_t tpm_quote[TPM_QUOTE_SIZE],
                            const uint8_t hw_mac_proof[HW_MAC_PROOF_SIZE],
                            uint8_t out[KTC0_SIZE])
{
    ktc0_inner_t inner;

    inner.timestamp = state->timestamp;
    memcpy(inner.client_x25519, state->client_pub, X25519_KEY_SIZE);
    memcpy(inner.tpm_quote, tpm_quote, TPM_QUOTE_SIZE);
    memcpy(inner.hw_mac_proof, hw_mac_proof, HW_MAC_PROOF_SIZE);
    memcpy(inner.legend_sig, state->legend_sig, LEGEND_SIG_SIZE);

    return packets_build_ktc0(state->handshake_key, &inner, out);
}

int
handshake_client_process_ktca(client_handshake_t *state,
                              const uint8_t data[KTCA_SIZE],
                              client_session_t *session)
{
    ktca_inner_t inner;
    uint8_t expected_proof[SERVER_PROOF_SIZE];
    uint8_t shared[X25519_KEY_SIZE];
    int ret;

    ret = packets_parse_ktca(state->handshake_key, data, &inner);
    if (ret != 0) return -1;

    if (inner.echoed_timestamp != state->timestamp) {
        return -1;
    }

    ret = crypto_compute_server_proof(state->legend_key,
                                      inner.server_x25519,
                                      inner.echoed_timestamp,
                                      expected_proof);
    if (ret != 0) return -1;

    if (crypto_verify_32(inner.server_proof, expected_proof) != 0) {
        sodium_memzero(expected_proof, sizeof(expected_proof));
        return -1;
    }

    ret = crypto_x25519_shared(state->client_priv, inner.server_x25519, shared);
    if (ret != 0) return -1;

    ret = crypto_derive_session_key(shared, session->session_key);
    if (ret != 0) return -1;

    session->mask_profile = inner.mask_profile;

    sodium_memzero(shared, X25519_KEY_SIZE);
    sodium_memzero(state->client_priv, X25519_KEY_SIZE);
    sodium_memzero(expected_proof, sizeof(expected_proof));

    return 0;
}

int
handshake_server_process_ktc0(const uint8_t handshake_key[HANDSHAKE_KEY_SIZE],
                              const uint8_t legend_key[LEGEND_KEY_SIZE],
                              const uint8_t data[KTC0_SIZE],
                              server_handshake_t *state)
{
    ktc0_inner_t inner;
    uint8_t expected_sig[LEGEND_SIG_SIZE];
    uint64_t now;
    int64_t diff;
    int ret;

    ret = packets_parse_ktc0(handshake_key, data, &inner);
    if (ret != 0) {
        return -1;
    }

    now = (uint64_t)time(NULL) * 1000;
    diff = (int64_t)(now - inner.timestamp);
    if (diff < -TIMESTAMP_WINDOW_MS || diff > TIMESTAMP_WINDOW_MS) {
        return -1;
    }

    ret = crypto_compute_legend_sig(legend_key,
                                    inner.timestamp,
                                    inner.client_x25519,
                                    inner.tpm_quote,
                                    inner.hw_mac_proof,
                                    expected_sig);
    if (ret != 0) return -1;

    if (crypto_verify_24(inner.legend_sig, expected_sig) != 0) {
        sodium_memzero(expected_sig, sizeof(expected_sig));
        return -1;
    }

    memcpy(state->handshake_key, handshake_key, HANDSHAKE_KEY_SIZE);
    memcpy(state->client_pub, inner.client_x25519, X25519_KEY_SIZE);
    state->echoed_timestamp = inner.timestamp;

    ret = crypto_generate_x25519_keypair(state->server_priv, state->server_pub);
    if (ret != 0) return -1;

    ret = crypto_compute_server_proof(legend_key,
                                      state->server_pub,
                                      state->echoed_timestamp,
                                      state->server_proof);
    if (ret != 0) return -1;

    {
        uint8_t shared[X25519_KEY_SIZE];
        ret = crypto_x25519_shared(state->server_priv, state->client_pub, shared);
        if (ret != 0) return -1;

        ret = crypto_derive_session_key(shared, state->session_key);
        sodium_memzero(shared, X25519_KEY_SIZE);
        if (ret != 0) return -1;
    }

    sodium_memzero(expected_sig, sizeof(expected_sig));
    return 0;
}

int
handshake_server_build_ktca(server_handshake_t *state,
                            uint64_t mask_profile,
                            uint8_t out[KTCA_SIZE])
{
    ktca_inner_t inner;

    inner.echoed_timestamp = state->echoed_timestamp;
    memcpy(inner.server_x25519, state->server_pub, X25519_KEY_SIZE);
    memcpy(inner.server_proof, state->server_proof, SERVER_PROOF_SIZE);
    inner.mask_profile = mask_profile;

    return packets_build_ktca(state->handshake_key, &inner, out);
}
