#include "utils.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

uint64_t
utils_timestamp_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int
utils_random_int(int min, int max)
{
    if (max <= min) return min;
    uint32_t r;
    randombytes_buf(&r, sizeof(r));
    return min + (int)(r % (uint32_t)(max - min + 1));
}

int
utils_generate_client_keys(const char *client_id, client_keys_t *keys)
{
    memset(keys, 0, sizeof(*keys));
    strncpy(keys->client_id, client_id, sizeof(keys->client_id) - 1);

    if (crypto_generate_root_key(keys->root_key) != 0)
        return -1;

    if (crypto_derive_handshake_key(keys->root_key, keys->handshake_key) != 0)
        return -1;

    if (crypto_derive_legend_key(keys->root_key, keys->legend_key) != 0)
        return -1;

    return 0;
}

static void
hex_encode(const uint8_t *in, size_t in_len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < in_len; i++) {
        out[i * 2] = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0F];
    }
    out[in_len * 2] = '\0';
}

static int
hex_decode(const char *in, uint8_t *out, size_t out_len)
{
    if (strlen(in) != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        char c1 = in[i * 2];
        char c2 = in[i * 2 + 1];
        int v1 = (c1 >= '0' && c1 <= '9') ? c1 - '0' :
                 (c1 >= 'a' && c1 <= 'f') ? c1 - 'a' + 10 :
                 (c1 >= 'A' && c1 <= 'F') ? c1 - 'A' + 10 : -1;
        int v2 = (c2 >= '0' && c2 <= '9') ? c2 - '0' :
                 (c2 >= 'a' && c2 <= 'f') ? c2 - 'a' + 10 :
                 (c2 >= 'A' && c2 <= 'F') ? c2 - 'A' + 10 : -1;
        if (v1 < 0 || v2 < 0) return -1;
        out[i] = (uint8_t)((v1 << 4) | v2);
    }
    return 0;
}

int
utils_save_keys(const char *filepath, const client_keys_t *keys)
{
    FILE *f = fopen(filepath, "w");
    if (!f) return -1;

    char hex_root[ROOT_KEY_SIZE * 2 + 1];
    char hex_hs[HANDSHAKE_KEY_SIZE * 2 + 1];
    char hex_lk[LEGEND_KEY_SIZE * 2 + 1];

    hex_encode(keys->root_key, ROOT_KEY_SIZE, hex_root);
    hex_encode(keys->handshake_key, HANDSHAKE_KEY_SIZE, hex_hs);
    hex_encode(keys->legend_key, LEGEND_KEY_SIZE, hex_lk);

    fprintf(f, "{\n");
    fprintf(f, "  \"client_id\": \"%s\",\n", keys->client_id);
    fprintf(f, "  \"root_key\": \"%s\",\n", hex_root);
    fprintf(f, "  \"handshake_key\": \"%s\",\n", hex_hs);
    fprintf(f, "  \"legend_key\": \"%s\"\n", hex_lk);
    fprintf(f, "}\n");

    fclose(f);
    chmod(filepath, 0600);

    sodium_memzero(hex_root, sizeof(hex_root));
    sodium_memzero(hex_hs, sizeof(hex_hs));
    sodium_memzero(hex_lk, sizeof(hex_lk));

    return 0;
}

int
utils_load_keys(const char *filepath, client_keys_t *keys)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return -1;

    char line[512];
    memset(keys, 0, sizeof(*keys));

    while (fgets(line, sizeof(line), f)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;

        char *val = colon + 1;
        while (*val == ' ' || *val == '"') val++;

        char *end = val + strlen(val) - 1;
        while (end > val && (*end == '\n' || *end == ',' ||
                              *end == '"' || *end == ' ')) {
            *end-- = '\0';
        }

        if (strstr(line, "client_id")) {
            strncpy(keys->client_id, val, sizeof(keys->client_id) - 1);
        } else if (strstr(line, "root_key")) {
            hex_decode(val, keys->root_key, ROOT_KEY_SIZE);
        } else if (strstr(line, "handshake_key")) {
            hex_decode(val, keys->handshake_key, HANDSHAKE_KEY_SIZE);
        } else if (strstr(line, "legend_key")) {
            hex_decode(val, keys->legend_key, LEGEND_KEY_SIZE);
        }
    }

    fclose(f);
    return 0;
}
