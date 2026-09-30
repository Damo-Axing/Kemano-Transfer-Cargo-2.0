#ifndef UTILS_H
#define UTILS_H

#include "ktc.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
    char client_id[64];
    uint8_t root_key[ROOT_KEY_SIZE];
    uint8_t handshake_key[HANDSHAKE_KEY_SIZE];
    uint8_t legend_key[LEGEND_KEY_SIZE];
} client_keys_t;

int utils_generate_client_keys(const char *client_id, client_keys_t *keys);
int utils_save_keys(const char *filepath, const client_keys_t *keys);
int utils_load_keys(const char *filepath, client_keys_t *keys);
uint64_t utils_timestamp_ms(void);
int utils_random_int(int min, int max);

#endif /* UTILS_H */
