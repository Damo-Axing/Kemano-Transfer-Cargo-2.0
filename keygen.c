#include "ktc.h"
#include "crypto.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

int
main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s --client-id <id> --output <path>\n", argv[0]);
        return 1;
    }

    const char *client_id = NULL;
    const char *output = NULL;

    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--client-id") == 0)
            client_id = argv[++i];
        else if (strcmp(argv[i], "--output") == 0)
            output = argv[++i];
    }

    if (!client_id || !output) {
        fprintf(stderr, "Missing --client-id or --output\n");
        return 1;
    }

    if (crypto_init() != 0) {
        fprintf(stderr, "crypto_init failed\n");
        return 1;
    }

    client_keys_t keys;
    if (utils_generate_client_keys(client_id, &keys) != 0) {
        fprintf(stderr, "Key generation failed\n");
        return 1;
    }

    if (utils_save_keys(output, &keys) != 0) {
        fprintf(stderr, "Cannot save keys to %s\n", output);
        return 1;
    }

    printf("[keygen] Generated keys for '%s'\n", client_id);
    printf("[keygen] Saved to %s\n", output);

    sodium_memzero(&keys, sizeof(keys));
    return 0;
}
