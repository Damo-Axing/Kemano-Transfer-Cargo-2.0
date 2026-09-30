#ifndef SACK_H
#define SACK_H

#include "packets.h"
#include <stdint.h>

typedef struct {
    uint8_t received[65536 / 8];
    int32_t max_continuous;
    int32_t max_seen;
    uint32_t total_received;
} sack_mgr_t;

void sack_init(sack_mgr_t *mgr);
void sack_add(sack_mgr_t *mgr, uint32_t seq);
uint32_t sack_ack_seq(sack_mgr_t *mgr);
int sack_get_ranges(sack_mgr_t *mgr, uint32_t *ranges, int max_pairs);
void sack_build_block(sack_mgr_t *mgr, sack_block_t *block);

#endif /* SACK_H */
