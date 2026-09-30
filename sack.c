#include "sack.h"
#include <string.h>

void
sack_init(sack_mgr_t *mgr)
{
    memset(mgr, 0, sizeof(*mgr));
    mgr->max_continuous = -1;
    mgr->max_seen = -1;
}

void
sack_add(sack_mgr_t *mgr, uint32_t seq)
{
    if (seq >= 65536) return;

    uint32_t idx = seq / 8;
    uint8_t bit = seq % 8;
    mgr->received[idx] |= (1 << bit);

    if ((int32_t)seq > mgr->max_seen)
        mgr->max_seen = seq;

    while (1) {
        int32_t next = mgr->max_continuous + 1;
        if (next < 0 || next >= 65536) break;
        uint32_t nidx = next / 8;
        uint8_t nbit = next % 8;
        if (mgr->received[nidx] & (1 << nbit)) {
            mgr->max_continuous = next;
        } else {
            break;
        }
    }

    mgr->total_received++;
}

uint32_t
sack_ack_seq(sack_mgr_t *mgr)
{
    if (mgr->max_continuous < 0) return 0;
    return (uint32_t)(mgr->max_continuous + 1);
}

int
sack_get_ranges(sack_mgr_t *mgr, uint32_t *ranges, int max_pairs)
{
    if (mgr->max_continuous >= mgr->max_seen)
        return 0;

    int count = 0;
    int32_t start = -1;

    for (int32_t seq = mgr->max_continuous + 1; seq <= mgr->max_seen; seq++) {
        uint32_t idx = seq / 8;
        uint8_t bit = seq % 8;
        int received = (mgr->received[idx] & (1 << bit)) != 0;

        if (received && start < 0) {
            start = seq;
        } else if (!received && start >= 0) {
            if (count >= max_pairs) break;
            ranges[count * 2] = (uint32_t)start;
            ranges[count * 2 + 1] = (uint32_t)(seq - 1);
            count++;
            start = -1;
        }
    }

    if (start >= 0 && count < max_pairs) {
        ranges[count * 2] = (uint32_t)start;
        ranges[count * 2 + 1] = (uint32_t)mgr->max_seen;
        count++;
    }

    return count;
}

void
sack_build_block(sack_mgr_t *mgr, sack_block_t *block)
{
    block->ack_seq = sack_ack_seq(mgr);

    uint32_t ranges[MAX_SACK_RANGES * 2];
    int count = sack_get_ranges(mgr, ranges, MAX_SACK_RANGES);

    block->count = (uint16_t)count;
    for (int i = 0; i < count; i++) {
        block->ranges[i].start = ranges[i * 2];
        block->ranges[i].end = ranges[i * 2 + 1];
    }
}
