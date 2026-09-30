#ifndef MASKING_H
#define MASKING_H

#include "ktc.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t profile_id;
    const char *name;
    int size_min;
    int size_max;
    int timing_min_ms;
    int timing_max_ms;
} mask_profile_t;

typedef struct {
    mask_profile_t profile;
} masking_t;

void masking_init(masking_t *m, uint64_t profile_id);
void masking_set_profile(masking_t *m, uint64_t profile_id);
size_t masking_pad_payload(masking_t *m,
                           const uint8_t *payload, size_t payload_len,
                           uint8_t *out, size_t max_out_len);
int masking_get_delay_ms(masking_t *m);

#endif /* MASKING_H */
