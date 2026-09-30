#include "masking.h"
#include "crypto.h"
#include <string.h>
#include <stdlib.h>

static const mask_profile_t profiles[] = {
    [PROFILE_RAW]            = {0, "RAW",              0,    0,    0,   0},
    [PROFILE_YOUTUBE_LIVE]   = {1, "YouTube Live",     1200, 1400, 100, 200},
    [PROFILE_ZOOM_VIDEO]     = {2, "Zoom Video",       200,  400,  20,  20},
    [PROFILE_DISCORD_VOICE]  = {3, "Discord Voice",    80,   120,  20,  20},
    [PROFILE_WEBRTC]         = {4, "WebRTC Generic",   1100, 1300, 10,  50},
    [PROFILE_HTTPS_CDN]      = {5, "HTTPS CDN",        1460, 1460, 1,   5},
    [PROFILE_DNS_HTTPS]      = {6, "DNS-over-HTTPS",   400,  600,  100, 500},
    [PROFILE_STEAM_DL]       = {7, "Steam Download",   1400, 1500, 5,   20},
    [PROFILE_STUN]           = {8, "STUN/WebRTC",      80,   120,  20,  20},
    [PROFILE_HTTP3_QUIC]     = {9, "HTTP/3 QUIC",      1200, 1400, 5,   30},
    [PROFILE_CLOUDFLARE]     = {10, "Cloudflare",      0,    0,    0,   0},
    [PROFILE_GOOGLE_QUIC]    = {11, "Google QUIC",     1200, 1400, 5,   30},
};

static const size_t profiles_count = sizeof(profiles) / sizeof(profiles[0]);

void
masking_init(masking_t *m, uint64_t profile_id)
{
    masking_set_profile(m, profile_id);
}

void
masking_set_profile(masking_t *m, uint64_t profile_id)
{
    if (profile_id >= profiles_count) {
        m->profile = profiles[PROFILE_RAW];
        return;
    }
    m->profile = profiles[profile_id];
}

size_t
masking_pad_payload(masking_t *m,
                    const uint8_t *payload, size_t payload_len,
                    uint8_t *out, size_t max_out_len)
{
    if (m->profile.size_min == 0 && m->profile.size_max == 0) {
        if (payload_len > max_out_len) return 0;
        memcpy(out, payload, payload_len);
        return payload_len;
    }

    int target = m->profile.size_min;
    if (m->profile.size_max > m->profile.size_min) {
        uint8_t rnd[4];
        crypto_random_bytes(rnd, 4);
        uint32_t r = (rnd[0] << 24) | (rnd[1] << 16) | (rnd[2] << 8) | rnd[3];
        int range = m->profile.size_max - m->profile.size_min;
        target = m->profile.size_min + (int)(r % (range + 1));
    }

    if ((size_t)target > max_out_len) return 0;
    if (payload_len > (size_t)target) return 0;

    memcpy(out, payload, payload_len);
    if ((size_t)target > payload_len) {
        crypto_random_bytes(out + payload_len, target - payload_len);
    }

    return (size_t)target;
}

int
masking_get_delay_ms(masking_t *m)
{
    if (m->profile.timing_min_ms == 0 && m->profile.timing_max_ms == 0)
        return 0;

    uint8_t rnd[4];
    crypto_random_bytes(rnd, 4);
    uint32_t r = (rnd[0] << 24) | (rnd[1] << 16) | (rnd[2] << 8) | rnd[3];

    int range = m->profile.timing_max_ms - m->profile.timing_min_ms;
    if (range <= 0) return m->profile.timing_min_ms;

    int delay = m->profile.timing_min_ms + (int)(r % (range + 1));

    int jitter = (delay * 10) / 100;
    if (jitter > 0) {
        crypto_random_bytes(rnd, 4);
        r = (rnd[0] << 24) | (rnd[1] << 16) | (rnd[2] << 8) | rnd[3];
        delay += (int)(r % (2 * jitter + 1)) - jitter;
    }

    return delay < 0 ? 0 : delay;
}
