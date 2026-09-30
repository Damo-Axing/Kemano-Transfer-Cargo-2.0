#ifndef SESSION_H
#define SESSION_H

#include "ktc.h"
#include "packets.h"
#include "bbr.h"
#include "sack.h"
#include <stdint.h>
#include <time.h>

typedef struct {
    uint8_t stream_id;
    uint32_t next_seq;
    uint32_t last_acked;
    sack_mgr_t sack;
    bbr_t bbr;
} stream_t;

typedef struct {
    uint8_t session_key[SESSION_KEY_SIZE];
    uint64_t mask_profile;
    stream_t streams[MAX_STREAMS];
    time_t last_received;
    time_t created_at;
    int closed;
} session_t;

int session_init(session_t *s,
                 const uint8_t session_key[SESSION_KEY_SIZE],
                 uint64_t mask_profile);

int session_send_data(session_t *s,
                      uint8_t stream_id,
                      const uint8_t *payload, size_t payload_len,
                      int compressed,
                      uint8_t *out, size_t *out_len,
                      size_t max_out_len);

int session_send_sack(session_t *s,
                      uint8_t stream_id,
                      uint8_t *out, size_t *out_len,
                      size_t max_out_len);

int session_send_halt(session_t *s,
                      uint8_t *out, size_t *out_len,
                      size_t max_out_len);

int session_send_alive(session_t *s,
                       uint8_t *out, size_t *out_len,
                       size_t max_out_len);

int session_receive(session_t *s,
                    const uint8_t *data, size_t data_len,
                    uint8_t stream_id, uint32_t expected_seq,
                    cargo_frame_t *out);

int session_is_timed_out(session_t *s);

#endif /* SESSION_H */
