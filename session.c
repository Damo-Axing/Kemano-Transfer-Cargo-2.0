#include "session.h"
#include "crypto.h"
#include "packets.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sodium.h>

int
session_init(session_t *s,
             const uint8_t session_key[SESSION_KEY_SIZE],
             uint64_t mask_profile)
{
    memcpy(s->session_key, session_key, SESSION_KEY_SIZE);
    s->mask_profile = mask_profile;
    s->last_received = time(NULL);
    s->created_at = time(NULL);
    s->closed = 0;

    for (int i = 0; i < MAX_STREAMS; i++) {
        s->streams[i].stream_id = (uint8_t)i;
        s->streams[i].next_seq = 0;
        s->streams[i].last_acked = 0;
        sack_init(&s->streams[i].sack);
        bbr_init(&s->streams[i].bbr);
    }

    return 0;
}

int
session_send_data(session_t *s,
                  uint8_t stream_id,
                  const uint8_t *payload, size_t payload_len,
                  int compressed,
                  uint8_t *out, size_t *out_len,
                  size_t max_out_len)
{
    if (stream_id < STREAM_DATA_MIN || stream_id > STREAM_DATA_MAX)
        return -1;

    stream_t *stream = &s->streams[stream_id];

    cargo_frame_t frame = {
        .cargo_seq = stream->next_seq,
        .stream_id = stream_id,
        .flags = compressed ? FLAG_COMPRESSED : 0,
        .payload_len = (uint32_t)payload_len,
        .payload = (uint8_t *)payload,
    };

    if (payload_len > 65535)
        frame.flags |= FLAG_EXT_LENGTH;

    int ret = packets_build_cargo(s->session_key, &frame, out, out_len, max_out_len);
    if (ret != 0) return -1;

    stream->next_seq++;
    return 0;
}

int
session_send_sack(session_t *s,
                  uint8_t stream_id,
                  uint8_t *out, size_t *out_len,
                  size_t max_out_len)
{
    if (stream_id >= MAX_STREAMS) return -1;

    stream_t *stream = &s->streams[stream_id];
    sack_block_t block;
    sack_build_block(&stream->sack, &block);

    uint8_t sack_buf[1024];
    size_t sack_len;
    int ret = packets_build_sack(&block, sack_buf, &sack_len, sizeof(sack_buf));
    if (ret != 0) return -1;

    cargo_frame_t frame = {
        .cargo_seq = stream->next_seq,
        .stream_id = stream_id,
        .flags = FLAG_SACK,
        .payload_len = (uint32_t)sack_len,
        .payload = sack_buf,
    };

    ret = packets_build_cargo(s->session_key, &frame, out, out_len, max_out_len);
    if (ret != 0) return -1;

    stream->next_seq++;
    return 0;
}

int
session_send_halt(session_t *s,
                  uint8_t *out, size_t *out_len,
                  size_t max_out_len)
{
    stream_t *stream = &s->streams[STREAM_CONTROL];
    int ret = packets_build_halt(s->session_key, STREAM_CONTROL,
                                 stream->next_seq, out, out_len, max_out_len);
    if (ret != 0) return -1;

    stream->next_seq++;
    s->closed = 1;
    return 0;
}

int
session_send_alive(session_t *s,
                   uint8_t *out, size_t *out_len,
                   size_t max_out_len)
{
    stream_t *stream = &s->streams[STREAM_CONTROL];
    int ret = packets_build_alive(s->session_key, STREAM_CONTROL,
                                  stream->next_seq, out, out_len, max_out_len);
    if (ret != 0) return -1;

    stream->next_seq++;
    return 0;
}

int
session_receive(session_t *s,
                const uint8_t *data, size_t data_len,
                uint8_t stream_id, uint32_t expected_seq,
                cargo_frame_t *out)
{
    if (stream_id >= MAX_STREAMS) return -1;

    int ret = packets_parse_cargo(s->session_key, data, data_len,
                                  stream_id, expected_seq, out);
    if (ret != 0) return -1;

    s->last_received = time(NULL);
    s->streams[stream_id].sack_add(&s->streams[stream_id].sack, out->cargo_seq);

    if (out->flags & FLAG_HALT) {
        s->closed = 1;
    }

    return 0;
}

int
session_is_timed_out(session_t *s)
{
    time_t now = time(NULL);
    return (now - s->last_received) * 1000 > SILENCE_TIMEOUT_MS;
}
