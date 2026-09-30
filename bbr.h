#ifndef BBR_H
#define BBR_H

#include <stdint.h>

typedef enum {
    BBR_STARTUP,
    BBR_DRAIN,
    BBR_PROBE_BW,
    BBR_PROBE_RTT,
} bbr_phase_t;

typedef struct {
    bbr_phase_t phase;
    double cwnd;
    double pacing_rate;
    double min_rtt;
    double btlbw;
    double last_bw_sample;
    int probe_bw_cycle;
    int probe_rtt_pending;
} bbr_t;

void bbr_init(bbr_t *bbr);
void bbr_on_ack(bbr_t *bbr, double rtt, size_t bytes_delivered, double now);
void bbr_on_loss(bbr_t *bbr);
double bbr_pacing_rate(bbr_t *bbr);
double bbr_cwnd(bbr_t *bbr);

#endif /* BBR_H */
