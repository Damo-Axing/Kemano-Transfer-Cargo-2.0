#include "bbr.h"
#include <string.h>
#include <math.h>

#define BBR_INIT_CWND 10.0
#define BBR_MIN_CWND 4.0
#define BBR_INIT_RTT 0.1

void
bbr_init(bbr_t *bbr)
{
    memset(bbr, 0, sizeof(*bbr));
    bbr->phase = BBR_STARTUP;
    bbr->cwnd = BBR_INIT_CWND;
    bbr->pacing_rate = 0.0;
    bbr->min_rtt = BBR_INIT_RTT;
    bbr->btlbw = 0.0;
    bbr->probe_bw_cycle = 0;
    bbr->probe_rtt_pending = 0;
}

void
bbr_on_ack(bbr_t *bbr, double rtt, size_t bytes_delivered, double now)
{
    if (rtt < bbr->min_rtt || bbr->min_rtt <= 0.0)
        bbr->min_rtt = rtt;

    double bw_sample = (double)bytes_delivered / (rtt > 0 ? rtt : 0.001);
    if (bw_sample > bbr->btlbw)
        bbr->btlbw = bw_sample;

    switch (bbr->phase) {
    case BBR_STARTUP:
        bbr->cwnd *= 2.0;
        if (bbr->btlbw > 0.0 && bbr->cwnd / bbr->btlbw > 3.0 * bbr->min_rtt) {
            bbr->phase = BBR_DRAIN;
        }
        break;

    case BBR_DRAIN:
        bbr->cwnd *= 0.75;
        if (bbr->cwnd <= bbr->btlbw * bbr->min_rtt) {
            bbr->phase = BBR_PROBE_BW;
        }
        break;

    case BBR_PROBE_BW: {
        static const double gains[8] = {1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0};
        bbr->probe_bw_cycle = (bbr->probe_bw_cycle + 1) % 8;
        bbr->cwnd = bbr->btlbw * bbr->min_rtt * gains[bbr->probe_bw_cycle];
        if (bbr->probe_bw_cycle == 0) {
            bbr->phase = BBR_PROBE_RTT;
            bbr->probe_rtt_pending = 1;
        }
        break;
    }

    case BBR_PROBE_RTT:
        bbr->cwnd = BBR_MIN_CWND;
        if (!bbr->probe_rtt_pending) {
            bbr->phase = BBR_PROBE_BW;
        }
        break;
    }

    if (bbr->cwnd < BBR_MIN_CWND)
        bbr->cwnd = BBR_MIN_CWND;

    bbr->pacing_rate = bbr->btlbw * 1.25;
    bbr->last_bw_sample = now;

    (void)now;
}

void
bbr_on_loss(bbr_t *bbr)
{
    bbr->cwnd *= 0.5;
    if (bbr->cwnd < BBR_MIN_CWND)
        bbr->cwnd = BBR_MIN_CWND;
}

double
bbr_pacing_rate(bbr_t *bbr)
{
    return bbr->pacing_rate;
}

double
bbr_cwnd(bbr_t *bbr)
{
    return bbr->cwnd;
}
