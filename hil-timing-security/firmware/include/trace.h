/*
 * Per-job timing records, buffered in RAM and drained by the Logging task.
 * All times are in CPU cycles; release is the nominal release instant.
 */
#ifndef TRACE_H
#define TRACE_H

#include <stdint.h>

enum trace_flags {
    TF_DEADLINE_MISS = 1u << 0,
    TF_ALARM         = 1u << 1,   /* timing monitor raised an alarm on this job */
    TF_MITIGATING    = 1u << 2,   /* a mitigation was active when the job ended */
    TF_DATA_REJECT   = 1u << 3,   /* input rejected by the plausibility guard */
    TF_SLOW_PATH     = 1u << 4,   /* data-dependent fault-handling branch taken */
};

typedef struct __attribute__((packed)) {
    uint8_t  task;
    uint8_t  flags;
    uint16_t mon_cost;    /* cycles spent in the timing monitor for this job */
    uint32_t seq;         /* job index k since the epoch */
    uint32_t release;     /* CYCCNT of the nominal release (wraps every ~23.8 s) */
    uint32_t start_lat;   /* start - release */
    uint32_t response;    /* end - release */
    uint32_t exec;        /* running cycles excluding preemption, including ISRs */
} trace_rec_t;

_Static_assert(sizeof(trace_rec_t) == 24, "trace record layout is part of the protocol");

void trace_push(const trace_rec_t *r);
/* Copy up to max records out of the ring; returns the number copied. */
uint32_t trace_pop(trace_rec_t *dst, uint32_t max);
uint32_t trace_drops(void);
void trace_reset(void);

#endif
