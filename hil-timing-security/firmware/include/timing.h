/*
 * Cycle-accurate timing based on the DWT cycle counter.
 *
 * Execution time is accounted per task with the FreeRTOS
 * traceTASK_SWITCHED_IN/OUT hooks, so preemption by other tasks is
 * excluded while interrupt time is included (ISR interference is one of
 * the effects under study).
 */
#ifndef TIMING_H
#define TIMING_H

#include <stddef.h>
#include <stdint.h>
#include "stm32f4xx.h"

typedef struct {
    volatile uint32_t in_stamp;   /* CYCCNT when the task was last switched in */
    volatile uint32_t acc;        /* accumulated running cycles (wraps) */
} exec_acct_t;

extern exec_acct_t g_acct[];      /* indexed by enum task_id */

static inline uint32_t cyc_now(void) { return DWT->CYCCNT; }

void timing_init(void);

/*
 * Running-cycle counter of the calling task, including the current slice.
 * A context switch between reading acc and in_stamp would lose a slice, so
 * re-read until both are stable around the CYCCNT sample (lock-free: no
 * interrupt masking inside the measured code).
 */
static inline uint32_t acct_exec_sample(const exec_acct_t *a, uint32_t *now_out)
{
    uint32_t acc, stamp, now;
    do {
        acc = a->acc;
        stamp = a->in_stamp;
        now = DWT->CYCCNT;
    } while (acc != a->acc || stamp != a->in_stamp);
    if (now_out)
        *now_out = now;
    return acc + (now - stamp);
}

static inline uint32_t acct_exec_now(const exec_acct_t *a)
{
    return acct_exec_sample(a, NULL);
}

/* Called from FreeRTOSConfig.h trace macros. */
void acct_switch_in(void *tag);
void acct_switch_out(void *tag);

/* Epoch: tick at which every periodic task has its first release. */
extern volatile uint32_t g_epoch_tick;
extern volatile uint32_t g_epoch_cyc;

void timing_tick_origin(uint32_t *tick, uint32_t *cyc);

#endif
