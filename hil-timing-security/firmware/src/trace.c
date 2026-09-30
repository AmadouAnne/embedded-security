#include "trace.h"
#include "FreeRTOS.h"
#include "task.h"

#define TRACE_CAP 1024u   /* power of two; ~2.7 s of jobs at the nominal rate */

static trace_rec_t ring[TRACE_CAP];
static volatile uint32_t head, tail, drops;

void trace_push(const trace_rec_t *r)
{
    taskENTER_CRITICAL();
    if (head - tail < TRACE_CAP) {
        ring[head & (TRACE_CAP - 1u)] = *r;
        head++;
    } else {
        drops++;
    }
    taskEXIT_CRITICAL();
}

uint32_t trace_pop(trace_rec_t *dst, uint32_t max)
{
    uint32_t n = 0;

    /* Only the Logging task pops, so tail needs no lock; copying each record
       under a short critical section keeps producers' slots consistent. */
    while (n < max) {
        taskENTER_CRITICAL();
        if (tail == head) {
            taskEXIT_CRITICAL();
            break;
        }
        dst[n++] = ring[tail & (TRACE_CAP - 1u)];
        tail++;
        taskEXIT_CRITICAL();
    }
    return n;
}

uint32_t trace_drops(void)
{
    return drops;
}

void trace_reset(void)
{
    taskENTER_CRITICAL();
    head = tail = drops = 0;
    taskEXIT_CRITICAL();
}
