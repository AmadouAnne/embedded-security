#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <stdint.h>
#include "ctx_offsets.h"

#define SCHED_NUM_TASKS 2

/* A task's full resumable register state, saved/restored by
 * context_switch.S. Layout (offsets in ctx_offsets.h) must match exactly --
 * checked with _Static_assert in scheduler.c. */
typedef struct {
    uintptr_t gprs[31]; /* x1..x31, indexed [xN - 1]; x0 is hardwired zero and never saved */
    uintptr_t mepc;
    uintptr_t mstatus;
} task_context_t;

typedef struct {
    task_context_t ctx;
    const char *name;
    /* The task's own PMP-granted regions, read from its dedicated linker
     * sections (.text.taskN / .data.taskN) -- see linker.ld. Reconfigured
     * into the live PMP CSRs on every context switch (pmp.c). */
    uintptr_t code_start, code_end;
    uintptr_t data_start, data_end;
    int alive;
} sched_task_t;

extern sched_task_t sched_tasks[SCHED_NUM_TASKS];

/* Set by scheduler_on_trap() to the context that context_switch.S's
 * restore path should load next. */
extern task_context_t *next_ctx;

void scheduler_init(void);
void __attribute__((noreturn)) scheduler_start(void);

/* Called by context_switch.S (trap_entry) after the interrupted task's
 * full context has been saved into sched_tasks[<current>].ctx. Reads
 * mcause/mepc/mtval itself (they're stable until the next trap, so no need
 * to thread them through as arguments). Decides, from either a genuine PMP
 * fault or an ordinary timer-driven preemption, which task runs next;
 * reprograms the PMP for exactly that task; rearms the timer; and points
 * next_ctx at its saved context. */
void scheduler_on_trap(void);

#endif /* SCHEDULER_H */
