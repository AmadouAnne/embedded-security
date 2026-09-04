#ifndef CLINT_H
#define CLINT_H

#include <stdint.h>

/* Enables the machine-timer interrupt source (mie.MTIE) and arms the first
 * deadline. Call once, before the first mret into U-mode. */
void clint_init(void);

/* Schedules the next machine-timer interrupt one quantum (10ms, at QEMU
 * virt's confirmed 10MHz mtime rate) from now. Called from
 * scheduler_on_trap() on every switch so the newly-running task also gets
 * preempted after its own slice. */
void clint_rearm(void);

#endif /* CLINT_H */
