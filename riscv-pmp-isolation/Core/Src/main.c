#include "uart.h"
#include "scheduler.h"

/* Phase 3: a minimal M-mode round-robin scheduler for two U-mode tasks,
 * each with its own PMP-granted code+data region, preempted by a real
 * timer interrupt (QEMU virt's CLINT) and context-switched with a full
 * hand-written register save/restore (context_switch.S) -- the structural
 * RISC-V/PMP equivalent of xTaskCreateRestricted()'s per-task
 * MemoryRegions being reprogrammed into the MPU on every FreeRTOS context
 * switch (see ../freertos-stm32).
 *
 * TaskA does legitimate work for a few scheduling quanta, then deliberately
 * writes into TaskB's own counter -- memory neither task shares, isolated
 * from the other by nothing but the PMP regions the scheduler swaps in and
 * out. That store traps into the scheduler instead of landing; TaskA is
 * marked dead; TaskB keeps running untouched, proving the violation was
 * contained to its source rather than corrupting or halting anything else.
 *
 * Phase 2's single-task demo (main.c calling pmp_configure() +
 * drop_to_user_mode() directly) is superseded by this file but its source
 * (untrusted_task.c, the old pmp_configure()/trap_handler()) is kept
 * unmodified for reference -- see README.md for its real captured output. */
int main(void)
{
    uart_init();
    uart_puts("=== RISC-V PMP Isolation -- Phase 3: round-robin scheduler ===\n");
    uart_puts("Two U-mode tasks, PMP regions swapped per task on every context switch.\n");

    scheduler_init();
    scheduler_start();
}
