#include <stdint.h>

/* Own data (counter + stack) -- the only RAM this task is granted R+W on
 * by pmp_configure_for_task() once it's scheduled. */
__attribute__((section(".data.taskA")))
volatile uint32_t task_a_counter = 0;

__attribute__((section(".data.taskA"), aligned(16)))
static uint8_t task_a_stack[512];

const uintptr_t task_a_stack_top = (uintptr_t)task_a_stack + sizeof(task_a_stack);

/* Declared but deliberately NOT part of this task's granted data region --
 * it lives in Task B's own .data.taskB, carved out by the linker exactly
 * like task_a_counter is carved out of .data.taskA. Referencing its
 * address costs nothing (this is a compile-time relocation); actually
 * touching it is what the PMP is there to stop. */
extern volatile uint32_t task_b_counter;

/* Deliberately calls no external function -- every other function in this
 * program lives in ordinary .text, not part of the R+X region granted to
 * this task; calling one would itself fault on instruction fetch (same
 * constraint as Phase 2's untrusted_task_entry -- see its comment). */
__attribute__((section(".text.taskA"), noreturn))
void task_a_entry(void)
{
    for (;;) {
        task_a_counter++;

        if (task_a_counter >= 5) {
            /* Deliberate cross-task violation: this is the Phase 3 point --
             * not "can an unprivileged task touch a kernel secret" (Phase
             * 2 already answered that), but "can two structurally
             * identical sibling tasks, isolated by nothing but PMP
             * regions the scheduler swaps in and out on every context
             * switch, actually corrupt each other". This store traps into
             * the scheduler (M-mode) instead of landing. */
            task_b_counter = 0xBADBADBAu;
        }

        for (volatile int i = 0; i < 5000; i++) {
            /* burn some cycles so the timer-driven preemption in the UART
             * log is visibly interleaving TaskA/TaskB, not just alternating
             * on every single increment */
        }
    }
}
