#include <stdint.h>

__attribute__((section(".data.taskB")))
volatile uint32_t task_b_counter = 0;

__attribute__((section(".data.taskB"), aligned(16)))
static uint8_t task_b_stack[512];

const uintptr_t task_b_stack_top = (uintptr_t)task_b_stack + sizeof(task_b_stack);

/* Task B never misbehaves -- it exists to prove the scheduler keeps a
 * well-behaved sibling making real, independent progress (its own counter
 * keeps advancing) both before and after TaskA gets caught and killed. */
__attribute__((section(".text.taskB"), noreturn))
void task_b_entry(void)
{
    for (;;) {
        task_b_counter++;

        for (volatile int i = 0; i < 5000; i++) {
        }
    }
}
