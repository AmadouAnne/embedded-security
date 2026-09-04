#include "untrusted_task.h"
#include <stdint.h>

/* Both placed in .data.scratch (see linker.ld) -- the only data region
 * granted to U-mode by pmp_configure(). Stack included deliberately: a
 * task's own stack must be inside its own granted region too, or its
 * very first local-variable spill would fault. */
__attribute__((section(".data.scratch")))
static volatile uint8_t scratch_buf[64];

__attribute__((section(".data.scratch"), aligned(16)))
uint8_t untrusted_stack[UNTRUSTED_STACK_BYTES];

/* Ordinary .data -- NOT inside any region granted to U-mode. */
volatile uint32_t g_secure_secret = 0xC0FFEEu;

/* Deliberately calls no external function: every other function in this
 * program (uart_puts, etc.) lives in ordinary .text, which is NOT part of
 * the RX region granted to this task -- calling one would itself fault on
 * instruction fetch. Real cross-domain calls need an explicit syscall
 * gateway, which is future work (see README.md, Phase 3). */
__attribute__((section(".text.untrusted"), noreturn))
void untrusted_task_entry(void)
{
    for (unsigned i = 0; i < sizeof(scratch_buf); i++) {
        scratch_buf[i] = (uint8_t)(i + 1);
    }

    /* g_secure_secret is outside every U-mode PMP grant: this store
     * traps into trap_handler (M-mode) instead of completing. */
    g_secure_secret = 0xBADBADBAu;

    /* Unreachable if the trap above is caught, which it always is. */
    for (;;) {
        __asm__ volatile("wfi");
    }
}
