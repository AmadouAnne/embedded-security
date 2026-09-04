#include "uart.h"
#include "pmp.h"
#include "trap.h"
#include "untrusted_task.h"
#include <stdint.h>

/* Reads mstatus, clears MPP (bits [12:11]) to 00 = U-mode, sets mepc to
 * the untrusted task's entry point, points sp at that task's own stack
 * (carved out of its PMP-granted scratch region -- see untrusted_task.c),
 * then `mret`s. The sp change and `mret` are one inline-asm block with no
 * C code in between, so nothing runs on an sp the compiler doesn't know
 * about. Never returns: `mret` jumps straight into U-mode. */
static void __attribute__((noreturn)) drop_to_user_mode(void)
{
    uintptr_t mstatus_val;
    __asm__ volatile("csrr %0, mstatus" : "=r"(mstatus_val));
    mstatus_val &= ~(uintptr_t)(3u << 11); /* MPP = 00 (U-mode) */
    __asm__ volatile("csrw mstatus, %0" :: "r"(mstatus_val));

    uintptr_t entry = (uintptr_t)untrusted_task_entry;
    __asm__ volatile("csrw mepc, %0" :: "r"(entry));

    uintptr_t new_sp = (uintptr_t)untrusted_stack + sizeof(untrusted_stack);
    __asm__ volatile(
        "mv sp, %0\n"
        "mret\n"
        :: "r"(new_sp)
        : "memory"
    );
    __builtin_unreachable();
}

int main(void)
{
    uart_init();
    uart_puts("=== RISC-V PMP Isolation -- Phase 2 ===\n");
    uart_puts("Configuring PMP: untrusted task gets R+X on its own code, R+W on its own scratch+stack.\n");
    uart_print_hex("g_secure_secret (before)", g_secure_secret);

    pmp_configure();
    trap_init();

    uart_puts("Dropping to U-mode, jumping into the untrusted task...\n");
    drop_to_user_mode();
}
