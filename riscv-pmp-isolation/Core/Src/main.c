#include "uart.h"

/* Phase 1: toolchain + linker + QEMU bring-up only. No PMP configuration
 * yet -- that's Phase 2 (see README.md for the full plan). This just
 * proves the whole chain (riscv64-elf-gcc -> linked M-mode ELF ->
 * QEMU virt) produces a running, UART-visible program before anything
 * security-relevant is built on top of it. */
int main(void)
{
    uart_puts("=== RISC-V PMP Isolation -- Phase 1 ===\n");
    uart_puts("Boot bring-up OK: M-mode, QEMU virt machine, polled UART.\n");
    uart_puts("No PMP configured yet -- see README.md for the phase plan.\n");

    for (;;) {
        __asm__ volatile("wfi");
    }
}
