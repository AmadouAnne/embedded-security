#include "trap.h"
#include "uart.h"
#include "sifive_test.h"
#include <stdint.h>

static const char *describe_mcause(uintptr_t mcause)
{
    /* Standard RISC-V synchronous exception codes (mcause bit 63/31 clear).
     * PMP violations surface as access-fault codes -- there's no paging
     * here, so "access fault" always means "PMP said no". */
    switch (mcause) {
        case 1: return "Instruction access fault (PMP denied fetch)";
        case 5: return "Load access fault (PMP denied read)";
        case 7: return "Store/AMO access fault (PMP denied write)";
        default: return "Unexpected trap (not a PMP access fault)";
    }
}

/* GCC's "interrupt" attribute generates the full trap prologue/epilogue
 * (saving/restoring every caller-saved register around this function) --
 * no hand-written assembly trap stub needed for this demo. This handler
 * never actually returns (sifive_poweroff() halts QEMU), so the generated
 * epilogue/mret is never reached. */
void __attribute__((interrupt("machine"), aligned(4))) trap_handler(void)
{
    uintptr_t mcause, mepc, mtval;
    __asm__ volatile("csrr %0, mcause" : "=r"(mcause));
    __asm__ volatile("csrr %0, mepc"   : "=r"(mepc));
    __asm__ volatile("csrr %0, mtval"  : "=r"(mtval));

    uart_puts("\n=== TRAP CAUGHT (M-mode) ===\n");
    uart_puts(describe_mcause(mcause));
    uart_puts("\n");
    uart_print_hex("mcause", mcause);
    uart_print_hex("mepc  ", mepc);
    uart_print_hex("mtval ", mtval);
    uart_puts("PMP blocked the untrusted task's out-of-region access before it landed.\n");

    sifive_poweroff();
}

void trap_init(uintptr_t handler)
{
    /* mtvec mode bits [1:0] = 00 selects direct mode: all traps vector to
     * `handler` exactly (no offsetting by cause). Both trap_handler and
     * trap_entry are at least 4-byte aligned (all RISC-V code is),
     * satisfying mtvec's alignment requirement for direct mode. */
    __asm__ volatile("csrw mtvec, %0" :: "r"(handler));
}
