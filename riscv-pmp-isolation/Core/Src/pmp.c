#include "pmp.h"
#include <stdint.h>

#define PMP_R      0x1u
#define PMP_W      0x2u
#define PMP_X      0x4u
#define PMP_A_OFF  (0u << 3)
#define PMP_A_TOR  (1u << 3)

/* Defined by linker.ld -- the exact bounds of the untrusted task's code
 * and its scratch/stack region. Using linker symbols instead of hardcoded
 * addresses means these regions always match wherever the linker actually
 * placed them. */
extern char _untrusted_text_start[];
extern char _untrusted_text_end[];
extern char _scratch_start[];
extern char _scratch_end[];

void pmp_configure(void)
{
    /* PMP addresses are always the byte address shifted right by 2,
     * regardless of the addressing mode (TOR here). In TOR mode, entry i
     * covers [pmpaddr(i-1), pmpaddr(i)) -- entry 0's implicit lower bound
     * is 0. So entries 0 and 2 below are pure boundary markers (A=OFF,
     * no permissions of their own); entries 1 and 3 are the ones that
     * actually match and grant access. */
    uintptr_t untrusted_text_start = (uintptr_t)_untrusted_text_start >> 2;
    uintptr_t untrusted_text_end   = (uintptr_t)_untrusted_text_end   >> 2;
    uintptr_t scratch_start        = (uintptr_t)_scratch_start        >> 2;
    uintptr_t scratch_end          = (uintptr_t)_scratch_end          >> 2;

    __asm__ volatile("csrw pmpaddr0, %0" :: "r"(untrusted_text_start));
    __asm__ volatile("csrw pmpaddr1, %0" :: "r"(untrusted_text_end));
    __asm__ volatile("csrw pmpaddr2, %0" :: "r"(scratch_start));
    __asm__ volatile("csrw pmpaddr3, %0" :: "r"(scratch_end));

    uint32_t cfg0 = PMP_A_OFF;                       /* entry 0: boundary only */
    uint32_t cfg1 = PMP_A_TOR | PMP_R | PMP_X;        /* entry 1: untrusted code, R+X */
    uint32_t cfg2 = PMP_A_OFF;                        /* entry 2: boundary only */
    uint32_t cfg3 = PMP_A_TOR | PMP_R | PMP_W;        /* entry 3: scratch+stack, R+W */

    uint32_t pmpcfg0 = cfg0 | (cfg1 << 8) | (cfg2 << 16) | (cfg3 << 24);
    __asm__ volatile("csrw pmpcfg0, %0" :: "r"(pmpcfg0));
}

void pmp_configure_for_task(uintptr_t code_start, uintptr_t code_end,
                             uintptr_t data_start, uintptr_t data_end)
{
    /* Same 4-entry TOR layout as pmp_configure() above, but reprogrammed
     * for whichever task is about to run -- reusing the same entries
     * rather than allocating one set per task means the total task count
     * isn't bounded by the CPU's PMP entry count (16 here), only by RAM,
     * matching how a real RTOS's MPU port reuses its configurable regions
     * per task rather than dedicating hardware regions permanently. */
    __asm__ volatile("csrw pmpaddr0, %0" :: "r"(code_start >> 2));
    __asm__ volatile("csrw pmpaddr1, %0" :: "r"(code_end   >> 2));
    __asm__ volatile("csrw pmpaddr2, %0" :: "r"(data_start >> 2));
    __asm__ volatile("csrw pmpaddr3, %0" :: "r"(data_end   >> 2));

    uint32_t cfg0 = PMP_A_OFF;
    uint32_t cfg1 = PMP_A_TOR | PMP_R | PMP_X;
    uint32_t cfg2 = PMP_A_OFF;
    uint32_t cfg3 = PMP_A_TOR | PMP_R | PMP_W;

    uint32_t pmpcfg0 = cfg0 | (cfg1 << 8) | (cfg2 << 16) | (cfg3 << 24);
    __asm__ volatile("csrw pmpcfg0, %0" :: "r"(pmpcfg0));
}
