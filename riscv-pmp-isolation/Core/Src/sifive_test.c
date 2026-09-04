#include "sifive_test.h"
#include <stdint.h>

/* QEMU virt machine's sifive_test "finisher" device, confirmed via the
 * machine's own device tree (test@100000, reg = <0x100000 0x1000>).
 * Writing 0x5555 there triggers a clean poweroff. */
#define SIFIVE_TEST_BASE 0x100000UL
#define FINISHER_PASS    0x5555u

void sifive_poweroff(void)
{
    *(volatile uint32_t *)SIFIVE_TEST_BASE = FINISHER_PASS;
    for (;;) {
        __asm__ volatile("wfi");
    }
}
