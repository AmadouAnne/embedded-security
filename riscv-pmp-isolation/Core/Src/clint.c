#include "clint.h"

/* QEMU virt machine's CLINT (confirmed via `qemu-system-riscv64 -M virt
 * -bios none -machine dumpdtb=virt.dtb` then `dtc -I dtb -O dts virt.dtb`:
 * clint@2000000 { reg = <0x2000000 0x10000>; }; timebase-frequency =
 * <0x989680> (10000000 Hz) at the top level). mtimecmp for hart 0 is at
 * CLINT_BASE + 0x4000; mtime (shared, free-running) at CLINT_BASE + 0xBFF8. */
#define CLINT_BASE       0x02000000UL
#define CLINT_MTIMECMP0  (CLINT_BASE + 0x4000UL)
#define CLINT_MTIME      (CLINT_BASE + 0xBFF8UL)

/* 10ms per scheduling quantum at the confirmed 10MHz mtime rate -- frequent
 * enough to show several real preemptions per second in the UART log,
 * without flooding it. */
/* 20ms per scheduling quantum at the confirmed 10MHz mtime rate. Tuned
 * empirically against the tasks' own busy-wait bound (task_a.c/task_b.c):
 * QEMU's TCG software emulation of a trivial `volatile` busy-wait loop is
 * far slower than real silicon (per-instruction interpretation overhead),
 * so a naively "small" loop bound can still take multiple real seconds to
 * complete a single pass -- confirmed by temporarily testing with a
 * 200000-iteration bound where a single-threaded outer loop pass took
 * long enough that no test run (even several real seconds long) ever saw
 * a task's counter advance past its first increment, which looked
 * identical to a genuine context-switch bug until traced back to this. */
#define TIMER_INTERVAL_TICKS 200000ULL

static volatile uint64_t *const mtime    = (volatile uint64_t *)CLINT_MTIME;
static volatile uint64_t *const mtimecmp = (volatile uint64_t *)CLINT_MTIMECMP0;

void clint_rearm(void)
{
    *mtimecmp = *mtime + TIMER_INTERVAL_TICKS;
}

void clint_init(void)
{
    uintptr_t mie;
    __asm__ volatile("csrr %0, mie" : "=r"(mie));
    mie |= (uintptr_t)1u << 7; /* MTIE: machine timer interrupt enable */
    __asm__ volatile("csrw mie, %0" :: "r"(mie));

    clint_rearm();
}
